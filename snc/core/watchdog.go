// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// connActivity tracks payload throughput for a single tunnel connection
// (control-node probe, SOCKS5-relayed TCP stream, or UDP relay session --
// all share the same watchdog since none of them are distinguishable at
// this layer, see the package doc comment below).
type connActivity struct {
	firstSentAt    time.Time // time of the first send since this entry was created
	lastSentAt     time.Time
	lastGoodRecvAt time.Time
}

// TunnelTrafficMonitor tracks payload throughput per connection so the
// watchdog can detect a one-sided outage: data sent but nothing received.
// Zero-payload frames and bypass-routed traffic are excluded by the callers.
//
// Previously this held a single global pair of timestamps fed by every
// connection in the process indiscriminately (dial-pool candidates racing
// several nodes in parallel, control-plane path-selection probes, and real
// SOCKS5-relayed user data all funneled into the same two variables).
// Confirmed in production (2026-08-10, arbiter+exit logs cross-referenced
// against this code) that this let ONE stalled or already-abandoned
// connection (e.g. a dial-pool candidate superseded by a retry on another
// node) trip IsStuck() and force a full-process restart
// (os.Exit(exitCodeStallRestart) on Android, same pattern on every other
// platform) even while a DIFFERENT connection in the same process was
// actively carrying real traffic -- the global "last sent" timestamp
// happened to belong to the stalled connection, and nothing else had *new*
// bytes to report in that exact tunnelStuckTimeout window, which is a
// routine, non-broken idle gap (e.g. between DNS bursts), not evidence of a
// dead tunnel. Tracking per-connection means a single stalled connection can
// no longer single-handedly declare the whole tunnel dead while any other
// tracked connection is healthy.
type TunnelTrafficMonitor struct {
	mu    sync.Mutex
	conns map[string]*connActivity

	// lastAnyRecvAt is the last time ANY control node answered a tunnel POST
	// with a real HTTP 200, even a pure empty-ack/padding response with no
	// application payload (RecordTunnelRecv above ignores those on purpose --
	// they don't prove any specific app stream is progressing). IsStuck uses
	// this as the actual last line of defense: the watchdog's job is to
	// catch total connectivity loss when every other recovery mechanism
	// (per-control retry, pool rebuild, router re-probe) has already failed,
	// not to react to one specific app stream stalling while the tunnel
	// itself is demonstrably alive and answering. Explicit product
	// direction, 2026-08-22: "вочдог — это последний рубеж на случай
	// полного отказа нормальных механизмов восстановления/фоллбэка".
	lastAnyRecvAt time.Time
}

// RecordAnyResponse notes that a control node just answered a tunnel POST
// with HTTP 200, regardless of whether the (decrypted) body carried any
// real application payload. Call this on every successful round-trip --
// see IsStuck's doc comment for why this is tracked separately from the
// per-connection payload bookkeeping above.
func (m *TunnelTrafficMonitor) RecordAnyResponse() {
	m.mu.Lock()
	m.lastAnyRecvAt = time.Now()
	m.mu.Unlock()
}

// TunnelMonitor is the package-level instance shared between tunnel.go and the tray watchdog.
var TunnelMonitor TunnelTrafficMonitor

// totalBytesSent/totalBytesRecv are process-wide cumulative application
// payload counters, incremented alongside TunnelTrafficMonitor's per-
// connection stuck-detection bookkeeping (RecordTunnelSent/RecordTunnelRecv
// already see every non-zero-length send/recv, so no new call sites are
// needed anywhere else in the tunnel data path). Atomic, not mutex-guarded,
// since they're independent counters read far more often (a UI polling once
// a second) than the mutex-guarded per-connection map is touched.
var totalBytesSent, totalBytesRecv int64

// TotalBytes returns the cumulative application-payload bytes sent and
// received by this process since startup -- for a live "uplink/downlink"
// display, not for billing/stats accuracy (padding/header bytes and
// bypass-routed traffic are excluded, same as the watchdog's own view).
func TotalBytes() (sent, recv int64) {
	return atomic.LoadInt64(&totalBytesSent), atomic.LoadInt64(&totalBytesRecv)
}

func (m *TunnelTrafficMonitor) entryLocked(connID string) *connActivity {
	if m.conns == nil {
		m.conns = make(map[string]*connActivity)
	}
	c := m.conns[connID]
	if c == nil {
		c = &connActivity{}
		m.conns[connID] = c
	}
	return c
}

// RecordTunnelSent notes that n bytes of application payload were sent through
// the tunnel on connID.  n == 0 is ignored (padding / header-only frames);
// connID == "" is ignored (caller doesn't have a connection to attribute this
// to, so there's nothing meaningful to track).
func (m *TunnelTrafficMonitor) RecordTunnelSent(connID string, n int) {
	if n == 0 || connID == "" {
		return
	}
	atomic.AddInt64(&totalBytesSent, int64(n))
	m.mu.Lock()
	c := m.entryLocked(connID)
	if c.firstSentAt.IsZero() {
		c.firstSentAt = time.Now()
	}
	c.lastSentAt = time.Now()
	m.mu.Unlock()
}

// RecordTunnelRecv notes that n bytes of real data arrived from the tunnel on
// connID.  n == 0 is ignored (padding-only responses where dlen == 0).
func (m *TunnelTrafficMonitor) RecordTunnelRecv(connID string, n int) {
	if n == 0 || connID == "" {
		return
	}
	atomic.AddInt64(&totalBytesRecv, int64(n))
	m.mu.Lock()
	c := m.entryLocked(connID)
	c.lastGoodRecvAt = time.Now()
	m.mu.Unlock()
}

// Forget drops connID's tracked state -- call when a connection closes
// normally so it stops being able to influence IsStuck. Safe to skip: stale
// entries also expire on their own via connActivityTTL inside IsStuck, so a
// missed Forget on some close path is bounded, not a leak that matters here.
func (m *TunnelTrafficMonitor) Forget(connID string) {
	if connID == "" {
		return
	}
	m.mu.Lock()
	delete(m.conns, connID)
	m.mu.Unlock()
}

// tunnelStuckTimeout is how long outbound traffic can go unanswered before a
// connection is considered one-sided.
const tunnelStuckTimeout = 10 * time.Second

// connActivityTTL bounds how long a connection is remembered without a
// Forget() call before it's dropped and stops being considered at all --
// guards against leaked entries (a caller that never explicitly closes)
// permanently padding the map or, worse, a long-dead entry's stale
// lastSentAt somehow re-entering the "recent" window through a clock issue.
const connActivityTTL = 2 * time.Minute

// IsStuck reports whether the tunnel as a whole looks dead: true only when
// EVERY connection that has recently sent real data is one-sided (no real
// reply within tunnelStuckTimeout). A single stalled connection can no
// longer trigger a false restart while at least one other tracked
// connection is healthy or genuinely idle -- see the package doc comment.
//
// Per connection, the semantics match the original global check: when recv
// has never been observed for that connection, it's considered stuck only
// after a full tunnelStuckTimeout has elapsed since ITS first send (cold-start
// grace period, e.g. first round-trip latency exceeding the check interval).
func (m *TunnelTrafficMonitor) IsStuck() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	// Last line of defense, not first: a control node answering at all --
	// even a content-free ack -- proves the tunnel itself is up. A specific
	// app stream not getting its own real data back within tunnelStuckTimeout
	// is exactly what the per-connection checks below exist to catch and
	// recover from at a smaller scope (stream re-open, pool re-probe); it is
	// not evidence the whole tunnel is dead, and must not trigger a full
	// process restart on its own while the control channel is demonstrably
	// alive. See RecordAnyResponse's doc comment.
	if !m.lastAnyRecvAt.IsZero() && now.Sub(m.lastAnyRecvAt) <= tunnelStuckTimeout {
		return false
	}
	// stuckConns/staleDropped are only collected for the log line below --
	// negligible cost (this map is small: one entry per currently-open
	// connection), and having the connID + exact silence duration in the log
	// is what turns "watchdog restarted the tunnel" from a black box into
	// something diagnosable from a single client log line, instead of the
	// multi-hour, multi-server log correlation this fix itself required to
	// even find the bug (see the package doc comment).
	var stuckConns []string
	var staleDropped int
	sawRecentSend := false
	for connID, c := range m.conns {
		if now.Sub(c.lastSentAt) > connActivityTTL {
			delete(m.conns, connID) // never explicitly closed -- stale, drop it
			staleDropped++
			continue
		}
		if now.Sub(c.lastSentAt) > tunnelStuckTimeout {
			continue // idle on this connection -- not evidence either way
		}
		sawRecentSend = true
		if c.lastGoodRecvAt.IsZero() {
			if now.Sub(c.firstSentAt) <= tunnelStuckTimeout {
				return false // this connection is still in its cold-start grace period
			}
			stuckConns = append(stuckConns, fmt.Sprintf("%.8s(never recv, sent %s ago)", connID, now.Sub(c.firstSentAt).Round(time.Millisecond)))
			continue // never received anything on this one, past grace -- it's stuck
		}
		if now.Sub(c.lastGoodRecvAt) <= tunnelStuckTimeout {
			return false // this connection is healthy -- the tunnel is not stuck
		}
		stuckConns = append(stuckConns, fmt.Sprintf("%.8s(silent %s)", connID, now.Sub(c.lastGoodRecvAt).Round(time.Millisecond)))
	}
	if sawRecentSend {
		Log.Printf("watchdog: IsStuck=true, %d connection(s) one-sided: %s (dropped %d stale entries this check)",
			len(stuckConns), strings.Join(stuckConns, ", "), staleDropped)
	}
	return sawRecentSend
}

// Reset clears all tracked connections.  Call on each successful reconnect so
// stale pre-reconnect entries don't suppress or bias the first watchdog cycle.
func (m *TunnelTrafficMonitor) Reset() {
	m.mu.Lock()
	m.conns = nil
	m.mu.Unlock()
}
