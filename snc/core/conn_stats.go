// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"encoding/json"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"tunnel_cat/binlog"
)

// ConnStatsCollector accumulates the connection-health event counters
// requested for the admin dashboard (see snc-arbiter's client_conn_stats
// table / conn_stats_client_api.go) between uploads. Event counters are
// deltas: Snapshot atomically reads and resets each one, so the caller gets
// "how many of this happened since I last asked" -- the same shape as
// DialerPool.DrainEvictions/Router.DrainFlapCount, which Snapshot also
// drains directly.
//
// One collector is shared for the lifetime of the client process (create
// once at startup, alongside the Router/DialerPool it snapshots from).
type ConnStatsCollector struct {
	connectsManual        int32
	connectsAuto          int32
	disconnectsManual     int32
	disconnectsAuto       int32
	wildcatSessionsOK     int32
	wildcatSessionsFailed int32
	wildcatSecondsTotal   int64 // sum of ended sessions' durations, OK + failed

	mu           sync.Mutex
	sessionStart time.Time // zero = not currently connected

	// wildcatStartUnix is the active WildCat session's start time (unix
	// seconds), 0 = none active. A plain atomic instead of a mutex-protected
	// time.Time specifically so save() (called from within Start/End) can
	// read it without any lock-ordering/reentrancy concern.
	wildcatStartUnix atomic.Int64

	statePath string // "" disables persistence
}

// connStatsPersisted is the on-disk shape of the pending event-delta
// counters -- written after every event and after every drain, so a counter
// incremented shortly before the process exits (user quits the app, a crash,
// an OS kill) survives to the next launch instead of vanishing with the
// atomic ints that used to be its only home. Gauges (pool/router-derived,
// SecondsOnline) aren't persisted -- Snapshot reads those fresh from live
// state every time, nothing to lose there.
type connStatsPersisted struct {
	ConnectsManual        int32 `json:"connects_manual"`
	ConnectsAuto          int32 `json:"connects_auto"`
	DisconnectsManual     int32 `json:"disconnects_manual"`
	DisconnectsAuto       int32 `json:"disconnects_auto"`
	WildcatSessionsOK     int32 `json:"wildcat_sessions_ok"`
	WildcatSessionsFailed int32 `json:"wildcat_sessions_failed"`
	WildcatSecondsTotal   int64 `json:"wildcat_seconds_total"`
	// WildcatStartUnix persists an in-progress WildCat session's start time
	// (0 = none in progress) -- Android in particular restarts its snc-core
	// process frequently (background/foreground service churn, network
	// changes) mid-session, often without ever reaching EndWildcatSession.
	// Without this, that session's very existence would be lost, not just
	// misclassified. Resolved as failed (an interrupted session, by
	// definition never confirmed to have worked) as soon as the next process
	// instance loads it -- see NewConnStatsCollector.
	WildcatStartUnix int64 `json:"wildcat_start_unix"`
}

// NewConnStatsCollector creates a collector, restoring any pending
// event-delta counters left over from a previous process instance that
// exited before it got the chance to upload them (see save's doc comment).
// statePath == "" disables persistence entirely, falling back to the
// original in-memory-only behavior -- pass "" from any caller without a
// stable per-device data directory to persist into.
func NewConnStatsCollector(statePath string) *ConnStatsCollector {
	c := &ConnStatsCollector{statePath: statePath}
	if statePath == "" {
		return c
	}
	b, err := os.ReadFile(statePath)
	if err != nil {
		return c // no prior state -- first run, or nothing was ever pending
	}
	var p connStatsPersisted
	if err := json.Unmarshal(b, &p); err != nil {
		Log.Printf("conn-stats: state file %s corrupt, ignoring: %v", statePath, err)
		return c
	}
	c.connectsManual = p.ConnectsManual
	c.connectsAuto = p.ConnectsAuto
	c.disconnectsManual = p.DisconnectsManual
	c.disconnectsAuto = p.DisconnectsAuto
	c.wildcatSessionsOK = p.WildcatSessionsOK
	c.wildcatSessionsFailed = p.WildcatSessionsFailed
	c.wildcatSecondsTotal = p.WildcatSecondsTotal
	if p.WildcatStartUnix != 0 {
		// A previous process instance's WildCat session never got closed
		// out -- the process died (crash, OS kill, force quit) before
		// EndWildcatSession ran. Resolve it as failed now rather than lose
		// it silently: an interrupted session was, by definition, never
		// confirmed to have worked. Duration is not attributed to
		// wildcatSecondsTotal since the gap may span sleep/suspend and
		// wouldn't be a meaningful session length.
		c.wildcatSessionsFailed++
		Log.Printf("conn-stats: found orphaned WildCat session from a previous process instance, counting as failed")
	}
	return c
}

// save writes the current event-delta counters to statePath, best-effort --
// a failed write just means persistence doesn't help this particular event,
// never worth surfacing as a hard error to a caller mid-event. No-op if
// persistence is disabled. Called after every counter mutation (cheap,
// these events are session-level, not high-frequency) and after every
// Snapshot drain, so the on-disk copy never lags the in-memory one.
func (c *ConnStatsCollector) save() {
	if c.statePath == "" {
		return
	}
	p := connStatsPersisted{
		ConnectsManual:        atomic.LoadInt32(&c.connectsManual),
		ConnectsAuto:          atomic.LoadInt32(&c.connectsAuto),
		DisconnectsManual:     atomic.LoadInt32(&c.disconnectsManual),
		DisconnectsAuto:       atomic.LoadInt32(&c.disconnectsAuto),
		WildcatSessionsOK:     atomic.LoadInt32(&c.wildcatSessionsOK),
		WildcatSessionsFailed: atomic.LoadInt32(&c.wildcatSessionsFailed),
		WildcatSecondsTotal:   atomic.LoadInt64(&c.wildcatSecondsTotal),
		WildcatStartUnix:      c.wildcatStartUnix.Load(),
	}
	b, err := json.Marshal(p)
	if err != nil {
		return
	}
	tmp := c.statePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return
	}
	os.Rename(tmp, c.statePath) //nolint:errcheck
}

// IncConnect records one successful connect, split manual (user pressed
// Connect) vs auto (watchdog restart, network-change reconnect, etc.). Wire
// this into each platform's onConnect(autoReconnect bool) wrapper.
func (c *ConnStatsCollector) IncConnect(manual bool) {
	if manual {
		atomic.AddInt32(&c.connectsManual, 1)
	} else {
		atomic.AddInt32(&c.connectsAuto, 1)
	}
	c.mu.Lock()
	c.sessionStart = time.Now()
	c.mu.Unlock()
	c.save()
	Log.Printf("conn-stats: connect manual=%v", manual)
}

// IncDisconnect records one disconnect, same manual/auto split as IncConnect.
// Wire this into each platform's onDisconnect(autoReconnect bool) wrapper.
func (c *ConnStatsCollector) IncDisconnect(manual bool) {
	if manual {
		atomic.AddInt32(&c.disconnectsManual, 1)
	} else {
		atomic.AddInt32(&c.disconnectsAuto, 1)
	}
	c.mu.Lock()
	c.sessionStart = time.Time{}
	c.mu.Unlock()
	c.save()
	Log.Printf("conn-stats: disconnect manual=%v", manual)
	// Fallback safety net: a WildCat session still marked active at full
	// disconnect means the platform's disconnect handler didn't already
	// close it out with a real byte-based verdict (EndWildcatSession) before
	// calling us -- e.g. an abrupt/auto disconnect path that skipped it.
	// Rather than leave wildcatStart dangling forever (never reported, and
	// blocking the next StartWildcatSession from resetting the clock), count
	// it as failed: the safe default for a session we never confirmed moved
	// real traffic. No-op if the caller already closed it out properly.
	c.EndWildcatSession(false, "disconnect fallback: no explicit EndWildcatSession before IncDisconnect")
}

// StartWildcatSession marks WildCat (third-party relay) as the active
// transport for this connection, starting the clock EndWildcatSession uses
// to compute the session's duration. Wire into each platform's connect path
// when WildCat is the chosen transport for this session (WildCat mode is
// decided once per connect on every platform, not toggled live mid-session).
// Idempotent: calling this again while already active is a no-op, so
// callers don't need to track whether one is already in progress.
func (c *ConnStatsCollector) StartWildcatSession() {
	if c.wildcatStartUnix.CompareAndSwap(0, time.Now().Unix()) {
		c.save()
		Log.Printf("conn-stats: wildcat session started")
	} else {
		Log.Printf("conn-stats: wildcat session already active, StartWildcatSession no-op")
	}
}

// EndWildcatSession closes out the current WildCat session, if one is
// active (no-op otherwise -- callers don't need to track state). success is
// the caller's own verdict on whether the session actually worked: it must
// reflect a real, live WLWTP/TURN session having been established, not just
// "WildCat was toggled on" -- see each platform's disconnect handler, which
// derives it from the relay pool's HadLiveSession() on the session's own Pool
// instance. Deliberately NOT based on bytes transferred (tried that first --
// see git history 2026-08-16 -- but counting bytes only on a relayed
// connection's close raced disconnect and undercounted real, working
// sessions as failed whenever a tunnel was still open at that moment).
// Always records the session's duration (OK or failed) into
// wildcatSecondsTotal.
//
// reason is a short, human-readable explanation for the verdict (e.g. "live
// WLWTP/TURN session established", "pool.HadLiveSession()=false: no relay
// ever came up", "disconnect fallback: ..."). Always logged -- added
// 2026-08-19 after investigating a real user's WildCat failures and finding
// this function previously recorded the outcome as a bare counter with zero
// accompanying log line, making the failure structurally undiagnosable from
// uploaded client logs even though the upload pipeline itself worked fine.
func (c *ConnStatsCollector) EndWildcatSession(success bool, reason string) {
	start := c.wildcatStartUnix.Swap(0)
	if start == 0 {
		Log.Printf("conn-stats: EndWildcatSession(success=%v, reason=%q) no-op — no session was active", success, reason)
		return
	}
	dur := time.Now().Unix() - start
	if dur < 0 {
		dur = 0
	}
	atomic.AddInt64(&c.wildcatSecondsTotal, dur)
	if success {
		atomic.AddInt32(&c.wildcatSessionsOK, 1)
	} else {
		atomic.AddInt32(&c.wildcatSessionsFailed, 1)
	}
	c.save()
	Log.Printf("conn-stats: wildcat session ended success=%v duration=%ds reason=%q", success, dur, reason)
}

// SecondsOnline returns the current session's elapsed time, or 0 if not
// currently connected (IncConnect not called since the last IncDisconnect).
func (c *ConnStatsCollector) SecondsOnline() int64 {
	c.mu.Lock()
	start := c.sessionStart
	c.mu.Unlock()
	if start.IsZero() {
		return 0
	}
	return int64(time.Since(start).Seconds())
}

// ConnStatsSnapshot is what gets sent in one upload -- see
// tunnel_cat/snc-arbiter/conn_stats_client_api.go's clientConnStatsPayload,
// whose JSON field names this must match.
type ConnStatsSnapshot struct {
	PoolTCP               int
	PoolUDP               int
	UnreachableControls   int
	TotalControls         int
	SecondsOnline         int64
	AvgFailRatio          float64
	ConnectsManual        int
	ConnectsAuto          int
	DisconnectsManual     int
	DisconnectsAuto       int
	FlapEvents            int
	Evictions             int
	WildcatSessionsOK     int
	WildcatSessionsFailed int
	WildcatSecondsTotal   int64
}

// Snapshot collects one report's worth of data: gauge values read fresh
// from router/pool right now, plus every event-delta counter drained (reset
// to zero) as a side effect -- so this must only be called by the uploader's
// own tick, never speculatively, or event counts will be lost between real
// uploads.
//
// pool/router may be nil (e.g. not yet connected) -- gauges come back zero
// and only the collector's own event deltas are still meaningful.
func (c *ConnStatsCollector) Snapshot(pool *DialerPool, router *Router) ConnStatsSnapshot {
	var s ConnStatsSnapshot
	s.SecondsOnline = c.SecondsOnline()
	s.ConnectsManual = int(atomic.SwapInt32(&c.connectsManual, 0))
	s.ConnectsAuto = int(atomic.SwapInt32(&c.connectsAuto, 0))
	s.DisconnectsManual = int(atomic.SwapInt32(&c.disconnectsManual, 0))
	s.DisconnectsAuto = int(atomic.SwapInt32(&c.disconnectsAuto, 0))
	s.WildcatSessionsOK = int(atomic.SwapInt32(&c.wildcatSessionsOK, 0))
	s.WildcatSessionsFailed = int(atomic.SwapInt32(&c.wildcatSessionsFailed, 0))
	s.WildcatSecondsTotal = atomic.SwapInt64(&c.wildcatSecondsTotal, 0)
	// Persist the now-zeroed counters immediately -- otherwise a process exit
	// between this drain and the caller's actual successful upload would
	// leave the stale pre-drain counts on disk, double-counting them into
	// whatever accumulates next after the process restarts.
	c.save()

	if router != nil {
		addrs := router.UnreachableControls()
		s.UnreachableControls = len(addrs)
		for _, addr := range addrs {
			StatsRing.WriteRecord(binlog.TagControlDead, []byte(addr))
		}
		all := router.AllControlAddrs()
		s.TotalControls = len(all)
		s.FlapEvents = router.DrainFlapCount()
	}
	if pool != nil {
		s.Evictions = pool.DrainEvictions()
		tcp, udp, avgFail := poolComposition(pool, router)
		s.PoolTCP, s.PoolUDP, s.AvgFailRatio = tcp, udp, avgFail
	}
	return s
}

// poolComposition walks the pool's dialers, classifying each by transport
// (via router.ControlTransport, keyed by the dialer's own ServerURL -- the
// only place this mapping lives, see Router.ControlTransport's doc comment)
// and averaging FailRatio() across all of them.
func poolComposition(pool *DialerPool, router *Router) (tcp, udp int, avgFail float64) {
	dialers := pool.Dialers()
	if len(dialers) == 0 {
		return 0, 0, 0
	}
	var sumFail float64
	for _, td := range dialers {
		isUDP := false
		if router != nil {
			isUDP = router.ControlTransport(td.ServerURL()) == transportUDP
		}
		if isUDP {
			udp++
		} else {
			tcp++
		}
		sumFail += td.FailRatio()
	}
	return tcp, udp, sumFail / float64(len(dialers))
}
