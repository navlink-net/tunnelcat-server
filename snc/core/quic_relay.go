// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

// QUIC-backed client<->control transport. Replaces the old UDP-SNCU fallback
// (udp_relay.go/udp_control.go, both removed) with a real QUIC connection to
// the control node.
//
// The key property that makes this a small, surgical change: the
// channel-byte + uTLS-handshake + HTTP machinery in tunnel.go (doPost,
// openStreamPost, retries, eviction windows, hooks — all of it) has no idea
// what carries its bytes. NewQUICRelayDialer only replaces TunnelDialer's raw
// connection factory (already an existing extension point, SetDialFunc/
// rawDialOverride, used by WildCat mode) with "open a new stream on an
// already-established QUIC connection" instead of "dial a new TCP socket".
// snc-control's tcpProxy.handle sees byte-identical application data either
// way (see snc-control/quic_tunnel.go's quicStreamConn).
//
// Unlike the old UDP fallback, streaming stays enabled: QUIC gives real
// ordered, reliable, multiplexed delivery, so a new stream per HTTP request
// is cheap (no handshake — it reuses the one established QUIC connection)
// and gets pipelining for free, without the legacy-polling/pipeWidth-less
// machinery the old datagram-based fallback needed to work around not having
// any of that.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

// quicClientALPN must match snc-control's quicALPN constant.
const quicClientALPN = "snc-tun-v1"

func quicClientTLSConfig() *tls.Config {
	return &tls.Config{
		NextProtos: []string{quicClientALPN},
		// Fleet uses self-signed certs; trust comes from node auth/manifest
		// pinning elsewhere in the stack, not the TLS chain -- same pattern
		// as updateHTTPClient's transport in updater.go.
		InsecureSkipVerify: true, //nolint:gosec
	}
}

func quicConnConfig() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout: 60 * time.Second,
		// A real handshake completes in well under a second on any working
		// path (measured 72-445ms against the live control fleet). This is
		// not a "how long does success take" budget, it's "how long to wait
		// before giving up" -- UDP has no RST-equivalent, so a blocked/
		// blackholed path (mobile carrier DPI, etc.) can only be recognised
		// by timing out, and quic-go just keeps retrying Initial packets via
		// its own PTO backoff until this fires. 10s meant a single bad
		// control could stall every real request routed through it for a
		// full 10s before the normal per-dialer backoff/eviction machinery
		// even got a failure to react to -- confirmed live 2026-08-25 via a
		// pinned realtime-UDP dialer hammering a QUIC-blocked mobile network
		// once per DNS query. 1s gives ~2-4x headroom over the worst
		// observed real handshake and lets failures surface fast enough for
		// dialWindow/circuit-breaker eviction to actually do its job instead
		// of every caller eating the full stall individually.
		HandshakeIdleTimeout: 1 * time.Second,
		KeepAlivePeriod:      20 * time.Second,
	}
}

// ProbeControlQUIC performs a real QUIC handshake against addr and reports
// whether it succeeded, along with the handshake RTT. Used by ProbeDataPlane
// as an additional transport tier alongside TCP.
func ProbeControlQUIC(addr string, timeout time.Duration) (rtt time.Duration, ok bool) {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = addr + ":443"
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	conn, err := quic.DialAddr(ctx, addr, quicClientTLSConfig(), nil)
	if err != nil {
		return 0, false
	}
	elapsed := time.Since(start)
	conn.CloseWithError(0, "") //nolint:errcheck
	return elapsed, true
}

// quicMaxConsecutiveDialFails bounds how many back-to-back dial failures
// quicControlConn tolerates before Failed() reports true. Needed for the
// case Failed()'s conn==nil check alone can't see: a path where QUIC is
// blocked outright and has NEVER once succeeded (e.g. a mobile carrier that
// drops all UDP:443) never gets a *quic.Conn to watch for closure, so
// without this a caller like udp_assoc.go's realtime-dialer pinning would
// retry the doomed dial forever, once per new destination, instead of ever
// falling back to the pool.
const quicMaxConsecutiveDialFails = 3

// quicControlConn manages one persistent QUIC connection to a control node,
// handing out fresh streams (wrapped as net.Conn) on demand and transparently
// reconnecting if the underlying connection has died.
type quicControlConn struct {
	addr string

	mu                   sync.Mutex
	conn                 *quic.Conn
	consecutiveDialFails int
}

func newQUICControlConn(addr string) *quicControlConn {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = addr + ":443"
	}
	return &quicControlConn{addr: addr}
}

func (q *quicControlConn) connect(ctx context.Context) (*quic.Conn, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.conn != nil {
		select {
		case <-q.conn.Context().Done():
			q.conn = nil // dead; fall through and redial
		default:
			return q.conn, nil
		}
	}
	// Matches quicConnConfig's HandshakeIdleTimeout -- this outer context is
	// just a safety net around the whole DialAddr call, not an independent
	// budget; no reason for it to be looser than the inner timeout it wraps.
	dialCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(dialCtx, q.addr, quicClientTLSConfig(), quicConnConfig())
	if err != nil {
		q.consecutiveDialFails++
		return nil, fmt.Errorf("quic-control: dial %s: %w", q.addr, err)
	}
	q.consecutiveDialFails = 0
	q.conn = conn
	return conn, nil
}

// openStream returns a fresh net.Conn-wrapped QUIC stream, reconnecting the
// underlying QUIC connection first if it had died.
func (q *quicControlConn) openStream(ctx context.Context) (net.Conn, error) {
	conn, err := q.connect(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		q.mu.Lock()
		if q.conn == conn {
			q.conn = nil // this connection is bad; next call redials
		}
		q.consecutiveDialFails++ // counts toward Failed()'s give-up threshold too
		q.mu.Unlock()
		return nil, fmt.Errorf("quic-control: open stream: %w", err)
	}
	return &quicClientStreamConn{stream: stream, conn: conn}, nil
}

// Failed reports whether this QUIC path currently looks unusable: either a
// previously-established connection has since closed, or dialing has failed
// quicMaxConsecutiveDialFails times in a row without ever succeeding (the
// case a bare conn==nil check can't distinguish from "just hasn't been
// dialed yet" -- see that constant's doc comment).
func (q *quicControlConn) Failed() bool {
	q.mu.Lock()
	if q.consecutiveDialFails >= quicMaxConsecutiveDialFails {
		q.mu.Unlock()
		return true
	}
	conn := q.conn
	q.mu.Unlock()
	if conn == nil {
		return false
	}
	select {
	case <-conn.Context().Done():
		return true
	default:
		return false
	}
}

// Close tears down the underlying QUIC connection, if any.
func (q *quicControlConn) Close() error {
	q.mu.Lock()
	conn := q.conn
	q.conn = nil
	q.mu.Unlock()
	if conn != nil {
		return conn.CloseWithError(0, "")
	}
	return nil
}

// quicClientStreamConn adapts a *quic.Stream into a net.Conn, borrowing the
// parent connection's addresses (a stream has no address of its own).
type quicClientStreamConn struct {
	stream *quic.Stream
	conn   *quic.Conn
}

func (c *quicClientStreamConn) Read(p []byte) (int, error)  { return c.stream.Read(p) }
func (c *quicClientStreamConn) Write(p []byte) (int, error) { return c.stream.Write(p) }
func (c *quicClientStreamConn) Close() error                { return c.stream.Close() }
func (c *quicClientStreamConn) LocalAddr() net.Addr         { return c.conn.LocalAddr() }
func (c *quicClientStreamConn) RemoteAddr() net.Addr        { return c.conn.RemoteAddr() }
func (c *quicClientStreamConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}
func (c *quicClientStreamConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}
func (c *quicClientStreamConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

// NewQUICRelayDialer returns a TunnelDialer whose requests ride QUIC streams
// to controlAddr instead of raw TCP sockets. Use when ProbeDataPlane found
// the control reachable only via QUIC (TCP blocked/failed).
func NewQUICRelayDialer(controlAddr string, auth *Authenticator) *TunnelDialer {
	qc := newQUICControlConn(controlAddr)
	td := newTunnelDialer(auth, true)
	td.SetDialFunc(func(ctx context.Context, _ string) (net.Conn, error) {
		return qc.openStream(ctx)
	})
	td.quicConn = qc
	return td
}
