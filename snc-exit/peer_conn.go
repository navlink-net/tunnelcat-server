// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// peerConn wraps a hijacked server-side HTTP connection (Exit2 side) or a raw
// TCP connection obtained after an HTTP CONNECT-style upgrade (Exit1 side).
// It satisfies net.Conn so the session pool can treat it like a direct dial.
type peerConn struct {
	conn net.Conn
	r    io.Reader // may be a bufio.Reader with unread bytes after HTTP header
}

func (c *peerConn) Read(b []byte) (int, error)         { return c.r.Read(b) }
func (c *peerConn) Write(b []byte) (int, error)        { return c.conn.Write(b) }
func (c *peerConn) Close() error                       { return c.conn.Close() }
func (c *peerConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *peerConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *peerConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *peerConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *peerConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// dialPeer opens a TCP connection to peer, sends the upgrade request, and
// returns a net.Conn ready for bidirectional piping to the target.
// nodeToken is this exit's own node token (used as X-Peer-Token).
// deadline bounds the entire call (TLS dial + request write + response read) —
// callers share one deadline across a whole fallback chain (see
// dialDecisionBudget in handler.go) so a stalled peer can never block past it.
func dialPeer(peer *PeerEntry, target, nodeToken string, deadline time.Time) (net.Conn, error) {
	addr := peer.Addr
	if !strings.Contains(addr, ":") {
		addr = addr + ":443"
	}

	dialTimeout := time.Until(deadline)
	if dialTimeout <= 0 {
		return nil, fmt.Errorf("peer dial %s: budget exhausted", addr)
	}

	// Dial raw TLS to the peer exit (skip hostname verification — exits use
	// self-signed or LE certs; arbiter fingerprint checking is out of scope here).
	rawConn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: dialTimeout},
		"tcp", addr,
		&tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	)
	if err != nil {
		return nil, fmt.Errorf("peer dial %s: %w", addr, err)
	}
	// Bounds the request write below AND the response read further down —
	// previously unbounded, which let a stalled peer hang this call (and thus
	// the whole fallback chain) indefinitely.
	rawConn.SetDeadline(deadline) //nolint:errcheck

	body, _ := json.Marshal(map[string]string{"target": target})

	req, err := http.NewRequest(http.MethodPost, "https://"+addr+"/api/peer/connect", bytes.NewReader(body))
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Peer-Token", nodeToken)
	req.Header.Set("X-No-Forward", "1")

	if err := req.Write(rawConn); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("peer send request: %w", err)
	}

	// Read only the response status line + headers; leave body stream open.
	br := bufio.NewReader(rawConn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("peer read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		rawConn.Close()
		return nil, fmt.Errorf("peer connect: status %d", resp.StatusCode)
	}

	// Handshake is done — clear the dial-decision deadline before handing off
	// the connection for long-lived bidirectional piping, otherwise it would
	// be killed mid-stream once the (short) dial budget elapses.
	rawConn.SetDeadline(time.Time{}) //nolint:errcheck

	// The response body IS the raw bidirectional pipe — no more HTTP framing.
	// bufio.Reader may have buffered bytes ahead; wrap so they are replayed.
	return &peerConn{conn: rawConn, r: br}, nil
}

// dialBestPeer races dialPeer against every candidate in parallel and
// returns the connection that completes first. dialPeer only succeeds once
// the peer itself has dialed target (see servePeerConnect's targetConn dial
// before it writes "200 OK"), so the winner of the race is the candidate
// with the lowest real end-to-end time to THIS target -- not a guess based
// on the peer's region or general health. Racing instead of a separate
// cheap probe-then-dial step also means session setup is bounded by the
// fastest candidate, never by trying candidates one at a time. Connections
// from slower or failed candidates are drained and closed in the
// background so the caller never blocks on stragglers.
func dialBestPeer(candidates []PeerEntry, target, nodeToken string, deadline time.Time) (net.Conn, PeerEntry, error) {
	if len(candidates) == 0 {
		return nil, PeerEntry{}, fmt.Errorf("no candidate peers")
	}
	type result struct {
		conn net.Conn
		peer PeerEntry
		err  error
	}
	ch := make(chan result, len(candidates))
	for _, p := range candidates {
		go func(p PeerEntry) {
			conn, err := dialPeer(&p, target, nodeToken, deadline)
			ch <- result{conn, p, err}
		}(p)
	}

	var errs []string
	for i := 0; i < len(candidates); i++ {
		r := <-ch
		if r.err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", r.peer.Addr, r.err))
			continue
		}
		if remaining := len(candidates) - i - 1; remaining > 0 {
			go func(n int) {
				for j := 0; j < n; j++ {
					if lr := <-ch; lr.err == nil {
						lr.conn.Close()
					}
				}
			}(remaining)
		}
		return r.conn, r.peer, nil
	}
	return nil, PeerEntry{}, fmt.Errorf("all %d peer(s) failed: %s", len(candidates), strings.Join(errs, "; "))
}

// ── Peer auth cache ───────────────────────────────────────────────────────────

// peerAuthCache caches validated peer node tokens to avoid per-request arbiter
// calls.  TTL matches localCacheTTL used in the user session auth cache.
type peerAuthCache struct {
	auth *authClient
	mu   sync.Mutex
	hits map[string]peerCacheEntry
}

type peerCacheEntry struct {
	addr        string
	validatedAt time.Time
}

func newPeerAuthCache(auth *authClient) *peerAuthCache {
	return &peerAuthCache{auth: auth, hits: make(map[string]peerCacheEntry)}
}

// Validate returns the peer's address if the token is a valid live exit node.
func (c *peerAuthCache) Validate(token string) (addr string, ok bool) {
	now := time.Now()
	c.mu.Lock()
	if e, found := c.hits[token]; found && now.Sub(e.validatedAt) < localCacheTTL {
		c.mu.Unlock()
		return e.addr, true
	}
	c.mu.Unlock()

	peerAddr, err := c.auth.validatePeerToken(token)
	if err != nil {
		logWarnf("peer-auth: validate failed token=%.8s…: %v", token, err)
		return "", false
	}

	c.mu.Lock()
	c.hits[token] = peerCacheEntry{addr: peerAddr, validatedAt: now}
	cutoff := now.Add(-localStaleTTL)
	for k, v := range c.hits {
		if v.validatedAt.Before(cutoff) {
			delete(c.hits, k)
		}
	}
	c.mu.Unlock()

	return peerAddr, true
}

// ValidateNode returns the node's address if the token belongs to any live approved
// node (exit or control). Used by the wildcat relay endpoint, which accepts requests
// from control nodes rather than peer exits.
func (c *peerAuthCache) ValidateNode(token string) (addr string, ok bool) {
	now := time.Now()
	c.mu.Lock()
	if e, found := c.hits[token]; found && now.Sub(e.validatedAt) < localCacheTTL {
		c.mu.Unlock()
		return e.addr, true
	}
	c.mu.Unlock()

	nodeAddr, _, err := c.auth.validateNodeToken(token)
	if err != nil {
		logWarnf("peer-auth: validate node failed token=%.8s…: %v", token, err)
		return "", false
	}

	c.mu.Lock()
	c.hits[token] = peerCacheEntry{addr: nodeAddr, validatedAt: now}
	cutoff := now.Add(-localStaleTTL)
	for k, v := range c.hits {
		if v.validatedAt.Before(cutoff) {
			delete(c.hits, k)
		}
	}
	c.mu.Unlock()

	return nodeAddr, true
}
