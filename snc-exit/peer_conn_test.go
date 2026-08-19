// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// stalledTLSPeer starts a TLS listener that completes the handshake for every
// incoming connection but then never writes anything back — simulating a
// peer exit that accepted the connection yet is otherwise stuck (overloaded,
// hung goroutine, one-way network partition). Returns the listener address
// and a stop func.
func stalledTLSPeer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	cfg, err := selfSignedTLSConfig(t.TempDir())
	if err != nil {
		t.Fatalf("selfSignedTLSConfig: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Drive the handshake, then sit on the connection forever without
			// replying — until the test tears the listener down.
			go func(c net.Conn) {
				buf := make([]byte, 4096)
				c.Read(buf) //nolint:errcheck // ignore: just drains the request, never responds
				<-done
				c.Close()
			}(conn)
		}
	}()
	return ln.Addr().String(), func() {
		close(done)
		ln.Close()
	}
}

// TestDialPeerRespectsDeadlineOnStalledPeer verifies the Part A fix: a peer
// that accepts the TCP/TLS connection but never sends a response must not
// block dialPeer past the caller-supplied deadline. Before the fix, dialPeer
// set no deadline at all on the connection once past the TLS dial, so
// http.ReadResponse could hang indefinitely — the root cause of the exit's
// unbounded fallback chain (see handler.go's dialDecisionBudget).
func TestDialPeerRespectsDeadlineOnStalledPeer(t *testing.T) {
	addr, stop := stalledTLSPeer(t)
	defer stop()

	peer := &PeerEntry{Addr: addr}
	budget := 1500 * time.Millisecond
	deadline := time.Now().Add(budget)

	start := time.Now()
	_, err := dialPeer(peer, "example.com:443", "test-node-token", deadline)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error from a peer that never responds, got nil")
	}
	// Generous margin over the budget for scheduling/GC jitter, but this must
	// stay well clear of "hangs forever" — a regression here would time out
	// the whole test run instead of failing cleanly.
	if elapsed > budget+2*time.Second {
		t.Errorf("dialPeer took %v, expected to give up at or shortly after the %v deadline", elapsed, budget)
	}
}

// TestDialPeerBudgetAlreadyExhausted verifies dialPeer fails fast (no dial
// attempt at all) when the shared deadline has already passed before it's
// even called — the case where earlier fallback stages consumed the whole
// dialDecisionBudget.
func TestDialPeerBudgetAlreadyExhausted(t *testing.T) {
	peer := &PeerEntry{Addr: "127.0.0.1:1"} // nothing listening; would fail anyway
	start := time.Now()
	_, err := dialPeer(peer, "example.com:443", "test-node-token", time.Now().Add(-time.Second))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error when the deadline has already passed")
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("dialPeer took %v with an already-expired deadline, expected an immediate failure", elapsed)
	}
}
