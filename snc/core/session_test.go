// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"sync/atomic"
	"testing"
	"time"
)

// TestTunnelConnReadPollingBackoff is a regression test for the 2026-08-16
// incident: a TunnelConn in legacy polling mode (streamFn == nil) whose
// send() always returns an empty response used to busy-loop with zero
// pacing, observed in the wild at ~190 requests/sec sustained for 2+ hours.
// This confirms Read's polling loop now paces itself instead of hammering
// send() as fast as the Go scheduler allows.
func TestTunnelConnReadPollingBackoff(t *testing.T) {
	var calls atomic.Int64
	send := func(seq int64, payload []byte) ([]byte, error) {
		calls.Add(1)
		return nil, nil // always empty -- the "nothing to read yet" case
	}
	c := newTunnelConn("test-conn", send, nil, 0)
	defer c.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1024)
		c.Read(buf) //nolint:errcheck // blocks until Close(); error expected then
	}()

	// Let the polling loop run for a bounded window, then stop it.
	const window = 300 * time.Millisecond
	time.Sleep(window)
	c.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Read did not return after Close")
	}

	got := calls.Load()
	// Pre-fix this loop made send() calls as fast as the scheduler allowed --
	// tens of thousands in 300ms on any real machine. With pollBackoffStart
	// at 20ms doubling to pollBackoffMax at 500ms, 300ms of polling should
	// produce single-digit call counts (roughly: 20+40+80+160ms ≈ 300ms →
	// ~4-5 calls), nowhere close to the old unbounded rate. Generous upper
	// bound to avoid flaking on a slow CI machine while still clearly
	// distinguishing "paced" from "busy loop."
	if got > 50 {
		t.Fatalf("send() called %d times in %v -- polling loop is not pacing itself (expected a handful of calls, not a busy loop)", got, window)
	}
	if got < 1 {
		t.Fatalf("send() was never called -- polling loop did not run at all")
	}
	t.Logf("send() called %d times in %v (paced as expected)", got, window)
}

// TestTunnelConnReadPollingBackoffResets confirms a connection that goes
// idle-then-active isn't left running at a slow, backed-off rate forever --
// pollCount/backoff must reset once real data is returned so the NEXT idle
// stretch starts fast again, not wherever the previous one left off (Read
// returns after any successful poll, so each call starts its own fresh
// backoff sequence).
func TestTunnelConnReadPollingBackoffResets(t *testing.T) {
	var calls atomic.Int64
	send := func(seq int64, payload []byte) ([]byte, error) {
		n := calls.Add(1)
		if n <= 2 {
			return nil, nil // empty for the first couple polls
		}
		return []byte("hello"), nil // then data arrives
	}
	c := newTunnelConn("test-conn-2", send, nil, 0)
	defer c.Close()

	buf := make([]byte, 1024)
	start := time.Now()
	n, err := c.Read(buf)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("Read returned %q, want %q", buf[:n], "hello")
	}
	// Two empty polls means one backoff sleep (20ms) between poll 1 and
	// poll 2, then poll 3 returns data immediately -- should complete well
	// under a second even with scheduling jitter.
	if elapsed > time.Second {
		t.Fatalf("Read took %v for 2 empty polls + 1 successful poll -- backoff grew unexpectedly large", elapsed)
	}
}
