// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"testing"
	"time"
)

func TestIsStuck_Idle(t *testing.T) {
	var m TunnelTrafficMonitor
	if m.IsStuck() {
		t.Fatal("empty monitor must not be stuck")
	}
}

func TestIsStuck_SingleConnStuckAfterGrace(t *testing.T) {
	var m TunnelTrafficMonitor
	m.RecordTunnelSent("a", 10)
	// Backdate past both the cold-start grace period and tunnelStuckTimeout,
	// but keep lastSentAt "recent" so this connection is still considered.
	m.mu.Lock()
	m.conns["a"].firstSentAt = time.Now().Add(-(tunnelStuckTimeout + time.Second))
	m.conns["a"].lastSentAt = time.Now().Add(-time.Millisecond)
	m.mu.Unlock()

	if !m.IsStuck() {
		t.Fatal("a connection that sent long ago and never received anything must be stuck")
	}
}

func TestIsStuck_SingleConnColdStartGrace(t *testing.T) {
	var m TunnelTrafficMonitor
	m.RecordTunnelSent("a", 10) // firstSentAt/lastSentAt == now, well within grace

	if m.IsStuck() {
		t.Fatal("a connection still within its cold-start grace period must not be stuck")
	}
}

func TestIsStuck_SingleConnHealthy(t *testing.T) {
	var m TunnelTrafficMonitor
	m.RecordTunnelSent("a", 10)
	m.RecordTunnelRecv("a", 20)

	if m.IsStuck() {
		t.Fatal("a connection with a recent recv must not be stuck")
	}
}

// TestIsStuck_OneStalledConnDoesNotMaskAHealthyOne is the actual production
// bug this file fixes (2026-08-10): a stalled/abandoned connection (e.g. a
// losing dial-pool candidate) must NOT be able to force a false "stuck"
// verdict -- and therefore a full-process restart -- while a different
// connection in the same process is genuinely healthy.
func TestIsStuck_OneStalledConnDoesNotMaskAHealthyOne(t *testing.T) {
	var m TunnelTrafficMonitor
	m.RecordTunnelSent("stalled", 10)
	m.RecordTunnelSent("healthy", 10)
	m.RecordTunnelRecv("healthy", 20)

	m.mu.Lock()
	m.conns["stalled"].firstSentAt = time.Now().Add(-(tunnelStuckTimeout + time.Second))
	m.conns["stalled"].lastSentAt = time.Now().Add(-time.Millisecond)
	m.mu.Unlock()

	if m.IsStuck() {
		t.Fatal("a healthy connection must prevent a stuck verdict even while another connection is genuinely one-sided")
	}
}

func TestIsStuck_AllConnsStalled(t *testing.T) {
	var m TunnelTrafficMonitor
	m.RecordTunnelSent("a", 10)
	m.RecordTunnelSent("b", 10)

	m.mu.Lock()
	for _, id := range []string{"a", "b"} {
		m.conns[id].firstSentAt = time.Now().Add(-(tunnelStuckTimeout + time.Second))
		m.conns[id].lastSentAt = time.Now().Add(-time.Millisecond)
	}
	m.mu.Unlock()

	if !m.IsStuck() {
		t.Fatal("when every tracked connection is one-sided, the tunnel must be reported stuck")
	}
}

func TestIsStuck_StaleEntryExpiresViaTTL(t *testing.T) {
	var m TunnelTrafficMonitor
	m.RecordTunnelSent("leaked", 10)

	m.mu.Lock()
	m.conns["leaked"].lastSentAt = time.Now().Add(-(connActivityTTL + time.Second))
	m.mu.Unlock()

	if m.IsStuck() {
		t.Fatal("a connection past connActivityTTL must be dropped, not counted as stuck")
	}
	m.mu.Lock()
	_, stillThere := m.conns["leaked"]
	m.mu.Unlock()
	if stillThere {
		t.Fatal("IsStuck must evict entries past connActivityTTL")
	}
}

func TestForget(t *testing.T) {
	var m TunnelTrafficMonitor
	m.RecordTunnelSent("a", 10)
	m.Forget("a")

	m.mu.Lock()
	_, ok := m.conns["a"]
	m.mu.Unlock()
	if ok {
		t.Fatal("Forget must remove the connection's tracked state")
	}
}

func TestReset(t *testing.T) {
	var m TunnelTrafficMonitor
	m.RecordTunnelSent("a", 10)
	m.RecordTunnelSent("b", 10)
	m.Reset()

	m.mu.Lock()
	n := len(m.conns)
	m.mu.Unlock()
	if n != 0 {
		t.Fatalf("Reset must clear all tracked connections, got %d remaining", n)
	}
	if m.IsStuck() {
		t.Fatal("a freshly-reset monitor must not be stuck")
	}
}

func TestRecordTunnel_IgnoresZeroPayloadAndEmptyConnID(t *testing.T) {
	var m TunnelTrafficMonitor
	m.RecordTunnelSent("", 10)
	m.RecordTunnelSent("a", 0)
	m.RecordTunnelRecv("", 10)
	m.RecordTunnelRecv("a", 0)

	m.mu.Lock()
	n := len(m.conns)
	m.mu.Unlock()
	if n != 0 {
		t.Fatalf("zero-payload and empty-connID calls must not create tracked entries, got %d", n)
	}
}
