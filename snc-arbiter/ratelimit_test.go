// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"testing"
	"time"
)

func TestTieredWindowLimiter_SingleTierCooldown(t *testing.T) {
	l := newTieredWindowLimiter()
	tier := limitTier{Window: 50 * time.Millisecond, Max: 1}
	if !l.Allow("k", tier) {
		t.Fatal("first call should be allowed")
	}
	if l.Allow("k", tier) {
		t.Fatal("second call within the window should be rejected")
	}
	time.Sleep(60 * time.Millisecond)
	if !l.Allow("k", tier) {
		t.Fatal("call after the window elapsed should be allowed")
	}
}

func TestTieredWindowLimiter_MultipleTiersAllMustPass(t *testing.T) {
	l := newTieredWindowLimiter()
	fast := limitTier{Window: 10 * time.Millisecond, Max: 1}
	slow := limitTier{Window: time.Hour, Max: 3}

	// 3 calls spaced past the fast cooldown should all succeed (within the slow cap).
	for i := 0; i < 3; i++ {
		if !l.Allow("k", fast, slow) {
			t.Fatalf("call %d should be allowed (within both tiers)", i)
		}
		time.Sleep(12 * time.Millisecond)
	}
	// 4th call: fast cooldown has elapsed, but the slow tier (max 3/hour) should now block it.
	if l.Allow("k", fast, slow) {
		t.Fatal("4th call should be rejected by the slow tier even though the fast cooldown elapsed")
	}
}

func TestTieredWindowLimiter_DoesNotDoubleRecordPerTierCheck(t *testing.T) {
	// Regression guard: a single Allow() call with N tiers must record exactly
	// one event, not one per tier -- otherwise a 3-tier check would consume a
	// day's quota 3x faster than intended.
	l := newTieredWindowLimiter()
	tiers := []limitTier{
		{Window: time.Hour, Max: 2},
		{Window: 2 * time.Hour, Max: 2},
		{Window: 3 * time.Hour, Max: 2},
	}
	if !l.Allow("k", tiers...) {
		t.Fatal("1st call should be allowed")
	}
	if !l.Allow("k", tiers...) {
		t.Fatal("2nd call should be allowed (max is 2)")
	}
	if l.Allow("k", tiers...) {
		t.Fatal("3rd call should be rejected -- if tiers were recorded independently, this would wrongly pass")
	}
}

func TestTieredWindowLimiter_KeysAreIndependent(t *testing.T) {
	l := newTieredWindowLimiter()
	tier := limitTier{Window: time.Hour, Max: 1}
	if !l.Allow("a", tier) {
		t.Fatal("key a should be allowed")
	}
	if !l.Allow("b", tier) {
		t.Fatal("key b should be independently allowed even though key a is now exhausted")
	}
	if l.Allow("a", tier) {
		t.Fatal("key a should still be exhausted")
	}
}

func TestTokenBucket_BurstThenSteadyState(t *testing.T) {
	b := newTokenBucket(3, 1000) // capacity 3, refills fast (1000/sec) for a quick test
	if !b.Allow() || !b.Allow() || !b.Allow() {
		t.Fatal("first 3 calls should consume the initial burst capacity")
	}
	if b.Allow() {
		t.Fatal("4th immediate call should be rejected -- burst exhausted")
	}
	time.Sleep(5 * time.Millisecond) // ~5 tokens refilled at 1000/sec
	if !b.Allow() {
		t.Fatal("call after refill should be allowed")
	}
}

func TestTokenBucket_OneSteadyCallerCannotStarveEveryoneForever(t *testing.T) {
	// This is exactly the failure mode a bare per-second cooldown has: one
	// caller hitting it in lockstep would permanently occupy the only slot.
	// A bucket with burst capacity must let a second caller through even
	// while a steady drip is ongoing, as long as it's within capacity.
	b := newTokenBucket(5, 1)
	used := 0
	for i := 0; i < 5; i++ {
		if b.Allow() {
			used++
		}
	}
	if used != 5 {
		t.Fatalf("expected all 5 burst tokens to be usable up front, got %d", used)
	}
}
