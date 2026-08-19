// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"sync"
	"testing"
	"time"
)

// seedFailRatio directly seeds td's rolling outcome window so FailRatio()
// reports approximately the given ratio, without waiting on real timers.
// total must be >= dialWinMinSamples and the window must span >= dialWinMinSpan.
func seedFailRatio(td *TunnelDialer, ratio float64, total int) {
	now := time.Now()
	fails := int(ratio * float64(total))
	td.dialWindow = make([]dialOutcome, 0, total)
	for i := 0; i < total; i++ {
		// Spread samples across a span comfortably over dialWinMinSpan so the
		// FailRatio guard doesn't zero them out.
		at := now.Add(-dialWinSize + time.Duration(i)*time.Millisecond)
		td.dialWindow = append(td.dialWindow, dialOutcome{at: at, success: i >= fails})
	}
}

func TestPickWeightHealthyDialerFullWeight(t *testing.T) {
	td := newTestDialer(t)
	got := pickWeight(td)
	want := 1.0 / float64(defaultPickRTT)
	if got != want {
		t.Errorf("healthy dialer: got weight %v, want %v (no RTT data, no failures)", got, want)
	}
}

func TestPickWeightScalesDownWithFailRatio(t *testing.T) {
	td := newTestDialer(t)
	seedFailRatio(td, 0.5, 20)

	got := pickWeight(td)
	base := 1.0 / float64(defaultPickRTT)
	want := base * 0.5
	if got != want {
		t.Errorf("50%% fail ratio: got weight %v, want %v", got, want)
	}
	if got >= base {
		t.Errorf("weight %v should be strictly less than the full-quality weight %v", got, base)
	}
}

func TestPickWeightFloorsAtSoftMinQuality(t *testing.T) {
	td := newTestDialer(t)
	seedFailRatio(td, 0.95, 20) // quality would be 0.05, below softMinQuality

	got := pickWeight(td)
	base := 1.0 / float64(defaultPickRTT)
	want := base * softMinQuality
	if got != want {
		t.Errorf("near-total fail ratio: got weight %v, want floor %v", got, want)
	}
	if got <= 0 {
		t.Errorf("weight must stay strictly positive (deprioritize, not exclude), got %v", got)
	}
}

// TestPickDeprioritizesWithoutExcluding is the end-to-end version of the "sick
// node stays in the pool but gets picked less" requirement: a struggling
// dialer (203.0.113.15-style — fine RTT, bad reliability) must be picked
// noticeably less often than a healthy sibling, but never literally zero.
func TestPickDeprioritizesWithoutExcluding(t *testing.T) {
	healthy := newTestDialer(t)
	sick := newTestDialer(t)
	seedFailRatio(sick, 0.6, 20) // above firstFailRatio(0.5) — would hard-evict via the
	// existing hook-based mechanism in real use; Pick() itself only sees the weight.

	pool := NewDialerPool([]*TunnelDialer{healthy, sick})

	const trials = 20000
	counts := map[*TunnelDialer]int{}
	for i := 0; i < trials; i++ {
		d := pool.Pick()
		if d == nil {
			t.Fatal("Pick returned nil")
		}
		counts[d]++
	}

	healthyCount, sickCount := counts[healthy], counts[sick]
	if sickCount == 0 {
		t.Error("sick dialer was never picked — should be deprioritized, not excluded")
	}
	if sickCount >= healthyCount {
		t.Errorf("sick dialer picked %d times, healthy only %d — expected sick to be picked less often", sickCount, healthyCount)
	}
	// With quality 0.4 vs 1.0, expect roughly a 1:2.5 ratio (~28.5%/71.5%); allow
	// a wide statistical margin since this is a random trial, just confirm the
	// skew is real and in the right direction rather than pinning exact counts.
	sickShare := float64(sickCount) / float64(trials)
	if sickShare > 0.40 {
		t.Errorf("sick dialer's pick share %.2f looks too high for a 0.6 fail ratio", sickShare)
	}
}

// TestPickExcludingNeverReturnsExcluded is the retry-on-a-different-node case
// (2026-08-12 incident): a dial just failed against one dialer, and the
// caller wants any other pool member for the retry, never the one that just
// failed, even by chance.
func TestPickExcludingNeverReturnsExcluded(t *testing.T) {
	a := newTestDialer(t)
	b := newTestDialer(t)
	pool := NewDialerPool([]*TunnelDialer{a, b})

	const trials = 1000
	for i := 0; i < trials; i++ {
		got := pool.PickExcluding(a)
		if got == nil {
			t.Fatal("PickExcluding returned nil with a healthy alternative available")
		}
		if got == a {
			t.Fatal("PickExcluding returned the excluded dialer")
		}
	}
}

// TestPickExcludingNilWhenOnlyOption mirrors Pick()'s "nothing left" contract:
// if the excluded dialer is the only one in the pool, there is nothing else
// to retry with, so it must return nil rather than falling back to it.
func TestPickExcludingNilWhenOnlyOption(t *testing.T) {
	a := newTestDialer(t)
	pool := NewDialerPool([]*TunnelDialer{a})

	if got := pool.PickExcluding(a); got != nil {
		t.Errorf("expected nil when the excluded dialer is the only pool member, got %v", got)
	}
}

// TestPickForHostSticksToSameDialer is the core same-session guarantee:
// repeat/parallel connections to the same host must land on the same
// dialer, unlike Pick's per-connection random draw.
func TestPickForHostSticksToSameDialer(t *testing.T) {
	a, b := newTestDialer(t), newTestDialer(t)
	pool := NewDialerPool([]*TunnelDialer{a, b})

	first := pool.PickForHost("example.com")
	if first == nil {
		t.Fatal("PickForHost returned nil")
	}
	for i := 0; i < 50; i++ {
		if got := pool.PickForHost("example.com"); got != first {
			t.Fatalf("PickForHost(%q) drifted from %v to %v on call %d", "example.com", first, got, i)
		}
	}
}

// TestPickForHostDoesNotCrossPollinateHosts confirms two different hosts are
// free to land on different dialers -- affinity is per-host, not global (that
// would just reintroduce the single-session-pinned-to-one-control problem at
// the whole-pool level instead of fixing the actual bug).
func TestPickForHostDoesNotCrossPollinateHosts(t *testing.T) {
	dialers := make([]*TunnelDialer, 10)
	for i := range dialers {
		dialers[i] = newTestDialer(t)
	}
	pool := NewDialerPool(dialers)

	seen := map[*TunnelDialer]bool{}
	for i := 0; i < 200; i++ {
		host := "host" + string(rune('a'+i%26)) + ".example.com"
		seen[pool.PickForHost(host)] = true
	}
	if len(seen) < 2 {
		t.Errorf("expected multiple distinct dialers across many different hosts, got %d", len(seen))
	}
}

// TestPickForHostFallsOffAnEvictedDialer is the "control can die" case: once
// a host's sticky dialer is evicted from the pool (its control died), the
// next PickForHost for that host must NOT keep returning the dead dialer --
// it has to notice and re-pick from what's actually still in the pool.
func TestPickForHostFallsOffAnEvictedDialer(t *testing.T) {
	a, b := newTestDialer(t), newTestDialer(t)
	pool := NewDialerPool([]*TunnelDialer{a, b})

	// Force the pin onto a explicitly (rather than looping until Pick()
	// happens to choose it) so the test is deterministic.
	pool.SetHostAffinity("example.com", a)
	if got := pool.PickForHost("example.com"); got != a {
		t.Fatalf("expected pinned dialer a, got %v", got)
	}

	pool.Evict(a)

	got := pool.PickForHost("example.com")
	if got != b {
		t.Fatalf("expected fallback to the only remaining dialer b after a's control died, got %v", got)
	}
	// And it should now be re-pinned to b, not re-rolling every call.
	for i := 0; i < 20; i++ {
		if got2 := pool.PickForHost("example.com"); got2 != b {
			t.Fatalf("expected re-pinned dialer b to stick, got %v on call %d", got2, i)
		}
	}
}

// TestPickForHostExpiresAfterTTL confirms a host's pin is eventually willing
// to move on (e.g. to rebalance towards a now-faster control) rather than
// sticking forever for the life of the process.
func TestPickForHostExpiresAfterTTL(t *testing.T) {
	a := newTestDialer(t)
	pool := NewDialerPool([]*TunnelDialer{a})
	pool.affinity = map[string]hostAffinityEntry{
		"example.com": {dialer: a, at: time.Now().Add(-hostAffinityTTL - time.Second)},
	}

	b := newTestDialer(t)
	pool.Add(b)
	pool.Evict(a) // only b left, so the re-pick after expiry is deterministic

	if got := pool.PickForHost("example.com"); got != b {
		t.Fatalf("expected expired pin to re-pick from the live pool, got %v", got)
	}
}

// TestSetHostAffinityIgnoresNilAndEmpty guards the no-op cases callers rely
// on not panicking or polluting the map (e.g. socks5.go calling this only
// when a retry actually succeeded).
func TestSetHostAffinityIgnoresNilAndEmpty(t *testing.T) {
	a := newTestDialer(t)
	pool := NewDialerPool([]*TunnelDialer{a})

	pool.SetHostAffinity("", a)
	pool.SetHostAffinity("example.com", nil)
	if len(pool.affinity) != 0 {
		t.Errorf("expected no affinity entries recorded, got %d", len(pool.affinity))
	}
}

// TestPickForUIDNegativeNeverPins is the safety guard for the real
// 2026-08-17 incident: an unresolved UID (-1) must never be pinned or
// matched against another unresolved lookup -- that would silently
// re-pin every unrelated connection whose UID lookup failed onto one
// shared dialer, exactly the whole-VPN-on-one-control bug this feature
// exists to prevent. Every call with a negative uid must be free to land
// on any dialer, independent of any other call.
func TestPickForUIDNegativeNeverPins(t *testing.T) {
	dialers := make([]*TunnelDialer, 10)
	for i := range dialers {
		dialers[i] = newTestDialer(t)
	}
	pool := NewDialerPool(dialers)

	seen := map[*TunnelDialer]bool{}
	for i := 0; i < 200; i++ {
		seen[pool.PickForUID(-1)] = true
	}
	if len(seen) < 2 {
		t.Errorf("expected repeated calls with uid=-1 to spread across multiple dialers (never pinned), got %d distinct", len(seen))
	}
	if len(pool.appAffinity) != 0 {
		t.Errorf("expected uid=-1 to never be recorded in appAffinity, got %d entries", len(pool.appAffinity))
	}
}

// TestPickForUIDSticksToSameDialer is the core same-app guarantee: every
// call for one UID must return the same dialer, unlike Pick's
// per-connection random draw -- so all of one app's connections (e.g. every
// tab a browser opens) exit through the same control.
func TestPickForUIDSticksToSameDialer(t *testing.T) {
	a, b := newTestDialer(t), newTestDialer(t)
	pool := NewDialerPool([]*TunnelDialer{a, b})

	const uid = 10123
	first := pool.PickForUID(uid)
	if first == nil {
		t.Fatal("PickForUID returned nil")
	}
	for i := 0; i < 50; i++ {
		if got := pool.PickForUID(uid); got != first {
			t.Fatalf("PickForUID(%d) drifted from %v to %v on call %d", uid, first, got, i)
		}
	}
}

// TestPickForUIDDoesNotCrossPollinateApps confirms two different UIDs are
// free to land on different dialers -- affinity is per-app, not global (that
// would just reintroduce the whole-VPN-on-one-control problem this design
// explicitly rejected in favor of per-app grouping).
func TestPickForUIDDoesNotCrossPollinateApps(t *testing.T) {
	dialers := make([]*TunnelDialer, 10)
	for i := range dialers {
		dialers[i] = newTestDialer(t)
	}
	pool := NewDialerPool(dialers)

	seen := map[*TunnelDialer]bool{}
	for uid := 10000; uid < 10200; uid++ {
		seen[pool.PickForUID(uid)] = true
	}
	if len(seen) < 2 {
		t.Errorf("expected multiple distinct dialers across many different app UIDs, got %d", len(seen))
	}
}

// TestPickForUIDConcurrentFirstCallsConverge is the exact real-world trigger:
// a browser opening many parallel connections at once, all calling
// PickForUID for the same UID before anything is pinned yet. They must all
// converge on one dialer, not race each other into picking different ones.
func TestPickForUIDConcurrentFirstCallsConverge(t *testing.T) {
	dialers := make([]*TunnelDialer, 8)
	for i := range dialers {
		dialers[i] = newTestDialer(t)
	}
	pool := NewDialerPool(dialers)

	const goroutines = 100
	const uid = 10123
	results := make(chan *TunnelDialer, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			results <- pool.PickForUID(uid)
		}()
	}
	wg.Wait()
	close(results)

	seen := map[*TunnelDialer]bool{}
	for d := range results {
		if d == nil {
			t.Fatal("PickForUID returned nil")
		}
		seen[d] = true
	}
	if len(seen) != 1 {
		t.Errorf("expected all %d concurrent first calls for one UID to converge on exactly 1 dialer, got %d distinct", goroutines, len(seen))
	}
}

// TestPickForUIDFallsOffAnEvictedDialer is the "control can die" case: once
// an app's sticky dialer is evicted from the pool (its control died), the
// next PickForUID call for that app must NOT keep returning the dead
// dialer -- it has to notice and re-pick from what's actually still there.
func TestPickForUIDFallsOffAnEvictedDialer(t *testing.T) {
	a, b := newTestDialer(t), newTestDialer(t)
	pool := NewDialerPool([]*TunnelDialer{a, b})
	const uid = 10123

	// Force the pin onto a explicitly (rather than looping until PickForUID
	// happens to choose it) so the test is deterministic.
	pool.SetUIDAffinity(uid, a)
	if got := pool.PickForUID(uid); got != a {
		t.Fatalf("expected pinned dialer a, got %v", got)
	}

	pool.Evict(a)

	got := pool.PickForUID(uid)
	if got != b {
		t.Fatalf("expected fallback to the only remaining dialer b after a's control died, got %v", got)
	}
	// And it should now be re-pinned to b, not re-rolling every call.
	for i := 0; i < 20; i++ {
		if got2 := pool.PickForUID(uid); got2 != b {
			t.Fatalf("expected re-pinned dialer b to stick, got %v on call %d", got2, i)
		}
	}
}

// TestSetUIDAffinityIgnoresNil guards the no-op case callers rely on not
// panicking or clobbering an existing pin (e.g. tun_dialer_linux.go calling
// this only when a fallback dial actually succeeded).
func TestSetUIDAffinityIgnoresNil(t *testing.T) {
	a := newTestDialer(t)
	pool := NewDialerPool([]*TunnelDialer{a})
	const uid = 10123

	pool.SetUIDAffinity(uid, a)
	pool.SetUIDAffinity(uid, nil)
	if pool.appAffinity[uid] != a {
		t.Errorf("expected uid %d to remain pinned to %v, got %v", uid, a, pool.appAffinity[uid])
	}
}
