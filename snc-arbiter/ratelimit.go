// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// simpleRateLimiter tracks the last-allowed time per key and rejects repeats
// within a cooldown window. Used to blunt abuse of unauthenticated public
// forms (e.g. /forgot-password) without an external service.
type simpleRateLimiter struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func newSimpleRateLimiter() *simpleRateLimiter {
	return &simpleRateLimiter{last: make(map[string]time.Time)}
}

// Allow reports whether a request for key may proceed, given cooldown since
// the last allowed request for the same key.
func (l *simpleRateLimiter) Allow(key string, cooldown time.Duration) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if last, ok := l.last[key]; ok && now.Sub(last) < cooldown {
		return false
	}
	l.last[key] = now
	if len(l.last) > 10000 {
		for k, t := range l.last {
			if now.Sub(t) > time.Hour {
				delete(l.last, k)
			}
		}
	}
	return true
}

// limitTier is one "at most Max events per Window" constraint. Multiple tiers
// can be checked together against the same event log (e.g. 1/10s AND 3/10min
// AND 10/day) -- see tieredWindowLimiter.
type limitTier struct {
	Window time.Duration
	Max    int
}

// tieredWindowLimiter enforces one or more simultaneous "at most N events per
// window" constraints per key, backed by a sliding-window event log (exact,
// not the approximation a fixed-window counter would give -- cheap here since
// Max is always small). Added 2026-08-08 for the arbiter API flood audit
// (see TODO.md) -- simpleRateLimiter above only supports a single fixed
// cooldown, which can't express "burst of 1 immediately, but capped at 3
// over 10 minutes" in one check.
type tieredWindowLimiter struct {
	mu     sync.Mutex
	events map[string][]time.Time
}

func newTieredWindowLimiter() *tieredWindowLimiter {
	return &tieredWindowLimiter{events: make(map[string][]time.Time)}
}

// Allow reports whether key may record one more event right now without
// violating any tier, and if so, atomically records it (check-and-record
// under one lock, so concurrent requests can't both slip through at a
// boundary). All tiers must pass; recording happens once, not once per tier.
func (l *tieredWindowLimiter) Allow(key string, tiers ...limitTier) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	evs := l.events[key]
	longest := time.Duration(0)
	for _, t := range tiers {
		if t.Window > longest {
			longest = t.Window
		}
		cutoff := now.Add(-t.Window)
		count := 0
		for _, e := range evs {
			if e.After(cutoff) {
				count++
			}
		}
		if count >= t.Max {
			return false
		}
	}

	// Record the event, pruning anything older than the longest tier so a
	// key's slice doesn't grow forever across a long-lived process.
	cutoff := now.Add(-longest)
	kept := evs[:0]
	for _, e := range evs {
		if e.After(cutoff) {
			kept = append(kept, e)
		}
	}
	l.events[key] = append(kept, now)

	// Bound total memory across all distinct keys -- opportunistic sweep.
	if len(l.events) > 10000 {
		for k, v := range l.events {
			if len(v) == 0 {
				delete(l.events, k)
			}
		}
	}
	return true
}

// tokenBucket is a classic token-bucket limiter: capacity tokens available
// up front (absorbs a legitimate burst), refilled at refillPerSec tokens/sec
// thereafter. Deliberately not a bare "1 request per interval" gate -- a
// single steady-drip caller (malicious or just a buggy client) would
// otherwise permanently starve that one slot for every other caller. Added
// 2026-08-08 for the arbiter API flood audit's global login cap.
type tokenBucket struct {
	mu           sync.Mutex
	tokens       float64
	capacity     float64
	refillPerSec float64
	last         time.Time
}

func newTokenBucket(capacity float64, refillPerSec float64) *tokenBucket {
	return &tokenBucket{tokens: capacity, capacity: capacity, refillPerSec: refillPerSec, last: time.Now()}
}

// Allow reports whether a token is available right now, consuming one if so.
func (b *tokenBucket) Allow() bool {
	now := time.Now()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens += now.Sub(b.last).Seconds() * b.refillPerSec
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// clientIP extracts the caller's IP from X-Forwarded-For (set by the reverse
// proxy in front of the arbiter) or falls back to RemoteAddr.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		return strings.TrimSpace(first)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
