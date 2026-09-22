// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"fmt"
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

// trustedProxyNets lists the CIDRs allowed to set X-Forwarded-For -- set once
// at startup by SetTrustedProxyCIDRs (see --trusted-proxy-cidrs in main.go).
// Defaults to loopback only (the common same-host nginx-in-front-of-arbiter
// deployment) so a fresh checkout is secure by default rather than trusting
// XFF from anyone who can open a TCP connection.
//
// Added 2026-09 security review #2: clientIP previously trusted the FIRST
// X-Forwarded-For value unconditionally. nginx's $proxy_add_x_forwarded_for
// (deploy/setup/nginx.sh, not in this public repo, but this is the standard
// directive) *appends* the real peer address rather than replacing a
// client-supplied header, so a direct request carrying
// "X-Forwarded-For: 1.2.3.4" arrived as "1.2.3.4, <real ip>" and clientIP
// picked the attacker-chosen "1.2.3.4" -- giving every login/signup/
// forgot-password/support-form attempt an independent rate-limit bucket on
// demand, fully defeating loginIPLimiter and friends.
var trustedProxyNets = mustParseCIDRs("127.0.0.1/32,::1/128")

func mustParseCIDRs(csv string) []*net.IPNet {
	nets, err := parseCIDRs(csv)
	if err != nil {
		panic(err) // only called with the literal default above; a bad --flag goes through SetTrustedProxyCIDRs instead
	}
	return nets
}

func parseCIDRs(csv string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, part := range strings.Split(csv, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("trusted-proxy-cidrs: invalid CIDR %q: %w", part, err)
		}
		out = append(out, ipnet)
	}
	return out, nil
}

// SetTrustedProxyCIDRs replaces the set of peer addresses clientIP will
// accept an X-Forwarded-For header from, given a comma-separated CIDR list
// (see --trusted-proxy-cidrs). An empty csv disables XFF trust entirely
// (clientIP always falls back to the raw TCP peer address).
func SetTrustedProxyCIDRs(csv string) error {
	nets, err := parseCIDRs(csv)
	if err != nil {
		return err
	}
	trustedProxyNets = nets
	return nil
}

func remoteAddrTrusted(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range trustedProxyNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP extracts the caller's IP. X-Forwarded-For is trusted only when
// the immediate TCP peer (r.RemoteAddr) is itself a configured trusted
// proxy (see trustedProxyNets/SetTrustedProxyCIDRs) -- otherwise it's
// attacker-controlled and ignored. When trusted, the LAST comma-separated
// value is used (the one the trusted proxy itself appended via
// $proxy_add_x_forwarded_for-style behavior), never the first (whatever the
// original client sent, unverified).
func clientIP(r *http.Request) string {
	if remoteAddrTrusted(r.RemoteAddr) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			last := strings.TrimSpace(parts[len(parts)-1])
			if last != "" {
				return last
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
