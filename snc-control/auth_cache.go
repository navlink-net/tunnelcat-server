// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// authCacheTTL mirrors the exit-side authStaleTTL (snc-exit/auth.go): logins
// are rare compared to per-connection session checks, so a long window is
// safe and keeps clients working through brief arbiter outages.
const authCacheTTL = 24 * time.Hour

// authCacheEntry holds a cached login response body, as last seen from an
// exit's deferred-auth cache (see snc-exit/auth.go authResultEntry).
type authCacheEntry struct {
	body     []byte
	cachedAt time.Time
}

// authCache is control's half of "deferred authentication": a small
// device-keyed cache of login responses, refilled on demand by querying an
// exit's /p/node/v1/auth-cache endpoint — never the arbiter directly. Control
// must never contact the arbiter or hold its address, under any
// circumstances or for any purpose; every arbiter-bound call goes through an
// exit instead (see exitProxyURL in exits.go).
//
// It exists so that a client whose primary (exit-terminated) login attempt
// comes back transient — e.g. the specific exit serving its tunnel can't
// reach the arbiter — has a second chance: control asks a *different* exit
// for that device's last known-good login and replays it.
type authCache struct {
	nodeToken string
	exits     *ExitRegistry

	mu      sync.Mutex
	entries map[string]*authCacheEntry
}

func newAuthCache(nodeToken string, exits *ExitRegistry) *authCache {
	return &authCache{
		nodeToken: nodeToken,
		exits:     exits,
		entries:   make(map[string]*authCacheEntry),
	}
}

// lookup returns a cached login response for deviceID. It first checks
// control's own cache; on a miss or stale entry it asks a random known exit
// for its cached entry (which the exit, in turn, only ever populates from
// successful arbiter logins — see authClient.authenticate), caches whatever
// comes back, and serves that.
//
// Returns (body, true) on a usable cached login, (nil, false) if nothing is
// available anywhere right now.
func (c *authCache) lookup(deviceID string) ([]byte, bool) {
	if deviceID == "" {
		return nil, false
	}

	now := time.Now()
	c.mu.Lock()
	if e, ok := c.entries[deviceID]; ok && now.Sub(e.cachedAt) < authCacheTTL {
		body := e.body
		c.mu.Unlock()
		logDebugf("auth-cache: local hit device=%.8s… age=%s", deviceID, now.Sub(e.cachedAt).Round(time.Second))
		return body, true
	}
	c.mu.Unlock()

	body, err := c.queryExit(deviceID)
	if err != nil {
		logWarnf("auth-cache: exit query failed device=%.8s…: %v", deviceID, err)
		// Fall back to whatever we had locally, even if stale — better than
		// nothing during an outage that also affects exit reachability.
		c.mu.Lock()
		e, ok := c.entries[deviceID]
		c.mu.Unlock()
		if ok {
			logWarnf("auth-cache: serving stale local entry device=%.8s… age=%s",
				deviceID, time.Since(e.cachedAt).Round(time.Second))
			return e.body, true
		}
		return nil, false
	}

	c.mu.Lock()
	c.entries[deviceID] = &authCacheEntry{body: body, cachedAt: now}
	cutoff := now.Add(-authCacheTTL)
	for k, v := range c.entries {
		if v.cachedAt.Before(cutoff) {
			delete(c.entries, k)
		}
	}
	c.mu.Unlock()

	return body, true
}

// queryExit asks a random known exit for its cached login for deviceID via
// /p/node/v1/auth-cache. Mirrors ExitRegistry.refresh()'s "never contact the
// arbiter directly — go through an exit" pattern (exits.go).
func (c *authCache) queryExit(deviceID string) ([]byte, error) {
	exit, err := c.exits.PickRandom()
	if err != nil {
		return nil, err
	}

	fetchURL := exitAuthCacheURL(exit.Addr, deviceID)
	req, err := http.NewRequest(http.MethodGet, fetchURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Node-Token", c.nodeToken)

	resp, err := nodeProxyClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("exit %s auth-cache: status %d", exit.Addr, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<16))
}

// exitAuthCacheURL builds the URL for querying an exit's deferred-auth cache,
// e.g. exitAuthCacheURL("1.2.3.4:443", "abc123") →
// "https://1.2.3.4:443/p/node/v1/auth-cache?device_id=abc123"
// (mirrors exitProxyURL in exits.go).
func exitAuthCacheURL(exitAddr, deviceID string) string {
	addr := strings.TrimPrefix(exitAddr, "https://")
	addr = strings.TrimPrefix(addr, "http://")
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = addr + ":443"
	}
	q := url.Values{"device_id": {deviceID}}
	return "https://" + addr + "/p/node/v1/auth-cache?" + q.Encode()
}
