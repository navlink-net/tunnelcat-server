// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	localCacheTTL = 1 * time.Minute // local cache before asking arbiter
	localStaleTTL = 3 * time.Hour   // stale fallback when arbiter unreachable

	authCacheTTL = 5 * time.Minute // serve a cached login without re-querying arbiter
	authStaleTTL = 24 * time.Hour  // deferred-auth fallback when arbiter unreachable;
	// logins are far rarer than session checks, so a
	// longer window is safe (see localStaleTTL above)
)

// authClient validates SNC session tokens via the arbiter.
// A short local cache prevents per-packet arbiter calls.
type authClient struct {
	arbiterURL string
	nodeToken  string
	client     *http.Client
	mu         sync.Mutex
	cache      map[string]*cacheEntry
	authCache  map[string]*authResultEntry
}

type cacheEntry struct {
	username    string
	clientID    string
	validatedAt time.Time
	denied      bool // arbiter explicitly denied this account (suspended/disabled)
}

// authResultEntry holds a cached successful login response (raw JSON body,
// e.g. {"session":"...","notifications":[...]}), keyed by device (see
// authDeviceKey). Used to "defer" authentication when the arbiter is briefly
// unreachable — see authenticate/deferredOrTransient below.
type authResultEntry struct {
	body     []byte
	cachedAt time.Time
}

func newAuthClient(arbiterURL, nodeToken string) *authClient {
	return &authClient{
		arbiterURL: strings.TrimRight(arbiterURL, "/"),
		nodeToken:  nodeToken,
		client:     &http.Client{Timeout: 5 * time.Second},
		cache:      make(map[string]*cacheEntry),
		authCache:  make(map[string]*authResultEntry),
	}
}

// validateSession returns the username and clientID for a SNC session token,
// whether the request must be rejected outright, and whether the result is
// transient (arbiter unreachable, nothing cached to fall back on).
//
// denied=true is the arbiter's explicit, deterministic verdict (see
// snc-arbiter/sessions.go's Validate doc comment for the two cases that
// produce it) — callers must reject (404).
//
// Design intent (spec, restated here so the caching logic below isn't
// mysterious): tokens are not re-validated with the arbiter on every request
// — the arbiter is a single point shared by the whole network and would
// fall over under per-packet auth checks (hence localCacheTTL below). Once a
// token is found invalid, every exit must *remember* that and keep rejecting
// it — but only ever on the strength of an explicit arbiter verdict, never
// invented locally from an absence of information. And because the arbiter
// itself can be unreachable from a given exit for up to localStaleTTL (3h)
// per spec, a *previously cached* verdict — valid or denied — must survive
// that outage unchanged: an exit that already knows a token is bad must not
// quietly start allowing it again just because it can't currently double
// check, and conversely a token an exit already trusts must keep working
// without the arbiter for that same window (this is a second, independent
// 3h grace period from the arbiter's own Camerlengo-outage tolerance in
// sessions.go — this one is about exit↔arbiter connectivity specifically).
//
// transient=true means the arbiter was unreachable and there is no cache at
// all (first time this token has ever been seen while the arbiter is down)
// — callers may return 503 so the client retries without re-authing.
func (a *authClient) validateSession(token string) (username, clientID string, denied, transient bool) {
	now := time.Now()

	a.mu.Lock()
	e := a.cache[token]
	if e != nil && now.Sub(e.validatedAt) < localCacheTTL {
		age := now.Sub(e.validatedAt).Round(time.Millisecond)
		a.mu.Unlock()
		logDebugf("auth: cache hit token=%.8s… user=%s denied=%v age=%s", token, e.username, e.denied, age)
		return e.username, e.clientID, e.denied, false
	}
	var stale *cacheEntry
	staleAge := time.Duration(0)
	if e != nil {
		stale = e
		staleAge = now.Sub(e.validatedAt).Round(time.Second)
	}
	a.mu.Unlock()

	queryStart := time.Now()
	username, clientID, denied, err := a.queryArbiter(token)
	queryDur := time.Since(queryStart).Round(time.Millisecond)
	if err != nil {
		logWarnf("auth: arbiter query failed token=%.8s… dur=%s: %v", token, queryDur, err)
		if stale != nil {
			logWarnf("auth: stale fallback token=%.8s… user=%s denied=%v stale-age=%s",
				token, stale.username, stale.denied, staleAge)
			// Propagate the last known explicit verdict as-is — a token we
			// already know is denied must stay denied through an arbiter
			// outage, exactly as much as a token we already trust must stay
			// trusted. Neither direction gets silently overridden here.
			return stale.username, stale.clientID, stale.denied, false
		}
		// Arbiter unreachable and no cache — signal transient so callers return 503.
		logWarnf("auth: arbiter unreachable, no cache for token=%.8s… → transient", token)
		return "", "", false, true
	}
	logDebugf("auth: arbiter ok token=%.8s… user=%q client_id=%s denied=%v dur=%s",
		token, username, clientID, denied, queryDur)

	a.mu.Lock()
	a.cache[token] = &cacheEntry{username: username, clientID: clientID, denied: denied, validatedAt: now}
	// Evict entries older than localStaleTTL.
	cutoff := now.Add(-localStaleTTL)
	evicted := 0
	for k, v := range a.cache {
		if v.validatedAt.Before(cutoff) {
			delete(a.cache, k)
			evicted++
		}
	}
	cacheSize := len(a.cache)
	a.mu.Unlock()

	if evicted > 0 {
		logDebugf("auth: evicted %d stale cache entries, remaining=%d", evicted, cacheSize)
	}
	return username, clientID, denied, false
}

// fetchManifest retrieves the signed control-node manifest from the arbiter.
// The exit relays this to clients so they can discover control nodes.
func (a *authClient) fetchManifest() ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, a.arbiterURL+"/api/manifest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Node-Token", a.nodeToken)
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("arbiter manifest: status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

// fetchClubManifest retrieves the signed+encrypted club manifest for the
// given club slug ("cat_club", "elite_cat_club") from the arbiter. Parallel
// to fetchManifest — same auth, same shape, independent cache upstream
// (see clubManifestPoller in handler.go).
func (a *authClient) fetchClubManifest(slug string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, a.arbiterURL+"/api/club-manifest?club="+slug, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Node-Token", a.nodeToken)
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch club manifest %s: %w", slug, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("arbiter club manifest %s: status %d", slug, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

func (a *authClient) queryArbiter(token string) (username, clientID string, denied bool, err error) {
	body, _ := json.Marshal(map[string]string{"session": token})

	req, reqErr := http.NewRequest(http.MethodPost, a.arbiterURL+"/api/session/validate", bytes.NewReader(body))
	if reqErr != nil {
		return "", "", false, fmt.Errorf("build request: %w", reqErr)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Node-Token", a.nodeToken)

	resp, doErr := a.client.Do(req)
	if doErr != nil {
		return "", "", false, fmt.Errorf("POST arbiter: %w", doErr)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var result struct {
		User     string `json:"user"`
		ClientID string `json:"client_id"`
		Denied   bool   `json:"denied"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", "", false, fmt.Errorf("parse arbiter response: %w", err)
	}
	return result.User, result.ClientID, result.Denied, nil
}

// authenticate handles the login commands (authenticateKey, verifyPassword,
// proxy-validate) with a caching layer that survives brief arbiter outages —
// "deferred authentication".
//
// Until now these requests fell through the catch-all reverse proxy straight
// to the arbiter with no cache and no stale-fallback (unlike validateSession
// above, which has both). That made login a single point of failure: clients
// with an already-active session kept working off validateSession's stale
// cache, but anyone needing to (re)authenticate during an arbiter outage was
// hard-rejected — even though control and exit were both alive and able to
// serve them.
//
// Behavior:
//   - cache hit (younger than authCacheTTL): replay immediately, no arbiter call
//   - arbiter reachable: proxy through, cache successful responses by device
//   - arbiter unreachable + cached login within authStaleTTL: replay the
//     cached response ("deferred" — the client gets in on its last
//     known-good session; the arbiter re-validates on the next attempt)
//   - arbiter unreachable + nothing cached: 503 + transient marker, so the
//     client retries instead of treating this as a credential rejection
func (a *authClient) authenticate(r *http.Request, command string, body []byte) (respBody []byte, status int) {
	deviceKey := authDeviceKey(command, body)
	now := time.Now()

	if deviceKey != "" {
		a.mu.Lock()
		if e, ok := a.authCache[deviceKey]; ok && now.Sub(e.cachedAt) < authCacheTTL {
			resp := e.body
			a.mu.Unlock()
			logDebugf("auth: cached login hit device=%.8s… age=%s", deviceKey, now.Sub(e.cachedAt).Round(time.Second))
			return resp, http.StatusOK
		}
		a.mu.Unlock()
	}

	req, reqErr := http.NewRequest(http.MethodPost, a.arbiterURL+r.URL.Path, bytes.NewReader(body))
	if reqErr != nil {
		return []byte(`{"error":"internal"}`), http.StatusInternalServerError
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Node-Token", a.nodeToken)
	if sess := r.Header.Get("X-Session"); sess != "" {
		// proxy-validate authenticates the *caller* (a BlackBadger instance)
		// via its own session token — must be forwarded to the arbiter.
		req.Header.Set("X-Session", sess)
	}

	resp, doErr := a.client.Do(req)
	if doErr != nil {
		return a.deferredOrTransient(deviceKey, doErr)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode != http.StatusOK || !looksLikeAuthSuccess(raw) {
		logInfof("auth: %s rejected device=%.8s… status=%d", command, deviceKey, resp.StatusCode)
		return raw, resp.StatusCode
	}

	if deviceKey != "" {
		a.mu.Lock()
		a.authCache[deviceKey] = &authResultEntry{body: raw, cachedAt: now}
		cutoff := now.Add(-authStaleTTL)
		for k, v := range a.authCache {
			if v.cachedAt.Before(cutoff) {
				delete(a.authCache, k)
			}
		}
		a.mu.Unlock()
	}
	return raw, http.StatusOK
}

// deferredOrTransient is reached when the arbiter could not be queried for an
// auth command. A cached login — even stale, up to authStaleTTL — is replayed
// so the client can get in on its last known-good session; with no cache at
// all, a transient 503 tells the client to retry rather than give up.
func (a *authClient) deferredOrTransient(deviceKey string, queryErr error) ([]byte, int) {
	if deviceKey != "" {
		a.mu.Lock()
		e, ok := a.authCache[deviceKey]
		a.mu.Unlock()
		if ok && time.Since(e.cachedAt) < authStaleTTL {
			logWarnf("auth: deferred — arbiter unreachable (%v), serving cached login device=%.8s… age=%s",
				queryErr, deviceKey, time.Since(e.cachedAt).Round(time.Second))
			return e.body, http.StatusOK
		}
	}
	logWarnf("auth: arbiter unreachable (%v), no cached login for device=%.8s… → transient", queryErr, deviceKey)
	return []byte(`{"error":"arbiter_unavailable","transient":true}`), http.StatusServiceUnavailable
}

// cachedAuth returns the cached login body for deviceKey, if any — used by
// the control-facing /p/node/v1/auth-cache endpoint (node_proxy.go) so a
// control node can recover a login for its clients via a *different* exit
// when the one terminating their tunnel is unreachable. Never touches the
// arbiter — purely a cache read.
func (a *authClient) cachedAuth(deviceKey string) ([]byte, bool) {
	if deviceKey == "" {
		return nil, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	e, ok := a.authCache[deviceKey]
	if !ok || time.Since(e.cachedAt) >= authStaleTTL {
		return nil, false
	}
	return e.body, true
}

// looksLikeAuthSuccess reports whether raw is a JSON object carrying a
// non-empty "session" field — the marker shared by authenticateKey,
// verifyPassword and proxy-validate success responses.
func looksLikeAuthSuccess(raw []byte) bool {
	var probe struct {
		Session string `json:"session"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false
	}
	return probe.Session != ""
}

// authDeviceKey derives a stable cache key for an auth command: the client's
// device_id when present (authenticateKey, verifyPassword), otherwise a hash
// of (command, username) — covers proxy-validate, which carries no device_id.
func authDeviceKey(command string, body []byte) string {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return ""
	}
	str := func(key string) string {
		v, ok := raw[key]
		if !ok {
			return ""
		}
		var s string
		json.Unmarshal(v, &s) //nolint:errcheck
		return s
	}
	if id := str("device_id"); id != "" {
		return "dev:" + id
	}
	user := str("username")
	if user == "" {
		user = str("user")
	}
	if user == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(command + ":" + user))
	return "user:" + hex.EncodeToString(sum[:])
}
