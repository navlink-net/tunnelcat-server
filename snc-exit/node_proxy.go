// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// nodeProxy serves unauthenticated (but TLS) endpoints for control nodes:
//
//	POST /p/node/v1/refresh                    — arbiter-signed force-refresh
//	ANY  /p/node/v1/arbiter/<path>             — proxy to arbiter, caller IP validated against manifest
//	GET  /p/node/v1/auth-cache?device_id=...   — read-only lookup in this exit's deferred-auth cache
//	GET  /p/node/v1/update/version             — cached control binary version
//	GET  /p/node/v1/update/snc-control         — cached control binary
//	GET  /p/node/v1/update/snc-control.sha256  — cached hash
//
// All paths under /p/node/v1/ are unauthenticated at the session level but:
//   - /p/node/v1/arbiter/* and /p/node/v1/auth-cache require the caller's IP
//     to appear in the signed manifest of known control nodes (fetched from
//     the arbiter).
//   - /p/node/v1/refresh requires a valid Ed25519 signature from the arbiter.
type nodeProxy struct {
	arbiterURL    string
	nodeToken     string            // this exit's arbiter token
	arbiterPubkey ed25519.PublicKey // for verifying /refresh requests; nil = disabled
	cacheDir      string            // directory where A2 stores cached control binaries
	proxy         *httputil.ReverseProxy

	// auth backs /p/node/v1/auth-cache — lets a control recover a client's
	// deferred-auth cache entry via this exit when the exit terminating the
	// client's tunnel is unreachable. See authClient.cachedAuth (auth.go).
	auth *authClient

	// getManifest returns the current cached manifest bytes (same source as
	// serveManifest uses).  Used to validate control caller IPs.
	getManifest func() ([]byte, error)

	// triggerRefresh is called by /p/node/v1/refresh to pull fresh data.
	triggerRefresh func()
}

func newNodeProxy(
	arbiterURL, nodeToken string,
	arbiterPubkey ed25519.PublicKey,
	cacheDir string,
	auth *authClient,
	getManifest func() ([]byte, error),
	triggerRefresh func(),
) *nodeProxy {
	target, err := url.Parse(strings.TrimRight(arbiterURL, "/"))
	if err != nil {
		logErrorf("node-proxy: invalid arbiter URL %q: %v", arbiterURL, err)
		os.Exit(1)
	}

	p := httputil.NewSingleHostReverseProxy(target)
	origDirector := p.Director
	p.Director = func(req *http.Request) {
		origDirector(req)
		req.Host = target.Host
		// Strip the /p/node/v1/arbiter prefix so the path reaching the
		// arbiter is the original arbiter API path (e.g. /api/heartbeat).
		req.URL.Path = strings.TrimPrefix(req.URL.Path, "/p/node/v1/arbiter")
		if req.URL.Path == "" {
			req.URL.Path = "/"
		}
	}

	return &nodeProxy{
		arbiterURL:     strings.TrimRight(arbiterURL, "/"),
		nodeToken:      nodeToken,
		arbiterPubkey:  arbiterPubkey,
		cacheDir:       cacheDir,
		proxy:          p,
		auth:           auth,
		getManifest:    getManifest,
		triggerRefresh: triggerRefresh,
	}
}

// ServeHTTP handles all /p/node/v1/ requests.
func (np *nodeProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	switch {
	case path == "/p/node/v1/refresh" && r.Method == http.MethodPost:
		np.handleRefresh(w, r)

	case strings.HasPrefix(path, "/p/node/v1/arbiter"):
		np.handleArbiterProxy(w, r)

	case path == "/p/node/v1/auth-cache" && r.Method == http.MethodGet:
		np.handleAuthCache(w, r)

	case strings.HasPrefix(path, "/p/node/v1/update/") && r.Method == http.MethodGet:
		np.handleUpdate(w, r)

	default:
		http.NotFound(w, r)
	}
}

// handleRefresh verifies the arbiter Ed25519 signature and triggers a cache refresh.
// Request body: raw bytes that were signed.
// Header X-Arbiter-Sig: base64url Ed25519 signature over the request body.
// Header X-Arbiter-TS: unix timestamp (must be within 60 s of now).
func (np *nodeProxy) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if np.arbiterPubkey == nil {
		logWarnf("node-proxy: /refresh received but no arbiter pubkey configured — ignoring")
		http.Error(w, `{"error":"refresh not configured"}`, http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1024))
	if err != nil {
		http.Error(w, `{"error":"read body"}`, http.StatusBadRequest)
		return
	}

	sigB64 := r.Header.Get("X-Arbiter-Sig")
	if sigB64 == "" {
		logWarnf("node-proxy: /refresh from %s: missing X-Arbiter-Sig", remoteIP(r))
		http.Error(w, `{"error":"missing signature"}`, http.StatusUnauthorized)
		return
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		logWarnf("node-proxy: /refresh from %s: bad signature encoding", remoteIP(r))
		http.Error(w, `{"error":"bad signature"}`, http.StatusUnauthorized)
		return
	}
	if !ed25519.Verify(np.arbiterPubkey, body, sig) {
		logWarnf("node-proxy: /refresh from %s: signature verification failed", remoteIP(r))
		http.Error(w, `{"error":"invalid signature"}`, http.StatusUnauthorized)
		return
	}

	// Parse timestamp from body to prevent replay attacks.
	var payload struct {
		TS int64 `json:"ts"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.TS == 0 {
		http.Error(w, `{"error":"bad payload"}`, http.StatusBadRequest)
		return
	}
	age := time.Since(time.Unix(payload.TS, 0)).Abs()
	if age > 60*time.Second {
		logWarnf("node-proxy: /refresh from %s: stale timestamp age=%s", remoteIP(r), age.Round(time.Second))
		http.Error(w, `{"error":"stale request"}`, http.StatusUnauthorized)
		return
	}

	logInfof("node-proxy: /refresh from %s — triggering cache refresh", remoteIP(r))
	if np.triggerRefresh != nil {
		go np.triggerRefresh()
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`)) //nolint:errcheck
}

// handleArbiterProxy proxies the request to the arbiter after verifying the
// caller's IP is in the signed manifest of known control nodes.
// Bootstrap paths (/api/heartbeat, /api/exits) are exempt from the IP check
// because a brand-new control has no heartbeat yet and therefore cannot appear
// in the manifest — the arbiter validates the token itself on those endpoints.
func (np *nodeProxy) handleArbiterProxy(w http.ResponseWriter, r *http.Request) {
	callerIP := remoteIP(r)
	arbiterPath := strings.TrimPrefix(r.URL.Path, "/p/node/v1/arbiter")

	bootstrap := arbiterPath == "/api/heartbeat" || arbiterPath == "/api/exits"
	if !bootstrap && !np.isKnownControl(callerIP) {
		logWarnf("node-proxy: arbiter-proxy rejected unknown control ip=%s path=%s", callerIP, r.URL.Path)
		http.Error(w, `{"error":"unauthorized"}`, http.StatusForbidden)
		return
	}

	logDebugf("node-proxy: arbiter-proxy ip=%s path=%s", callerIP, arbiterPath)
	np.proxy.ServeHTTP(w, r)
}

// handleAuthCache serves a control's lookup into this exit's deferred-auth
// cache (authClient.authCache, keyed by device — see auth.go authDeviceKey).
// It lets a control recover a client's last known-good login via a *different*
// exit when the one terminating that client's tunnel is unreachable — the
// control-side half of "deferred authentication". Read-only: never queries
// the arbiter, only ever returns what this exit already has cached.
func (np *nodeProxy) handleAuthCache(w http.ResponseWriter, r *http.Request) {
	callerIP := remoteIP(r)
	if !np.isKnownControl(callerIP) {
		logWarnf("auth-cache: rejected unknown caller ip=%s", callerIP)
		http.Error(w, `{"error":"unauthorized"}`, http.StatusForbidden)
		return
	}
	if np.auth == nil {
		http.NotFound(w, r)
		return
	}
	deviceID := r.URL.Query().Get("device_id")
	if deviceID == "" {
		http.Error(w, `{"error":"device_id required"}`, http.StatusBadRequest)
		return
	}
	body, ok := np.auth.cachedAuth("dev:" + deviceID)
	if !ok {
		http.NotFound(w, r)
		return
	}
	logDebugf("auth-cache: served device=%.8s… to control=%s", deviceID, callerIP)
	w.Header().Set("Content-Type", "application/json")
	w.Write(body) //nolint:errcheck
}

// isKnownControl returns true if ip appears in the manifest's node address list.
func (np *nodeProxy) isKnownControl(ip string) bool {
	data, err := np.getManifest()
	if err != nil || len(data) == 0 {
		// No manifest available — fail open so controls aren't locked out on
		// arbiter outage, but log prominently.
		logWarnf("node-proxy: manifest unavailable, allowing control ip=%s (fail-open)", ip)
		return true
	}

	var sl struct {
		Nodes []struct {
			Addr string `json:"addr"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(data, &sl); err != nil {
		logWarnf("node-proxy: manifest parse error: %v — failing open", err)
		return true
	}

	for _, n := range sl.Nodes {
		host, _, err := net.SplitHostPort(n.Addr)
		if err != nil {
			host = n.Addr // addr without port
		}
		if host == ip {
			return true
		}
	}
	return false
}

// handleUpdate serves cached control binary files from cacheDir.
// Allowed names: version, snc-control, snc-control.sha256
func (np *nodeProxy) handleUpdate(w http.ResponseWriter, r *http.Request) {
	if np.cacheDir == "" {
		http.Error(w, `{"error":"update cache not configured"}`, http.StatusNotFound)
		return
	}

	name := strings.TrimPrefix(r.URL.Path, "/p/node/v1/update/")
	switch name {
	case "version", "snc-control", "snc-control.sha256":
		// allowed
	default:
		http.NotFound(w, r)
		return
	}

	data, err := os.ReadFile(filepath.Join(np.cacheDir, name))
	if err != nil {
		http.NotFound(w, r)
		return
	}

	switch name {
	case "snc-control":
		w.Header().Set("Content-Type", "application/octet-stream")
	default:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	w.Write(data) //nolint:errcheck
}

// serveProbe handles GET /p/v1/probe?url=<target> from control nodes.
// The exit makes an outbound HTTP HEAD request to the target URL and returns 200 or 503.
// Used by controls to verify this exit's data-plane connectivity to the open internet.
// Auth: caller IP must appear in the signed manifest of known control nodes.
func (np *nodeProxy) serveProbe(w http.ResponseWriter, r *http.Request) {
	callerIP := remoteIP(r)
	if !np.isKnownControl(callerIP) {
		logWarnf("probe: rejected unknown caller ip=%s", callerIP)
		http.Error(w, `{"error":"unauthorized"}`, http.StatusForbidden)
		return
	}

	rawURL := r.URL.Query().Get("url")
	if rawURL == "" {
		http.Error(w, `{"error":"url required"}`, http.StatusBadRequest)
		return
	}

	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		http.Error(w, `{"error":"invalid url: https/http only"}`, http.StatusBadRequest)
		return
	}
	if isPrivateHost(parsed.Hostname()) {
		http.Error(w, `{"error":"private address not allowed"}`, http.StatusBadRequest)
		return
	}

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodHead, rawURL, nil)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, http.StatusInternalServerError)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		logDebugf("probe: %s → fail: %v", rawURL, err)
		http.Error(w, `{"error":"probe failed"}`, http.StatusServiceUnavailable)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		logDebugf("probe: %s → HTTP %d", rawURL, resp.StatusCode)
		http.Error(w, `{"error":"probe returned error status"}`, http.StatusServiceUnavailable)
		return
	}
	logDebugf("probe: %s → ok status=%d", rawURL, resp.StatusCode)
	w.WriteHeader(http.StatusOK)
}

// isPrivateHost resolves host and returns true if any resolved IP is loopback,
// private, or link-local. Used to prevent SSRF via the probe endpoint.
func isPrivateHost(host string) bool {
	ips, err := net.LookupHost(host)
	if err != nil {
		return false // unresolvable; let the actual request fail
	}
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return true
		}
	}
	return false
}
