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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// relayAPIHandler serves the relay tracker endpoints over TLS.
// Reached via ChRelayAPI channel (TLS session ID byte[1] == 0x01).
type relayAPIHandler struct {
	updateDir      string            // directory containing update files; empty = updates disabled
	arbiterPubkey  ed25519.PublicKey // for verifying /p/v1/refresh requests; nil = disabled
	triggerRefresh func()            // called on /p/v1/refresh to force exit-list reload
	exits          *ExitRegistry     // for /p/v1/ping, /p/v1/log/get, manifest polling
	nodeToken      string            // node token sent to arbiter as X-Node-Token
	authCache      *authCache        // for /p/v1/auth/cached — deferred-auth fallback

	onClientCacheRefresh func()                     // called on /p/v1/refresh to trigger immediate client binary re-check
	onNewManifest        func(raw []byte, ts int64) // called when a fresh manifest is cached; used by DHT gossip

	contentChunks *contentChunkCache // fallback chunk fetch-through for /p/v1/content/chunk; nil = disabled

	// manifest cache: populated by startManifestPoller, served at /p/v1/manifest.
	manifestMu      sync.RWMutex
	manifestData    []byte
	manifestFetched time.Time

	// club manifest cache: populated by startClubManifestPoller (see
	// club_relay_api.go), served at /p/v1/club-manifest. Independent of the
	// general manifest cache above — a parallel channel, not a variant.
	clubManifestMu      sync.RWMutex
	clubManifestData    map[string][]byte
	clubManifestFetched map[string]time.Time
}

func newRelayAPIHandler(updateDir string, arbiterPubkey ed25519.PublicKey, triggerRefresh func(), exits *ExitRegistry, nodeToken string, authCache *authCache) *relayAPIHandler {
	return &relayAPIHandler{
		updateDir:      updateDir,
		arbiterPubkey:  arbiterPubkey,
		triggerRefresh: triggerRefresh,
		exits:          exits,
		nodeToken:      nodeToken,
		authCache:      authCache,
	}
}

func (h *relayAPIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/p/v1/relay/list" && r.Method == http.MethodGet:
		// Backward-compat stub: relay list is now served via DHT; return empty.
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"version":2,"relays":[]}`)) //nolint:errcheck
	case r.URL.Path == "/p/v1/myip" && r.Method == http.MethodGet:
		h.myip(w, r)
	case strings.HasPrefix(r.URL.Path, "/p/v1/update/") && r.Method == http.MethodGet:
		h.serveUpdate(w, r)
	case r.URL.Path == "/p/v1/log/get" && r.Method == http.MethodGet:
		h.logGet(w, r)
	case r.URL.Path == "/p/v1/health" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`)) //nolint:errcheck
	case r.URL.Path == "/p/v1/ping" && r.Method == http.MethodGet:
		if h.exits != nil && !h.exits.anyAlive() {
			return
		}
		rttMs := 0.0
		if h.exits != nil {
			rttMs = h.exits.MinEffectiveRTT()
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct { //nolint:errcheck
			OK    bool    `json:"ok"`
			RTTMs float64 `json:"rtt_ms"`
		}{OK: true, RTTMs: rttMs})
	case r.URL.Path == "/p/v1/manifest" && r.Method == http.MethodGet:
		h.serveManifest(w, r)
	case r.URL.Path == "/p/v1/club-manifest" && r.Method == http.MethodGet:
		h.serveClubManifest(w, r)
	case r.URL.Path == "/p/v1/club-key" && r.Method == http.MethodGet:
		h.serveClubKey(w, r)
	case r.URL.Path == "/p/v1/club-recommend" && r.Method == http.MethodPost:
		h.serveClubRecommend(w, r)
	case r.URL.Path == "/p/v1/content/chunk" && r.Method == http.MethodGet:
		h.serveContentChunk(w, r)
	case r.URL.Path == "/p/v1/refresh" && r.Method == http.MethodPost:
		h.refresh(w, r)
	case r.URL.Path == "/p/v1/auth/cached" && r.Method == http.MethodPost:
		h.authCached(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *relayAPIHandler) myip(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	logDebugf("myip: request from RemoteAddr=%q → ip=%q", r.RemoteAddr, host)
	w.Header().Set("Content-Type", "application/json")
	if encErr := json.NewEncoder(w).Encode(map[string]string{"ip": host}); encErr != nil {
		logWarnf("myip: encode error: %v", encErr)
	}
	logDebugf("myip: response sent ip=%q", host)
}

// authCached handles POST /p/v1/auth/cached — the control-side fallback for
// "deferred authentication" (incident 2026-06-08). A client whose primary
// login attempt (terminated at an exit, see snc-exit/auth.go authenticate)
// came back transient — i.e. that exit could not reach the arbiter and had
// no cached login of its own — asks control whether *any* exit has a cached
// login for this device.
//
// Control never validates credentials itself and never talks to the arbiter
// or holds its address, under any circumstances or for any purpose:
// authCache.lookup only ever reads from its own short-lived cache or queries
// an exit's read-only /p/node/v1/auth-cache endpoint.
func (h *relayAPIHandler) authCached(w http.ResponseWriter, r *http.Request) {
	if h.authCache == nil {
		http.NotFound(w, r)
		return
	}
	var req struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || req.DeviceID == "" {
		http.Error(w, `{"error":"device_id required"}`, http.StatusBadRequest)
		return
	}

	body, ok := h.authCache.lookup(req.DeviceID)
	if !ok {
		logDebugf("auth-cached: no cached login anywhere for device=%.8s…", req.DeviceID)
		http.Error(w, `{"error":"no cached login","transient":true}`, http.StatusServiceUnavailable)
		return
	}
	logInfof("auth-cached: served deferred login for device=%.8s…", req.DeviceID)
	w.Header().Set("Content-Type", "application/json")
	w.Write(body) //nolint:errcheck
}

// serveUpdate serves files from updateDir under /p/v1/update/.
func (h *relayAPIHandler) serveUpdate(w http.ResponseWriter, r *http.Request) {
	if h.updateDir == "" {
		http.Error(w, "updates not configured", http.StatusNotFound)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/p/v1/update/")
	switch name {
	case "version", "client", "client.sha256",
		"client-android-version", "client-android", "client-android.sha256":
		// allowed
	default:
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(h.updateDir, name)
	data, err := os.ReadFile(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch name {
	case "version", "client.sha256", "client-android-version", "client-android.sha256":
		w.Header().Set("Content-Type", "text/plain")
	case "client":
		w.Header().Set("Content-Type", "application/zip")
	case "client-android":
		w.Header().Set("Content-Type", "application/vnd.android.package-archive")
	}
	w.Write(data) //nolint:errcheck
}

// refresh handles POST /p/v1/refresh from the arbiter.
// Verifies the Ed25519 signature, checks the timestamp, and triggers an
// immediate exit-list reload.
func (h *relayAPIHandler) refresh(w http.ResponseWriter, r *http.Request) {
	if h.arbiterPubkey == nil {
		logWarnf("relay-api: /refresh received but no arbiter pubkey configured")
		http.Error(w, `{"error":"refresh not configured"}`, http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1024))
	if err != nil {
		http.Error(w, `{"error":"read body"}`, http.StatusBadRequest)
		return
	}
	sigB64 := r.Header.Get("X-Arbiter-Sig")
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		logWarnf("relay-api: /refresh bad signature from %s", r.RemoteAddr)
		http.Error(w, `{"error":"bad signature"}`, http.StatusUnauthorized)
		return
	}
	if !ed25519.Verify(h.arbiterPubkey, body, sig) {
		logWarnf("relay-api: /refresh signature verification failed from %s", r.RemoteAddr)
		http.Error(w, `{"error":"invalid signature"}`, http.StatusUnauthorized)
		return
	}
	var payload struct {
		TS int64 `json:"ts"`
	}
	if err := json.Unmarshal(body, &payload); err != nil || payload.TS == 0 {
		http.Error(w, `{"error":"bad payload"}`, http.StatusBadRequest)
		return
	}
	age := time.Since(time.Unix(payload.TS, 0)).Abs()
	if age > 60*time.Second {
		logWarnf("relay-api: /refresh stale timestamp age=%s from %s", age.Round(time.Second), r.RemoteAddr)
		http.Error(w, `{"error":"stale request"}`, http.StatusUnauthorized)
		return
	}
	logInfof("relay-api: /refresh from %s — triggering exit-list reload + client cache refresh", r.RemoteAddr)
	if h.triggerRefresh != nil {
		go h.triggerRefresh()
	}
	if h.onClientCacheRefresh != nil {
		go h.onClientCacheRefresh()
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`)) //nolint:errcheck
}

func (h *relayAPIHandler) logGet(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node")
	if nodeID == "" {
		http.Error(w, "node query param required", http.StatusBadRequest)
		return
	}
	exit, err := h.exits.PickRandom()
	if err != nil {
		http.Error(w, "no exit available", http.StatusServiceUnavailable)
		return
	}
	target := exitProxyURL(exit.Addr, "/api/log/get?node="+nodeID)
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	req.Header.Set("X-Node-Token", h.nodeToken)
	resp, err := nodeProxyClient().Do(req)
	if err != nil {
		logWarnf("log-get: forward via exit=%s node=%.16s…: %v", exit.Addr, nodeID, err)
		http.Error(w, "forward error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.Header().Set("Content-Encoding", resp.Header.Get("Content-Encoding"))
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body) //nolint:errcheck
}

// logUpload (client -> control's relay-API channel -> a randomly picked
// exit -> arbiter) was removed 2026-08-11: that path was hop-by-hop TLS
// only, so both control and whichever exit happened to relay a given
// upload saw the full decompressed log content in plaintext -- found after
// a raw third-party OAuth token turned up in cleartext in a real user's uploaded
// logs. Clients now POST directly to https://navlink.net/api/log/client-upload
// over their own live tunnel dialer (tunnel_cat/snc/core/log_upload.go),
// which is genuinely end-to-end and removes this blind intermediary
// entirely -- see snc-arbiter/log_upload_client_api.go.

const manifestPollInterval = 5 * time.Minute

func (h *relayAPIHandler) startManifestPoller() {
	go h.manifestPollLoop()
}

func (h *relayAPIHandler) manifestPollLoop() {
	h.pollManifestOnce()
	t := time.NewTicker(manifestPollInterval)
	defer t.Stop()
	for range t.C {
		h.pollManifestOnce()
	}
}

func (h *relayAPIHandler) pollManifestOnce() {
	if h.exits == nil {
		return
	}
	exit, err := h.exits.PickRandom()
	if err != nil {
		logDebugf("manifest-poller: no exits available: %v", err)
		return
	}
	addr := strings.TrimPrefix(strings.TrimPrefix(exit.Addr, "https://"), "http://")
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = addr + ":443"
	}
	url := "https://" + addr + "/api/manifest"
	resp, err := nodeProxyClient().Get(url)
	if err != nil {
		logWarnf("manifest-poller: GET %s: %v", url, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logWarnf("manifest-poller: exit %s returned %d", exit.Addr, resp.StatusCode)
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		logWarnf("manifest-poller: read: %v", err)
		return
	}
	if len(data) == 0 {
		logWarnf("manifest-poller: exit %s returned empty manifest", exit.Addr)
		return
	}
	h.manifestMu.Lock()
	h.manifestData = data
	h.manifestFetched = time.Now()
	onManifest := h.onNewManifest
	h.manifestMu.Unlock()
	logInfof("manifest-poller: cached %d bytes from exit %s", len(data), exit.Addr)

	// Extract ts from the manifest JSON to pass to DHT gossip.
	if onManifest != nil {
		var hdr struct {
			TS int64 `json:"ts"`
		}
		if jsonErr := json.Unmarshal(data, &hdr); jsonErr == nil && hdr.TS > 0 {
			go onManifest(data, hdr.TS)
		}
	}
}

func (h *relayAPIHandler) serveManifest(w http.ResponseWriter, r *http.Request) {
	h.manifestMu.RLock()
	data := h.manifestData
	h.manifestMu.RUnlock()
	if len(data) == 0 {
		http.Error(w, `{"error":"manifest not yet available"}`, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data) //nolint:errcheck
}

// WLWTPPortsForSelf returns the dynamic WLWTP ports assigned to this node
// in the latest cached manifest. selfAddr must be in "ip:port" form
// matching the key used by the arbiter (e.g. "89.169.155.120:443").
func (h *relayAPIHandler) WLWTPPortsForSelf(selfAddr string) []int {
	h.manifestMu.RLock()
	data := h.manifestData
	h.manifestMu.RUnlock()
	if len(data) == 0 {
		return nil
	}
	var m struct {
		NodeWLWTPPorts map[string][]int `json:"node_wlwtp_ports"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	return m.NodeWLWTPPorts[selfAddr]
}
