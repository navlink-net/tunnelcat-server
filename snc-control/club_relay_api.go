// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// club_relay_api.go — control-side half of the parallel club-manifest
// channel. Mirrors the general manifest's poll/cache/serve mechanics in
// relay_api.go exactly, keyed per club slug — same clubSlugs constant
// shape as snc-exit/club_handler.go (kept independently, not shared code,
// since exit and control are separate binaries/modules boundary-wise).
//
// club-key is different: it's a per-user check (X-Session), not something
// control can cache — it's forwarded live through the exit's existing
// generic "/p/node/v1/arbiter/*" proxy (see exits.go's exitProxyURL),
// exactly like logGet already does for a different endpoint.

var relayClubSlugs = []string{"cat_club", "elite_cat_club"}

const clubManifestPollInterval = 5 * time.Minute

func (h *relayAPIHandler) startClubManifestPoller() {
	go h.clubManifestPollLoop()
}

func (h *relayAPIHandler) clubManifestPollLoop() {
	h.pollClubManifestsOnce()
	t := time.NewTicker(clubManifestPollInterval)
	defer t.Stop()
	for range t.C {
		h.pollClubManifestsOnce()
	}
}

func (h *relayAPIHandler) pollClubManifestsOnce() {
	for _, slug := range relayClubSlugs {
		h.pollClubManifestOnce(slug)
	}
}

func (h *relayAPIHandler) pollClubManifestOnce(slug string) {
	if h.exits == nil {
		return
	}
	exit, err := h.exits.PickRandom()
	if err != nil {
		logDebugf("club-manifest-poller %s: no exits available: %v", slug, err)
		return
	}
	addr := strings.TrimPrefix(strings.TrimPrefix(exit.Addr, "https://"), "http://")
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = addr + ":443"
	}
	url := "https://" + addr + "/api/club-manifest?club=" + slug
	resp, err := nodeProxyClient().Get(url)
	if err != nil {
		logWarnf("club-manifest-poller %s: GET %s: %v", slug, url, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logWarnf("club-manifest-poller %s: exit %s returned %d", slug, exit.Addr, resp.StatusCode)
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		logWarnf("club-manifest-poller %s: read: %v", slug, err)
		return
	}
	if len(data) == 0 {
		logWarnf("club-manifest-poller %s: exit %s returned empty manifest", slug, exit.Addr)
		return
	}

	h.clubManifestMu.Lock()
	if h.clubManifestData == nil {
		h.clubManifestData = make(map[string][]byte)
		h.clubManifestFetched = make(map[string]time.Time)
	}
	h.clubManifestData[slug] = data
	h.clubManifestFetched[slug] = time.Now()
	h.clubManifestMu.Unlock()
	logInfof("club-manifest-poller %s: cached %d bytes from exit %s", slug, len(data), exit.Addr)
}

// serveClubManifest handles GET /p/v1/club-manifest?club=<slug>.
func (h *relayAPIHandler) serveClubManifest(w http.ResponseWriter, r *http.Request) {
	slug := r.URL.Query().Get("club")
	h.clubManifestMu.RLock()
	data := h.clubManifestData[slug]
	h.clubManifestMu.RUnlock()
	if len(data) == 0 {
		http.Error(w, `{"error":"club manifest not yet available"}`, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data) //nolint:errcheck
}

// serveClubKey handles GET /p/v1/club-key?club=<slug> — forwards the
// client's X-Session header live through a random exit's generic arbiter
// proxy to the arbiter's /api/club-key. Not cacheable (per-user), unlike
// the manifest above.
func (h *relayAPIHandler) serveClubKey(w http.ResponseWriter, r *http.Request) {
	slug := r.URL.Query().Get("club")
	if slug == "" {
		http.Error(w, `{"error":"club required"}`, http.StatusBadRequest)
		return
	}
	sessionTok := r.Header.Get("X-Session")
	if sessionTok == "" {
		http.Error(w, `{"error":"X-Session required"}`, http.StatusUnauthorized)
		return
	}
	if h.exits == nil {
		http.Error(w, `{"error":"no exits available"}`, http.StatusServiceUnavailable)
		return
	}
	exit, err := h.exits.PickRandom()
	if err != nil {
		http.Error(w, `{"error":"no exits available"}`, http.StatusServiceUnavailable)
		return
	}
	target := exitProxyURL(exit.Addr, "/api/club-key?club="+slug)
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	req.Header.Set("X-Session", sessionTok)
	resp, err := nodeProxyClient().Do(req)
	if err != nil {
		logWarnf("club-key: forward via exit=%s club=%s: %v", exit.Addr, slug, err)
		http.Error(w, `{"error":"forward error"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body) //nolint:errcheck
}

// serveClubRecommend handles POST /p/v1/club-recommend — forwards the
// client's X-Session header and JSON body live through a random exit's
// generic arbiter proxy to the arbiter's /api/club-recommend. Same
// per-user, not-cacheable shape as serveClubKey.
func (h *relayAPIHandler) serveClubRecommend(w http.ResponseWriter, r *http.Request) {
	sessionTok := r.Header.Get("X-Session")
	if sessionTok == "" {
		http.Error(w, `{"error":"X-Session required"}`, http.StatusUnauthorized)
		return
	}
	if h.exits == nil {
		http.Error(w, `{"error":"no exits available"}`, http.StatusServiceUnavailable)
		return
	}
	exit, err := h.exits.PickRandom()
	if err != nil {
		http.Error(w, `{"error":"no exits available"}`, http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil {
		http.Error(w, `{"error":"read body"}`, http.StatusBadRequest)
		return
	}
	target := exitProxyURL(exit.Addr, "/api/club-recommend")
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	req.Header.Set("X-Session", sessionTok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := nodeProxyClient().Do(req)
	if err != nil {
		logWarnf("club-recommend: forward via exit=%s: %v", exit.Addr, err)
		http.Error(w, `{"error":"forward error"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body) //nolint:errcheck
}
