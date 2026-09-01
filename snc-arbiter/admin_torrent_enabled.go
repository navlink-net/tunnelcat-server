// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"net/http"
	"sync"
)

// torrentState caches the torrent_enabled toggle in memory.
//
// Half of the client-side torrent feature's double gate (see
// tunnel_cat/snc/core/torrent.go's TorrentGate doc comment) -- the other
// half is each user's local settings toggle. This half is the fleet-wide
// admin kill switch, broadcast to clients via the signed manifest's
// advisory torrent_enabled field (see apiManifest/apiManifestClientFetch).
// Unlike relay_enabled/ipv6_enabled, this one defaults to false (absent
// setting = disabled), since bundling a BitTorrent client is opt-in by
// deliberate product decision, not opt-out.
type torrentState struct {
	mu      sync.RWMutex
	enabled bool
}

// loadTorrentState refreshes the in-memory toggle from DB.
// Default is false (torrent feature disabled) when the setting is absent.
func (h *handler) loadTorrentState() {
	val, ok, err := h.db.getSetting("torrent_enabled")
	if err != nil {
		logWarnf("torrent: load setting: %v", err)
		return
	}
	h.torrentFeature.mu.Lock()
	defer h.torrentFeature.mu.Unlock()
	h.torrentFeature.enabled = ok && val == "1"
}

// torrentFeatureEnabled returns the current torrent-feature toggle (safe
// for concurrent use). Named to avoid colliding with the pre-existing
// per-exit torrent_allowed egress filter (torrent_allowed.go) -- that one
// governs whether an exit node may carry torrent traffic at all; this one
// governs whether the client-side BitTorrent engine is allowed to run.
func (h *handler) torrentFeatureEnabled() bool {
	h.torrentFeature.mu.RLock()
	defer h.torrentFeature.mu.RUnlock()
	return h.torrentFeature.enabled
}

// adminTorrentToggle handles POST /admin/torrent/toggle.
// Reads form field "enable" ("1" = enabled, "0" = disabled).
func (h *handler) adminTorrentToggle(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	enable := r.FormValue("enable") == "1"
	admin := h.currentUser(r)
	who := "admin"
	if admin != nil {
		who = admin.Username
	}

	val := "0"
	if enable {
		val = "1"
	}
	if err := h.db.setSetting("torrent_enabled", val, who); err != nil {
		logWarnf("torrent: toggle: %v", err)
	}
	h.loadTorrentState()

	action := "disabled"
	if enable {
		action = "enabled"
	}
	logInfof("admin: torrent feature %s by %s", action, who)
	http.Redirect(w, r, "/admin?flash=Torrent+feature+"+action, http.StatusSeeOther)
}
