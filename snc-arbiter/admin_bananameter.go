// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ── GET /admin/api/network/bananameter?range=24h|7d|30d ─────────────────────

// apiAdminNetworkBananameter serves the system-wide BananaMeter chart data
// for the Network Stats tab: client/control/exit each as their own series
// over the same timeline (see TODO.md "BananaMeter-based tunnel
// diagnostics" for why comparing these three legs localizes a slowdown).
func (h *handler) apiAdminNetworkBananameter(w http.ResponseWriter, r *http.Request) {
	window := statsRangeWindow(r.URL.Query().Get("range"))
	buckets, err := h.db.networkBananameterHistory(time.Now().Add(-window))
	if err != nil {
		jsonErr(w, "query failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"buckets": buckets}) //nolint:errcheck
}

// ── GET /admin/api/network/bananameter/by-type?type=control|exit&range= ────

// apiAdminTypeBananameter serves the per-node-type breakdown chart data for
// the Controls/Egresses tabs: the bold combined average plus each node's
// own thin series, so an admin can see which specific node caused a drop
// in the average instead of just seeing the average drop (see TODO.md
// "BananaMeter-based tunnel diagnostics").
func (h *handler) apiAdminTypeBananameter(w http.ResponseWriter, r *http.Request) {
	sourceType := r.URL.Query().Get("type")
	if sourceType != "control" && sourceType != "exit" {
		jsonErr(w, "type must be 'control' or 'exit'", http.StatusBadRequest)
		return
	}
	window := statsRangeWindow(r.URL.Query().Get("range"))
	data, err := h.db.typeBananameterBreakdown(sourceType, time.Now().Add(-window))
	if err != nil {
		jsonErr(w, "query failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data) //nolint:errcheck
}

// ── GET /admin/api/nodes/{id}/bananameter?range=24h|7d|30d ──────────────────

// apiAdminNodeBananameter serves one node's own BananaMeter chart data (its
// own probe history) plus, for a control node, the per-exit breakdown of
// which specific exit its probes went through -- see TODO.md.
func (h *handler) apiAdminNodeBananameter(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 {
		jsonErr(w, "bad path", http.StatusBadRequest)
		return
	}
	nodeID, err := strconv.ParseInt(parts[len(parts)-2], 10, 64)
	if err != nil {
		jsonErr(w, "bad node id", http.StatusBadRequest)
		return
	}
	node, err := h.db.nodeByID(nodeID)
	if err != nil || node == nil {
		jsonErr(w, "node not found", http.StatusNotFound)
		return
	}

	window := statsRangeWindow(r.URL.Query().Get("range"))
	since := time.Now().Add(-window)

	buckets, err := h.db.nodeBananameterHistory(node.Type, node.Addr, since)
	if err != nil {
		jsonErr(w, "query failed", http.StatusInternalServerError)
		return
	}
	resp := map[string]interface{}{"buckets": buckets}

	if node.Type == "control" {
		peers, err := h.db.nodeBananameterPeers(node.Type, node.Addr, since)
		if err != nil {
			jsonErr(w, "query failed", http.StatusInternalServerError)
			return
		}
		resp["peers"] = peers
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

// ── GET /admin/users/{username}/stats ────────────────────────────────────────

// userStatsPageData is passed to admin_user_stats.html.
type userStatsPageData struct {
	Username string
	Stats    *UserStatRow // nil if this user has no traffic recorded yet
	Devices  []KeyRow
}

// adminUserStatsPage renders GET /admin/users/{username}/stats -- the
// per-user detail page: devices, aggregate data volume, and (via JS fetch)
// per-device BananaMeter speed history.
func (h *handler) adminUserStatsPage(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 4 {
		http.NotFound(w, r)
		return
	}
	username, err := url.PathUnescape(parts[2])
	if err != nil || username == "" {
		http.NotFound(w, r)
		return
	}

	statsRows, err := h.db.QueryUserStats(username)
	if err != nil {
		jsonErr(w, "database error", http.StatusInternalServerError)
		return
	}
	var stats *UserStatRow
	for i := range statsRows {
		if statsRows[i].Username == username {
			stats = &statsRows[i]
			break
		}
	}

	devices, err := h.db.QueryUserKeys(username)
	if err != nil {
		jsonErr(w, "database error", http.StatusInternalServerError)
		return
	}

	u := h.currentUser(r)
	h.renderPage(w, "admin_user_stats.html", pageData{
		User: u,
		Data: userStatsPageData{Username: username, Stats: stats, Devices: devices},
	})
}

// ── GET /admin/api/users/{username}/bananameter?range=24h|7d|30d ────────────

// apiAdminUserBananameter serves one user's per-device BananaMeter history,
// for the speed-per-device chart on their stats page.
func (h *handler) apiAdminUserBananameter(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 {
		jsonErr(w, "bad path", http.StatusBadRequest)
		return
	}
	username, err := url.PathUnescape(parts[len(parts)-2])
	if err != nil || username == "" {
		jsonErr(w, "bad username", http.StatusBadRequest)
		return
	}

	window := statsRangeWindow(r.URL.Query().Get("range"))
	buckets, err := h.db.userBananameterHistory(username, time.Now().Add(-window))
	if err != nil {
		jsonErr(w, "query failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"buckets": buckets}) //nolint:errcheck
}
