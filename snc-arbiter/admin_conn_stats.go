// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ── GET /admin/api/users/{username}/conn-stats?range=24h|7d|30d ────────────

// apiAdminUserConnStats serves one user's per-device connection-stats
// history, for the connection-health chart(s) on their stats page --
// mirrors apiAdminUserBananameter's shape exactly.
func (h *handler) apiAdminUserConnStats(w http.ResponseWriter, r *http.Request) {
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
	buckets, err := h.db.userConnStatsHistory(username, time.Now().Add(-window))
	if err != nil {
		jsonErr(w, "query failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"buckets": buckets}) //nolint:errcheck
}

// ── GET /admin/api/network/conn-stats?range=24h|7d|30d ──────────────────────

// apiAdminNetworkConnStats serves the fleet-wide average connection-stats
// chart data for the Users tab -- mirrors apiAdminNetworkBananameter's shape.
func (h *handler) apiAdminNetworkConnStats(w http.ResponseWriter, r *http.Request) {
	window := statsRangeWindow(r.URL.Query().Get("range"))
	since := time.Now().Add(-window)
	buckets, err := h.db.fleetConnStatsHistory(since)
	if err != nil {
		jsonErr(w, "query failed", http.StatusInternalServerError)
		return
	}
	// "Rejected sessions" is reported exclusively by exits now (see
	// db_rejected_sessions.go) -- clients no longer send it at all, so
	// fleetConnStatsHistory's own client_conn_stats-sourced value is always
	// 0. Overlay the real exit-reported counts onto the same buckets by
	// timestamp so the chart keeps its existing position/shape on the
	// dashboard, just backed by the correct source.
	rejected, err := h.db.fleetRejectedSessionsHistory(since)
	if err != nil {
		logWarnf("apiAdminNetworkConnStats: rejected sessions query: %v", err)
	} else {
		byBucket := make(map[int64]int64, len(rejected))
		for _, rb := range rejected {
			byBucket[rb.Ts] = rb.Count
		}
		for i := range buckets {
			buckets[i].RejectedSessions = float64(byBucket[buckets[i].Ts])
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"buckets": buckets}) //nolint:errcheck
}
