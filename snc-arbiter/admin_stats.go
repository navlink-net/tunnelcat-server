// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ── POST /api/node/stats ──────────────────────────────────────────────────────

// nodeStatsPayload is what exit nodes POST to report per-user traffic stats.
type nodeStatsPayload struct {
	Users    []userStatEntry `json:"users"`
	Sessions []sessionEntry  `json:"sessions"`
	// RejectedSessions: how many sessions this exit gave up on since its last
	// flush because it couldn't deliver the user's data to the target or get
	// a response back -- see snc-exit/stats.go's RecordRejectedSession and
	// its three call sites in snc-exit/handler.go. The sole source of the
	// admin dashboard's "rejected sessions" stat (clients no longer report
	// this at all -- see tunnel_cat commit history 2026-08-16).
	RejectedSessions int64 `json:"rejected_sessions"`
}

// sessionEntry is one completed session, reported post-factum once a user
// has gone idle long enough (see snc-exit/stats.go's sweep()) -- never a
// live/in-progress figure.
type sessionEntry struct {
	Username string `json:"username"`
	Seconds  int64  `json:"seconds"`
	EndedAt  int64  `json:"ended_at"`
}

type userStatEntry struct {
	Username  string `json:"username"`
	Country   string `json:"country"` // ISO-2 from control_ip CIDR lookup, or ""
	BytesUp   int64  `json:"bytes_up"`
	BytesDown int64  `json:"bytes_down"`
	Conns     int64  `json:"conns"`
	LastSeen  int64  `json:"last_seen"` // Unix timestamp
}

// apiNodeStats handles POST /api/node/stats.
// Authenticated by X-Node-Token (any approved node).
func (h *handler) apiNodeStats(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Node-Token")
	if token == "" {
		jsonErr(w, "X-Node-Token required", http.StatusUnauthorized)
		return
	}
	node, err := h.db.nodeByToken(token)
	if err != nil || node == nil {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var payload nodeStatsPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}

	usernames := make([]string, 0, len(payload.Users))
	for _, u := range payload.Users {
		lastSeen := time.Unix(u.LastSeen, 0)
		if lastSeen.IsZero() || u.LastSeen == 0 {
			lastSeen = time.Now()
		}
		// If exit didn't supply a country, try to derive it from the node's own address.
		country := u.Country
		if country == "" {
			country = h.regionOf(node.Addr)
		}
		if err := h.db.UpsertUserStats(u.Username, country, u.BytesUp, u.BytesDown, u.Conns, lastSeen); err != nil {
			logWarnf("apiNodeStats: upsert user=%s: %v", u.Username, err)
		}
		usernames = append(usernames, u.Username)
	}
	// Full replace, not a merge -- this flush's user list IS this node's
	// current snapshot for the live "Active users" count (db_active_users.go).
	if err := h.db.UpsertNodeActiveUsers(node.ID, usernames, time.Now().Unix()); err != nil {
		logWarnf("apiNodeStats: upsert node active users node=%d: %v", node.ID, err)
	}

	for _, s := range payload.Sessions {
		endedAt := s.EndedAt
		if endedAt == 0 {
			endedAt = time.Now().Unix()
		}
		if err := h.db.insertSessionDuration(s.Username, node.ID, s.Seconds, endedAt); err != nil {
			logWarnf("apiNodeStats: insert session user=%s: %v", s.Username, err)
		}
	}

	if payload.RejectedSessions > 0 {
		if err := h.db.insertRejectedSessions(node.ID, payload.RejectedSessions, time.Now().Unix()); err != nil {
			logWarnf("apiNodeStats: insert rejected sessions node=%d: %v", node.ID, err)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`)) //nolint:errcheck
}

// ── GET /admin/api/users/stats ────────────────────────────────────────────────

type adminUsersStatsResponse struct {
	Users []userStatRow `json:"users"`
}

type userStatRow struct {
	Username     string `json:"username"`
	FirstSeen    string `json:"first_seen"`
	LastSeen     string `json:"last_seen"`
	LastSeenUnix int64  `json:"last_seen_unix"`
	Active       bool   `json:"active"` // seen within 5 min (server-side, no clock skew)
	Recent       bool   `json:"recent"` // seen within 30 min
	BytesUp      int64  `json:"bytes_up"`
	BytesDown    int64  `json:"bytes_down"`
	Country      string `json:"country"`
	Conns        int64  `json:"conns"`
	Suspended    bool   `json:"suspended"` // user_enabled=0
}

// apiAdminUsersStats handles GET /admin/api/users/stats?q=<search>.
// Requires admin session.
func (h *handler) apiAdminUsersStats(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	like := "%"
	if q != "" {
		like = "%" + q + "%"
	}

	now := time.Now()
	active5m := now.Add(-5 * time.Minute)
	active30m := now.Add(-30 * time.Minute)

	resp := adminUsersStatsResponse{}

	stats, err := h.db.QueryUserStats(like)
	if err != nil {
		logWarnf("apiAdminUsersStats: query: %v", err)
		jsonErr(w, "database error", http.StatusInternalServerError)
		return
	}
	for _, s := range stats {
		resp.Users = append(resp.Users, userStatRow{
			Username:     s.Username,
			FirstSeen:    s.FirstSeen.UTC().Format("2006-01-02 15:04"),
			LastSeen:     s.LastSeen.UTC().Format("2006-01-02 15:04"),
			LastSeenUnix: s.LastSeen.Unix(),
			Active:       s.LastSeen.After(active5m),
			Recent:       s.LastSeen.After(active30m),
			BytesUp:      s.BytesUp,
			BytesDown:    s.BytesDown,
			Country:      s.Country,
			Conns:        s.Conns,
			Suspended:    s.Suspended,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

// ── GET /admin/api/users/summary ────────────────────────────────────────────

// apiAdminUsersSummary serves GET /admin/api/users/summary?range=24h|7d|30d --
// scalar summary numbers for the Users tab of the network-stats page, next
// to (not replacing) the existing time-series charts there: average session
// duration and distinct users connected, all scoped to the same range
// toggle those charts already use (statsRangeWindow).
// Also includes session_duration_buckets, 10-min-bucketed history for the
// avg-session-duration chart -- the scalar avg_session_seconds above is just
// that same data collapsed to one number for the range, so both come from
// the same query window in one round trip rather than two.
func (h *handler) apiAdminUsersSummary(w http.ResponseWriter, r *http.Request) {
	window := statsRangeWindow(r.URL.Query().Get("range"))
	since := time.Now().Add(-window)

	avgSessionSeconds, err := h.db.AvgSessionDuration(window)
	if err != nil {
		logWarnf("apiAdminUsersSummary: avg session duration: %v", err)
	}
	sessionBuckets, err := h.db.AvgSessionDurationHistory(since)
	if err != nil {
		logWarnf("apiAdminUsersSummary: avg session duration history: %v", err)
	}
	distinctUsers, err := h.db.CountActiveUsers(window)
	if err != nil {
		logWarnf("apiAdminUsersSummary: distinct users: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
		"avg_session_seconds":      avgSessionSeconds,
		"session_duration_buckets": sessionBuckets,
		"distinct_users":           distinctUsers,
	})
}

// ── GET /admin/api/users/export.csv ──────────────────────────────────────────

// apiAdminUsersCSV exports all users as a CSV file.
// Columns: email, status, country, first_seen, last_seen, bytes_up, bytes_down, connections
func (h *handler) apiAdminUsersCSV(w http.ResponseWriter, r *http.Request) {
	stats, err := h.db.QueryUserStats("%")
	if err != nil {
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="users.csv"`)

	cw := csv.NewWriter(w)
	cw.Write([]string{"email", "status", "country", "first_seen", "last_seen", "bytes_up", "bytes_down", "connections"}) //nolint:errcheck
	for _, u := range stats {
		status := "active"
		if u.Suspended {
			status = "suspended"
		}
		cw.Write([]string{ //nolint:errcheck
			u.Username,
			status,
			u.Country,
			u.FirstSeen.UTC().Format("2006-01-02 15:04"),
			u.LastSeen.UTC().Format("2006-01-02 15:04"),
			fmt.Sprintf("%d", u.BytesUp),
			fmt.Sprintf("%d", u.BytesDown),
			fmt.Sprintf("%d", u.Conns),
		})
	}
	cw.Flush()
}

// ── GET /admin/users ──────────────────────────────────────────────────────────

// adminUsersPage renders the user stats admin page.
func (h *handler) adminUsersPage(w http.ResponseWriter, r *http.Request) {
	u := h.currentUser(r)
	h.renderPage(w, "admin_users.html", pageData{User: u})
}
