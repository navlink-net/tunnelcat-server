// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/json"
	"net/http"
)

// apiSessionToken handles GET /api/session/token — browser-facing, called with
// credentials:include so the existing HttpOnly snc_session cookie is sent.
// Returns the raw session token in the JSON body so a page's own JS (which
// cannot read an HttpOnly cookie directly) can hand it to a *different*
// origin's API as a bearer credential. That other service is expected to
// treat the token as opaque and validate it server-to-server via
// apiSessionVerify below -- it must never trust a username/role claimed by
// the browser directly.
func (h *handler) apiSessionToken(w http.ResponseWriter, r *http.Request) {
	sess, err := h.webSession(r)
	if err != nil || sess == nil {
		jsonErr(w, "not logged in", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": sess.Token}) //nolint:errcheck
}

// apiSessionVerify handles POST /api/session/verify {token} — server-to-server
// only (not meant to be called from a browser). Lets another service (e.g.
// CATalogue, the container-app store, deliberately kept as its own process/DB per the
// 2026-08-12 decision not to fold new functionality into the arbiter) check
// who a bearer token it was handed actually belongs to, without needing its
// own copy of the session table.
func (h *handler) apiSessionVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		jsonErr(w, "invalid request", http.StatusBadRequest)
		return
	}
	sess, err := h.db.getSession(req.Token)
	if err != nil || sess == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"valid": false}) //nolint:errcheck
		return
	}
	u, err := h.db.getOrCreateUser(sess.Username)
	if err != nil {
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
		"valid":    true,
		"username": sess.Username,
		"role":     u.Role,
	})
}
