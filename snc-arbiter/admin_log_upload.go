// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// adminLogUploadRequireAdmin gates the two JSON endpoints below the same way
// adminGenerateKey does: admin session cookie OR X-Admin-Token header. No
// HTML page yet -- these are callable directly (curl / an ops script), the
// same way /admin/key/generate was before admin_keygen.html existed. A
// proper admin-panel page for this is a separate UI decision, not bundled
// in here.
func (h *handler) adminLogUploadRequireAdmin(r *http.Request) bool {
	if h.checkAdminAPIToken(r) {
		return true
	}
	u := h.currentUser(r)
	return u != nil && u.Role == "admin"
}

// adminLogUploadGlobalSet handles POST /admin/api/log-upload/global
// {"enabled": bool} -- the system-wide kill switch (see db.go's
// globalLogUploadEnabled), runtime-toggleable with no rebuild/redeploy.
func (h *handler) adminLogUploadGlobalSet(w http.ResponseWriter, r *http.Request) {
	if !h.adminLogUploadRequireAdmin(r) {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<10)).Decode(&req); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	who := "admin-token"
	if u := h.currentUser(r); u != nil {
		who = u.Username
	}
	if err := h.db.setGlobalLogUploadEnabled(req.Enabled, who); err != nil {
		logWarnf("admin-log-upload: set global enabled=%v: %v", req.Enabled, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	logInfof("admin-log-upload: %s set global enabled=%v", who, req.Enabled)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"enabled": req.Enabled}) //nolint:errcheck
}

// adminLogUploadUserOverride handles POST /admin/api/log-upload/user-override
// {"username": "...", "disabled": bool} -- forces log upload off (or clears
// that force) for one account regardless of that user's own preference. Set
// disabled=true for e.g. a compliance request or an abuse investigation;
// disabled=false clears it, returning control to the user's own setting.
func (h *handler) adminLogUploadUserOverride(w http.ResponseWriter, r *http.Request) {
	if !h.adminLogUploadRequireAdmin(r) {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Username string `json:"username"`
		Disabled bool   `json:"disabled"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<10)).Decode(&req); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" {
		jsonErr(w, "username required", http.StatusBadRequest)
		return
	}
	u, err := h.db.findUser(req.Username)
	if err != nil || u == nil {
		jsonErr(w, "no such user", http.StatusNotFound)
		return
	}
	if err := h.db.setUserLogUploadAdminDisabled(req.Username, req.Disabled); err != nil {
		logWarnf("admin-log-upload: set user=%s admin_disabled=%v: %v", req.Username, req.Disabled, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	who := "admin-token"
	if au := h.currentUser(r); au != nil {
		who = au.Username
	}
	logInfof("admin-log-upload: %s set user=%s admin_disabled=%v", who, req.Username, req.Disabled)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"username": req.Username, "disabled": req.Disabled}) //nolint:errcheck
}

// adminLogUploadStatus handles GET /admin/api/log-upload/status?username=...
// -- support/investigation helper: shows the global switch plus, if a
// username is given, that account's own preference/override/effective
// state, without having to reconstruct logUploadAllowed's logic by hand.
func (h *handler) adminLogUploadStatus(w http.ResponseWriter, r *http.Request) {
	if !h.adminLogUploadRequireAdmin(r) {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	resp := map[string]interface{}{
		"global_enabled": h.db.globalLogUploadEnabled(),
	}
	if username := strings.TrimSpace(r.URL.Query().Get("username")); username != "" {
		userEnabled, adminDisabled := h.db.userLogUploadPrefs(username)
		resp["username"] = username
		resp["user_enabled"] = userEnabled
		resp["admin_disabled"] = adminDisabled
		resp["effective"] = h.db.logUploadAllowed(username)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}
