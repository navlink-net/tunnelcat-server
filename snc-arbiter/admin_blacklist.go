// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"net/http"
	"strconv"
	"strings"
)

// adminBlacklistPage redirects GET /admin/blacklist to the combined lists page.
func (h *handler) adminBlacklistPage(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/admin/whitelist", http.StatusFound)
}

// adminBlacklistAdd handles POST /admin/blacklist/add.
func (h *handler) adminBlacklistAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	addr := strings.TrimSpace(r.FormValue("addr"))
	reason := strings.TrimSpace(r.FormValue("reason"))
	if addr == "" {
		http.Redirect(w, r, "/admin/whitelist", http.StatusFound)
		return
	}
	if err := h.db.addBlacklistEntry(addr, reason); err != nil {
		logWarnf("blacklist add: %v", err)
	}
	logInfof("blacklist: added addr=%s reason=%s", addr, reason)
	http.Redirect(w, r, "/admin/whitelist", http.StatusFound)
}

// adminBlacklistDelete handles POST /admin/blacklist/delete.
func (h *handler) adminBlacklistDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := h.db.deleteBlacklistEntry(id); err != nil {
		logWarnf("blacklist delete %d: %v", id, err)
	}
	logInfof("blacklist: deleted id=%d", id)
	http.Redirect(w, r, "/admin/whitelist", http.StatusFound)
}

// apiBlacklist returns the signed blacklist manifest.
// GET /api/blacklist — authenticated by exit node token.
func (h *handler) apiBlacklist(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Node-Token")
	if token == "" {
		jsonErr(w, "X-Node-Token required", http.StatusUnauthorized)
		return
	}
	node, err := h.db.nodeByToken(token)
	if err != nil || node == nil || node.Type != "exit" {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	entries, err := h.db.listBlacklistEntries()
	if err != nil {
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	data, err := h.signer.signBlacklist(entries)
	if err != nil {
		jsonErr(w, "signing error", http.StatusInternalServerError)
		return
	}
	logInfof("blacklist: serving to node=%s count=%d", node.Addr, len(entries))
	w.Header().Set("Content-Type", "application/json")
	w.Write(data) //nolint:errcheck
}
