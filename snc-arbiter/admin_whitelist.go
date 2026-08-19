// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"net/http"
	"strconv"
	"strings"
)

type listsPageData struct {
	Whitelist      []WhitelistEntry
	Blacklist      []BlacklistEntry
	TorrentBlocked []TorrentBlockedEntry
}

// adminWhitelistPage renders GET /admin/whitelist — combined whitelist+blacklist+torrent-blocked page.
func (h *handler) adminWhitelistPage(w http.ResponseWriter, r *http.Request) {
	wl, err := h.db.listWhitelistEntries()
	if err != nil {
		logWarnf("whitelist page: %v", err)
	}
	bl, err := h.db.listBlacklistEntries()
	if err != nil {
		logWarnf("blacklist page: %v", err)
	}
	ta, err := h.db.listTorrentBlockedEntries()
	if err != nil {
		logWarnf("torrent-blocked page: %v", err)
	}
	u := h.currentUser(r)
	h.renderPage(w, "admin_lists.html", pageData{User: u, Data: listsPageData{Whitelist: wl, Blacklist: bl, TorrentBlocked: ta}})
}

// adminWhitelistAdd handles POST /admin/whitelist/add.
func (h *handler) adminWhitelistAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	entryType := r.FormValue("type")
	value := strings.TrimSpace(r.FormValue("value"))
	if entryType != "domain" && entryType != "wildcard" && entryType != "cidr" {
		http.Error(w, "invalid type", http.StatusBadRequest)
		return
	}
	if value == "" {
		http.Redirect(w, r, "/admin/whitelist", http.StatusFound)
		return
	}
	if err := h.db.addWhitelistEntry(entryType, value); err != nil {
		logWarnf("whitelist add: %v", err)
	}
	logInfof("whitelist: added type=%s value=%s", entryType, value)
	http.Redirect(w, r, "/admin/whitelist", http.StatusFound)
}

// adminWhitelistDelete handles POST /admin/whitelist/delete.
func (h *handler) adminWhitelistDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := h.db.deleteWhitelistEntry(id); err != nil {
		logWarnf("whitelist delete %d: %v", id, err)
	}
	logInfof("whitelist: deleted id=%d", id)
	http.Redirect(w, r, "/admin/whitelist", http.StatusFound)
}

// apiWhitelist returns the signed whitelist manifest.
// GET /api/whitelist — authenticated by exit node token.
func (h *handler) apiWhitelist(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Node-Token")
	if token == "" {
		jsonErr(w, "X-Node-Token required", http.StatusUnauthorized)
		return
	}
	node, err := h.db.nodeByToken(token)
	if err != nil || node == nil || (node.Type != "exit" && node.Type != "control") {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	entries, err := h.db.listWhitelistEntries()
	if err != nil {
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	data, err := h.signer.signWhitelist(entries)
	if err != nil {
		jsonErr(w, "signing error", http.StatusInternalServerError)
		return
	}
	logInfof("whitelist: serving to node=%s count=%d", node.Addr, len(entries))
	w.Header().Set("Content-Type", "application/json")
	w.Write(data) //nolint:errcheck
}
