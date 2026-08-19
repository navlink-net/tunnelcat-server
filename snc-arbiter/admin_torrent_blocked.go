// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"net/http"
	"strconv"
	"strings"
)

// adminTorrentBlockedAdd handles POST /admin/torrent-blocked/add.
func (h *handler) adminTorrentBlockedAdd(w http.ResponseWriter, r *http.Request) {
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
	if err := h.db.addTorrentBlockedEntry(addr, reason); err != nil {
		logWarnf("torrent-blocked add: %v", err)
	}
	logInfof("torrent-blocked: added addr=%s reason=%s", addr, reason)
	http.Redirect(w, r, "/admin/whitelist", http.StatusFound)
}

// adminTorrentBlockedDelete handles POST /admin/torrent-blocked/delete.
func (h *handler) adminTorrentBlockedDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := h.db.deleteTorrentBlockedEntry(id); err != nil {
		logWarnf("torrent-blocked delete %d: %v", id, err)
	}
	logInfof("torrent-blocked: deleted id=%d", id)
	http.Redirect(w, r, "/admin/whitelist", http.StatusFound)
}

// apiTorrentBlocked returns the signed torrent-blocked-exits manifest.
// GET /api/torrent-blocked — authenticated by exit node token. Exits use
// SelfAllowed for their own dial policy and Addrs to filter which peers to
// redirect torrent connections to (peer is skipped if it's in Addrs).
func (h *handler) apiTorrentBlocked(w http.ResponseWriter, r *http.Request) {
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
	entries, err := h.db.listTorrentBlockedEntries()
	if err != nil {
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	data, err := h.signer.signTorrentBlocked(entries, node.Addr)
	if err != nil {
		jsonErr(w, "signing error", http.StatusInternalServerError)
		return
	}
	logInfof("torrent-blocked: serving to node=%s count=%d", node.Addr, len(entries))
	w.Header().Set("Content-Type", "application/json")
	w.Write(data) //nolint:errcheck
}
