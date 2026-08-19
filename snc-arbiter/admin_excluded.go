// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// adminExcludedAdd handles POST /api/admin/excluded/add.
func (h *handler) adminExcludedAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	addr := strings.TrimSpace(r.FormValue("addr"))
	reason := strings.TrimSpace(r.FormValue("reason"))
	if addr == "" {
		http.Error(w, "addr required", http.StatusBadRequest)
		return
	}
	if err := h.db.addExcludedNode(addr, reason); err != nil {
		logWarnf("excluded add: %v", err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	logInfof("excluded: added addr=%s reason=%s", addr, reason)
	w.WriteHeader(http.StatusNoContent)
}

// adminExcludedDelete handles POST /api/admin/excluded/delete.
func (h *handler) adminExcludedDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := h.db.deleteExcludedNode(id); err != nil {
		logWarnf("excluded delete %d: %v", id, err)
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	logInfof("excluded: deleted id=%d", id)
	w.WriteHeader(http.StatusNoContent)
}

// adminExcludedList handles GET /api/admin/excluded — returns JSON list.
func (h *handler) adminExcludedList(w http.ResponseWriter, r *http.Request) {
	entries, err := h.db.listExcludedNodes()
	if err != nil {
		jsonErr(w, "db error", http.StatusInternalServerError)
		return
	}
	type row struct {
		ID     int64  `json:"id"`
		Addr   string `json:"addr"`
		Reason string `json:"reason"`
	}
	out := make([]row, len(entries))
	for i, e := range entries {
		out[i] = row{ID: e.ID, Addr: e.Addr, Reason: e.Reason}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out) //nolint:errcheck
}
