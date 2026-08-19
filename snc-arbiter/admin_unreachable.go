// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/json"
	"net/http"
	"time"
)

// ── GET /admin/api/network/unreachable/by-type?type=control&range= ─────────

// apiAdminTypeUnreachability serves the per-node unreachability breakdown
// for the Controls tab: how often each individual control was reported
// unreachable by clients, bucketed the same way as the bananameter chart on
// the same tab (see typeBananameterBreakdown) so both can share the same
// charting code. Events come from end-user clients (see
// snc/core/router.go's UnreachableControls) -- control-only; there is no
// exit-side counterpart, and none should be added here without a fresh
// explicit ask (see the 2026-08-16 exit-unreachability scope-creep this
// endpoint originally, wrongly, also served).
func (h *handler) apiAdminTypeUnreachability(w http.ResponseWriter, r *http.Request) {
	targetType := r.URL.Query().Get("type")
	if targetType != "control" {
		jsonErr(w, "type must be 'control'", http.StatusBadRequest)
		return
	}
	window := statsRangeWindow(r.URL.Query().Get("range"))
	data, err := h.db.typeUnreachabilityBreakdown(targetType, time.Now().Add(-window))
	if err != nil {
		jsonErr(w, "query failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data) //nolint:errcheck
}
