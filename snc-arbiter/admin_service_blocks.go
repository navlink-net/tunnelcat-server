// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"net/http"
	"strconv"
	"strings"
)

// validRegionCodes mirrors the region vocabulary already used for node
// RegionOverride (see the `allowed` map in handler.go's node-region-set
// handler) -- deliberately the same six codes, no separate list to keep in sync.
//
// Provider tags (e.g. "HETZNER") share this same vocabulary and the same
// underlying service_region_blocks table/matching code: an exit compares a
// rule's blocked-set against both its own region AND its own --provider-tag
// (see snc-exit's IsBlockedForRegion call sites), so "block this domain from
// Hetzner-hosted exits regardless of region" is just a rule whose blocked
// set contains "HETZNER" instead of (or alongside) a region code.
var validRegionCodes = map[string]bool{
	"RU": true, "EU": true, "US": true, "CN": true, "IR": true, "OTHER": true,
	"HETZNER": true,
}

type serviceBlocksPageData struct {
	Blocks []ServiceRegionBlock
}

// adminServiceBlocksPage renders GET /admin/service-blocks.
func (h *handler) adminServiceBlocksPage(w http.ResponseWriter, r *http.Request) {
	blocks, err := h.db.listServiceRegionBlocks()
	if err != nil {
		logWarnf("service-blocks page: %v", err)
	}
	u := h.currentUser(r)
	h.renderPage(w, "admin_service_blocks.html", pageData{User: u, Data: serviceBlocksPageData{Blocks: blocks}})
}

// adminServiceBlocksAdd handles POST /admin/service-blocks/add.
func (h *handler) adminServiceBlocksAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	entryType := r.FormValue("type")
	value := strings.TrimSpace(r.FormValue("value"))
	reason := strings.TrimSpace(r.FormValue("reason"))
	if entryType != "domain" && entryType != "wildcard" && entryType != "cidr" {
		http.Error(w, "invalid type", http.StatusBadRequest)
		return
	}
	var regions []string
	for _, r := range r.Form["regions"] {
		r = strings.ToUpper(strings.TrimSpace(r))
		if validRegionCodes[r] {
			regions = append(regions, r)
		}
	}
	if value == "" || len(regions) == 0 {
		http.Redirect(w, r, "/admin/service-blocks", http.StatusFound)
		return
	}
	if err := h.db.addServiceRegionBlock(entryType, value, regions, reason); err != nil {
		logWarnf("service-blocks add: %v", err)
	}
	logInfof("service-blocks: added type=%s value=%s regions=%v reason=%q", entryType, value, regions, reason)
	http.Redirect(w, r, "/admin/service-blocks", http.StatusFound)
}

// adminServiceBlocksDelete handles POST /admin/service-blocks/delete.
func (h *handler) adminServiceBlocksDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := h.db.deleteServiceRegionBlock(id); err != nil {
		logWarnf("service-blocks delete %d: %v", id, err)
	}
	logInfof("service-blocks: deleted id=%d", id)
	http.Redirect(w, r, "/admin/service-blocks", http.StatusFound)
}

// apiServiceRegionBlocks returns the signed service-region-block manifest.
// GET /api/service-blocks — authenticated by exit/control node token.
func (h *handler) apiServiceRegionBlocks(w http.ResponseWriter, r *http.Request) {
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
	entries, err := h.db.listServiceRegionBlocks()
	if err != nil {
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	data, err := h.signer.signServiceRegionBlocks(entries)
	if err != nil {
		jsonErr(w, "signing error", http.StatusInternalServerError)
		return
	}
	logInfof("service-blocks: serving to node=%s count=%d", node.Addr, len(entries))
	w.Header().Set("Content-Type", "application/json")
	w.Write(data) //nolint:errcheck
}
