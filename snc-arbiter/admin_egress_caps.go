// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
)

type egressCapEntry struct {
	Value  string // as stored in whitelist_entries
	Type   string // "domain" | "wildcard" | "cidr"
	Status string // "ok" | "fail" | "unknown" | "na"
}

type egressCapsPageData struct {
	Node        Node
	Entries     []egressCapEntry
	Extra       []egressCapEntry // caps keys with no matching whitelist entry (stale)
	OkCount     int
	TotalProbed int // excludes CIDR entries
}

// capsKeyFor returns the key used in the capabilities map for a whitelist entry.
// Domain entries map directly; wildcard entries strip the leading ".*." prefix
// (the exit normalises "*.example.com" → ".example.com" and probes "example.com").
// CIDR entries are not probed and return "".
func capsKeyFor(entryType, value string) string {
	v := strings.ToLower(value)
	switch entryType {
	case "domain":
		return v
	case "wildcard":
		v = strings.TrimPrefix(v, "*")
		v = strings.TrimPrefix(v, ".")
		return v
	}
	return "" // cidr — not probeable
}

// adminEgressCapsPage renders GET /admin/egress/{id}/caps.
func (h *handler) adminEgressCapsPage(w http.ResponseWriter, r *http.Request) {
	// Path: /admin/egress/{id}/caps
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 4 {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	node, err := h.db.nodeByID(id)
	if err != nil || node == nil {
		http.NotFound(w, r)
		return
	}
	if node.Type != "exit" {
		http.Error(w, "not an egress node", http.StatusBadRequest)
		return
	}

	wlEntries, _ := h.db.listWhitelistEntries()
	caps := node.Capabilities // nil means no data reported yet

	matched := map[string]bool{}
	var entries []egressCapEntry
	okCount, totalProbed := 0, 0

	for _, e := range wlEntries {
		key := capsKeyFor(e.Type, e.Value)
		var status string
		switch {
		case e.Type == "cidr":
			status = "na"
		case caps == nil:
			status = "unknown"
		default:
			if ok, exists := caps[key]; exists {
				matched[key] = true
				totalProbed++
				if ok {
					status = "ok"
					okCount++
				} else {
					status = "fail"
				}
			} else {
				status = "unknown"
			}
		}
		entries = append(entries, egressCapEntry{Value: e.Value, Type: e.Type, Status: status})
	}

	// Caps keys not matched to any current whitelist entry (stale probes).
	var extra []egressCapEntry
	for k, ok := range caps {
		if matched[k] {
			continue
		}
		status := "fail"
		if ok {
			status = "ok"
		}
		extra = append(extra, egressCapEntry{Value: k, Type: "domain", Status: status})
	}
	sort.Slice(extra, func(i, j int) bool { return extra[i].Value < extra[j].Value })

	u := h.currentUser(r)
	h.renderPage(w, "admin_egress_caps.html", pageData{
		User: u,
		Data: egressCapsPageData{
			Node:        *node,
			Entries:     entries,
			Extra:       extra,
			OkCount:     okCount,
			TotalProbed: totalProbed,
		},
	})
}
