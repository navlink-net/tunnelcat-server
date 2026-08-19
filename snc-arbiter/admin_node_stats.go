// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type nodeStatsPageData struct {
	Node Node
}

// adminNodeStatsPage renders GET /admin/nodes/{id}/stats — the per-node
// history page (RTT/throughput/CPU/mem/disk graphs + total bytes transferred).
func (h *handler) adminNodeStatsPage(w http.ResponseWriter, r *http.Request) {
	// Path: /admin/nodes/{id}/stats
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

	u := h.currentUser(r)
	h.renderPage(w, "admin_node_stats.html", pageData{
		User: u,
		Data: nodeStatsPageData{Node: *node},
	})
}

// statsRangeWindow maps the ?range= query param to a lookback duration.
func statsRangeWindow(v string) time.Duration {
	switch v {
	case "1h":
		return time.Hour
	case "7d":
		return 7 * 24 * time.Hour
	case "30d":
		return 30 * 24 * time.Hour
	default:
		return 24 * time.Hour
	}
}

// apiAdminNodeStats serves GET /admin/api/nodes/{id}/stats?range=24h|7d|30d —
// 10-minute-bucketed history for the node's stats graphs, plus its current
// cumulative bytes-transferred total. Ranges beyond the 30-day DB retention
// window are not served here (older samples are archived off-disk).
func (h *handler) apiAdminNodeStats(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 {
		jsonErr(w, "bad path", http.StatusBadRequest)
		return
	}
	nodeID, err := strconv.ParseInt(parts[len(parts)-2], 10, 64)
	if err != nil {
		jsonErr(w, "bad node id", http.StatusBadRequest)
		return
	}

	window := statsRangeWindow(r.URL.Query().Get("range"))
	buckets, totalBytes, err := h.db.nodeStatsRange(nodeID, time.Now().Add(-window))
	if err != nil {
		jsonErr(w, "query failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
		"buckets":     buckets,
		"total_bytes": totalBytes,
	})
}

// apiAdminNetworkUsage serves GET /admin/api/network/usage?range=24h|7d|30d —
// users-online and traffic-per-user history, sampled every 10 minutes
// network-wide (not per node type — active users aren't attributable to a
// single node).
func (h *handler) apiAdminNetworkUsage(w http.ResponseWriter, r *http.Request) {
	window := statsRangeWindow(r.URL.Query().Get("range"))
	buckets, err := h.db.usageStatsRange(time.Now().Add(-window))
	if err != nil {
		jsonErr(w, "query failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
		"buckets": buckets,
	})
}

// apiAdminNetworkPeaks serves GET /admin/api/network/peaks?type=control|exit&range=24h|7d|30d —
// per-node peak RTT/CPU/mem/disk/bandwidth and total bytes transferred over
// the range, sorted by traffic descending — the "peak load" / "load
// distribution across nodes" section of the network stats tab.
func (h *handler) apiAdminNetworkPeaks(w http.ResponseWriter, r *http.Request) {
	nodeType := r.URL.Query().Get("type")
	if nodeType != "control" && nodeType != "exit" {
		jsonErr(w, "type must be 'control' or 'exit'", http.StatusBadRequest)
		return
	}
	window := statsRangeWindow(r.URL.Query().Get("range"))
	rows, err := h.db.nodePeaksAndDistribution(nodeType, time.Now().Add(-window))
	if err != nil {
		jsonErr(w, "query failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
		"nodes": rows,
	})
}

// apiAdminNetworkStats serves GET /admin/api/network/stats?type=control|exit&range=24h|7d|30d —
// 10-minute-bucketed history aggregated across every approved node of the
// given type, for the network-wide stats tab.
func (h *handler) apiAdminNetworkStats(w http.ResponseWriter, r *http.Request) {
	nodeType := r.URL.Query().Get("type")
	if nodeType != "control" && nodeType != "exit" {
		jsonErr(w, "type must be 'control' or 'exit'", http.StatusBadRequest)
		return
	}

	window := statsRangeWindow(r.URL.Query().Get("range"))
	buckets, totalBytes, err := h.db.networkStatsRange(nodeType, time.Now().Add(-window))
	if err != nil {
		jsonErr(w, "query failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
		"buckets":     buckets,
		"total_bytes": totalBytes,
	})
}
