// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/json"
	"net/http"
	"time"
)

// checkConnStatsClientKey mirrors checkLogUploadClientKey/checkBananameterClientKey's
// shape: a single shared secret embedded in every client build, deliberately
// separate from those keys so a key extracted from a client binary can only
// ever write connection-stats samples, nothing else (same "compromise blast
// radius" convention as every other client-facing shared key here).
func (h *handler) checkConnStatsClientKey(r *http.Request) bool {
	return h.checkClientOrLegacyKey(r, h.connStatsClientKey)
}

// clientConnStatsPayload is the JSON body of POST /api/conn-stats/client-upload.
// Username is self-reported (same trust model as clientBananameterPayload's
// Username field, sourced from KeyData.Username) -- this is telemetry, not
// an auth boundary. Device identity comes from the X-Node-ID/X-Node-Type
// headers, same as log-upload.
type clientConnStatsPayload struct {
	Username            string  `json:"username"`
	ClientVersion       string  `json:"client_version"`
	Ts                  int64   `json:"ts"`
	PoolTCP             int     `json:"pool_tcp"`
	PoolUDP             int     `json:"pool_udp"`
	UnreachableControls int     `json:"unreachable_controls"`
	TotalControls       int     `json:"total_controls"`
	SecondsOnline       int64   `json:"seconds_online"`
	AvgFailRatio        float64 `json:"avg_fail_ratio"`
	RejectedSessions    int     `json:"rejected_sessions"`
	ConnectsManual      int     `json:"connects_manual"`
	ConnectsAuto        int     `json:"connects_auto"`
	DisconnectsManual   int     `json:"disconnects_manual"`
	DisconnectsAuto     int     `json:"disconnects_auto"`
	FlapEvents          int     `json:"flap_events"`
	Evictions           int     `json:"evictions"`
}

// apiClientConnStatsUpload handles POST /api/conn-stats/client-upload -- a
// client's own periodic connection-health snapshot (pool composition,
// reachability, session events), sent directly over its live tunnel dialer
// to navlink.net every ~5 minutes, same cadence and channel shape as
// LogUploader (tunnel_cat/snc/core/conn_stats_upload.go / log_upload.go).
//
// Must be registered on the :8080 web plane (see the case in web_handler.go
// and its comment) -- end-user clients only ever reach the arbiter via
// https://navlink.net/..., never :443 directly. Same dual-listener trap
// that has bitten both /api/bananameter/client-result and
// /api/log/client-upload before -- registering here proactively.
func (h *handler) apiClientConnStatsUpload(w http.ResponseWriter, r *http.Request) {
	if !h.checkConnStatsClientKey(r) {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	nodeID := r.Header.Get("X-Node-ID")
	if nodeID == "" {
		jsonErr(w, "X-Node-ID required", http.StatusBadRequest)
		return
	}
	nodeType := r.Header.Get("X-Node-Type")
	if !validNodeType(nodeType) {
		nodeType = "android" // legacy fallback, matches apiLogClientUpload
	}

	var p clientConnStatsPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	if p.Username == "" {
		jsonErr(w, "username required", http.StatusBadRequest)
		return
	}
	ts := p.Ts
	if ts == 0 {
		ts = time.Now().Unix()
	}

	err := h.db.insertConnStats(connStatsReport{
		Ts:                    ts,
		Username:              p.Username,
		DeviceID:              nodeID,
		NodeType:              nodeType,
		ClientVersion:         p.ClientVersion,
		PoolTCP:               p.PoolTCP,
		PoolUDP:               p.PoolUDP,
		UnreachableControls:   p.UnreachableControls,
		TotalControls:         p.TotalControls,
		SecondsOnline:         p.SecondsOnline,
		AvgFailRatio:          p.AvgFailRatio,
		RejectedSessions:      p.RejectedSessions,
		ConnectsManual:        p.ConnectsManual,
		ConnectsAuto:          p.ConnectsAuto,
		DisconnectsManual:     p.DisconnectsManual,
		DisconnectsAuto:       p.DisconnectsAuto,
		FlapEvents:            p.FlapEvents,
		Evictions:             p.Evictions,
	})
	if err != nil {
		logWarnf("conn-stats-client-upload: insert user=%s device=%.16s…: %v", p.Username, nodeID, err)
		jsonErr(w, "store error", http.StatusInternalServerError)
		return
	}

	logInfof("conn-stats-client-upload: stored user=%s type=%s device=%.16s…", p.Username, nodeType, nodeID)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`)) //nolint:errcheck
}
