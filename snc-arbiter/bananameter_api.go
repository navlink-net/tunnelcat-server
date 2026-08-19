// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/json"
	"net/http"
	"time"
)

// ── POST /api/node/bananameter-result (control/exit, X-Node-Token) ─────────

type nodeBananameterPayload struct {
	ViaExit         string  `json:"via_exit"` // control only: which exit this specific test used
	Ts              int64   `json:"ts"`
	DurationSeconds float64 `json:"duration_seconds"`
	PayloadBytes    int64   `json:"payload_bytes"`
	PingMs          float64 `json:"ping_ms"`
	ThroughputBps   float64 `json:"throughput_bps"`
}

// apiNodeBananameterResult handles POST /api/node/bananameter-result --
// a control or exit node reporting the result of its own periodic
// bananameter.net probe (see TODO.md "BananaMeter-based tunnel
// diagnostics"). Control includes via_exit (which exit carried this
// specific test, since control always tests through a real exit, never
// bypassing it); exit's own probe is a direct dial, so via_exit is empty.
func (h *handler) apiNodeBananameterResult(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Node-Token")
	if token == "" {
		jsonErr(w, "X-Node-Token required", http.StatusUnauthorized)
		return
	}
	node, err := h.db.nodeByToken(token)
	if err != nil || node == nil {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var p nodeBananameterPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	ts := p.Ts
	if ts == 0 {
		ts = time.Now().Unix()
	}

	err = h.db.insertBananameterResult(bananameterResult{
		SourceType:      node.Type,
		SourceID:        node.Addr,
		ViaExit:         p.ViaExit,
		Ts:              ts,
		DurationSeconds: p.DurationSeconds,
		PayloadBytes:    p.PayloadBytes,
		PingMs:          p.PingMs,
		ThroughputBps:   p.ThroughputBps,
	})
	if err != nil {
		logWarnf("apiNodeBananameterResult: insert node=%s: %v", node.Addr, err)
		jsonErr(w, "database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`)) //nolint:errcheck
}

// ── POST /api/bananameter/client-result (client, shared Bearer key) ────────

// checkBananameterClientKey mirrors checkAppLogKey's shape (see applog.go):
// a single shared secret embedded in every client build, deliberately
// separate from appLogKey and uploadKey so a key extracted from a client
// binary can only ever write bananameter results, nothing else. Client
// identity fields in the body are self-reported (same trust model as
// app-log upload's X-Device-ID) -- this is telemetry, not an auth boundary.
func (h *handler) checkBananameterClientKey(r *http.Request) bool {
	return h.checkClientOrLegacyKey(r, h.bananameterClientKey)
}

type clientBananameterPayload struct {
	ClientID        string  `json:"client_id"`
	DeviceID        string  `json:"device_id"`
	Username        string  `json:"username"`
	Ts              int64   `json:"ts"`
	DurationSeconds float64 `json:"duration_seconds"`
	PayloadBytes    int64   `json:"payload_bytes"`
	PingMs          float64 `json:"ping_ms"`
	ThroughputBps   float64 `json:"throughput_bps"`
}

// apiClientBananameterResult handles POST /api/bananameter/client-result.
// Reached by a connected client over the tunnel like any other API call to
// navlink.net -- no special frame type, no exit-side tagging (see TODO.md:
// "для клиентских никто ничего не дописывает" -- unlike control's own
// probe, a client result is not attributed to a specific exit, since the
// client is not supposed to know which exit it used in the first place).
func (h *handler) apiClientBananameterResult(w http.ResponseWriter, r *http.Request) {
	if !h.checkBananameterClientKey(r) {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var p clientBananameterPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	if p.ClientID == "" {
		jsonErr(w, "client_id required", http.StatusBadRequest)
		return
	}
	ts := p.Ts
	if ts == 0 {
		ts = time.Now().Unix()
	}

	err := h.db.insertBananameterResult(bananameterResult{
		SourceType:      "client",
		SourceID:        p.ClientID,
		Username:        p.Username,
		DeviceID:        p.DeviceID,
		Ts:              ts,
		DurationSeconds: p.DurationSeconds,
		PayloadBytes:    p.PayloadBytes,
		PingMs:          p.PingMs,
		ThroughputBps:   p.ThroughputBps,
	})
	if err != nil {
		logWarnf("apiClientBananameterResult: insert client=%s: %v", p.ClientID, err)
		jsonErr(w, "database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`)) //nolint:errcheck
}
