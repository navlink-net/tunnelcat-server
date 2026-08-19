// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"net/http"
	"sync"
)

// relayState caches the relay_enabled toggle in memory.
type relayState struct {
	mu      sync.RWMutex
	enabled bool
}

// loadRelayState refreshes the in-memory toggle from DB.
// Default is true (relay enabled) when the setting is absent.
func (h *handler) loadRelayState() {
	val, ok, err := h.db.getSetting("relay_enabled")
	if err != nil {
		logWarnf("relay: load setting: %v", err)
		return
	}
	h.relay.mu.Lock()
	defer h.relay.mu.Unlock()
	h.relay.enabled = !ok || val != "0"
}

// relayEnabled returns the current relay toggle (safe for concurrent use).
func (h *handler) relayEnabled() bool {
	h.relay.mu.RLock()
	defer h.relay.mu.RUnlock()
	return h.relay.enabled
}

// adminRelayToggle handles POST /admin/relay/toggle.
// Reads form field "enable" ("1" = enabled, "0" = disabled).
func (h *handler) adminRelayToggle(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	enable := r.FormValue("enable") == "1"
	admin := h.currentUser(r)
	who := "admin"
	if admin != nil {
		who = admin.Username
	}

	val := "0"
	if enable {
		val = "1"
	}
	if err := h.db.setSetting("relay_enabled", val, who); err != nil {
		logWarnf("relay: toggle: %v", err)
	}
	h.loadRelayState()

	action := "disabled"
	if enable {
		action = "enabled"
	}
	logInfof("admin: relay registration %s by %s", action, who)
	http.Redirect(w, r, "/admin?flash=Relay+"+action, http.StatusSeeOther)
}
