// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"net/http"
	"sync"
)

// ipv6State caches the ipv6_enabled toggle in memory.
type ipv6State struct {
	mu      sync.RWMutex
	enabled bool
}

// loadIPv6State refreshes the in-memory toggle from DB.
// Default is true (IPv6 enabled) when the setting is absent.
func (h *handler) loadIPv6State() {
	val, ok, err := h.db.getSetting("ipv6_enabled")
	if err != nil {
		logWarnf("ipv6: load setting: %v", err)
		return
	}
	h.ipv6.mu.Lock()
	defer h.ipv6.mu.Unlock()
	h.ipv6.enabled = !ok || val != "0"
}

// ipv6Enabled returns the current IPv6 toggle (safe for concurrent use).
func (h *handler) ipv6Enabled() bool {
	h.ipv6.mu.RLock()
	defer h.ipv6.mu.RUnlock()
	return h.ipv6.enabled
}

// adminIPv6Toggle handles POST /admin/ipv6/toggle.
// Reads form field "enable" ("1" = enabled, "0" = disabled).
//
// When disabled, this is broadcast to clients via the signed manifest's
// advisory ipv6_enabled field (see apiManifest) -- clients that see it false
// force their own "disable IPv6" behavior on and hide the manual toggle,
// since at that point it's arbiter-controlled, not a user choice. Added
// 2026-08-12: confirmed every exit node lacks IPv6 connectivity entirely and
// cannot get it from the hosting providers in use, which was silently
// breaking Facebook/WhatsApp (both now heavily IPv6-preferred) -- routing
// IPv6 into a tunnel whose exits can never dial it just hands apps a dead
// address instead of letting them fall back to IPv4.
func (h *handler) adminIPv6Toggle(w http.ResponseWriter, r *http.Request) {
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
	if err := h.db.setSetting("ipv6_enabled", val, who); err != nil {
		logWarnf("ipv6: toggle: %v", err)
	}
	h.loadIPv6State()

	action := "disabled"
	if enable {
		action = "enabled"
	}
	logInfof("admin: IPv6 %s by %s", action, who)
	http.Redirect(w, r, "/admin?flash=IPv6+"+action, http.StatusSeeOther)
}
