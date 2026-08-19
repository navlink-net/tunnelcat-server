// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import "net/http"

// checkClientOrLegacyKey accepts either the new shared clientTelemetryKey or
// the given endpoint-specific legacy key -- see clientTelemetryKey's doc
// comment on the handler struct for why the fleet moved to one shared key,
// and why the legacy fields stay checked indefinitely (already-shipped
// client builds have the old per-endpoint keys baked in and can't be
// retroactively updated).
func (h *handler) checkClientOrLegacyKey(r *http.Request, legacy string) bool {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return false
	}
	if h.clientTelemetryKey != "" && auth == "Bearer "+h.clientTelemetryKey {
		return true
	}
	if legacy != "" && auth == "Bearer "+legacy {
		return true
	}
	return false
}
