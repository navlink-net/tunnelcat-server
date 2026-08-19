// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"io"
	"net/http"
)

// checkAppLogKey returns true if the request carries the configured app-log
// upload key as a Bearer token. This key is embedded in client APKs (Lisinder,
// Proekt, ...) so app-layer (Kotlin) diagnostic logs can be shipped directly
// to the arbiter without a node registration/token — unlike X-Node-Token,
// which is reserved for registered control/exit nodes (see apiLogUpload).
// Deliberately a *separate* key from uploadKey (which can push client
// binaries via /admin/downloads/upload) so an extracted-from-APK key can only
// ever write log blobs, never a release build.
func (h *handler) checkAppLogKey(r *http.Request) bool {
	return h.checkClientOrLegacyKey(r, h.appLogKey)
}

// apiAppLogUpload receives a gzip-compressed Kotlin/app-layer log bundle
// directly from a client app (not forwarded by a control node — see
// apiLogUpload for that path). Stored under the "android" node-log bucket
// (nodeLogStore.validNodeType has no separate "app" type) via the same
// nodeLogStore used for native snc-core logs, keeping one storage/eviction
// implementation for both.
//
// Headers: Authorization: Bearer <app-log key>, X-App-ID (e.g.
// com.navlink.lisinder), X-Device-ID (client-generated persistent UUID).
func (h *handler) apiAppLogUpload(w http.ResponseWriter, r *http.Request) {
	if !h.checkAppLogKey(r) {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	appID := r.Header.Get("X-App-ID")
	deviceID := r.Header.Get("X-Device-ID")
	if appID == "" || deviceID == "" {
		jsonErr(w, "X-App-ID and X-Device-ID required", http.StatusBadRequest)
		return
	}

	nodeID := sanitizeAppLogNodeID(appID, deviceID)
	if !validLogNodeID(nodeID) {
		jsonErr(w, "invalid X-App-ID/X-Device-ID", http.StatusBadRequest)
		return
	}

	data, err := io.ReadAll(io.LimitReader(r.Body, int64(nodeLogMaxLen)+1))
	if err != nil {
		jsonErr(w, "read error", http.StatusBadRequest)
		return
	}

	// "" username: this endpoint's identity is X-App-ID/X-Device-ID (Lisinder/
	// Proekt app-layer logs, see sanitizeAppLogNodeID above), not an SNC
	// account -- no username to resolve here, falls back to the nodeID-keyed
	// layout, same as before the 2026-08-15 per-user storage reorg.
	if err := h.logs.Store("android", nodeID, "", data); err != nil {
		logWarnf("applog-upload: store node=%.32s…: %v", nodeID, err)
		jsonErr(w, "store error", http.StatusInternalServerError)
		return
	}

	logInfof("applog-upload: stored node=%.32s… size=%d from=%s", nodeID, len(data), r.RemoteAddr)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`)) //nolint:errcheck
}

// sanitizeAppLogNodeID builds a nodeLogStore-safe ID from an app package name
// and a device UUID, e.g. "com.navlink.lisinder" + "a1b2..." ->
// "com-navlink-lisinder_a1b2...". validLogNodeID only allows
// [a-zA-Z0-9_-], so package-name dots are folded to '-'.
func sanitizeAppLogNodeID(appID, deviceID string) string {
	clean := make([]rune, 0, len(appID))
	for _, c := range appID {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			clean = append(clean, c)
		} else {
			clean = append(clean, '-')
		}
	}
	return string(clean) + "_" + deviceID
}
