// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// apiUpdateManifest is the generic, control-node-authenticated counterpart to
// the public apiDownloadsInfo: it lists every currently-uploaded OTA-
// distributable slug (see otaSlugs) with its version/hash/availability.
// Control nodes poll this instead of hardcoding a per-app fetch call, so a
// new distributable type needs no control-side code change — see otaSlugs's
// doc comment in admin_downloads.go.
func (h *handler) apiUpdateManifest(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Node-Token")
	if token == "" {
		jsonErr(w, "X-Node-Token required", http.StatusUnauthorized)
		return
	}
	node, err := h.db.nodeByToken(token)
	if err != nil || node == nil || node.Type != "control" {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	resp := make(map[string]downloadInfoEntry, len(otaSlugs))
	for _, slug := range otaSlugs {
		canonicalName, ok := clientBinaryTypes[slug]
		if !ok {
			continue
		}
		info := h.readClientBinaryInfo(canonicalName)
		if info.Size == 0 {
			continue
		}
		resp[slug] = downloadInfoEntry{Available: true, Version: info.Version, Hash: info.Hash}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

// apiUpdateDist serves the raw bytes of one OTA-distributable slug's binary,
// version, or hash sidecar to a control node. Path shape:
// /api/update/dist/<slug>/<kind>, kind ∈ {bin, version, sha256}.
func (h *handler) apiUpdateDist(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/update/dist/")
	slug, kind, found := strings.Cut(rest, "/")
	if !found {
		http.NotFound(w, r)
		return
	}
	canonicalName, ok := clientBinaryTypes[slug]
	if !ok || !isOtaSlug(slug) {
		http.NotFound(w, r)
		return
	}

	var filename string
	switch kind {
	case "version":
		filename = canonicalName + ".version"
	case "sha256":
		filename = canonicalName + ".sha256"
	case "bin":
		filename = canonicalName
	default:
		http.NotFound(w, r)
		return
	}

	h.apiUpdateFile(w, r, "control", filename)
}

func isOtaSlug(slug string) bool {
	for _, s := range otaSlugs {
		if s == slug {
			return true
		}
	}
	return false
}
