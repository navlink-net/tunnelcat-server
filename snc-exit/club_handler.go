// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"fmt"
	"net/http"
	"time"
)

// club_handler.go — exit-side half of the parallel club-manifest channel.
// Mirrors serveManifest/cachedManifest (handler.go) exactly, just keyed per
// club slug instead of a single global cache. See
// tunnel_cat/docs/club-membership.md for the overall design.

// clubSlugs is the fixed, known-in-advance set of club slugs this exit
// fetches manifests for. Small and rarely-changing by design (see the admin
// panel's clubs.go on the arbiter) — a discovery endpoint would be more
// machinery than the actual churn justifies.
var clubSlugs = []string{"cat_club", "elite_cat_club"}

// serveClubManifest handles GET /api/club-manifest?club=<slug>.
func (h *handler) serveClubManifest(w http.ResponseWriter, r *http.Request) {
	slug := r.URL.Query().Get("club")
	if !isKnownClubSlug(slug) {
		http.Error(w, `{"error":"unknown club"}`, http.StatusBadRequest)
		return
	}
	data, err := h.cachedClubManifest(slug)
	if err != nil {
		logWarnf("club-manifest %s: %v", slug, err)
		http.Error(w, `{"error":"club manifest unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data) //nolint:errcheck
}

func (h *handler) cachedClubManifest(slug string) ([]byte, error) {
	h.clubManifestMu.Lock()
	defer h.clubManifestMu.Unlock()

	if data, ok := h.clubManifestData[slug]; ok && len(data) > 0 && time.Since(h.clubManifestFetched[slug]) < manifestTTL {
		return data, nil
	}

	data, err := h.auth.fetchClubManifest(slug)
	if err == nil && len(data) == 0 {
		err = fmt.Errorf("club manifest %s: empty response from arbiter", slug)
	}
	if err != nil {
		if stale, ok := h.clubManifestData[slug]; ok && len(stale) > 0 {
			logWarnf("club-manifest %s: refresh failed (%v), serving stale data", slug, err)
			return stale, nil
		}
		return nil, err
	}
	h.clubManifestData[slug] = data
	h.clubManifestFetched[slug] = time.Now()
	logInfof("club-manifest %s: fetched from arbiter size=%d bytes", slug, len(data))
	return data, nil
}

func isKnownClubSlug(slug string) bool {
	for _, s := range clubSlugs {
		if s == slug {
			return true
		}
	}
	return false
}
