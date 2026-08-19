// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// makeManifestHandler builds a minimal handler aimed at the given arbiter URL.
// Only the auth field is populated — sufficient for manifest cache tests.
func makeManifestHandler(t *testing.T, arbiterURL string) *handler {
	t.Helper()
	return &handler{
		auth: &authClient{
			arbiterURL: arbiterURL,
			nodeToken:  "test-token",
			client:     &http.Client{},
		},
	}
}

func TestCachedManifest_EmptyBody_Returns503(t *testing.T) {
	arbiter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // 200, empty body
	}))
	defer arbiter.Close()

	h := makeManifestHandler(t, arbiter.URL)
	req := httptest.NewRequest(http.MethodGet, "/api/manifest", nil)
	rec := httptest.NewRecorder()
	h.serveManifest(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestCachedManifest_EmptyBody_ServesStaleFallback(t *testing.T) {
	arbiter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // 200, empty body
	}))
	defer arbiter.Close()

	stale := []byte(`{"type":"manifest","ts":1,"nodes":[],"sig":"x"}`)
	h := makeManifestHandler(t, arbiter.URL)
	h.manifestData = stale
	// Expire the cache so cachedManifest tries to refresh (and gets empty body).
	h.manifestFetched = time.Now().Add(-manifestTTL - time.Second)

	req := httptest.NewRequest(http.MethodGet, "/api/manifest", nil)
	rec := httptest.NewRecorder()
	h.serveManifest(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 (stale fallback), got %d", rec.Code)
	}
	if rec.Body.String() != string(stale) {
		t.Errorf("expected stale body, got: %s", rec.Body.String())
	}
}

func TestCachedManifest_ArbiterError_ServesStale(t *testing.T) {
	arbiter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer arbiter.Close()

	stale := []byte(`{"type":"manifest","ts":1,"nodes":[],"sig":"x"}`)
	h := makeManifestHandler(t, arbiter.URL)
	h.manifestData = stale
	h.manifestFetched = time.Now().Add(-manifestTTL - time.Second)

	req := httptest.NewRequest(http.MethodGet, "/api/manifest", nil)
	rec := httptest.NewRecorder()
	h.serveManifest(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 (stale fallback), got %d", rec.Code)
	}
}
