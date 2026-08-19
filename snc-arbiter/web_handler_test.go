// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHealthCheck_DBUp confirms /healthz reports 200 when the DB is reachable.
func TestHealthCheck_DBUp(t *testing.T) {
	h := &handler{db: newTestDB(t)}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	h.healthCheck(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
}

// TestHealthCheck_DBDown confirms /healthz reports 503 (not a panic or a
// false 200) when the DB connection is broken -- this is the exact signal
// the load balancer needs to pull an instance out of rotation.
func TestHealthCheck_DBDown(t *testing.T) {
	db := newTestDB(t)
	db.db.Close() // simulate a broken DB connection
	h := &handler{db: db}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	h.healthCheck(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}
