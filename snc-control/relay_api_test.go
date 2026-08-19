// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func makeRelayAPIHandler(t *testing.T, pub ed25519.PublicKey, onRefresh func()) *relayAPIHandler {
	t.Helper()
	// newRelayAPIHandler no longer takes a relay-registry argument -- the old
	// in-memory relay list it built was superseded by DHT-based relay
	// discovery (see relay_api.go's "/p/v1/relay/list" backward-compat stub,
	// which now just returns an empty list). This helper's call shape had
	// drifted from the real signature since that migration; go build never
	// caught it because _test.go files aren't compiled by `go build`, only
	// by `go vet`/`go test`, which weren't part of the normal build check.
	return newRelayAPIHandler("" /* no updateDir */, pub, onRefresh, nil /* exits */, "" /* nodeToken */, nil /* authCache */)
}

func signedRefreshRequest(t *testing.T, priv ed25519.PrivateKey, ts int64) *http.Request {
	t.Helper()
	body, _ := json.Marshal(map[string]int64{"ts": ts})
	sig := ed25519.Sign(priv, body)
	req := httptest.NewRequest(http.MethodPost, "/p/v1/refresh", bytes.NewReader(body))
	req.Header.Set("X-Arbiter-Sig", base64.RawURLEncoding.EncodeToString(sig))
	return req
}

func TestRefreshEndpoint_Valid(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	called := false
	h := makeRelayAPIHandler(t, pub, func() { called = true })

	req := signedRefreshRequest(t, priv, time.Now().Unix())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 got %d: %s", rec.Code, rec.Body.String())
	}
	time.Sleep(10 * time.Millisecond) // triggerRefresh runs in goroutine
	if !called {
		t.Error("expected triggerRefresh to be called")
	}
}

func TestRefreshEndpoint_InvalidSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	h := makeRelayAPIHandler(t, pub, nil)

	req := signedRefreshRequest(t, otherPriv, time.Now().Unix())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 got %d", rec.Code)
	}
}

func TestRefreshEndpoint_StaleTimestamp(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	h := makeRelayAPIHandler(t, pub, nil)

	req := signedRefreshRequest(t, priv, time.Now().Add(-2*time.Minute).Unix())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 got %d", rec.Code)
	}
}

func TestRefreshEndpoint_NoPubkey(t *testing.T) {
	h := makeRelayAPIHandler(t, nil /* no pubkey */, nil)

	body, _ := json.Marshal(map[string]int64{"ts": time.Now().Unix()})
	req := httptest.NewRequest(http.MethodPost, "/p/v1/refresh", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 got %d", rec.Code)
	}
}

func TestRefreshEndpoint_MissingSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	h := makeRelayAPIHandler(t, pub, nil)

	body, _ := json.Marshal(map[string]int64{"ts": time.Now().Unix()})
	req := httptest.NewRequest(http.MethodPost, "/p/v1/refresh", bytes.NewReader(body))
	// no X-Arbiter-Sig header
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 got %d", rec.Code)
	}
}

// ── /p/v1/manifest ────────────────────────────────────────────────────────────

func TestManifestEndpoint_NotPopulated_Returns503(t *testing.T) {
	h := makeRelayAPIHandler(t, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/p/v1/manifest", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestManifestEndpoint_Populated_Returns200(t *testing.T) {
	h := makeRelayAPIHandler(t, nil, nil)
	payload := []byte(`{"type":"manifest","ts":1,"nodes":[{"addr":"1.2.3.4:443"}],"sig":"x"}`)
	h.manifestData = payload

	req := httptest.NewRequest(http.MethodGet, "/p/v1/manifest", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if rec.Body.String() != string(payload) {
		t.Errorf("body mismatch: got %q", rec.Body.String())
	}
}

func TestManifestEndpoint_PostNotAllowed(t *testing.T) {
	h := makeRelayAPIHandler(t, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/p/v1/manifest", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for POST, got %d", rec.Code)
	}
}

func TestManifestPoller_FetchesFromExit(t *testing.T) {
	payload := []byte(`{"type":"manifest","ts":1,"nodes":[{"addr":"1.2.3.4:443"}],"sig":"x"}`)
	exitSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/manifest" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(payload) //nolint:errcheck
			return
		}
		http.NotFound(w, r)
	}))
	defer exitSrv.Close()

	h := makeRelayAPIHandler(t, nil, nil)
	exits := newExitRegistry("", nil, "")
	exits.LoadBootstrap([]string{strings.TrimPrefix(exitSrv.URL, "https://")})
	h.exits = exits

	h.pollManifestOnce()

	h.manifestMu.RLock()
	got := h.manifestData
	h.manifestMu.RUnlock()

	if !bytes.Equal(got, payload) {
		t.Errorf("manifest mismatch: got %q, want %q", got, payload)
	}
}

func TestManifestPoller_IgnoresEmptyResponse(t *testing.T) {
	exitSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // 200, empty body
	}))
	defer exitSrv.Close()

	h := makeRelayAPIHandler(t, nil, nil)
	exits := newExitRegistry("", nil, "")
	exits.LoadBootstrap([]string{strings.TrimPrefix(exitSrv.URL, "https://")})
	h.exits = exits

	h.pollManifestOnce()

	h.manifestMu.RLock()
	got := h.manifestData
	h.manifestMu.RUnlock()

	if len(got) != 0 {
		t.Errorf("expected nil manifest after empty response, got %d bytes", len(got))
	}
}

func TestRefreshEndpoint_NotCalledWithoutCallback(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	h := makeRelayAPIHandler(t, pub, nil /* nil callback — must not panic */)

	req := signedRefreshRequest(t, priv, time.Now().Unix())
	rec := httptest.NewRecorder()

	// Must not panic even when triggerRefresh is nil.
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 got %d", rec.Code)
	}
}
