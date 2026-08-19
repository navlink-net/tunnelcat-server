// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// makeNodeProxy builds a minimal nodeProxy for testing without a real reverse proxy.
func makeNodeProxy(t *testing.T, pubkey ed25519.PublicKey, manifest []byte, cacheDir string, onRefresh func()) *nodeProxy {
	t.Helper()
	return &nodeProxy{
		arbiterURL:    "https://arbiter.test",
		nodeToken:     "test-token",
		arbiterPubkey: pubkey,
		cacheDir:      cacheDir,
		proxy:         nil, // not needed for unit tests
		getManifest: func() ([]byte, error) {
			if manifest == nil {
				return nil, fmt.Errorf("no manifest")
			}
			return manifest, nil
		},
		triggerRefresh: onRefresh,
	}
}

func makeManifest(addrs ...string) []byte {
	type node struct {
		Addr string `json:"addr"`
	}
	type manifest struct {
		Type  string `json:"type"`
		TS    int64  `json:"ts"`
		Nodes []node `json:"nodes"`
		Sig   string `json:"sig"`
	}
	nodes := make([]node, len(addrs))
	for i, a := range addrs {
		nodes[i] = node{Addr: a}
	}
	data, _ := json.Marshal(manifest{Type: "manifest", TS: time.Now().Unix(), Nodes: nodes, Sig: "fake"})
	return data
}

// ── isKnownControl ────────────────────────────────────────────────────────────

func TestIsKnownControl_IPPresent(t *testing.T) {
	np := makeNodeProxy(t, nil, makeManifest("1.2.3.4:443", "5.6.7.8:443"), "", nil)
	if !np.isKnownControl("1.2.3.4") {
		t.Error("expected 1.2.3.4 to be known")
	}
	if !np.isKnownControl("5.6.7.8") {
		t.Error("expected 5.6.7.8 to be known")
	}
}

func TestIsKnownControl_IPAbsent(t *testing.T) {
	np := makeNodeProxy(t, nil, makeManifest("1.2.3.4:443"), "", nil)
	if np.isKnownControl("9.9.9.9") {
		t.Error("expected 9.9.9.9 to be unknown")
	}
}

func TestIsKnownControl_AddrWithoutPort(t *testing.T) {
	np := makeNodeProxy(t, nil, makeManifest("10.0.0.1"), "", nil)
	if !np.isKnownControl("10.0.0.1") {
		t.Error("expected 10.0.0.1 (no port in manifest) to be known")
	}
}

func TestIsKnownControl_ManifestUnavailable_FailOpen(t *testing.T) {
	np := makeNodeProxy(t, nil, nil, "", nil) // getManifest returns error
	// Fail-open: when manifest is unavailable, allow the caller.
	if !np.isKnownControl("1.2.3.4") {
		t.Error("expected fail-open when manifest is unavailable")
	}
}

func TestIsKnownControl_EmptyManifest(t *testing.T) {
	np := makeNodeProxy(t, nil, makeManifest() /* no nodes */, "", nil)
	if np.isKnownControl("1.2.3.4") {
		t.Error("expected 1.2.3.4 to be unknown in empty manifest")
	}
}

// ── handleRefresh ─────────────────────────────────────────────────────────────

func signRefreshPayload(t *testing.T, priv ed25519.PrivateKey, ts int64) (body []byte, sigHeader string) {
	t.Helper()
	body, _ = json.Marshal(map[string]int64{"ts": ts})
	sig := ed25519.Sign(priv, body)
	return body, base64.RawURLEncoding.EncodeToString(sig)
}

func TestHandleRefresh_Valid(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	refreshed := false
	np := makeNodeProxy(t, pub, makeManifest(), "", func() { refreshed = true })

	body, sig := signRefreshPayload(t, priv, time.Now().Unix())
	req := httptest.NewRequest(http.MethodPost, "/p/node/v1/refresh", bytes.NewReader(body))
	req.Header.Set("X-Arbiter-Sig", sig)
	rec := httptest.NewRecorder()

	np.handleRefresh(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 got %d: %s", rec.Code, rec.Body.String())
	}
	// triggerRefresh is called in a goroutine; give it a moment.
	time.Sleep(10 * time.Millisecond)
	if !refreshed {
		t.Error("expected triggerRefresh to be called")
	}
}

func TestHandleRefresh_InvalidSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	np := makeNodeProxy(t, pub, makeManifest(), "", nil)

	body, sig := signRefreshPayload(t, otherPriv, time.Now().Unix())
	req := httptest.NewRequest(http.MethodPost, "/p/node/v1/refresh", bytes.NewReader(body))
	req.Header.Set("X-Arbiter-Sig", sig)
	rec := httptest.NewRecorder()

	np.handleRefresh(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 got %d", rec.Code)
	}
}

func TestHandleRefresh_StaleTimestamp(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	np := makeNodeProxy(t, pub, makeManifest(), "", nil)

	staleTS := time.Now().Add(-2 * time.Minute).Unix()
	body, sig := signRefreshPayload(t, priv, staleTS)
	req := httptest.NewRequest(http.MethodPost, "/p/node/v1/refresh", bytes.NewReader(body))
	req.Header.Set("X-Arbiter-Sig", sig)
	rec := httptest.NewRecorder()

	np.handleRefresh(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 got %d", rec.Code)
	}
}

func TestHandleRefresh_NoPubkey(t *testing.T) {
	np := makeNodeProxy(t, nil /* no pubkey */, makeManifest(), "", nil)

	body, _ := json.Marshal(map[string]int64{"ts": time.Now().Unix()})
	req := httptest.NewRequest(http.MethodPost, "/p/node/v1/refresh", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	np.handleRefresh(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 got %d", rec.Code)
	}
}

func TestHandleRefresh_MissingSignatureHeader(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	np := makeNodeProxy(t, pub, makeManifest(), "", nil)

	body, _ := signRefreshPayload(t, priv, time.Now().Unix())
	req := httptest.NewRequest(http.MethodPost, "/p/node/v1/refresh", bytes.NewReader(body))
	// deliberately omit X-Arbiter-Sig
	rec := httptest.NewRecorder()

	np.handleRefresh(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 got %d", rec.Code)
	}
}

// ── handleUpdate ──────────────────────────────────────────────────────────────

func TestHandleUpdate_Disabled(t *testing.T) {
	np := makeNodeProxy(t, nil, nil, "" /* no cacheDir */, nil)
	req := httptest.NewRequest(http.MethodGet, "/p/node/v1/update/version", nil)
	rec := httptest.NewRecorder()
	np.handleUpdate(rec, req)
	if rec.Code == http.StatusOK {
		t.Error("expected non-200 when cacheDir is empty")
	}
}

func TestHandleUpdate_BadName(t *testing.T) {
	dir := t.TempDir()
	np := makeNodeProxy(t, nil, nil, dir, nil)

	for _, name := range []string{"../etc/passwd", "snc-arbiter", "", "."} {
		req := httptest.NewRequest(http.MethodGet, "/p/node/v1/update/"+name, nil)
		rec := httptest.NewRecorder()
		np.handleUpdate(rec, req)
		if rec.Code == http.StatusOK {
			t.Errorf("expected non-200 for name %q, got %d", name, rec.Code)
		}
	}
}

func TestHandleUpdate_ServeFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "version"), []byte("20260415\n"), 0644)

	np := makeNodeProxy(t, nil, nil, dir, nil)
	req := httptest.NewRequest(http.MethodGet, "/p/node/v1/update/version", nil)
	rec := httptest.NewRecorder()
	np.handleUpdate(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 got %d", rec.Code)
	}
	if body := rec.Body.String(); body != "20260415\n" {
		t.Errorf("unexpected body: %q", body)
	}
}

func TestHandleUpdate_MissingFile(t *testing.T) {
	dir := t.TempDir() // empty — no files
	np := makeNodeProxy(t, nil, nil, dir, nil)
	req := httptest.NewRequest(http.MethodGet, "/p/node/v1/update/snc-control", nil)
	rec := httptest.NewRecorder()
	np.handleUpdate(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 got %d", rec.Code)
	}
}
