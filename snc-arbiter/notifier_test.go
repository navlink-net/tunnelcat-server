// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// ── splitHostPort ─────────────────────────────────────────────────────────────

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		addr     string
		wantHost string
		wantPort string
		wantErr  bool
	}{
		{"1.2.3.4:443", "1.2.3.4", "443", false},
		{"example.com:8080", "example.com", "8080", false},
		{"1.2.3.4", "1.2.3.4", "", true},
		{"example.com", "example.com", "", true},
		{"[::1]:443", "[::1]", "443", false},
	}

	for _, tc := range cases {
		host, port, err := splitHostPort(tc.addr)
		if tc.wantErr {
			if err == nil {
				t.Errorf("splitHostPort(%q): expected error, got host=%q port=%q", tc.addr, host, port)
			}
			continue
		}
		if err != nil {
			t.Errorf("splitHostPort(%q): unexpected error: %v", tc.addr, err)
			continue
		}
		if host != tc.wantHost || port != tc.wantPort {
			t.Errorf("splitHostPort(%q): got (%q,%q), want (%q,%q)",
				tc.addr, host, port, tc.wantHost, tc.wantPort)
		}
	}
}

// ── exitRefreshURL ────────────────────────────────────────────────────────────

func TestExitRefreshURL(t *testing.T) {
	cases := []struct {
		addr string
		want string
	}{
		{"1.2.3.4:443", "https://1.2.3.4:443/p/node/v1/refresh"},
		{"1.2.3.4", "https://1.2.3.4:443/p/node/v1/refresh"},
		{"exit.example.com:8443", "https://exit.example.com:8443/p/node/v1/refresh"},
		{"https://1.2.3.4:443", "https://1.2.3.4:443/p/node/v1/refresh"},
	}
	for _, tc := range cases {
		got := exitRefreshURL(tc.addr)
		if got != tc.want {
			t.Errorf("exitRefreshURL(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}

// ── controlRefreshURL ─────────────────────────────────────────────────────────

func TestControlRefreshURL(t *testing.T) {
	cases := []struct {
		addr string
		want string
	}{
		{"1.2.3.4:443", "https://1.2.3.4:443/p/v1/refresh"},
		{"1.2.3.4", "https://1.2.3.4:443/p/v1/refresh"},
		{"ctrl.example.com:8443", "https://ctrl.example.com:8443/p/v1/refresh"},
	}
	for _, tc := range cases {
		got := controlRefreshURL(tc.addr)
		if got != tc.want {
			t.Errorf("controlRefreshURL(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}

// ── buildRefreshPayload ───────────────────────────────────────────────────────

func TestBuildRefreshPayload(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	sk := &signingKey{priv: priv, pub: pub}
	n := &Notifier{signer: sk}

	body, sigStr, err := n.buildRefreshPayload()
	if err != nil {
		t.Fatalf("buildRefreshPayload: %v", err)
	}

	// Body must be valid JSON with a "ts" field close to now.
	var payload struct {
		TS int64 `json:"ts"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("body not valid JSON: %v", err)
	}
	age := time.Since(time.Unix(payload.TS, 0)).Abs()
	if age > 5*time.Second {
		t.Errorf("ts is stale: age=%s", age)
	}

	// Signature must be verifiable with the public key.
	sig, err := base64.RawURLEncoding.DecodeString(sigStr)
	if err != nil {
		t.Fatalf("sig not valid base64url: %v", err)
	}
	if !ed25519.Verify(pub, body, sig) {
		t.Error("signature verification failed")
	}
}
