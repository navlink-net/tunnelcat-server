// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"testing"
)

// ── exitProxyURL ──────────────────────────────────────────────────────────────

func TestExitProxyURL(t *testing.T) {
	cases := []struct {
		exitAddr   string
		arbiterPath string
		want       string
	}{
		{"1.2.3.4:443", "/api/heartbeat", "https://1.2.3.4:443/p/node/v1/arbiter/api/heartbeat"},
		{"1.2.3.4", "/api/exits", "https://1.2.3.4:443/p/node/v1/arbiter/api/exits"},
		{"exit.example.com:8443", "/api/heartbeat", "https://exit.example.com:8443/p/node/v1/arbiter/api/heartbeat"},
		{"https://1.2.3.4:443", "/api/exits", "https://1.2.3.4:443/p/node/v1/arbiter/api/exits"},
	}
	for _, tc := range cases {
		got := exitProxyURL(tc.exitAddr, tc.arbiterPath)
		if got != tc.want {
			t.Errorf("exitProxyURL(%q, %q) = %q, want %q", tc.exitAddr, tc.arbiterPath, got, tc.want)
		}
	}
}

// ── PickRandom ────────────────────────────────────────────────────────────────

func makeRegistry(addrs ...string) *ExitRegistry {
	r := newExitRegistry("token", nil, "")
	nodes := make([]ExitNode, len(addrs))
	for i, a := range addrs {
		nodes[i] = ExitNode{Addr: a}
	}
	r.mu.Lock()
	r.exits = nodes
	r.mu.Unlock()
	return r
}

func TestPickRandom_Empty(t *testing.T) {
	r := makeRegistry()
	_, err := r.PickRandom()
	if err == nil {
		t.Error("expected error when exit list is empty")
	}
}

func TestPickRandom_Single(t *testing.T) {
	r := makeRegistry("1.2.3.4:443")
	exit, err := r.PickRandom()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exit.Addr != "1.2.3.4:443" {
		t.Errorf("got addr %q, want %q", exit.Addr, "1.2.3.4:443")
	}
}

func TestPickRandom_Multiple(t *testing.T) {
	addrs := []string{"1.1.1.1:443", "2.2.2.2:443", "3.3.3.3:443"}
	r := makeRegistry(addrs...)

	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		exit, err := r.PickRandom()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		seen[exit.Addr] = true
	}
	// With 50 samples from 3 exits, all should appear (probability of missing
	// one is (2/3)^50 ≈ 1.2e-9 — negligible).
	for _, addr := range addrs {
		if !seen[addr] {
			t.Errorf("addr %q never picked in 50 draws", addr)
		}
	}
}

// ── min ───────────────────────────────────────────────────────────────────────

func TestMin(t *testing.T) {
	cases := [][3]int{{1, 2, 1}, {5, 3, 3}, {4, 4, 4}, {0, 1, 0}}
	for _, tc := range cases {
		if got := min(tc[0], tc[1]); got != tc[2] {
			t.Errorf("min(%d,%d) = %d, want %d", tc[0], tc[1], got, tc[2])
		}
	}
}
