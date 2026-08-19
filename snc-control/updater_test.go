// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"testing"
)

func TestExitBaseURL(t *testing.T) {
	cases := []struct {
		addr string
		want string
	}{
		{"1.2.3.4:443", "https://1.2.3.4:443"},
		{"1.2.3.4", "https://1.2.3.4:443"},
		{"exit.example.com:8443", "https://exit.example.com:8443"},
		{"https://1.2.3.4:443", "https://1.2.3.4:443"},
		{"http://1.2.3.4:443", "https://1.2.3.4:443"},
	}
	for _, tc := range cases {
		got := exitBaseURL(tc.addr)
		if got != tc.want {
			t.Errorf("exitBaseURL(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}
