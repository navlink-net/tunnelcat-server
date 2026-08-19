// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"testing"

	"tunnel_cat/binlog"
)

func TestTagForLine(t *testing.T) {
	cases := []struct {
		line string
		want binlog.Tag
	}{
		// Real formatted lines, as log.LstdFlags|log.Lmsgprefix actually produces them.
		{"2026/08/15 12:00:00 [snc] socks5: routing decision target=example.com generalBypass=true\n", binlog.TagSocks5},
		{"2026/08/15 12:00:00 [snc] bypass: no CIDR loaded, not bypassing\n", binlog.TagBypass},
		{"2026/08/15 12:00:00 [snc] tunnel: dial ok\n", binlog.TagTunnel},
		{"2026/08/15 12:00:00 [snc] router: route added\n", binlog.TagTunnel},
		{"2026/08/15 12:00:00 [snc] log-upload: sent 512 bytes\n", binlog.TagUpload},
		{"2026/08/15 12:00:00 [snc] conn-stats-upload: sent\n", binlog.TagUpload},
		{"2026/08/15 12:00:00 [snc] bananameter: probe ok\n", binlog.TagUpload},
		{"2026/08/15 12:00:00 [snc] updater: checking for update\n", binlog.TagUpdate},
		{"2026/08/15 12:00:00 [snc] watchdog: tick\n", binlog.TagSystem},
		{"2026/08/15 12:00:00 [snc] === ShortNerdCat 202608151800 started ===\n", binlog.TagGeneric}, // no "word:" prefix at all
		{"2026/08/15 12:00:00 [snc] unknown-subsystem-nobody-registered: whatever\n", binlog.TagGeneric},
		{"", binlog.TagGeneric},
		{"[kl] snc_lifecycle style, no core prefix at all\n", binlog.TagGeneric},

		// Real lines from bypass.go / router.go that contain a ']' *after*
		// the subsystem prefix (e.g. an embedded URL in brackets, or
		// "path[N]") -- these must still classify correctly. A naive
		// "find the last ']' in the whole line" approach breaks here: it
		// latches onto the later bracket instead of the "[snc] " log-prefix
		// bracket and loses the subsystem word entirely.
		{"2026/08/15 12:00:00 [snc] bypass: build request [https://exit.example.com/verify]: connection refused\n", binlog.TagBypass},
		{"2026/08/15 12:00:00 [snc] router: path[0] score=95 hops=2 via=X\n", binlog.TagTunnel},
		{"2026/08/15 12:00:00 [snc] router: advanced to path[3]\n", binlog.TagTunnel},
	}
	for _, c := range cases {
		got := tagForLine([]byte(c.line))
		if got != c.want {
			t.Errorf("tagForLine(%q) = %v, want %v", c.line, got, c.want)
		}
	}
}

// TestSubsystemTagsCoverKnownPrefixes is a light guard against the mapping
// table silently drifting from the codebase: every prefix here is a real,
// currently-used Log.Printf subsystem (see the grep in the 2026-08-15
// tagging work). This doesn't scan source files (too fragile / slow for a
// unit test) -- it just pins the known set so an accidental table edit that
// drops one is caught immediately.
func TestSubsystemTagsCoverKnownPrefixes(t *testing.T) {
	known := []string{
		"TUN", "admin-status", "bananameter", "bypass", "conn-stats-upload",
		"decoy", "dialer-pool", "discovery", "holepunch", "log", "log-upload",
		"mirror", "mirror-transport", "nat", "nodeid", "procfilter", "relay",
		"router", "socks5", "tunnel", "udp-assoc", "udp-dns", "udp-relay",
		"updater", "watchdog",
	}
	for _, k := range known {
		if _, ok := subsystemTags[k]; !ok {
			t.Errorf("subsystemTags missing entry for known subsystem %q", k)
		}
	}
}
