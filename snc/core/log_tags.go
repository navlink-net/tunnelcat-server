// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"bytes"

	"tunnel_cat/binlog"
)

// subsystemTags maps this codebase's existing "subsystem: message" log-line
// convention (already used at every Log.Printf call site, unchanged by this
// file) to a binlog.Tag, so the on-disk rotating log (see rotatingWriter.Write
// in log.go) can classify records for filtering (tools/decode_snc_log.py
// --tag) without touching any of the ~180 existing call sites.
//
// Deliberately grouped into a small, stable set of topics rather than one
// tag per exact subsystem string -- keeps the tag space meaningful for
// filtering instead of just mirroring file names. A subsystem prefix with no
// entry here falls back to binlog.TagGeneric -- adding a new Log.Printf call
// site never requires a change here, it just stays unclassified until
// someone adds one.
//
// Keep in sync with binlog.TagNames and decode_snc_log.py's TAG_NAMES.
var subsystemTags = map[string]binlog.Tag{
	// TagTunnel: dataplane -- packet/connection routing and transport.
	"tunnel":           binlog.TagTunnel,
	"router":           binlog.TagTunnel,
	"relay":            binlog.TagTunnel,
	"nat":              binlog.TagTunnel,
	"TUN":              binlog.TagTunnel,
	"discovery":        binlog.TagTunnel,
	"holepunch":        binlog.TagTunnel,
	"dialer-pool":      binlog.TagTunnel,
	"mirror":           binlog.TagTunnel,
	"mirror-transport": binlog.TagTunnel,
	"udp-relay":        binlog.TagTunnel,
	"udp-assoc":        binlog.TagTunnel,
	"udp-dns":          binlog.TagTunnel,
	"nodeid":           binlog.TagTunnel,
	"decoy":            binlog.TagTunnel,

	// TagSocks5: the local SOCKS5 proxy and its per-connection routing decisions.
	"socks5": binlog.TagSocks5,

	// TagBypass: country/CIDR direct-dial bypass decisions.
	"bypass": binlog.TagBypass,

	// TagUpload: telemetry/diagnostic upload subsystems.
	"log-upload":        binlog.TagUpload,
	"conn-stats-upload": binlog.TagUpload,
	"bananameter":       binlog.TagUpload,

	// TagUpdate: client self-update.
	"updater": binlog.TagUpdate,

	// TagSystem: process/lifecycle housekeeping.
	"log":          binlog.TagSystem,
	"watchdog":     binlog.TagSystem,
	"procfilter":   binlog.TagSystem,
	"admin-status": binlog.TagSystem,
}

// tagForLine extracts the "subsystem" word from a formatted log line and
// looks it up in subsystemTags. Lines are shaped like
// "2026/08/15 12:00:00 [snc] socks5: routing decision ..." -- Log is
// constructed in log.go as log.New(os.Stderr, "[snc] ",
// log.LstdFlags|log.Lmsgprefix), so logLinePrefix below is the exact,
// fixed literal that always immediately precedes the subsystem word;
// logLinePrefix must be kept in sync if Log's own prefix ever changes.
//
// Deliberately anchors on that fixed literal rather than "find the last
// ']' in the line" -- a first version of this function did exactly that
// and silently misclassified any line whose *message* also contains a
// ']', which turns out to be common in this codebase (e.g. bypass.go's
// "build request [%s]: %v", router.go's "path[%d]") -- the scan would
// latch onto that later bracket instead of the log-prefix one and lose
// the subsystem word entirely. Caught by TestTagForLine, 2026-08-15.
//
// Falls back to binlog.TagGeneric if the prefix isn't found, no
// colon-terminated subsystem word follows it, or the word isn't in the
// table -- never errors, since a log line failing to classify is not a
// reason to lose it.
const logLinePrefix = "[snc] "

func tagForLine(line []byte) binlog.Tag {
	start := 0
	if idx := bytes.Index(line, []byte(logLinePrefix)); idx >= 0 {
		start = idx + len(logLinePrefix)
	}
	rest := line[start:]
	colon := bytes.IndexByte(rest, ':')
	if colon <= 0 {
		return binlog.TagGeneric
	}
	word := string(rest[:colon])
	if tag, ok := subsystemTags[word]; ok {
		return tag
	}
	return binlog.TagGeneric
}
