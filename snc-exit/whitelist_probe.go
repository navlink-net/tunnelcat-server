// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/tls"
	"database/sql"
	"net"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	wlProbeInterval = 2 * time.Minute
	wlProbeAttempts = 3
	wlProbeTimeout  = 5 * time.Second
)

// WhitelistProbe periodically tests TCP+TLS connectivity to each whitelisted
// domain. Results are persisted locally (survive restarts) and exposed via
// /api/peer/capabilities so peer exits can route around incapable nodes.
type WhitelistProbe struct {
	db   *sql.DB
	mu   sync.RWMutex
	caps map[string]bool // domain → reachable; in-memory mirror of DB
}

func newWhitelistProbe(dbPath string) (*WhitelistProbe, error) {
	db, err := sql.Open("sqlite", dbPath+"?_timeout=5000")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS whitelist_reachability (
			value       TEXT    PRIMARY KEY,
			can_reach   INTEGER NOT NULL DEFAULT 1,
			last_probed INTEGER NOT NULL DEFAULT 0
		)`); err != nil {
		db.Close()
		return nil, err
	}
	wp := &WhitelistProbe{db: db, caps: make(map[string]bool)}
	wp.loadFromDB()
	return wp, nil
}

func (wp *WhitelistProbe) loadFromDB() {
	rows, err := wp.db.Query(`SELECT value, can_reach FROM whitelist_reachability`)
	if err != nil {
		return
	}
	defer rows.Close()
	wp.mu.Lock()
	for rows.Next() {
		var v string
		var c int
		if rows.Scan(&v, &c) == nil {
			wp.caps[v] = c != 0
		}
	}
	wp.mu.Unlock()
}

// Start launches the background probe loop using domains from wl.
func (wp *WhitelistProbe) Start(wl *whitelistCache) {
	go wp.probeLoop(wl)
}

func (wp *WhitelistProbe) probeLoop(wl *whitelistCache) {
	wp.runProbes(wl)
	t := time.NewTicker(wlProbeInterval)
	defer t.Stop()
	for range t.C {
		wp.runProbes(wl)
	}
}

func (wp *WhitelistProbe) runProbes(wl *whitelistCache) {
	wl.mu.RLock()
	entries := wl.entries
	wl.mu.RUnlock()

	seen := map[string]bool{}
	for _, e := range entries {
		var domain string
		switch e.entryType {
		case "domain":
			domain = e.value
		case "wildcard":
			// e.value is already the suffix (".example.com") — probe "example.com"
			domain = strings.TrimPrefix(e.value, ".")
		default:
			continue // CIDRs are not probeable
		}
		if seen[domain] {
			continue
		}
		seen[domain] = true
		ok := wp.probeDomain(domain)
		wp.recordResult(domain, ok)
	}
}

// probeDomain makes up to wlProbeAttempts TCP+TLS connections to domain:443.
// Returns true if any attempt succeeds; false if all wlProbeAttempts fail.
func (wp *WhitelistProbe) probeDomain(domain string) bool {
	addr := net.JoinHostPort(domain, "443")
	for i := 0; i < wlProbeAttempts; i++ {
		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: wlProbeTimeout},
			"tcp", addr,
			&tls.Config{ServerName: domain},
		)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

func (wp *WhitelistProbe) recordResult(domain string, ok bool) {
	now := time.Now().Unix()
	canReach := 0
	if ok {
		canReach = 1
	}
	wp.db.Exec(`
		INSERT INTO whitelist_reachability(value, can_reach, last_probed) VALUES(?,?,?)
		ON CONFLICT(value) DO UPDATE SET can_reach=excluded.can_reach, last_probed=excluded.last_probed`,
		domain, canReach, now) //nolint:errcheck

	wp.mu.Lock()
	wp.caps[domain] = ok
	wp.mu.Unlock()

	if !ok {
		logWarnf("whitelist-probe: %s UNREACHABLE (all %d attempts failed)", domain, wlProbeAttempts)
	} else {
		logDebugf("whitelist-probe: %s reachable", domain)
	}
}

// CanReach reports whether this exit can reach domain.
// Returns true (assume capable) if no probe result is available yet.
func (wp *WhitelistProbe) CanReach(domain string) bool {
	wp.mu.RLock()
	v, ok := wp.caps[domain]
	wp.mu.RUnlock()
	if !ok {
		return true
	}
	return v
}

// Capabilities returns a snapshot of all probed domain→reachable mappings.
func (wp *WhitelistProbe) Capabilities() map[string]bool {
	wp.mu.RLock()
	defer wp.mu.RUnlock()
	out := make(map[string]bool, len(wp.caps))
	for k, v := range wp.caps {
		out[k] = v
	}
	return out
}
