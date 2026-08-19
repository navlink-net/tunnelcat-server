// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	torrentAllowedRefreshInterval = 5 * time.Minute
	torrentAllowedFetchTimeout    = 10 * time.Second
)

// torrentAllowedCache fetches the signed torrent-blocked-exits list from the
// arbiter (blacklist model: an exit allows torrent egress unless its own addr
// is on the list). Deliberately arbiter-controlled, not a local flag/env-var:
// an admin flips a node's torrent policy from one place (the arbiter's
// /admin/whitelist page) without SSHing into and restarting the exit itself.
// Mirrors blacklistCache's fetch/cache/verify machinery closely on purpose.
type torrentAllowedCache struct {
	arbiterURL string
	nodeToken  string
	pubkey     ed25519.PublicKey
	client     *http.Client

	mu          sync.RWMutex
	blocked     map[string]struct{} // lower-cased addr strings, for peer filtering
	selfAllowed bool                // this exit's own resolved policy
}

// signedTorrentBlockedWire is the JSON structure returned by the arbiter.
type signedTorrentBlockedWire struct {
	TS          int64    `json:"ts"`
	Addrs       []string `json:"addrs"` // blocked exit addrs
	SelfAllowed bool     `json:"self_allowed"`
	Sig         string   `json:"sig"`
}

func newTorrentAllowedCache(arbiterURL, nodeToken string, pubkey ed25519.PublicKey) *torrentAllowedCache {
	return &torrentAllowedCache{
		arbiterURL: strings.TrimRight(arbiterURL, "/"),
		nodeToken:  nodeToken,
		pubkey:     pubkey,
		client:     &http.Client{Timeout: torrentAllowedFetchTimeout},
		blocked:    make(map[string]struct{}),
		// Default to allowed until the first fetch completes — matches the
		// blacklist model's default (absence from the list = allowed), so a
		// freshly started exit doesn't spuriously reject torrent traffic
		// during the brief window before its first successful fetch.
		selfAllowed: true,
	}
}

// Start fetches the list immediately, then refreshes every 5 minutes.
func (ta *torrentAllowedCache) Start() {
	go ta.refreshLoop()
}

func (ta *torrentAllowedCache) refreshLoop() {
	if err := ta.fetch(); err != nil {
		logWarnf("torrent-blocked: initial fetch failed: %v", err)
	}
	t := time.NewTicker(torrentAllowedRefreshInterval)
	defer t.Stop()
	for range t.C {
		if err := ta.fetch(); err != nil {
			logWarnf("torrent-blocked: refresh failed: %v", err)
		}
	}
}

// SelfAllowed reports whether this exit itself is allowed to carry torrent
// traffic directly.
func (ta *torrentAllowedCache) SelfAllowed() bool {
	ta.mu.RLock()
	defer ta.mu.RUnlock()
	return ta.selfAllowed
}

// IsAllowed reports whether addr (a peer exit's address) is allowed to carry
// torrent traffic directly — true unless addr is on the arbiter's blocked list.
func (ta *torrentAllowedCache) IsAllowed(addr string) bool {
	key := strings.ToLower(addr)
	ta.mu.RLock()
	_, blocked := ta.blocked[key]
	ta.mu.RUnlock()
	return !blocked
}

func (ta *torrentAllowedCache) fetch() error {
	req, err := http.NewRequest(http.MethodGet, ta.arbiterURL+"/api/torrent-blocked", nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Node-Token", ta.nodeToken)

	resp, err := ta.client.Do(req)
	if err != nil {
		return fmt.Errorf("GET /api/torrent-blocked: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("arbiter torrent-blocked: status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	blocked, selfAllowed, err := ta.parseAndVerify(data)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	ta.mu.Lock()
	ta.blocked = blocked
	ta.selfAllowed = selfAllowed
	ta.mu.Unlock()

	logInfof("torrent-blocked: fetched %d entries from arbiter self_allowed=%v", len(blocked), selfAllowed)
	return nil
}

func (ta *torrentAllowedCache) parseAndVerify(data []byte) (map[string]struct{}, bool, error) {
	var wire signedTorrentBlockedWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, false, fmt.Errorf("unmarshal: %w", err)
	}
	if ta.pubkey != nil {
		canonical, err := json.Marshal(struct {
			TS    int64    `json:"ts"`
			Addrs []string `json:"addrs"`
		}{TS: wire.TS, Addrs: wire.Addrs})
		if err != nil {
			return nil, false, fmt.Errorf("marshal canonical: %w", err)
		}
		sig, err := base64.RawURLEncoding.DecodeString(wire.Sig)
		if err != nil || len(sig) != ed25519.SignatureSize {
			return nil, false, fmt.Errorf("invalid signature encoding")
		}
		if !ed25519.Verify(ta.pubkey, canonical, sig) {
			return nil, false, fmt.Errorf("signature verification failed")
		}
	}
	blocked := make(map[string]struct{}, len(wire.Addrs))
	for _, a := range wire.Addrs {
		if a != "" {
			blocked[strings.ToLower(a)] = struct{}{}
		}
	}
	return blocked, wire.SelfAllowed, nil
}
