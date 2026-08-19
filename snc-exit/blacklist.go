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
	blacklistRefreshInterval = 5 * time.Minute
	blacklistFetchTimeout    = 10 * time.Second
)

// blacklistCache fetches the signed address blacklist from the arbiter and provides
// IsBlacklisted lookups for exit dial decisions.
type blacklistCache struct {
	arbiterURL string
	nodeToken  string
	pubkey     ed25519.PublicKey
	client     *http.Client

	mu    sync.RWMutex
	addrs map[string]struct{} // lower-cased addr strings
}

// signedBlacklistWire is the JSON structure returned by the arbiter.
type signedBlacklistWire struct {
	TS    int64    `json:"ts"`
	Addrs []string `json:"addrs"`
	Sig   string   `json:"sig"`
}

func newBlacklistCache(arbiterURL, nodeToken string, pubkey ed25519.PublicKey) *blacklistCache {
	return &blacklistCache{
		arbiterURL: strings.TrimRight(arbiterURL, "/"),
		nodeToken:  nodeToken,
		pubkey:     pubkey,
		client:     &http.Client{Timeout: blacklistFetchTimeout},
		addrs:      make(map[string]struct{}),
	}
}

// Start fetches the blacklist immediately, then refreshes every 5 minutes.
func (bl *blacklistCache) Start() {
	go bl.refreshLoop()
}

func (bl *blacklistCache) refreshLoop() {
	if err := bl.fetch(); err != nil {
		logWarnf("blacklist: initial fetch failed: %v", err)
	}
	t := time.NewTicker(blacklistRefreshInterval)
	defer t.Stop()
	for range t.C {
		if err := bl.fetch(); err != nil {
			logWarnf("blacklist: refresh failed: %v", err)
		}
	}
}

// IsBlacklisted reports whether host is in the blacklist.
// host is the destination hostname or IP (without port).
func (bl *blacklistCache) IsBlacklisted(host string) bool {
	key := strings.ToLower(host)
	bl.mu.RLock()
	_, ok := bl.addrs[key]
	bl.mu.RUnlock()
	return ok
}

func (bl *blacklistCache) fetch() error {
	req, err := http.NewRequest(http.MethodGet, bl.arbiterURL+"/api/blacklist", nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Node-Token", bl.nodeToken)

	resp, err := bl.client.Do(req)
	if err != nil {
		return fmt.Errorf("GET /api/blacklist: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("arbiter blacklist: status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	addrs, err := bl.parseAndVerify(data)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	bl.mu.Lock()
	bl.addrs = addrs
	bl.mu.Unlock()

	logInfof("blacklist: fetched %d entries from arbiter", len(addrs))
	return nil
}

func (bl *blacklistCache) parseAndVerify(data []byte) (map[string]struct{}, error) {
	var wire signedBlacklistWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	if bl.pubkey != nil {
		canonical, err := json.Marshal(struct {
			TS    int64    `json:"ts"`
			Addrs []string `json:"addrs"`
		}{TS: wire.TS, Addrs: wire.Addrs})
		if err != nil {
			return nil, fmt.Errorf("marshal canonical: %w", err)
		}
		sig, err := base64.RawURLEncoding.DecodeString(wire.Sig)
		if err != nil || len(sig) != ed25519.SignatureSize {
			return nil, fmt.Errorf("invalid signature encoding")
		}
		if !ed25519.Verify(bl.pubkey, canonical, sig) {
			return nil, fmt.Errorf("signature verification failed")
		}
	}
	addrs := make(map[string]struct{}, len(wire.Addrs))
	for _, a := range wire.Addrs {
		if a != "" {
			addrs[strings.ToLower(a)] = struct{}{}
		}
	}
	return addrs, nil
}
