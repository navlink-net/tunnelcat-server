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
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	whitelistRefreshInterval = 1 * time.Hour
	whitelistStaleTTL        = 24 * time.Hour // serve stale if arbiter unreachable
	whitelistFetchTimeout    = 10 * time.Second
)

// whitelistEntry is a parsed whitelist rule.
type whitelistEntry struct {
	entryType string // "domain" | "wildcard" | "cidr"
	value     string // exact domain, wildcard suffix (e.g. ".netflix.com"), or CIDR string
	network   *net.IPNet
}

// whitelistCache fetches the signed whitelist from the arbiter, verifies the
// Ed25519 signature, and provides IsWhitelisted lookups for routing decisions
// (see handler.go's "whitelist peer-routing": if this exit can't reach a
// whitelisted target directly, forward through a peer exit that can).
type whitelistCache struct {
	arbiterURL string
	nodeToken  string
	pubkey     ed25519.PublicKey
	cacheFile  string
	client     *http.Client

	mu        sync.RWMutex
	entries   []whitelistEntry
	fetchedAt time.Time
}

// signedWhitelistWire is the JSON structure returned by the arbiter.
type signedWhitelistWire struct {
	TS      int64 `json:"ts"`
	Entries []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"entries"`
	Sig string `json:"sig"`
}

func newWhitelistCache(arbiterURL, nodeToken string, pubkey ed25519.PublicKey, cacheFile string) *whitelistCache {
	return &whitelistCache{
		arbiterURL: strings.TrimRight(arbiterURL, "/"),
		nodeToken:  nodeToken,
		pubkey:     pubkey,
		cacheFile:  cacheFile,
		client:     &http.Client{Timeout: whitelistFetchTimeout},
	}
}

// Start loads the on-disk cache then begins hourly background refreshes.
func (wl *whitelistCache) Start() {
	if err := wl.loadFromDisk(); err != nil {
		logInfof("whitelist: no valid disk cache: %v — will fetch from arbiter", err)
	} else {
		logInfof("whitelist: loaded %d entries from disk cache", wl.count())
	}
	go wl.refreshLoop()
}

func (wl *whitelistCache) refreshLoop() {
	// Immediate fetch on startup.
	if err := wl.fetch(); err != nil {
		logWarnf("whitelist: initial fetch failed: %v", err)
	}
	t := time.NewTicker(whitelistRefreshInterval)
	defer t.Stop()
	for range t.C {
		if err := wl.fetch(); err != nil {
			logWarnf("whitelist: refresh failed: %v", err)
		}
	}
}

// IsWhitelisted reports whether traffic to host (and/or IP) matches any rule.
// host is the DNS name; ip is the remote IP string (may be "").
func (wl *whitelistCache) IsWhitelisted(host, ip string) bool {
	wl.mu.RLock()
	entries := wl.entries
	wl.mu.RUnlock()
	for _, e := range entries {
		switch e.entryType {
		case "domain":
			if strings.EqualFold(host, e.value) {
				return true
			}
		case "wildcard":
			// e.value is already the suffix, e.g. ".netflix.com"
			if len(host) > len(e.value) && strings.HasSuffix(strings.ToLower(host), e.value) {
				return true
			}
		case "cidr":
			if ip != "" && e.network != nil {
				if parsed := net.ParseIP(ip); parsed != nil && e.network.Contains(parsed) {
					return true
				}
			}
		}
	}
	return false
}

// count returns the current number of whitelist rules.
func (wl *whitelistCache) count() int {
	wl.mu.RLock()
	defer wl.mu.RUnlock()
	return len(wl.entries)
}

// fetch retrieves and verifies a fresh whitelist from the arbiter.
func (wl *whitelistCache) fetch() error {
	req, err := http.NewRequest(http.MethodGet, wl.arbiterURL+"/api/whitelist", nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Node-Token", wl.nodeToken)

	start := time.Now()
	resp, err := wl.client.Do(req)
	if err != nil {
		return fmt.Errorf("GET /api/whitelist: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("arbiter whitelist: status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	entries, err := wl.parseAndVerify(data)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	wl.mu.Lock()
	wl.entries = entries
	wl.fetchedAt = time.Now()
	wl.mu.Unlock()

	if wl.cacheFile != "" {
		if err := os.WriteFile(wl.cacheFile, data, 0600); err != nil {
			logWarnf("whitelist: write disk cache: %v", err)
		}
	}
	logInfof("whitelist: fetched %d entries from arbiter dur=%s", len(entries), time.Since(start).Round(time.Millisecond))
	return nil
}

func (wl *whitelistCache) loadFromDisk() error {
	if wl.cacheFile == "" {
		return fmt.Errorf("no cache file configured")
	}
	data, err := os.ReadFile(wl.cacheFile)
	if err != nil {
		return err
	}
	entries, err := wl.parseAndVerify(data)
	if err != nil {
		return err
	}
	// Don't serve a very stale disk cache.
	var wire signedWhitelistWire
	if jerr := json.Unmarshal(data, &wire); jerr == nil {
		age := time.Since(time.Unix(wire.TS, 0))
		if age > whitelistStaleTTL {
			return fmt.Errorf("disk cache too old (%s)", age.Round(time.Hour))
		}
	}
	wl.mu.Lock()
	wl.entries = entries
	wl.fetchedAt = time.Now()
	wl.mu.Unlock()
	return nil
}

// parseAndVerify parses the signed whitelist JSON and verifies the Ed25519 sig.
func (wl *whitelistCache) parseAndVerify(data []byte) ([]whitelistEntry, error) {
	var wire signedWhitelistWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	if wl.pubkey != nil {
		// Re-marshal the signed payload (same struct the arbiter signs).
		canonical, err := json.Marshal(struct {
			TS      int64 `json:"ts"`
			Entries []struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"entries"`
		}{TS: wire.TS, Entries: wire.Entries})
		if err != nil {
			return nil, fmt.Errorf("marshal canonical: %w", err)
		}
		sig, err := base64.RawURLEncoding.DecodeString(wire.Sig)
		if err != nil || len(sig) != ed25519.SignatureSize {
			return nil, fmt.Errorf("invalid signature encoding")
		}
		if !ed25519.Verify(wl.pubkey, canonical, sig) {
			return nil, fmt.Errorf("signature verification failed")
		}
	}
	entries := make([]whitelistEntry, 0, len(wire.Entries))
	for _, e := range wire.Entries {
		parsed := whitelistEntry{entryType: e.Type}
		switch e.Type {
		case "domain":
			parsed.value = strings.ToLower(e.Value)
		case "wildcard":
			// Normalise "*.example.com" → ".example.com" for HasSuffix matching.
			parsed.value = strings.ToLower(strings.TrimPrefix(e.Value, "*"))
		case "cidr":
			_, ipNet, err := net.ParseCIDR(e.Value)
			if err != nil {
				logWarnf("whitelist: skip bad CIDR %q: %v", e.Value, err)
				continue
			}
			parsed.value = e.Value
			parsed.network = ipNet
		default:
			logWarnf("whitelist: unknown entry type %q — skipping", e.Type)
			continue
		}
		entries = append(entries, parsed)
	}
	return entries, nil
}
