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
	serviceBlockRefreshInterval = 1 * time.Hour
	serviceBlockStaleTTL        = 24 * time.Hour // serve stale if arbiter unreachable
	serviceBlockFetchTimeout    = 10 * time.Second
)

// serviceBlockEntry is a parsed "don't dial this directly from these
// regions" rule. Same shape as whitelistEntry deliberately.
type serviceBlockEntry struct {
	entryType string // "domain" | "wildcard" | "cidr"
	value     string
	network   *net.IPNet
	regions   map[string]bool // blocked-for set, e.g. {"RU": true}
}

// serviceBlockCache fetches the signed service-region-block manifest from the
// arbiter, verifies the Ed25519 signature, and answers "is host/ip blocked
// for region" lookups used to redirect a dial through a peer instead. Mirrors
// whitelistCache's fetch/cache/verify machinery closely on purpose.
type serviceBlockCache struct {
	arbiterURL string
	nodeToken  string
	pubkey     ed25519.PublicKey
	cacheFile  string
	client     *http.Client

	mu        sync.RWMutex
	entries   []serviceBlockEntry
	fetchedAt time.Time
}

// signedServiceBlocksWire is the JSON structure returned by the arbiter.
type signedServiceBlocksWire struct {
	TS      int64 `json:"ts"`
	Entries []struct {
		Type           string   `json:"type"`
		Value          string   `json:"value"`
		BlockedRegions []string `json:"blocked_regions"`
	} `json:"entries"`
	Sig string `json:"sig"`
}

func newServiceBlockCache(arbiterURL, nodeToken string, pubkey ed25519.PublicKey, cacheFile string) *serviceBlockCache {
	return &serviceBlockCache{
		arbiterURL: strings.TrimRight(arbiterURL, "/"),
		nodeToken:  nodeToken,
		pubkey:     pubkey,
		cacheFile:  cacheFile,
		client:     &http.Client{Timeout: serviceBlockFetchTimeout},
	}
}

// Start loads the on-disk cache then begins hourly background refreshes.
func (sb *serviceBlockCache) Start() {
	if err := sb.loadFromDisk(); err != nil {
		logInfof("service-blocks: no valid disk cache: %v — will fetch from arbiter", err)
	} else {
		logInfof("service-blocks: loaded %d rule(s) from disk cache", sb.count())
	}
	go sb.refreshLoop()
}

func (sb *serviceBlockCache) refreshLoop() {
	if err := sb.fetch(); err != nil {
		logWarnf("service-blocks: initial fetch failed: %v", err)
	}
	t := time.NewTicker(serviceBlockRefreshInterval)
	defer t.Stop()
	for range t.C {
		if err := sb.fetch(); err != nil {
			logWarnf("service-blocks: refresh failed: %v", err)
		}
	}
}

func (sb *serviceBlockCache) count() int {
	sb.mu.RLock()
	defer sb.mu.RUnlock()
	return len(sb.entries)
}

// IsBlockedForRegion reports whether host/ip matches a rule that blocks the
// given region. host is the DNS name (may be ""); ip is the remote IP string
// (may be ""). region is the dialing exit's own resolved region code.
func (sb *serviceBlockCache) IsBlockedForRegion(host, ip, region string) bool {
	if region == "" {
		return false // nothing to compare against
	}
	sb.mu.RLock()
	entries := sb.entries
	sb.mu.RUnlock()
	for _, e := range entries {
		if !e.regions[region] {
			continue
		}
		switch e.entryType {
		case "domain":
			if host != "" && strings.EqualFold(host, e.value) {
				return true
			}
		case "wildcard":
			if host != "" && len(host) > len(e.value) && strings.HasSuffix(strings.ToLower(host), e.value) {
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

func (sb *serviceBlockCache) fetch() error {
	req, err := http.NewRequest(http.MethodGet, sb.arbiterURL+"/api/service-blocks", nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Node-Token", sb.nodeToken)

	start := time.Now()
	resp, err := sb.client.Do(req)
	if err != nil {
		return fmt.Errorf("GET /api/service-blocks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("arbiter service-blocks: status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	entries, err := sb.parseAndVerify(data)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	sb.mu.Lock()
	sb.entries = entries
	sb.fetchedAt = time.Now()
	sb.mu.Unlock()

	if sb.cacheFile != "" {
		if err := os.WriteFile(sb.cacheFile, data, 0600); err != nil {
			logWarnf("service-blocks: write disk cache: %v", err)
		}
	}
	logInfof("service-blocks: fetched %d rule(s) from arbiter dur=%s", len(entries), time.Since(start).Round(time.Millisecond))
	return nil
}

func (sb *serviceBlockCache) loadFromDisk() error {
	if sb.cacheFile == "" {
		return fmt.Errorf("no cache file configured")
	}
	data, err := os.ReadFile(sb.cacheFile)
	if err != nil {
		return err
	}
	entries, err := sb.parseAndVerify(data)
	if err != nil {
		return err
	}
	var wire signedServiceBlocksWire
	if jerr := json.Unmarshal(data, &wire); jerr == nil {
		age := time.Since(time.Unix(wire.TS, 0))
		if age > serviceBlockStaleTTL {
			return fmt.Errorf("disk cache too old (%s)", age.Round(time.Hour))
		}
	}
	sb.mu.Lock()
	sb.entries = entries
	sb.fetchedAt = time.Now()
	sb.mu.Unlock()
	return nil
}

func (sb *serviceBlockCache) parseAndVerify(data []byte) ([]serviceBlockEntry, error) {
	var wire signedServiceBlocksWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	if sb.pubkey != nil {
		canonical, err := json.Marshal(struct {
			TS      int64 `json:"ts"`
			Entries []struct {
				Type           string   `json:"type"`
				Value          string   `json:"value"`
				BlockedRegions []string `json:"blocked_regions"`
			} `json:"entries"`
		}{TS: wire.TS, Entries: wire.Entries})
		if err != nil {
			return nil, fmt.Errorf("marshal canonical: %w", err)
		}
		sig, err := base64.RawURLEncoding.DecodeString(wire.Sig)
		if err != nil || len(sig) != ed25519.SignatureSize {
			return nil, fmt.Errorf("invalid signature encoding")
		}
		if !ed25519.Verify(sb.pubkey, canonical, sig) {
			return nil, fmt.Errorf("signature verification failed")
		}
	}
	entries := make([]serviceBlockEntry, 0, len(wire.Entries))
	for _, e := range wire.Entries {
		parsed := serviceBlockEntry{entryType: e.Type, regions: make(map[string]bool, len(e.BlockedRegions))}
		for _, r := range e.BlockedRegions {
			parsed.regions[strings.ToUpper(r)] = true
		}
		switch e.Type {
		case "domain":
			parsed.value = strings.ToLower(e.Value)
		case "wildcard":
			parsed.value = strings.ToLower(strings.TrimPrefix(e.Value, "*"))
		case "cidr":
			_, ipNet, err := net.ParseCIDR(e.Value)
			if err != nil {
				logWarnf("service-blocks: skip bad CIDR %q: %v", e.Value, err)
				continue
			}
			parsed.value = e.Value
			parsed.network = ipNet
		default:
			logWarnf("service-blocks: unknown entry type %q — skipping", e.Type)
			continue
		}
		entries = append(entries, parsed)
	}
	return entries, nil
}
