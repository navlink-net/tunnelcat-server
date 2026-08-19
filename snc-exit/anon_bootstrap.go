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
	anonBootstrapRefreshInterval = 1 * time.Hour
	anonBootstrapStaleTTL        = 24 * time.Hour // serve stale if arbiter unreachable
	anonBootstrapFetchTimeout    = 10 * time.Second
)

// anonAllowlistEntry is a parsed "anon bootstrap sessions may reach this"
// rule. Same shape as whitelistEntry/serviceBlockEntry deliberately.
type anonAllowlistEntry struct {
	entryType string // "domain" | "wildcard" | "cidr"
	value     string
	network   *net.IPNet
}

// anonBootstrapCache fetches the signed anon-bootstrap manifest (shared
// token + destination allowlist) from the arbiter, verifies the Ed25519
// signature, and answers "is this the bootstrap token" / "is host/ip
// reachable under it" lookups. Mirrors whitelistCache/serviceBlockCache's
// fetch/cache/verify machinery closely on purpose.
//
// The bootstrap token lets a client with no account reach a small,
// admin-configured set of destinations (namely shortnerdcat.navlink.net,
// so the app can open a webview and let the user buy a key) without a
// round-trip to the arbiter's session validator — see handleTunnel's use
// of IsBootstrapToken, checked before h.auth.validateSession.
type anonBootstrapCache struct {
	arbiterURL string
	nodeToken  string
	pubkey     ed25519.PublicKey
	cacheFile  string
	client     *http.Client

	mu        sync.RWMutex
	token     string
	entries   []anonAllowlistEntry
	fetchedAt time.Time
}

// signedAnonBootstrapWire is the JSON structure returned by the arbiter.
type signedAnonBootstrapWire struct {
	TS      int64  `json:"ts"`
	Token   string `json:"token"`
	Entries []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"entries"`
	Sig string `json:"sig"`
}

func newAnonBootstrapCache(arbiterURL, nodeToken string, pubkey ed25519.PublicKey, cacheFile string) *anonBootstrapCache {
	return &anonBootstrapCache{
		arbiterURL: strings.TrimRight(arbiterURL, "/"),
		nodeToken:  nodeToken,
		pubkey:     pubkey,
		cacheFile:  cacheFile,
		client:     &http.Client{Timeout: anonBootstrapFetchTimeout},
	}
}

// Start loads the on-disk cache then begins hourly background refreshes.
func (ab *anonBootstrapCache) Start() {
	if err := ab.loadFromDisk(); err != nil {
		logInfof("anon-bootstrap: no valid disk cache: %v — will fetch from arbiter", err)
	} else {
		logInfof("anon-bootstrap: loaded token + %d rule(s) from disk cache", ab.count())
	}
	go ab.refreshLoop()
}

func (ab *anonBootstrapCache) refreshLoop() {
	if err := ab.fetch(); err != nil {
		logWarnf("anon-bootstrap: initial fetch failed: %v", err)
	}
	t := time.NewTicker(anonBootstrapRefreshInterval)
	defer t.Stop()
	for range t.C {
		if err := ab.fetch(); err != nil {
			logWarnf("anon-bootstrap: refresh failed: %v", err)
		}
	}
}

func (ab *anonBootstrapCache) count() int {
	ab.mu.RLock()
	defer ab.mu.RUnlock()
	return len(ab.entries)
}

// IsBootstrapToken reports whether token is the current shared anon
// bootstrap token. Empty tokens never match.
func (ab *anonBootstrapCache) IsBootstrapToken(token string) bool {
	if token == "" {
		return false
	}
	ab.mu.RLock()
	defer ab.mu.RUnlock()
	return ab.token != "" && token == ab.token
}

// IsAllowed reports whether host/ip is in the anon-bootstrap destination
// allowlist. host is the DNS name (may be ""); ip is the remote IP string
// (may be "").
func (ab *anonBootstrapCache) IsAllowed(host, ip string) bool {
	ab.mu.RLock()
	entries := ab.entries
	ab.mu.RUnlock()
	for _, e := range entries {
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

func (ab *anonBootstrapCache) fetch() error {
	req, err := http.NewRequest(http.MethodGet, ab.arbiterURL+"/api/anon-bootstrap", nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Node-Token", ab.nodeToken)

	start := time.Now()
	resp, err := ab.client.Do(req)
	if err != nil {
		return fmt.Errorf("GET /api/anon-bootstrap: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("arbiter anon-bootstrap: status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	token, entries, err := ab.parseAndVerify(data)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	ab.mu.Lock()
	ab.token = token
	ab.entries = entries
	ab.fetchedAt = time.Now()
	ab.mu.Unlock()

	if ab.cacheFile != "" {
		if err := os.WriteFile(ab.cacheFile, data, 0600); err != nil {
			logWarnf("anon-bootstrap: write disk cache: %v", err)
		}
	}
	logInfof("anon-bootstrap: fetched token + %d rule(s) from arbiter dur=%s", len(entries), time.Since(start).Round(time.Millisecond))
	return nil
}

func (ab *anonBootstrapCache) loadFromDisk() error {
	if ab.cacheFile == "" {
		return fmt.Errorf("no cache file configured")
	}
	data, err := os.ReadFile(ab.cacheFile)
	if err != nil {
		return err
	}
	token, entries, err := ab.parseAndVerify(data)
	if err != nil {
		return err
	}
	var wire signedAnonBootstrapWire
	if jerr := json.Unmarshal(data, &wire); jerr == nil {
		age := time.Since(time.Unix(wire.TS, 0))
		if age > anonBootstrapStaleTTL {
			return fmt.Errorf("disk cache too old (%s)", age.Round(time.Hour))
		}
	}
	ab.mu.Lock()
	ab.token = token
	ab.entries = entries
	ab.fetchedAt = time.Now()
	ab.mu.Unlock()
	return nil
}

func (ab *anonBootstrapCache) parseAndVerify(data []byte) (string, []anonAllowlistEntry, error) {
	var wire signedAnonBootstrapWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return "", nil, fmt.Errorf("unmarshal: %w", err)
	}
	if ab.pubkey != nil {
		canonical, err := json.Marshal(struct {
			TS      int64  `json:"ts"`
			Token   string `json:"token"`
			Entries []struct {
				Type  string `json:"type"`
				Value string `json:"value"`
			} `json:"entries"`
		}{TS: wire.TS, Token: wire.Token, Entries: wire.Entries})
		if err != nil {
			return "", nil, fmt.Errorf("marshal canonical: %w", err)
		}
		sig, err := base64.RawURLEncoding.DecodeString(wire.Sig)
		if err != nil || len(sig) != ed25519.SignatureSize {
			return "", nil, fmt.Errorf("invalid signature encoding")
		}
		if !ed25519.Verify(ab.pubkey, canonical, sig) {
			return "", nil, fmt.Errorf("signature verification failed")
		}
	}
	entries := make([]anonAllowlistEntry, 0, len(wire.Entries))
	for _, e := range wire.Entries {
		parsed := anonAllowlistEntry{entryType: e.Type}
		switch e.Type {
		case "domain":
			parsed.value = strings.ToLower(e.Value)
		case "wildcard":
			parsed.value = strings.ToLower(strings.TrimPrefix(e.Value, "*"))
		case "cidr":
			_, ipNet, err := net.ParseCIDR(e.Value)
			if err != nil {
				logWarnf("anon-bootstrap: skip bad CIDR %q: %v", e.Value, err)
				continue
			}
			parsed.value = e.Value
			parsed.network = ipNet
		default:
			logWarnf("anon-bootstrap: unknown entry type %q — skipping", e.Type)
			continue
		}
		entries = append(entries, parsed)
	}
	return wire.Token, entries, nil
}
