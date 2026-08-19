// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// cidrNet holds parsed CIDR ranges for IP containment checks.
type cidrNet struct {
	nets []*net.IPNet
}

func parseCIDRNet(cidrs []string) *cidrNet {
	s := &cidrNet{}
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err == nil {
			s.nets = append(s.nets, n)
		}
	}
	return s
}

func (c *cidrNet) contains(ip net.IP) bool {
	for _, n := range c.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// allCountriesPayload mirrors the arbiter's multi-country response format.
type allCountriesPayload struct {
	TS        int64                      `json:"ts"`
	Countries map[string]json.RawMessage `json:"countries"`
}

// cidrPayloadCIDRs is used only to extract the cidrs field for building the
// in-memory lookup sets; the raw JSON is returned verbatim to clients.
type cidrPayloadCIDRs struct {
	CIDRs []string `json:"cidrs"`
}

// cidrCache fetches the multi-country CIDR map from the arbiter hourly and
// provides two operations:
//   - Lookup(ipStr) — returns the raw signed cidrPayload JSON for the country
//     that contains ip, or nil if no bucket matches.
//   - The raw payloads are arbiter-signed and returned verbatim, so clients can
//     verify them with the arbiter's Ed25519 pubkey.
type cidrCache struct {
	nodeToken string
	exits     *ExitRegistry

	mu       sync.RWMutex
	sets     map[string]*cidrNet       // country → CIDR set (for detection)
	payloads map[string]json.RawMessage // country → raw signed JSON (pass-through to clients)

	stop chan struct{}
}

func newCIDRCache(nodeToken string, exits *ExitRegistry) *cidrCache {
	return &cidrCache{
		nodeToken: nodeToken,
		exits:     exits,
		stop:      make(chan struct{}),
	}
}

// Start fetches immediately, then refreshes every hour.
func (c *cidrCache) Start() {
	go func() {
		c.refresh()
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-c.stop:
				return
			case <-t.C:
				c.refresh()
			}
		}
	}()
}

// Stop shuts down the background goroutine.
func (c *cidrCache) Stop() {
	close(c.stop)
}

// Lookup returns the arbiter-signed CIDR payload for the country bucket
// that contains ipStr.  Returns nil if no country matches ("others" fallback).
func (c *cidrCache) Lookup(ipStr string) []byte {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	for country, s := range c.sets {
		if s.contains(ip) {
			if raw, ok := c.payloads[country]; ok {
				out := make([]byte, len(raw))
				copy(out, raw)
				return out
			}
		}
	}
	return nil
}

// lookupCC returns the ISO-3166 region code for ip, or "" if not matched.
func (c *cidrCache) lookupCC(ip net.IP) string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for cc, s := range c.sets {
		if s.contains(ip) {
			return cc
		}
	}
	return ""
}

func (c *cidrCache) refresh() {
	exit, err := c.exits.PickRandom()
	if err != nil {
		logWarnf("cidr: no exits available: %v", err)
		return
	}
	req, err := http.NewRequest(http.MethodGet, exitProxyURL(exit.Addr, "/api/cidr/all"), nil)
	if err != nil {
		logWarnf("cidr: build request: %v", err)
		return
	}
	req.Header.Set("X-Node-Token", c.nodeToken)

	resp, err := nodeProxyClient().Do(req)
	if err != nil {
		logWarnf("cidr: fetch: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		logDebugf("cidr: arbiter has no CIDR data configured")
		return
	}
	if resp.StatusCode != http.StatusOK {
		logWarnf("cidr: fetch status %d", resp.StatusCode)
		return
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 50<<20))
	if err != nil {
		logWarnf("cidr: read body: %v", err)
		return
	}

	var outer allCountriesPayload
	if err := json.Unmarshal(data, &outer); err != nil {
		logWarnf("cidr: parse outer: %v", err)
		return
	}
	if len(outer.Countries) == 0 {
		logWarnf("cidr: arbiter returned empty countries map")
		return
	}

	newSets := make(map[string]*cidrNet, len(outer.Countries))
	newPayloads := make(map[string]json.RawMessage, len(outer.Countries))
	for cc, raw := range outer.Countries {
		var p cidrPayloadCIDRs
		if err := json.Unmarshal(raw, &p); err != nil {
			logWarnf("cidr: parse %s: %v", cc, err)
			continue
		}
		newSets[cc] = parseCIDRNet(p.CIDRs)
		newPayloads[cc] = raw
	}

	c.mu.Lock()
	c.sets = newSets
	c.payloads = newPayloads
	c.mu.Unlock()

	logInfof("cidr: refreshed %d country buckets from arbiter", len(newSets))
}
