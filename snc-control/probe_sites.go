// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ProbeSiteRegistry holds the per-region URL sets used to verify exit data-plane health.
// Fetched from the arbiter (via exit proxy, never direct -- see exitProxyURL
// in fetch() below) every 2 hours and on start; cached to disk so the list
// survives arbiter outages and is updated centrally without redeploying
// controls. Deliberately holds no arbiter address of its own.
type ProbeSiteRegistry struct {
	nodeToken string
	cacheFile string
	exits     *ExitRegistry

	mu    sync.RWMutex
	sites map[string][]string
}

func newProbeSiteRegistry(nodeToken, cacheFile string, exits *ExitRegistry) *ProbeSiteRegistry {
	return &ProbeSiteRegistry{
		nodeToken: nodeToken,
		cacheFile: cacheFile,
		exits:     exits,
	}
}

// Start fetches probe sites immediately, falls back to disk cache on failure,
// then refreshes every interval.
func (p *ProbeSiteRegistry) Start(interval time.Duration) {
	if err := p.fetch(); err != nil {
		logWarnf("probe-sites: initial fetch failed: %v — trying disk cache", err)
		p.loadCache()
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			if err := p.fetch(); err != nil {
				logWarnf("probe-sites: refresh failed: %v", err)
			}
		}
	}()
}

// ForRegion returns the probe URLs for the given region code.
// Falls back to the "" (unknown) entry if the region has no specific list.
// Returns nil if no sites have been loaded yet (probe step is skipped by caller).
func (p *ProbeSiteRegistry) ForRegion(region string) []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.sites == nil {
		return nil
	}
	if urls, ok := p.sites[region]; ok && len(urls) > 0 {
		return urls
	}
	return p.sites[""]
}

func (p *ProbeSiteRegistry) fetch() error {
	exit, err := p.exits.PickRandom()
	if err != nil {
		return fmt.Errorf("no exits available: %w", err)
	}
	fetchURL := exitProxyURL(exit.Addr, "/api/probe-sites")

	req, err := http.NewRequest(http.MethodGet, fetchURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Node-Token", p.nodeToken)

	resp, err := nodeProxyClient().Do(req)
	if err != nil {
		return fmt.Errorf("fetch via %s: %w", exit.Addr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("arbiter returned %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	var sites map[string][]string
	if err := json.Unmarshal(raw, &sites); err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	if len(sites) == 0 {
		return fmt.Errorf("empty response")
	}

	p.mu.Lock()
	p.sites = sites
	p.mu.Unlock()

	p.saveCache(raw)
	logInfof("probe-sites: loaded %d regions via %s", len(sites), exit.Addr)
	return nil
}

func (p *ProbeSiteRegistry) loadCache() {
	if p.cacheFile == "" {
		return
	}
	data, err := os.ReadFile(p.cacheFile)
	if err != nil {
		return
	}
	var sites map[string][]string
	if err := json.Unmarshal(data, &sites); err != nil || len(sites) == 0 {
		return
	}
	p.mu.Lock()
	p.sites = sites
	p.mu.Unlock()
	logInfof("probe-sites: loaded %d regions from disk cache", len(sites))
}

func (p *ProbeSiteRegistry) saveCache(data []byte) {
	if p.cacheFile == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p.cacheFile), 0700); err != nil {
		logWarnf("probe-sites: cache dir: %v", err)
		return
	}
	if err := os.WriteFile(p.cacheFile, data, 0600); err != nil {
		logWarnf("probe-sites: cache write: %v", err)
	}
}
