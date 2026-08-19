// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// clientCache pulls whatever client binaries the arbiter currently has
// available for OTA distribution (see /api/update/manifest) via a random
// exit node and caches them locally so update_http.go can serve them to VPN
// clients as /client-<slug>[-version|.sha256].
//
// The set of slugs to cache is entirely driven by the arbiter's manifest at
// runtime -- adding a new distributable app is a change on the arbiter only
// (see otaSlugs in snc-arbiter/admin_downloads.go); this file and every
// control node need no code change or redeploy to pick it up.
//
// Each slug is cached under cacheDir/<slug>/ as:
//
//	version — version string
//	bin     — the binary itself
//	sha256  — hex SHA-256 of bin
type clientCache struct {
	nodeToken string
	cacheDir  string
	exits     *ExitRegistry

	mu        sync.Mutex
	stop      chan struct{}
	refreshCh chan struct{} // buffered(1): signals an immediate fetch cycle
}

func newClientCache(nodeToken, cacheDir string, exits *ExitRegistry) *clientCache {
	return &clientCache{
		nodeToken: nodeToken,
		cacheDir:  cacheDir,
		exits:     exits,
		stop:      make(chan struct{}),
		refreshCh: make(chan struct{}, 1),
	}
}

func (c *clientCache) Start() {
	if c.cacheDir == "" {
		return
	}
	c.cleanupLegacyCache()
	go c.loop()
}

// cleanupLegacyCache removes the flat cache files written by the
// pre-refactor clientCache (one hardcoded fetchOne per platform, no
// subdirectories). The current code only ever reads/writes
// cacheDir/<slug>/{bin,version,sha256}, so these are pure dead weight --
// left in place they also block MkdirAll for any slug whose name happens to
// collide with an old flat filename (this hit "macos" in production).
func (c *clientCache) cleanupLegacyCache() {
	legacyNames := []string{
		"client", "client.sha256", "version",
		"client-android", "client-android-version", "client-android.sha256",
		"macos", "macos-version", "macos.sha256",
	}
	for _, name := range legacyNames {
		path := filepath.Join(c.cacheDir, name)
		fi, err := os.Lstat(path)
		if err != nil || fi.IsDir() {
			continue
		}
		if err := os.Remove(path); err != nil {
			logWarnf("client-cache: removing legacy cache file %s: %v", path, err)
			continue
		}
		logInfof("client-cache: removed legacy cache file %s", path)
	}
}

func (c *clientCache) Stop() {
	close(c.stop)
}

// Refresh triggers an immediate fetch cycle without waiting for the 15-minute
// ticker. Called by relay_api when arbiter sends a /p/v1/refresh signal.
func (c *clientCache) Refresh() {
	select {
	case c.refreshCh <- struct{}{}:
	default:
	}
}

func (c *clientCache) loop() {
	// Initial delay: let exits stabilise before first fetch.
	select {
	case <-time.After(45 * time.Second):
	case <-c.refreshCh:
	case <-c.stop:
		return
	}
	c.fetchAll()

	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			c.fetchAll()
		case <-c.refreshCh:
			c.fetchAll()
		case <-c.stop:
			return
		}
	}
}

type manifestEntry struct {
	Available bool   `json:"available"`
	Version   string `json:"version"`
	Hash      string `json:"hash"`
}

func (c *clientCache) fetchAll() {
	c.mu.Lock()
	defer c.mu.Unlock()

	exit, err := c.exits.PickRandom()
	if err != nil {
		logWarnf("client-cache: no exits available: %v", err)
		return
	}
	client := nodeProxyClient()

	manifest, err := c.getManifest(client, exit.Addr)
	if err != nil {
		logWarnf("client-cache: manifest fetch via %s: %v", exit.Addr, err)
		return
	}

	for slug, entry := range manifest {
		if !entry.Available {
			continue
		}
		c.fetchOne(slug, entry.Version, entry.Hash)
	}
}

func (c *clientCache) getManifest(client *http.Client, exitAddr string) (map[string]manifestEntry, error) {
	req, err := http.NewRequest(http.MethodGet, exitProxyURL(exitAddr, "/api/update/manifest"), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Node-Token", c.nodeToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var manifest map[string]manifestEntry
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&manifest); err != nil {
		return nil, err
	}
	return manifest, nil
}

// fetchOne fetches a single distributable's binary (identified by slug) and
// atomically installs it in cacheDir/<slug>/, unless already at remoteVersion.
func (c *clientCache) fetchOne(slug, remoteVersion, expectedHash string) {
	remoteVersion = strings.TrimSpace(remoteVersion)
	if remoteVersion == "" {
		return
	}

	slugDir := filepath.Join(c.cacheDir, slug)
	cached, _ := os.ReadFile(filepath.Join(slugDir, "version"))
	if strings.TrimSpace(string(cached)) == remoteVersion {
		logDebugf("client-cache(%s): already at version %s", slug, remoteVersion)
		return
	}

	exit, err := c.exits.PickRandom()
	if err != nil {
		logWarnf("client-cache(%s): no exits available: %v", slug, err)
		return
	}

	logInfof("client-cache(%s): fetching version %s via %s", slug, remoteVersion, exit.Addr)

	// A pre-refactor deploy of this node may have left a flat cache file
	// (e.g. "macos") sitting at exactly the path this slug's subdirectory
	// needs -- MkdirAll can't create a directory over an existing file.
	// Confirmed 2026-08-10: every control node had a stale flat "macos"
	// file from the old cache layout, silently blocking macos/ from ever
	// being created and leaving /client-macos-version 404 indefinitely.
	if fi, err := os.Lstat(slugDir); err == nil && !fi.IsDir() {
		if err := os.Remove(slugDir); err != nil {
			logWarnf("client-cache(%s): removing stale legacy cache file %s: %v", slug, slugDir, err)
			return
		}
		logInfof("client-cache(%s): removed stale legacy cache file %s", slug, slugDir)
	}

	if err := os.MkdirAll(slugDir, 0755); err != nil {
		logWarnf("client-cache(%s): mkdir: %v", slug, err)
		return
	}

	tmpPath := filepath.Join(slugDir, "bin.tmp")
	if err := c.downloadBinary(exit.Addr, "/api/update/dist/"+slug+"/bin", tmpPath, expectedHash); err != nil {
		logWarnf("client-cache(%s): download: %v", slug, err)
		os.Remove(tmpPath) //nolint:errcheck
		return
	}

	finalPath := filepath.Join(slugDir, "bin")
	if err := os.Rename(tmpPath, finalPath); err != nil {
		logWarnf("client-cache(%s): rename: %v", slug, err)
		os.Remove(tmpPath) //nolint:errcheck
		return
	}

	os.WriteFile(filepath.Join(slugDir, "sha256"), []byte(expectedHash+"\n"), 0644)   //nolint:errcheck
	os.WriteFile(filepath.Join(slugDir, "version"), []byte(remoteVersion+"\n"), 0644) //nolint:errcheck

	logInfof("client-cache(%s): version %s cached sha256=%.16s…", slug, remoteVersion, expectedHash)
}

// binaryDownloadTimeout is generous: client binaries are 30-100MB and travel
// control → exit → arbiter, so the brisk nodeProxyClient timeout (15s, tuned
// for small JSON probes) cuts the transfer off mid-stream every cycle — see
// the "context deadline exceeded ... while reading body" loop that left
// client-cache(android) stuck on a stale version while a fresh build sat on
// the arbiter.
const binaryDownloadTimeout = 5 * time.Minute

func binaryDownloadClient() *http.Client {
	return &http.Client{
		Timeout: binaryDownloadTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
}

func (c *clientCache) downloadBinary(exitAddr, path, dst, expectedHash string) error {
	req, err := http.NewRequest(http.MethodGet, exitProxyURL(exitAddr, path), nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Node-Token", c.nodeToken)
	resp, err := binaryDownloadClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		f.Close()
		return err
	}
	f.Close()

	actualHash := fmt.Sprintf("%x", h.Sum(nil))
	if actualHash != expectedHash {
		return fmt.Errorf("SHA-256 mismatch: expected %s got %s", expectedHash, actualHash)
	}
	return nil
}
