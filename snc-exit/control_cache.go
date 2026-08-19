// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// controlCache fetches the snc-control binary from the arbiter and stores it
// locally so control nodes can download updates via /p/node/v1/update/*.
//
// Files written to cacheDir:
//
//	version           — version string (e.g. "20260415")
//	snc-control       — binary (Linux amd64)
//	snc-control.sha256 — hex SHA-256 of the binary
type controlCache struct {
	arbiterURL string
	nodeToken  string
	cacheDir   string // empty = caching disabled

	mu          sync.Mutex
	lastRefresh time.Time

	stop chan struct{}
}

func newControlCache(arbiterURL, nodeToken, cacheDir string) *controlCache {
	return &controlCache{
		arbiterURL: strings.TrimRight(arbiterURL, "/"),
		nodeToken:  nodeToken,
		cacheDir:   cacheDir,
		stop:       make(chan struct{}),
	}
}

// Start launches the background refresh loop.
func (c *controlCache) Start() {
	if c.cacheDir == "" {
		logInfof("control-cache: cacheDir empty — update serving disabled")
		return
	}
	go c.loop()
}

func (c *controlCache) loop() {
	// Initial fetch after 30 s to let the exit settle.
	select {
	case <-time.After(30 * time.Second):
	case <-c.stop:
		return
	}
	c.fetch()

	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			c.fetch()
		case <-c.stop:
			return
		}
	}
}

// Refresh triggers an immediate fetch regardless of the last refresh time.
// Safe to call concurrently; called from /p/node/v1/refresh.
func (c *controlCache) Refresh() {
	if c.cacheDir == "" {
		return
	}
	go c.fetch()
}

// Stop shuts down the background loop.
func (c *controlCache) Stop() {
	close(c.stop)
}

func (c *controlCache) fetch() {
	c.mu.Lock()
	defer c.mu.Unlock()

	client := &http.Client{Timeout: 60 * time.Second}

	// 1. Fetch version string.
	remoteVersion, err := c.getString(client, "/api/update/control-version")
	if err != nil {
		logWarnf("control-cache: version fetch: %v", err)
		return
	}
	remoteVersion = strings.TrimSpace(remoteVersion)
	if remoteVersion == "" {
		logWarnf("control-cache: empty version from arbiter")
		return
	}

	// Check if already up to date.
	cached, _ := os.ReadFile(filepath.Join(c.cacheDir, "version"))
	if strings.TrimSpace(string(cached)) == remoteVersion {
		logDebugf("control-cache: already at version %s", remoteVersion)
		c.lastRefresh = time.Now()
		return
	}

	logInfof("control-cache: fetching snc-control version %s from arbiter", remoteVersion)

	// 2. Fetch expected SHA-256.
	hashStr, err := c.getString(client, "/api/update/control.sha256")
	if err != nil {
		logWarnf("control-cache: sha256 fetch: %v", err)
		return
	}
	fields := strings.Fields(hashStr)
	if len(fields) == 0 {
		logWarnf("control-cache: empty sha256 response")
		return
	}
	expectedHash := strings.ToLower(fields[0])

	// 3. Download binary to a temp file.
	tmpPath := filepath.Join(c.cacheDir, "snc-control.tmp")
	if err := c.downloadBinary(client, "/api/update/control", tmpPath, expectedHash); err != nil {
		logWarnf("control-cache: download: %v", err)
		os.Remove(tmpPath)
		return
	}

	// 4. Atomic rename into place.
	finalPath := filepath.Join(c.cacheDir, "snc-control")
	if err := os.Rename(tmpPath, finalPath); err != nil {
		logWarnf("control-cache: rename: %v", err)
		os.Remove(tmpPath)
		return
	}

	// 5. Write hash and version files.
	os.WriteFile(filepath.Join(c.cacheDir, "snc-control.sha256"), []byte(expectedHash+"\n"), 0644) //nolint:errcheck
	os.WriteFile(filepath.Join(c.cacheDir, "version"), []byte(remoteVersion+"\n"), 0644)           //nolint:errcheck

	c.lastRefresh = time.Now()
	logInfof("control-cache: snc-control %s cached ok sha256=%.16s…", remoteVersion, expectedHash)
}

func (c *controlCache) getString(client *http.Client, path string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, c.arbiterURL+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Node-Token", c.nodeToken)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return string(b), err
}

func (c *controlCache) downloadBinary(client *http.Client, path, dst, expectedHash string) error {
	req, err := http.NewRequest(http.MethodGet, c.arbiterURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Node-Token", c.nodeToken)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
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
