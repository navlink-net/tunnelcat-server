// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

// content_manifest.go — control-side registry for the torrent-like content
// manifest. Mirrors the existing control-manifest poll pattern
// (relay_api.go: pollManifestOnce/manifestPollLoop) rather than exits.go's
// merge-registry, because this is also a single opaque signed blob pushed
// to the DHT on change, not a set of nodes to merge.
//
// Deliberately does NOT verify the Ed25519 signature here — same
// "dumb relay of signed bytes" role the DHT layer already plays for the
// control-manifest (dht/dht_node.go: SetManifest only compares timestamps).
// Real verification happens where the manifest is applied — the client's
// MirrorManager (snc/core/mirror.go) — as defense in depth, not here.

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const contentManifestPollInterval = 5 * time.Minute

type contentManifestRegistry struct {
	exits     *ExitRegistry
	nodeToken string
	cacheFile string

	mu  sync.RWMutex
	raw []byte
	ts  int64

	// OnNew is called (outside any lock) whenever refresh() finds a genuinely
	// newer manifest. Set once at startup, mirrors relayAPIHandler.onNewManifest.
	OnNew func(raw []byte, ts int64)
}

func newContentManifestRegistry(exits *ExitRegistry, nodeToken, cacheFile string) *contentManifestRegistry {
	return &contentManifestRegistry{exits: exits, nodeToken: nodeToken, cacheFile: cacheFile}
}

// LoadCached pre-populates the registry from the on-disk cache so the
// control has something to serve/gossip immediately after a restart,
// without waiting for the first successful refresh.
func (r *contentManifestRegistry) LoadCached() {
	if r.cacheFile == "" {
		return
	}
	data, err := os.ReadFile(r.cacheFile)
	if err != nil {
		logDebugf("content-manifest: no disk cache: %v", err)
		return
	}
	var hdr struct {
		TS int64 `json:"ts"`
	}
	if err := json.Unmarshal(data, &hdr); err != nil {
		logWarnf("content-manifest: disk cache corrupt, ignoring: %v", err)
		return
	}
	r.mu.Lock()
	r.raw = data
	r.ts = hdr.TS
	r.mu.Unlock()
	logInfof("content-manifest: loaded from disk cache ts=%d (%d bytes)", hdr.TS, len(data))
}

// Start fetches the content manifest immediately, then refreshes on interval.
func (r *contentManifestRegistry) Start(interval time.Duration) {
	go func() {
		r.refresh()
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			r.refresh()
		}
	}()
}

func (r *contentManifestRegistry) refresh() {
	exit, err := r.exits.PickRandom()
	if err != nil {
		logDebugf("content-manifest: no exits available for refresh: %v", err)
		return
	}
	url := exitProxyURL(exit.Addr, "/api/content-manifest")
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Set("X-Node-Token", r.nodeToken)
	resp, err := nodeProxyClient().Do(req)
	if err != nil {
		logWarnf("content-manifest: fetch via %s: %v", exit.Addr, err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		logDebugf("content-manifest: disabled on arbiter (404 via %s)", exit.Addr)
		return
	}
	if resp.StatusCode != http.StatusOK {
		logWarnf("content-manifest: exit %s returned %d", exit.Addr, resp.StatusCode)
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		logWarnf("content-manifest: read via %s: %v", exit.Addr, err)
		return
	}
	var hdr struct {
		TS int64 `json:"ts"`
	}
	if err := json.Unmarshal(data, &hdr); err != nil || hdr.TS == 0 {
		logWarnf("content-manifest: malformed payload from %s: %v", exit.Addr, err)
		return
	}

	r.mu.Lock()
	if hdr.TS <= r.ts {
		r.mu.Unlock()
		logDebugf("content-manifest: ts=%d from %s not newer than cached=%d — skip", hdr.TS, exit.Addr, r.ts)
		return
	}
	r.raw = data
	r.ts = hdr.TS
	onNew := r.OnNew
	r.mu.Unlock()

	r.persist(data)
	logInfof("content-manifest: refreshed via exit=%s ts=%d (%d bytes)", exit.Addr, hdr.TS, len(data))
	if onNew != nil {
		onNew(data, hdr.TS)
	}
}

func (r *contentManifestRegistry) persist(data []byte) {
	if r.cacheFile == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(r.cacheFile), 0700); err != nil {
		logWarnf("content-manifest: cache dir: %v", err)
		return
	}
	if err := os.WriteFile(r.cacheFile, data, 0600); err != nil {
		logWarnf("content-manifest: cache write: %v", err)
	}
}
