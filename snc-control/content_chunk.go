// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

// content_chunk.go — on-demand fallback cache for content-manifest chunks,
// served via the relay API at /p/v1/content/chunk. Only exercised when a
// client has no reachable P2P peer for a given chunk (snc/core/mirror.go
// tries hole-punched peers first) — this is not a full eager mirror, just a
// small LRU-ish cache so control doesn't refetch the same chunk from the
// arbiter on every client request.

import (
	"fmt"
	"io"
	"net/http"
	"sync"
)

// contentChunkCacheMax bounds memory use: at 16 KB/chunk this is ~4 MB.
const contentChunkCacheMax = 256

type chunkCacheEntry struct {
	data []byte
	seq  uint64
}

type contentChunkCache struct {
	exits     *ExitRegistry
	nodeToken string

	mu     sync.Mutex
	seq    uint64
	byHash map[string]*chunkCacheEntry
}

func newContentChunkCache(exits *ExitRegistry, nodeToken string) *contentChunkCache {
	return &contentChunkCache{exits: exits, nodeToken: nodeToken, byHash: make(map[string]*chunkCacheEntry)}
}

// Get returns chunk bytes for hash, fetching from the arbiter via the
// exit-proxy and caching on first miss.
func (c *contentChunkCache) Get(hash string) ([]byte, error) {
	c.mu.Lock()
	if e, ok := c.byHash[hash]; ok {
		c.mu.Unlock()
		return e.data, nil
	}
	c.mu.Unlock()

	data, err := c.fetch(hash)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.seq++
	c.byHash[hash] = &chunkCacheEntry{data: data, seq: c.seq}
	if len(c.byHash) > contentChunkCacheMax {
		c.evictOldestLocked()
	}
	c.mu.Unlock()
	return data, nil
}

// evictOldestLocked removes the least-recently-inserted entry. Caller must hold c.mu.
func (c *contentChunkCache) evictOldestLocked() {
	var oldestHash string
	oldestSeq := ^uint64(0)
	for h, e := range c.byHash {
		if e.seq < oldestSeq {
			oldestSeq = e.seq
			oldestHash = h
		}
	}
	if oldestHash != "" {
		delete(c.byHash, oldestHash)
	}
}

func (c *contentChunkCache) fetch(hash string) ([]byte, error) {
	exit, err := c.exits.PickRandom()
	if err != nil {
		return nil, fmt.Errorf("no exits available: %w", err)
	}
	url := exitProxyURL(exit.Addr, "/api/content-chunk?hash="+hash)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Node-Token", c.nodeToken)
	resp, err := nodeProxyClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch via %s: %w", exit.Addr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("exit %s returned %d", exit.Addr, resp.StatusCode)
	}
	// A chunk is contentChunkSize (16 KB, snc-arbiter/content_manifest.go) —
	// this ceiling is generous headroom, not a size assumption.
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read via %s: %w", exit.Addr, err)
	}
	logInfof("content-chunk: fetched hash=%.12s… (%d bytes) via exit=%s", hash, len(data), exit.Addr)
	return data, nil
}

// ── HTTP handler ─────────────────────────────────────────────────────────────

func (h *relayAPIHandler) serveContentChunk(w http.ResponseWriter, r *http.Request) {
	if h.contentChunks == nil {
		http.NotFound(w, r)
		return
	}
	hash := r.URL.Query().Get("hash")
	if !isHexSHA256(hash) {
		http.Error(w, `{"error":"bad hash"}`, http.StatusBadRequest)
		return
	}
	data, err := h.contentChunks.Get(hash)
	if err != nil {
		logWarnf("content-chunk: serve hash=%.12s…: %v", hash, err)
		http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(data) //nolint:errcheck
}

func isHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
