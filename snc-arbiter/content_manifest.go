// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

// content_manifest.go — torrent-like content mirroring: builds a signed
// manifest of an arbitrary, admin-designated directory (--content-dir) and
// serves individual chunks by hash. Consumed by control nodes via the
// generic exit-proxy (same path as /api/exits), which cache it and push it
// into their DHT node for gossip to clients. See docs/architecture.md and
// the "torrent-like content mirroring" plan for the full picture.
//
// Content population (what actually goes in --content-dir) is out of scope
// here — this file only mirrors whatever is already there.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// contentChunkSize is deliberately small (16 KB) so each chunk fits as a
// single UDP datagram over a hole-punched P2P connection without relying on
// IP fragmentation surviving arbitrary NAT/ISP paths.
const contentChunkSize = 16 * 1024

type chunkLocation struct {
	absPath string
	offset  int64
	size    int
}

// contentManifestCache avoids rehashing the whole content directory on every
// poll from every control node — recomputed only when the directory listing
// (paths/sizes/mtimes) actually changes.
type contentManifestCache struct {
	mu         sync.Mutex
	raw        []byte
	dirState   string
	chunkIndex map[string]chunkLocation // hex chunk hash -> location on disk
}

// ensureFresh rebuilds the cache if the content directory has changed since
// the last build. No-op (fast path: one stat-walk) when nothing changed.
func (c *contentManifestCache) ensureFresh(dir string, signer *signingKey) error {
	state, err := dirFingerprint(dir)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.raw != nil && state == c.dirState {
		return nil
	}

	files, index, err := buildContentFileList(dir)
	if err != nil {
		return err
	}
	raw, err := signer.signContentManifest(files)
	if err != nil {
		return err
	}
	c.raw = raw
	c.dirState = state
	c.chunkIndex = index
	logInfof("content-manifest: rebuilt (%d files, %d chunks)", len(files), len(index))
	return nil
}

// dirFingerprint returns a cheap change-detection string for dir: every
// regular file's relative path, size, and mtime, sorted for stability.
func dirFingerprint(dir string) (string, error) {
	var lines []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		lines = append(lines, fmt.Sprintf("%s:%d:%d", filepath.ToSlash(rel), info.Size(), info.ModTime().UnixNano()))
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n"), nil
}

// buildContentFileList walks dir and chunks+hashes every regular file.
func buildContentFileList(dir string) ([]ContentFileEntry, map[string]chunkLocation, error) {
	var files []ContentFileEntry
	index := make(map[string]chunkLocation)

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		relSlash := filepath.ToSlash(rel)

		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}
		defer f.Close()

		var hashes []string
		var offset int64
		buf := make([]byte, contentChunkSize)
		for {
			n, rerr := io.ReadFull(f, buf)
			if n > 0 {
				sum := sha256.Sum256(buf[:n])
				h := hex.EncodeToString(sum[:])
				hashes = append(hashes, h)
				index[h] = chunkLocation{absPath: path, offset: offset, size: n}
				offset += int64(n)
			}
			if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
				break
			}
			if rerr != nil {
				return fmt.Errorf("read %s: %w", path, rerr)
			}
		}

		files = append(files, ContentFileEntry{
			Path:        relSlash,
			Size:        offset,
			ChunkSize:   contentChunkSize,
			ChunkHashes: hashes,
		})
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, index, nil
}

// ── HTTP handlers ────────────────────────────────────────────────────────────

// authRelayNode validates X-Node-Token and returns the calling control/exit
// node, or writes an error response itself and returns nil.
func (h *handler) authRelayNode(w http.ResponseWriter, r *http.Request) *Node {
	token := r.Header.Get("X-Node-Token")
	if token == "" {
		jsonErr(w, "X-Node-Token required", http.StatusUnauthorized)
		return nil
	}
	node, err := h.db.nodeByToken(token)
	if err != nil || node == nil || (node.Type != "control" && node.Type != "exit") {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return nil
	}
	return node
}

// apiContentManifest returns the signed content-manifest. Control and exit
// nodes (identified by their token) may call this — mirrors apiExits.
func (h *handler) apiContentManifest(w http.ResponseWriter, r *http.Request) {
	node := h.authRelayNode(w, r)
	if node == nil {
		return
	}
	if h.contentDir == "" {
		jsonErr(w, "content mirroring disabled", http.StatusNotFound)
		return
	}
	if err := h.contentCache.ensureFresh(h.contentDir, h.signer); err != nil {
		logWarnf("content-manifest: build failed: %v", err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	logInfof("content-manifest: serving token=%.8s… node=%s", r.Header.Get("X-Node-Token"), node.Addr)
	w.Header().Set("Content-Type", "application/json")
	h.contentCache.mu.Lock()
	raw := h.contentCache.raw
	h.contentCache.mu.Unlock()
	w.Write(raw) //nolint:errcheck
}

// apiContentChunk streams a single chunk identified by its hex SHA-256 hash,
// seeking directly into the source file — no separate chunk-store on disk.
func (h *handler) apiContentChunk(w http.ResponseWriter, r *http.Request) {
	node := h.authRelayNode(w, r)
	if node == nil {
		return
	}
	if h.contentDir == "" {
		jsonErr(w, "content mirroring disabled", http.StatusNotFound)
		return
	}
	if err := h.contentCache.ensureFresh(h.contentDir, h.signer); err != nil {
		logWarnf("content-chunk: build failed: %v", err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}

	hash := strings.ToLower(r.URL.Query().Get("hash"))
	h.contentCache.mu.Lock()
	loc, ok := h.contentCache.chunkIndex[hash]
	h.contentCache.mu.Unlock()
	if !ok {
		jsonErr(w, "chunk not found", http.StatusNotFound)
		return
	}

	f, err := os.Open(loc.absPath)
	if err != nil {
		logWarnf("content-chunk: open %s: %v", loc.absPath, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	if _, err := f.Seek(loc.offset, io.SeekStart); err != nil {
		logWarnf("content-chunk: seek %s: %v", loc.absPath, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	if _, err := io.CopyN(w, f, int64(loc.size)); err != nil {
		logWarnf("content-chunk: copy %s: %v", loc.absPath, err)
	}
}
