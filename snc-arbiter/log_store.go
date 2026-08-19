// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	remoteLogBase    = "/mnt/remote/snc/logs"
	logMaxTotalBytes = int64(500) << 30 // 500 GB
	nodeLogMaxLen    = 50 << 20         // 50 MB per upload
	logQueueDepth    = 128              // buffered async work items before dropping
)

type logWork struct {
	nodeType string
	nodeID   string
	username string // "" = unknown/not applicable -- falls back to nodeID-keyed layout
	data     []byte
	raw      bool // true = plain text (compress first); false = already gzip
	evict    bool // true = eviction-only pass, no write
}

// nodeLogStore writes structured log bundles to the remote SSHFS mount.
//
// Layout: <base>/<type>/<username-or-nodeID>/YYYYMMDD_HHMMSS_<nodeID>.zip --
// 2026-08-15: reorganized from the original flat <type>/<nodeID>/*.log.gz
// layout specifically so a targeted investigation ("this user, this date
// range") can list/download just that one directory's files instead of
// having to pull from the full 500 GB store. A device upload is always
// self-contained (one user, one moment) -- there's no merging or batching
// here, each upload is still exactly one file, just filed under the
// person it came from instead of only the anonymous device id that sent
// it. When the caller can't resolve a username (control/exit/arbiter node
// types have no user concept at all; an unrecognized device_id for a
// client type) the nodeID itself is used as the directory key instead,
// same as before this reorg.
//
// Each stored file is now a real .zip (via archive/zip, Method: Store --
// the payload is already gzip-compressed by the client, so there's nothing
// to gain from asking zip to compress it again) with one entry holding the
// bytes exactly as received. Deliberately still doesn't decompress or
// otherwise look at upload content server-side -- see apiLogClientUpload's
// comment on why that was tried and reverted. Using zip as the container
// (rather than the old bare .log.gz) means the exact same tool
// (tools/decode_snc_log.py) and workflow ("download, unpack, study") apply
// uniformly whether a bundle came from the automatic per-upload path here
// or a manual Share-Logs export -- one format, not two.
//
// Enforces a 500 GB total size cap by evicting oldest files first, across
// both the new .zip suffix and pre-2026-08-15 .log.gz files still on disk
// (see evictIfNeeded) -- old files aren't migrated, just left in place and
// still counted/evicted like anything else.
//
// All SSHFS writes are serialised through a single background worker goroutine
// so slow mounts never block the HTTP request goroutines (and thus never block auth).
type nodeLogStore struct {
	dir    string
	workCh chan logWork
}

func newNodeLogStore(dir string) *nodeLogStore {
	ls := &nodeLogStore{
		dir:    dir,
		workCh: make(chan logWork, logQueueDepth),
	}
	for _, t := range []string{"android", "windows", "macos", "linux", "ios", "control", "exit", "arbiter"} {
		if err := sudoMkdirAll(filepath.Join(dir, t)); err != nil {
			logWarnf("log-store: mkdir %s/%s: %v", dir, t, err)
		}
	}
	go ls.worker()
	return ls
}

// worker is the single background goroutine that performs all SSHFS writes.
// Running one writer eliminates the need for a mutex and ensures slow mounts
// never starve HTTP handler goroutines.
func (ls *nodeLogStore) worker() {
	for w := range ls.workCh {
		if w.evict {
			ls.evictIfNeeded(0)
			continue
		}
		if w.raw {
			if err := ls.writeRaw(w.nodeType, w.nodeID, w.data); err != nil {
				logWarnf("log-store: storeRaw type=%s node=%.16s…: %v", w.nodeType, w.nodeID, err)
			}
		} else {
			if err := ls.write(w.nodeType, w.nodeID, w.username, w.data); err != nil {
				logWarnf("log-store: store type=%s node=%.16s… user=%s: %v", w.nodeType, w.nodeID, w.username, err)
			}
		}
	}
}

// sudoMkdirAll creates dir and parents. The SSHFS mount at remoteLogBase is
// owned by the arbiter process user, so a direct os.MkdirAll suffices.
// The name is kept for call-site compatibility.
func sudoMkdirAll(dir string) error {
	return os.MkdirAll(dir, 0755)
}

// sudoWriteFile writes data atomically to path. Uses a temp file in the same
// directory then renames, which is safe on SSHFS (FUSE supports rename).
func sudoWriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".log_tmp_")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName) //nolint:errcheck
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName) //nolint:errcheck
		return fmt.Errorf("close temp: %w", err)
	}
	return os.Rename(tmpName, path)
}

// Store enqueues a gzip-compressed log bundle for background writing.
// Returns immediately — never blocks the caller.
// nodeType must be one of: android, windows, control, exit, arbiter.
// username organizes the on-disk layout (see the type doc comment) -- pass
// "" when there's no user concept for this upload (control/exit/arbiter
// node logs, app-layer logs with no username field) or the caller couldn't
// resolve one; the nodeID-keyed layout is used in that case, same as
// before this reorg.
func (ls *nodeLogStore) Store(nodeType, nodeID, username string, data []byte) error {
	if !validNodeType(nodeType) {
		nodeType = "android"
	}
	if !validLogNodeID(nodeID) {
		return fmt.Errorf("invalid node_id %q", nodeID)
	}
	select {
	case ls.workCh <- logWork{nodeType: nodeType, nodeID: nodeID, username: username, data: data, raw: false}:
	default:
		logWarnf("log-store: queue full, dropping log from %s/%s", nodeType, nodeID)
	}
	return nil
}

// StoreRaw enqueues plain text for gzip-compression and background writing.
// Returns immediately — never blocks the caller.
func (ls *nodeLogStore) StoreRaw(nodeType, nodeID string, plain []byte) error {
	return ls.storeRaw(nodeType, nodeID, plain)
}

func (ls *nodeLogStore) storeRaw(nodeType, nodeID string, plain []byte) error {
	if !validNodeType(nodeType) {
		nodeType = "arbiter"
	}
	if !validLogNodeID(nodeID) {
		return fmt.Errorf("invalid node_id %q", nodeID)
	}
	select {
	case ls.workCh <- logWork{nodeType: nodeType, nodeID: nodeID, data: plain, raw: true}:
	default:
		logWarnf("log-store: queue full, dropping arbiter log from %s/%s", nodeType, nodeID)
	}
	return nil
}

// write is the synchronous write path called only from the worker goroutine.
// Directory key is username when known, else nodeID (see Store's doc
// comment); the filename always carries the full nodeID regardless, so
// Get can find a specific device's files either way (see findLatest).
func (ls *nodeLogStore) write(nodeType, nodeID, username string, data []byte) error {
	key := nodeID
	if username != "" {
		key = sanitizeDirKey(username)
	}
	nodeDir := filepath.Join(ls.dir, nodeType, key)
	if err := sudoMkdirAll(nodeDir); err != nil {
		return fmt.Errorf("mkdir %s: %w", nodeDir, err)
	}

	zipped, err := zipWrap(nodeID, data)
	if err != nil {
		return fmt.Errorf("zip: %w", err)
	}

	ls.evictIfNeeded(int64(len(zipped)))
	name := time.Now().UTC().Format("20060102_150405") + "_" + nodeID + ".zip"
	return sudoWriteFile(filepath.Join(nodeDir, name), zipped)
}

// zipWrap packages data (already gzip-compressed by the caller -- see
// LogUploader.upload / snc-control's uploadControl) as the sole entry of a
// new zip archive. Method: Store, not Deflate -- the payload is already
// compressed, so asking zip to deflate it again would spend CPU for
// essentially nothing while occasionally growing the result slightly.
// Deliberately doesn't decompress or inspect data's content -- see
// apiLogClientUpload's comment on why the arbiter stays out of that.
func zipWrap(nodeID string, data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateHeader(&zip.FileHeader{
		Name:     nodeID + ".log.gz",
		Method:   zip.Store,
		Modified: time.Now().UTC(),
	})
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// sanitizeDirKey turns a username (typically an email address) into a
// filesystem-safe directory component, folding anything outside
// validLogNodeID's charset to '-' -- mirrors sanitizeAppLogNodeID's
// approach in applog.go for the same reason (package-name dots there,
// email @ and . here).
func sanitizeDirKey(s string) string {
	clean := make([]rune, 0, len(s))
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			clean = append(clean, c)
		} else {
			clean = append(clean, '-')
		}
	}
	if len(clean) == 0 {
		return "unknown"
	}
	if len(clean) > 64 {
		clean = clean[:64]
	}
	return string(clean)
}

// writeRaw gzip-compresses plain text then calls write. Worker goroutine
// only. Unlike write above, this still uses the pre-2026-08-15 flat
// <type>/<nodeID>/*.log.gz layout with no zip wrapping -- left as-is
// because StoreRaw (its only caller-facing entry point) currently has zero
// callers anywhere in this codebase; not worth changing untested,
// unexercised code to match a layout nothing writes through it yet. If a
// caller shows up, bring this in line with write() at that point.
func (ls *nodeLogStore) writeRaw(nodeType, nodeID string, plain []byte) error {
	nodeDir := filepath.Join(ls.dir, nodeType, nodeID)
	if err := sudoMkdirAll(nodeDir); err != nil {
		return fmt.Errorf("mkdir %s: %w", nodeDir, err)
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(plain); err != nil {
		return err
	}
	if err := gw.Close(); err != nil {
		return err
	}

	ls.evictIfNeeded(int64(buf.Len()))
	name := time.Now().UTC().Format("20060102_150405") + ".log.gz"
	return sudoWriteFile(filepath.Join(nodeDir, name), buf.Bytes())
}

// StartCleanup launches a goroutine that enforces the size cap every hour.
func (ls *nodeLogStore) StartCleanup() {
	go func() {
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for range t.C {
			// Route through the worker so eviction doesn't run concurrently with writes.
			ls.workCh <- logWork{evict: true}
		}
	}()
}

// evictIfNeeded deletes oldest .zip/.log.gz files until total + incoming <=
// 500 GB. Matches both suffixes so pre-2026-08-15 .log.gz files left on disk
// by the old layout keep counting against and being evicted from the same
// cap as new .zip files -- there's no migration step, old files just age
// out normally alongside new ones. Must only be called from the worker
// goroutine.
func (ls *nodeLogStore) evictIfNeeded(incoming int64) {
	type entry struct {
		path    string
		modTime time.Time
		size    int64
	}
	var files []entry
	var total int64

	_ = filepath.WalkDir(ls.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".log.gz") && !strings.HasSuffix(d.Name(), ".zip") {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		files = append(files, entry{path: path, modTime: info.ModTime(), size: info.Size()})
		total += info.Size()
		return nil
	})

	if total+incoming <= logMaxTotalBytes {
		return
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].modTime.Before(files[j].modTime)
	})
	for _, f := range files {
		if total+incoming <= logMaxTotalBytes {
			break
		}
		os.Remove(f.path) //nolint:errcheck
		total -= f.size
		logInfof("log-store: evicted %s (%.0f KB, total %.1f GB freed)",
			f.path, float64(f.size)/1024, float64(logMaxTotalBytes-total)/float64(1<<30))
	}
}

// Get returns the most recent log file for nodeID, searching the whole
// store regardless of which directory key (username or nodeID) it landed
// under. Two layouts to match, since files from before 2026-08-15 are
// never migrated:
//   - legacy: <type>/<nodeID>/<timestamp>.log.gz -- the immediate parent
//     directory IS the nodeID.
//   - current: <type>/<username-or-nodeID>/<timestamp>_<nodeID>.zip -- the
//     nodeID is embedded in the filename instead (see write()).
//
// This is a full walk, not an indexed lookup -- acceptable here because Get
// is called for one specific, already-identified device (e.g. apiLogGet,
// itself only reachable by an authenticated control node), not as part of
// the "give me everything for a time range" investigation flow the
// username-keyed directories exist for -- that flow lists a known user's
// directory directly instead of calling this at all.
func (ls *nodeLogStore) Get(nodeID string) ([]byte, error) {
	if !validLogNodeID(nodeID) {
		return nil, fmt.Errorf("invalid node_id %q", nodeID)
	}
	var newest string
	var newestTime time.Time
	_ = filepath.WalkDir(ls.dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".log.gz") && !strings.HasSuffix(name, ".zip") {
			return nil
		}
		parentIsNodeID := filepath.Base(filepath.Dir(path)) == nodeID
		nameHasNodeID := strings.Contains(name, nodeID)
		if !parentIsNodeID && !nameHasNodeID {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.ModTime().After(newestTime) {
			newestTime = info.ModTime()
			newest = path
		}
		return nil
	})
	if newest == "" {
		return nil, fmt.Errorf("no logs found for node %q", nodeID)
	}
	return os.ReadFile(newest)
}

// IsMounted returns true if the log directory is accessible (storage is mounted).
func IsMounted(dir string) bool {
	_, err := os.Stat(dir)
	return err == nil
}

func validNodeType(t string) bool {
	switch t {
	case "android", "windows", "macos", "linux", "ios", "control", "exit", "arbiter":
		return true
	}
	return false
}

func validLogNodeID(id string) bool {
	if len(id) < 4 || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
