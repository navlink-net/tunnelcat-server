// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"tunnel_cat/binlog"
)

const (
	logMaxBytes   = 10 * 1024 * 1024  // 10 MB per file before rotation
	logTotalBytes = 200 * 1024 * 1024 // 200 MB total across all log files
	logKeepDays   = 7

	tunLogMaxBytes   = 2 * 1024 * 1024  // 2 MB per tun-traffic log file
	tunLogTotalBytes = 20 * 1024 * 1024 // 20 MB total across all tun-traffic log files
	tunLogKeepDays   = 3

	// mainLogPrefix names the main rotating log file set on disk (the one
	// "Share Logs" exports and LogUploader now reads from directly -- see
	// log_upload.go). Exported so LogUploader can list/read the same files
	// InitLogging writes, without either package needing to know the other's
	// internals beyond this shared naming convention.
	mainLogPrefix = "snc_"
)

// LogDir is the directory InitLogging opened its rotating log files in --
// set once, at InitLogging time. LogUploader reads directly from the files
// here instead of a separate in-memory buffer (see log_upload.go's history
// comment for why the old ring-buffer approach was replaced).
var LogDir string

// Version is set at build time via -ldflags "-X tunnel_cat/snc/core.Version=202604120936".
// Format: YYYYMMDDHHmm (12 digits), always -- there is no fallback value. A build
// that failed to inject this (e.g. a stale ldflags import path after a module
// rename) must not ship silently as some placeholder version; see the init()
// check below, which was added after exactly that happened: every build script
// still referenced the pre-repo-split path "shortnerdcat/snc/core.Version",
// which -X silently no-ops on when it doesn't match the actual compiled
// package path -- so every platform shipped internally reporting "dev" from
// 2026-08-04 (the repo split) until this was caught on 2026-08-06.
var Version = "dev"

// init fails the process immediately if Version was never overridden by the
// build's ldflags, or was overridden with something that isn't a real
// YYYYMMDDHHmm timestamp. Deliberately loud (stderr + exit, not a log line)
// so a broken build script fails to even start instead of silently shipping
// an unversioned binary -- silence is exactly how the "dev" leak went
// unnoticed for two days.
func init() {
	if !isValidVersionStamp(Version) {
		fmt.Fprintf(os.Stderr,
			"FATAL: snc/core.Version is %q, not a real YYYYMMDDHHmm build stamp -- "+
				"the build's -ldflags -X target doesn't match this package's actual "+
				"import path (tunnel_cat/snc/core.Version). Refusing to start.\n", Version)
		os.Exit(1)
	}
}

func isValidVersionStamp(v string) bool {
	if len(v) != 12 {
		return false
	}
	for _, c := range v {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// Log is the package-level logger. Initialised by InitLogging; falls back to
// stderr if InitLogging has not been called.
var Log = log.New(os.Stderr, "[snc] ", log.LstdFlags|log.Lmsgprefix)

// TunLog logs every TCP/UDP connection entering the TUN interface.
// Initialised by InitTunLogging; discards output until then.
var TunLog = log.New(io.Discard, "", log.LstdFlags)

// InitLogging opens (or creates) today's log file in dir, redirects the
// package logger there, and prunes old log files.
// Call once from main before anything else.
func InitLogging(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("log dir: %w", err)
	}

	pruneLogFiles(dir, mainLogPrefix, logMaxBytes, logTotalBytes, logKeepDays)

	rw, err := newRotatingWriter(dir, mainLogPrefix, logMaxBytes, logTotalBytes, logKeepDays, tagForLine)
	if err != nil {
		return err
	}
	LogDir = dir

	Log.SetOutput(rw)
	log.SetOutput(rw)
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)

	Log.Printf("=== ShortNerdCat %s started ===", Version)
	return nil
}

// InitTunLogging opens a separate rotating log file for TUN traffic.
// Call after InitLogging.
func InitTunLogging(dir string) error {
	rw, err := newRotatingWriter(dir, "snc_tun_", tunLogMaxBytes, tunLogTotalBytes, tunLogKeepDays,
		func([]byte) binlog.Tag { return binlog.TagTunnel })
	if err != nil {
		return err
	}
	TunLog.SetOutput(rw)
	return nil
}

// ── Rotating writer ───────────────────────────────────────────────────────────

// rotatingWriter binlog-frames every Write before it reaches disk -- clients
// must never store or transmit plain-text log content (2026-08-17 directive,
// following a real incident where a client's on-disk/uploaded logs turned
// out to still be plain text despite an earlier "convert clients to binary
// logging" effort that, in hindsight, only ever reached the old in-memory
// upload ring buffer, never the disk file "Share Logs" exports or either
// platform's separate lifecycle logger). Network-node services
// (snc-arbiter/snc-control/snc-exit) are explicitly NOT in scope -- they
// keep plain text, unchanged.
//
// Go's log package calls Write once per Printf with the whole formatted
// line, so one Write call becomes exactly one binlog record -- same
// granularity the old ring buffer used. tagFn classifies each line (see
// tagForLine for the main log; TunLog uses a fixed TagTunnel since its
// lines don't follow the "[snc] subsystem: ..." convention tagForLine
// parses).
type rotatingWriter struct {
	mu         sync.Mutex
	dir        string
	prefix     string
	maxBytes   int64
	totalBytes int64
	keepDays   int
	tagFn      func([]byte) binlog.Tag
	f          *os.File
	written    int64
}

func newRotatingWriter(dir, prefix string, maxBytes, totalBytes int64, keepDays int, tagFn func([]byte) binlog.Tag) (*rotatingWriter, error) {
	rw := &rotatingWriter{dir: dir, prefix: prefix, maxBytes: maxBytes, totalBytes: totalBytes, keepDays: keepDays, tagFn: tagFn}
	if err := rw.openNew(); err != nil {
		return nil, err
	}
	return rw, nil
}

func (rw *rotatingWriter) Write(p []byte) (int, error) {
	framed := binlog.AppendRecord(nil, rw.tagFn(p), p)

	rw.mu.Lock()

	if rw.written+int64(len(framed)) > rw.maxBytes {
		_ = rw.f.Close()
		if err := rw.openNewLocked(); err != nil {
			rw.mu.Unlock()
			// Rotation failed; old file is closed. Fall back to stderr so the
			// message is not lost, then return as if written (avoid log.Printf loops).
			// Deliberately the raw text here, not framed -- stderr is a last-resort
			// diagnostic path, never stored or transmitted, so the "no plain text"
			// rule doesn't apply to it.
			_, werr := os.Stderr.Write(p)
			return len(p), werr
		}
		// Prune in a goroutine to avoid deadlock (pruneLogFiles may call Log.Printf → Write).
		dir, prefix, maxB, total, days := rw.dir, rw.prefix, rw.maxBytes, rw.totalBytes, rw.keepDays
		go pruneLogFiles(dir, prefix, maxB, total, days)
	}

	_, err := rw.f.Write(framed)
	rw.written += int64(len(framed))
	rw.mu.Unlock()
	// Callers (Go's log package) only care that their own byte count was
	// accepted, not the framed on-wire length -- matches the old ring
	// buffer's Write contract (see its removed doc comment, same reasoning).
	return len(p), err
}

func (rw *rotatingWriter) openNew() error {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	return rw.openNewLocked()
}

func (rw *rotatingWriter) openNewLocked() error {
	name := filepath.Join(rw.dir,
		rw.prefix+time.Now().Format("2006-01-02_150405")+".log")
	// 0644, not 0600: on macOS this daemon runs as root while "Show Logs in
	// Finder" opens the folder in the logged-in user's own session (see
	// openLogsToUser/openLogsInFinder in snc/mac/cmd/shortnerdcat/main_darwin.go).
	// That helper only re-chmods files once, at daemon startup — any file
	// created afterward by a rotation (the common case on a long-running
	// client) was left root-only and unreadable to the user until the next
	// restart. Creating every file world-readable from the start makes the
	// startup chmod pass merely redundant instead of load-bearing.
	f, err := os.OpenFile(name, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("log rotate: %w", err)
	}
	if fi, err := f.Stat(); err == nil {
		rw.written = fi.Size()
	} else {
		rw.written = 0
	}
	rw.f = f
	return nil
}

var _ io.Writer = (*rotatingWriter)(nil)

// ── Old log pruning ───────────────────────────────────────────────────────────

func pruneLogFiles(dir, prefix string, _, totalBytes int64, keepDays int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().AddDate(0, 0, -keepDays)

	type logFile struct {
		path string
		size int64
		mod  time.Time
	}
	var logs []logFile
	for _, e := range entries {
		name := e.Name()
		// Require exact prefix: the character after the prefix must be a digit (start
		// of the timestamp), so "snc_" does not accidentally match "snc_tun_" files.
		if e.IsDir() || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".log") {
			continue
		}
		if rest := name[len(prefix):]; len(rest) == 0 || rest[0] < '0' || rest[0] > '9' {
			continue
		}
		fi, err := os.Stat(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		logs = append(logs, logFile{filepath.Join(dir, e.Name()), fi.Size(), fi.ModTime()})
	}
	sort.Slice(logs, func(i, j int) bool { return logs[i].path < logs[j].path })

	deleted := 0

	var keep []logFile
	for _, lf := range logs {
		if lf.mod.Before(cutoff) {
			if os.Remove(lf.path) == nil {
				deleted++
			}
		} else {
			keep = append(keep, lf)
		}
	}

	var total int64
	for _, lf := range keep {
		total += lf.size
	}
	for i := 0; i < len(keep) && total > totalBytes; i++ {
		if os.Remove(keep[i].path) == nil {
			total -= keep[i].size
			deleted++
		}
	}

	if deleted > 0 {
		Log.Printf("log: pruned %d %s*.log file(s) (keep_days=%d, total_limit=%dMB)", deleted, prefix, keepDays, totalBytes>>20)
	}
}
