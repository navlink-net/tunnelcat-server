// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

const (
	logMaxBytes  = 10 * 1024 * 1024
	logKeepFiles = 5
	logRingSize  = 1 << 20 // 1 MB ring buffer for upload
)

var logger = log.New(os.Stderr, "", log.LstdFlags)

// controlRingBuf is tee'd into the logger; flushed every 5 min by startControlLogUploader.
var controlRingBuf *ringBuffer

func initLogging(path string) error {
	controlRingBuf = newRingBuffer(logRingSize)
	var sink io.Writer
	if path != "" {
		r, err := newRotator(path, logMaxBytes, logKeepFiles)
		if err != nil {
			return fmt.Errorf("open log file: %w", err)
		}
		sink = io.MultiWriter(os.Stderr, r, controlRingBuf)
	} else {
		sink = io.MultiWriter(os.Stderr, controlRingBuf)
	}
	logger.SetOutput(sink)
	logger.SetFlags(log.LstdFlags)
	log.SetOutput(sink)
	log.SetFlags(log.LstdFlags)
	return nil
}

// ── size-based log rotator ────────────────────────────────────────────────────

type rotator struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	keep     int
	f        *os.File
	written  int64
}

func newRotator(path string, maxBytes int64, keep int) (*rotator, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	info, _ := f.Stat()
	written := int64(0)
	if info != nil {
		written = info.Size()
	}
	return &rotator{path: path, maxBytes: maxBytes, keep: keep, f: f, written: written}, nil
}

func (r *rotator) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n, err := r.f.Write(p)
	r.written += int64(n)
	if r.written >= r.maxBytes {
		r.rotate()
	}
	return n, err
}

func (r *rotator) rotate() {
	r.f.Close()
	for i := r.keep - 1; i >= 1; i-- {
		from := fmt.Sprintf("%s.%d", r.path, i)
		to := fmt.Sprintf("%s.%d", r.path, i+1)
		os.Rename(from, to) //nolint:errcheck
	}
	os.Rename(r.path, r.path+".1") //nolint:errcheck
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		r.f = os.Stderr
		return
	}
	r.f = f
	r.written = 0
}

// ── convenience wrappers ──────────────────────────────────────────────────────

func logDebugf(format string, args ...interface{}) {
	logger.Printf("DEBUG "+format, args...)
}

func logInfof(format string, args ...interface{}) {
	logger.Printf("INFO  "+format, args...)
}

func logWarnf(format string, args ...interface{}) {
	logger.Printf("WARN  "+format, args...)
}

func logErrorf(format string, args ...interface{}) {
	logger.Printf("ERROR "+format, args...)
}

// startupBanner deliberately does not take or log an arbiter address --
// control must never hold the arbiter's address for any purpose, including
// printing it (see the 2026-08-10 audit in bananameter_probe.go).
func startupBanner(listen string) {
	logInfof("snc-control starting  listen=%s  pid=%d  time=%s",
		listen, os.Getpid(), time.Now().Format(time.RFC3339))
}
