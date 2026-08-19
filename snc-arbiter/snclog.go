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
	logMaxBytes  = 10 * 1024 * 1024 // rotate at 10 MB
	logKeepFiles = 5
)

var logger = log.New(os.Stderr, "", log.LstdFlags)

func initLogging(path string) error {
	var w io.Writer = os.Stderr
	if path != "" {
		r, err := newRotator(path, logMaxBytes, logKeepFiles)
		if err != nil {
			return fmt.Errorf("open log file: %w", err)
		}
		w = io.MultiWriter(os.Stderr, r)
	}
	logger.SetOutput(w)
	logger.SetFlags(log.LstdFlags)
	log.SetOutput(w)
	log.SetFlags(log.LstdFlags)
	return nil
}

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
		os.Rename(from, to)
	}
	os.Rename(r.path, r.path+".1")
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		r.f = os.Stderr
		return
	}
	r.f = f
	r.written = 0
}

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

func startupBanner(listen, authWith string) {
	logInfof("snc-arbiter starting  listen=%s  auth=%s  pid=%d  time=%s",
		listen, authWith, os.Getpid(), time.Now().Format(time.RFC3339))
}
