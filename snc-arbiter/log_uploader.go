// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"log"
	"os"
	"sync"
	"time"
)

const (
	logUploadInterval = 5 * time.Minute
	logRingSize       = 1 << 20 // 1 MB in-memory ring buffer
)

// ringBuffer is a fixed-capacity circular byte buffer.
// When full, new writes overwrite the oldest data. Thread-safe.
type ringBuffer struct {
	mu   sync.Mutex
	buf  []byte
	pos  int
	full bool
}

func newRingBuffer(size int) *ringBuffer {
	return &ringBuffer{buf: make([]byte, size)}
}

func (rb *ringBuffer) Write(p []byte) (int, error) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	n := len(p)
	cap := len(rb.buf)
	if n >= cap {
		copy(rb.buf, p[n-cap:])
		rb.pos = 0
		rb.full = true
		return n, nil
	}
	end := rb.pos + n
	if end <= cap {
		copy(rb.buf[rb.pos:], p)
	} else {
		first := cap - rb.pos
		copy(rb.buf[rb.pos:], p[:first])
		copy(rb.buf, p[first:])
		rb.full = true
	}
	rb.pos = end % cap
	return n, nil
}

// Snapshot returns a linearised copy of the buffer contents and resets it.
func (rb *ringBuffer) Snapshot() []byte {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	cap := len(rb.buf)
	var out []byte
	if !rb.full {
		out = make([]byte, rb.pos)
		copy(out, rb.buf[:rb.pos])
	} else {
		out = make([]byte, cap)
		copy(out, rb.buf[rb.pos:])
		copy(out[cap-rb.pos:], rb.buf[:rb.pos])
	}
	// Reset after snapshot so next upload only contains new data.
	rb.pos = 0
	rb.full = false
	return out
}

// arbiterRingBuf is the ring buffer tee'd into the arbiter's logger.
var arbiterRingBuf *ringBuffer

// initLoggingWithRing extends initLogging by also tee-ing all log output
// into arbiterRingBuf so startArbiterLogUploader can flush it to remote storage.
func initLoggingWithRing(path string) error {
	arbiterRingBuf = newRingBuffer(logRingSize)
	var w = arbiterRingBuf // start with ring only; file added below
	if path != "" {
		r, err := newRotator(path, logMaxBytes, logKeepFiles)
		if err != nil {
			return err
		}
		w2 := multiWriter(os.Stderr, r, arbiterRingBuf)
		logger.SetOutput(w2)
		log.SetOutput(w2)
	} else {
		logger.SetOutput(multiWriter(os.Stderr, w))
		log.SetOutput(multiWriter(os.Stderr, w))
	}
	return nil
}

// startArbiterLogUploader periodically flushes the ring buffer to remote storage.
// nodeID is derived from the hostname so each arbiter instance gets its own folder.
func startArbiterLogUploader(ls *nodeLogStore) {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "arbiter"
	}
	nodeID := sanitiseID(hostname)

	go func() {
		t := time.NewTicker(logUploadInterval)
		defer t.Stop()
		for range t.C {
			if arbiterRingBuf == nil {
				continue
			}
			snap := arbiterRingBuf.Snapshot()
			if len(snap) == 0 {
				continue
			}
			if err := ls.storeRaw("arbiter", nodeID, snap); err != nil {
				logWarnf("log-uploader: arbiter store: %v", err)
			} else {
				logDebugf("log-uploader: arbiter flushed %d bytes to remote", len(snap))
			}
		}
	}()
}

// sanitiseID replaces characters not allowed in node IDs with underscores.
func sanitiseID(s string) string {
	out := make([]byte, 0, len(s))
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' {
			out = append(out, byte(c))
		} else {
			out = append(out, '_')
		}
	}
	if len(out) < 4 {
		out = append(out, "arb"...)
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return string(out)
}

// multiWriter is a simple variadic io.MultiWriter helper.
func multiWriter(writers ...interface{ Write([]byte) (int, error) }) *multiWriterImpl {
	ww := make([]interface{ Write([]byte) (int, error) }, len(writers))
	copy(ww, writers)
	return &multiWriterImpl{ww}
}

type multiWriterImpl struct {
	ws []interface{ Write([]byte) (int, error) }
}

func (m *multiWriterImpl) Write(p []byte) (int, error) {
	for _, w := range m.ws {
		w.Write(p) //nolint:errcheck
	}
	return len(p), nil
}
