// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"net/http"
	"sync"
	"time"
)

const logUploadInterval = 5 * time.Minute

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

// Snapshot returns a linearised copy and resets the buffer.
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
	rb.pos = 0
	rb.full = false
	return out
}

// startControlLogUploader launches a goroutine that gzip-compresses the ring buffer
// every 5 minutes and POSTs it to the arbiter via a random exit (the standard chain).
// nodeID is the first 16 characters of the node token.
func startControlLogUploader(exits *ExitRegistry, token string) {
	nodeID := token
	if len(nodeID) > 16 {
		nodeID = nodeID[:16]
	}

	proxyClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}

	go func() {
		t := time.NewTicker(logUploadInterval)
		defer t.Stop()
		for range t.C {
			uploadControl(exits, proxyClient, token, nodeID)
		}
	}()
}

func uploadControl(exits *ExitRegistry, client *http.Client, token, nodeID string) {
	if controlRingBuf == nil {
		return
	}
	snap := controlRingBuf.Snapshot()
	if len(snap) == 0 {
		return
	}

	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	if _, err := w.Write(snap); err != nil {
		logWarnf("log-uploader: gzip: %v", err)
		return
	}
	if err := w.Close(); err != nil {
		logWarnf("log-uploader: gzip close: %v", err)
		return
	}

	// Route through a random live exit — control never calls arbiter directly.
	exit, err := exits.PickRandom()
	if err != nil {
		logWarnf("log-uploader: no exit available: %v", err)
		return
	}
	uploadURL := exitProxyURL(exit.Addr, "/api/log/upload")

	req, err := http.NewRequest(http.MethodPost, uploadURL, &gz)
	if err != nil {
		logWarnf("log-uploader: build request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("X-Node-Token", token)
	req.Header.Set("X-Node-ID", nodeID)
	req.Header.Set("X-Node-Type", "control")

	resp, err := client.Do(req)
	if err != nil {
		logWarnf("log-uploader: POST via exit=%s failed: %v", exit.Addr, err)
		return
	}
	resp.Body.Close()
	logDebugf("log-uploader: sent %d bytes via exit=%s status=%d", gz.Len(), exit.Addr, resp.StatusCode)
}
