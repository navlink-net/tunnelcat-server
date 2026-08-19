// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

//go:build linux

package androidcore

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"net/http"
	"time"

	snc "tunnel_cat/snc/core"
)

const logUploadInterval = 5 * time.Minute

// logUploader periodically reads unsent content straight from the on-disk
// rotating log (see snc.LogDir/snc.InitLogging) and POSTs it to the arbiter
// (via navlink.net) over the device's own live tunnel dialer -- the same
// path snc.BananameterProber's arbiter report already uses, and the same
// shared snc.LogUploader the desktop platforms use (see
// tunnel_cat/snc/core/log_upload.go, which does the actual work; this is a
// thin per-platform wrapper).
//
// 2026-08-17: snc.LogUploader itself moved from a 256KB in-memory ring
// buffer (this file used to keep its own unused copy of that same
// ringBuffer type, dead code never actually wired to anything) to reading
// directly from the on-disk rotating log with a persisted cursor -- see
// that file's doc comment for why (a real user's automatic uploads were
// found to cover far less, and staler, ground than the same device's
// manually-exported "Share Logs" files for the identical time window).
//
// 2026-08-11: replaced the old relay-API-channel path (control -> a
// randomly picked exit -> arbiter). That path was hop-by-hop TLS only, so
// both control and the exit that happened to relay a given upload saw the
// full decompressed log content in plaintext -- found after a raw VK OAuth
// token turned up in cleartext in a real user's uploaded logs. Routing
// through the real tunnel dialer to navlink.net is indistinguishable from
// any other of the user's own tunneled HTTPS traffic (no separate uTLS/
// ChRelayAPI fingerprint to single out) and is genuinely end-to-end: the
// tunnel encrypts device->egress, TLS covers egress->navlink.net->arbiter,
// and neither control nor exit ever holds the plaintext.
//
// This only changes the periodic disk-log auto-upload. UploadLogBytes (the
// relay-API-channel function below) is unchanged and still used by the
// separate, explicitly user-triggered "app-log" IPC command -- a different
// trigger source not touched by this change.
type logUploader struct {
	inner *snc.LogUploader
}

func NewLogUploader(nodeID string) *logUploader {
	return &logUploader{inner: snc.NewLogUploader(nodeID, "android")}
}

// Start launches the background upload goroutine. Non-blocking. pickDialer
// matches snc.LogUploader.Start and snc.BananameterProber.Start exactly --
// see main_linux.go's bananameterProberOnce wiring for the pool.Pick()
// closure already available at the call site.
func (lu *logUploader) Start(pickDialer func() *snc.TunnelDialer) {
	lu.inner.Start(pickDialer)
}

func (lu *logUploader) Stop() { lu.inner.Stop() }

// UploadLogBytes gzip-compresses plain and POSTs it to the control's
// /p/v1/log/upload endpoint via the relay API channel (uTLS, ChRelayAPI
// session ID), bypassing the VPN TUN with dialControl. Shared by the
// periodic native ring-buffer upload (logUploader.upload) and one-off
// app-layer log uploads requested by Kotlin over the local IPC socket
// (see snc-core's "app-log" IPC command) — both must go through this same
// control-plane channel rather than any endpoint the client addresses
// directly, so the arbiter's address is never exposed to a client device.
//
// Why the relay API channel (not a plain HTTPS client):
// The relay API channel uses uTLS with a browser fingerprint and a ChRelayAPI
// session header. This matches the same transport fingerprint as all other
// control-plane traffic, so DPI cannot single out log uploads as a distinct
// traffic class and block them separately from the tunnel itself.
func UploadLogBytes(srvURL, nodeID string, auth *snc.Authenticator, nodeType string, plain []byte) error {
	if len(plain) == 0 {
		return nil
	}

	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	if _, err := w.Write(plain); err != nil {
		return fmt.Errorf("gzip write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("gzip close: %w", err)
	}

	// Use the relay API HTTP client: uTLS + ChRelayAPI session ID + dialControl-protected.
	// This is the same channel used by FetchMyIP and relay registration — it reaches
	// the control's relayAPIHandler without going through the VPN TUN.
	client := snc.NewRelayAPIH1Client()
	req, err := http.NewRequest(http.MethodPost, srvURL+"/p/v1/log/upload", &gz)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Session", auth.Token())
	req.Header.Set("X-Node-ID", nodeID)
	req.Header.Set("X-Node-Type", nodeType)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post: %w", err)
	}
	resp.Body.Close()
	snc.Log.Printf("log-upload: sent %d bytes compressed type=%s status=%d", gz.Len(), nodeType, resp.StatusCode)
	return nil
}
