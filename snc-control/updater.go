// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// controlUpdater periodically checks for a newer snc-control binary on a
// random exit node and applies it atomically.
//
// Update flow:
//  1. GET /p/node/v1/update/version on a random exit
//  2. If remote version > current (lexicographic YYYYMMDD…) — continue
//  3. GET /p/node/v1/update/snc-control.sha256
//  4. GET /p/node/v1/update/snc-control → temp file
//  5. Verify SHA-256; abort on mismatch
//  6. Atomic rename temp → binary path
//  7. os.Exit(0) — systemd/supervisor restarts with the new binary
type controlUpdater struct {
	exits      *ExitRegistry
	version    string // current version (e.g. "20260415")
	binaryPath string // absolute path to own executable
}

func newControlUpdater(exits *ExitRegistry, version, binaryPath string) *controlUpdater {
	return &controlUpdater{exits: exits, version: version, binaryPath: binaryPath}
}

// Start launches the background update-checker goroutine.
func (u *controlUpdater) Start() {
	go u.loop()
}

func (u *controlUpdater) loop() {
	// First check after 60 s to let exits settle.
	time.Sleep(60 * time.Second)
	u.checkAndApply()

	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for range t.C {
		u.checkAndApply()
	}
}

func (u *controlUpdater) checkAndApply() {
	exit, err := u.exits.PickRandom()
	if err != nil {
		logDebugf("updater: no exits available, skipping check")
		return
	}

	base := exitBaseURL(exit.Addr)
	c := nodeProxyClient()

	// 1. Fetch remote version.
	remoteVersion, err := u.getString(c, base+"/p/node/v1/update/version")
	if err != nil {
		logWarnf("updater: version check from %s: %v", exit.Addr, err)
		return
	}
	remoteVersion = strings.TrimSpace(remoteVersion)
	if remoteVersion == "" || remoteVersion <= u.version {
		logDebugf("updater: up to date (remote=%s current=%s)", remoteVersion, u.version)
		return
	}
	logInfof("updater: new version %s available (current %s) from %s",
		remoteVersion, u.version, exit.Addr)

	// 2. Fetch expected SHA-256.
	hashStr, err := u.getString(c, base+"/p/node/v1/update/snc-control.sha256")
	if err != nil {
		logWarnf("updater: sha256 fetch: %v", err)
		return
	}
	fields := strings.Fields(hashStr)
	if len(fields) == 0 {
		logWarnf("updater: empty sha256 response")
		return
	}
	expectedHash := strings.ToLower(fields[0])

	// 3–4. Download binary to temp file.
	tmpPath := u.binaryPath + ".tmp"
	if err := u.downloadBinary(c, base+"/p/node/v1/update/snc-control", tmpPath, expectedHash); err != nil {
		logWarnf("updater: download: %v", err)
		os.Remove(tmpPath)
		return
	}

	// 5. Atomic rename into place (Linux allows overwriting a running binary).
	if err := os.Rename(tmpPath, u.binaryPath); err != nil {
		logWarnf("updater: rename %s → %s: %v", tmpPath, u.binaryPath, err)
		os.Remove(tmpPath)
		return
	}
	logInfof("updater: installed %s sha256=%.16s… — restarting", remoteVersion, expectedHash)

	// 6. Exit — systemd/supervisor restarts with the new binary.
	// Use exec to flush logs before exit.
	exec.Command("sync").Run() //nolint:errcheck
	os.Exit(0)
}

func (u *controlUpdater) getString(c *http.Client, url string) (string, error) {
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return string(b), err
}

func (u *controlUpdater) downloadBinary(c *http.Client, url, dst, expectedHash string) error {
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		f.Close()
		return err
	}
	f.Close()

	actual := fmt.Sprintf("%x", h.Sum(nil))
	if actual != expectedHash {
		return fmt.Errorf("SHA-256 mismatch: expected %s got %s", expectedHash, actual)
	}
	return nil
}

// exitBaseURL returns "https://host:port" for an exit addr.
func exitBaseURL(addr string) string {
	addr = strings.TrimPrefix(addr, "https://")
	addr = strings.TrimPrefix(addr, "http://")
	if _, _, err := strings.Cut(addr, ":"); !err {
		addr = addr + ":443"
	}
	return "https://" + addr
}
