// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

//go:build linux && !android

package core

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	updateBinary = "shortnerdcat-update"
	oldBinary    = "shortnerdcat.old"
	updatePort   = "8090"
)

// Updater periodically checks for a newer client binary on any known control
// server and downloads it. Protocol identical to macOS/Windows:
// GET /p/v1/update/version → compare → download → verify SHA-256 → call OnReady.
type Updater struct {
	getControls func() []string
	OnReady     func(version string)
}

// NewUpdater creates an Updater that queries controls via getControls.
func NewUpdater(getControls func() []string) *Updater {
	return &Updater{getControls: getControls}
}

// Start launches the background update-checker goroutine.
func (u *Updater) Start() {
	go u.loop()
}

func (u *Updater) loop() {
	time.Sleep(60 * time.Second)
	u.checkAndDownload()

	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		u.checkAndDownload()
	}
}

var updateHTTPClient = &http.Client{
	Timeout: 60 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	},
}

func updateBase(controlBase string) string {
	u, err := url.Parse(strings.TrimRight(controlBase, "/"))
	if err != nil {
		return ""
	}
	return "https://" + u.Hostname() + ":" + updatePort
}

func (u *Updater) checkAndDownload() {
	controls := u.getControls()
	if len(controls) == 0 {
		Log.Printf("updater: no controls available, skipping check")
		return
	}

	for _, base := range controls {
		upBase := updateBase(base)
		if upBase == "" {
			continue
		}

		resp, err := updateHTTPClient.Get(upBase + "/client-linux-version")
		if err != nil {
			Log.Printf("updater: version check %s: %v", upBase, err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		remoteVersion := strings.TrimSpace(string(body))
		if remoteVersion == "" || !isNumericVersion(remoteVersion) {
			continue
		}
		if remoteVersion <= Version {
			Log.Printf("updater: up to date (remote=%s current=%s)", remoteVersion, Version)
			return
		}
		Log.Printf("updater: new version %s available (current %s), downloading from %s",
			remoteVersion, Version, upBase)

		resp2, err := updateHTTPClient.Get(upBase + "/client-linux.sha256")
		if err != nil {
			Log.Printf("updater: sha256 fetch from %s: %v", upBase, err)
			continue
		}
		body2, _ := io.ReadAll(resp2.Body)
		resp2.Body.Close()
		fields := strings.Fields(string(body2))
		if len(fields) == 0 {
			continue
		}
		expectedHash := strings.ToLower(fields[0])

		exe, err := os.Executable()
		if err != nil {
			Log.Printf("updater: executable: %v", err)
			return
		}
		updatePath := filepath.Join(filepath.Dir(exe), updateBinary)

		const maxAttempts = 3
		var actualHash string
		downloaded := false
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			resp3, err := updateHTTPClient.Get(upBase + "/client-linux")
			if err != nil {
				Log.Printf("updater: download attempt %d/%d from %s: %v", attempt, maxAttempts, upBase, err)
				continue
			}
			f, err := os.OpenFile(updatePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err != nil {
				resp3.Body.Close()
				Log.Printf("updater: create %s: %v", updatePath, err)
				return
			}
			h := sha256.New()
			_, copyErr := io.Copy(io.MultiWriter(f, h), resp3.Body)
			f.Close()
			resp3.Body.Close()
			if copyErr != nil {
				os.Remove(updatePath) //nolint:errcheck
				Log.Printf("updater: download attempt %d/%d error from %s: %v", attempt, maxAttempts, upBase, copyErr)
				continue
			}
			actualHash = fmt.Sprintf("%x", h.Sum(nil))
			if actualHash != expectedHash {
				os.Remove(updatePath) //nolint:errcheck
				Log.Printf("updater: SHA-256 mismatch attempt %d/%d: expected %s got %s",
					attempt, maxAttempts, expectedHash, actualHash)
				continue
			}
			downloaded = true
			break
		}
		if !downloaded {
			Log.Printf("updater: all %d download attempts failed for %s, trying next control", maxAttempts, upBase)
			continue
		}

		Log.Printf("updater: %s downloaded and verified (sha256=%.16s…), ready to install",
			remoteVersion, actualHash)
		if u.OnReady != nil {
			u.OnReady(remoteVersion)
		}
		return
	}
}

// ApplyTorrentDownloadedDeb stages a torrent-downloaded update at the same
// updateBinary path ApplyPendingUpdate expects. Unlike Windows (ZIP) and the
// existing HTTP path here (a raw binary, /client-linux), the artifact
// available via the torrent swarm for the "linux" slug is the published
// .deb package (see deploy/torrent/sync-and-publish.sh's PRODUCTS entry --
// the same file the download page's Linux button serves), since no raw-
// binary torrent product exists. The binary is extracted from it at
// usr/bin/shortnerdcat (see snc/linux/build.sh's DEB_STAGING layout) via
// dpkg-deb -x, present on essentially any Debian-family system this .deb is
// meant to be installed on in the first place -- avoids pulling in a pure-Go
// xz decoder just to unpack data.tar.xz by hand.
//
// No separate SHA-256 check here, unlike the HTTP path -- the torrent
// engine already verified every piece against the magnet's btih before
// reporting the download complete.
func ApplyTorrentDownloadedDeb(debPath string) error {
	tmpDir, err := os.MkdirTemp("", "snc-torrent-update-*")
	if err != nil {
		return fmt.Errorf("mkdtemp: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	cmd := exec.Command("dpkg-deb", "-x", debPath, tmpDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("dpkg-deb -x: %w (output: %s)", err, string(out))
	}

	extracted := filepath.Join(tmpDir, "usr", "bin", "shortnerdcat")
	if _, err := os.Stat(extracted); err != nil {
		return fmt.Errorf("extracted binary not found at %s: %w", extracted, err)
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("executable: %w", err)
	}
	updatePath := filepath.Join(filepath.Dir(exe), updateBinary)

	data, err := os.ReadFile(extracted)
	if err != nil {
		return fmt.Errorf("read extracted binary: %w", err)
	}
	if err := os.WriteFile(updatePath, data, 0755); err != nil {
		return fmt.Errorf("write %s: %w", updatePath, err)
	}
	return nil
}

// isNumericVersion returns true when s is at least 12 ASCII digits (YYYYMMDDHHMMSS).
func isNumericVersion(s string) bool {
	if len(s) < 12 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// ApplyPendingUpdate checks for a downloaded update binary and, if found,
// replaces the current executable and relaunches.
func ApplyPendingUpdate() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	dir := filepath.Dir(exe)
	updatePath := filepath.Join(dir, updateBinary)

	if _, err := os.Stat(updatePath); os.IsNotExist(err) {
		return
	}

	oldPath := filepath.Join(dir, oldBinary)

	if err := os.Rename(exe, oldPath); err != nil {
		fmt.Fprintf(os.Stderr, "update: rename current exe: %v\n", err)
		return
	}
	if err := os.Rename(updatePath, exe); err != nil {
		fmt.Fprintf(os.Stderr, "update: rename update exe: %v\n", err)
		os.Rename(oldPath, exe) //nolint:errcheck
		return
	}
	os.Chmod(exe, 0755) //nolint:errcheck

	if UpdateSignalFunc != nil {
		UpdateSignalFunc()
	}

	cmd := exec.Command(exe, os.Args[1:]...)
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "update: relaunch: %v\n", err)
		os.Rename(exe, updatePath) //nolint:errcheck
		os.Rename(oldPath, exe)    //nolint:errcheck
		return
	}

	os.Exit(0)
}

// UpdateCleanup removes the stale .old binary left by a previous update.
func UpdateCleanup() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	old := filepath.Join(filepath.Dir(exe), oldBinary)
	if err := os.Remove(old); err == nil {
		Log.Printf("updater: removed stale %s", oldBinary)
	}
}
