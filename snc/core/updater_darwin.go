// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

//go:build darwin && !ios

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
	// updateDMG is what /client-macos actually serves: the same notarized
	// .dmg that mac/deploy.sh uploads for the browser download page
	// (admin_downloads.go stores exactly one artifact per binary_type —
	// "macos" -> "shortnerdcat.dmg" — reused for both routes). It is NOT a
	// raw Mach-O binary, unlike the Windows/Linux updaters' payloads, so it
	// must be mounted and have the real executable extracted before it can
	// be exec'd. See extractBinaryFromDMG / ApplyPendingUpdate below.
	updateDMG  = "shortnerdcat-update.dmg"
	oldBinary  = "shortnerdcat.old"
	updatePort = "8090"
)

// Updater periodically checks for a newer client binary on any known control
// server and downloads it. Protocol is identical to the Windows version:
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

// updateHTTPClient skips cert verification — controls are addressed by IP.
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

		// 1. Fetch remote version.
		resp, err := updateHTTPClient.Get(upBase + "/client-macos-version")
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

		// 2. Fetch expected SHA-256.
		resp2, err := updateHTTPClient.Get(upBase + "/client-macos.sha256")
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

		// 3. Download binary and verify SHA-256; retry up to 3 times on failure.
		exe, err := os.Executable()
		if err != nil {
			Log.Printf("updater: executable: %v", err)
			return
		}
		updatePath := filepath.Join(filepath.Dir(exe), updateDMG)

		const maxAttempts = 3
		var actualHash string
		downloaded := false
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			resp3, err := updateHTTPClient.Get(upBase + "/client-macos")
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
				Log.Printf("updater: SHA-256 mismatch attempt %d/%d from %s: expected %s got %s",
					attempt, maxAttempts, upBase, expectedHash, actualHash)
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

// extractedBinary is the staging name for the real Mach-O pulled out of the
// downloaded .dmg, held in the same directory as the running exe so the
// final swap-in below is an os.Rename (same filesystem) rather than a copy.
const extractedBinary = "shortnerdcat-update-extracted"

// extractBinaryFromDMG mounts dmgPath read-only, locates the single .app
// bundle it contains, and copies out Contents/MacOS/<binaryName> to destPath
// (same directory as the caller's exe). Always detaches the mount before
// returning, success or failure, so a bad update never leaves a volume
// mounted indefinitely.
//
// Why this exists: mac/deploy.sh only ever builds and uploads one artifact —
// the notarized ShortNerdCat.dmg (see build.sh's `hdiutil convert ...
// -format UDZO`) — and admin_downloads.go stores it under a single canonical
// name ("shortnerdcat.dmg") that both the human-facing /download page *and*
// the machine-facing /api/update/client-macos OTA route serve verbatim. A
// .dmg is an Apple disk-image container, not a Mach-O executable — you
// cannot os.Rename it into an exe's place and exec.Command it, the same way
// you can't do that with a .zip or .tar.gz. Earlier code did exactly that
// (renamed the raw downloaded .dmg over the running binary), which meant
// every OTA relaunch attempt on macOS failed with "exec format error",
// silently rolled back via the oldPath swap below, and logged only to
// stderr (core.Log isn't initialised yet on the boot-time call path) — so a
// client could sit on a months-old build forever, re-downloading the same
// 60+MB .dmg every 30 minutes, with nothing in snc_*.log ever hinting why.
// The Windows updater doesn't have this problem because it deals with a
// .zip of the *installer* and explicitly unzips the .exe out
// (extractExeFromZip in updater.go) before ever trying to run it; the mac
// client needs the equivalent step, just via `hdiutil attach` instead of
// archive/zip since a DMG isn't a zip-shaped container.
func extractBinaryFromDMG(dmgPath, binaryName, destPath string) error {
	out, err := exec.Command("hdiutil", "attach",
		"-nobrowse", "-readonly", "-noautoopen", dmgPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("hdiutil attach: %v: %s", err, strings.TrimSpace(string(out)))
	}

	// hdiutil attach's plain-text output is one line per device/partition
	// entry, tab-separated; the mounted volume's entry is the one whose last
	// field is a /Volumes/... path. Scanning for "/Volumes/" rather than
	// parsing fixed columns is what mac/build.sh itself does (see its own
	// `awk '$3 ~ /^\/Volumes\//'` DMG-mounting step) and is robust to the
	// column count varying by disk-image internal layout.
	var mountPoint string
	for _, line := range strings.Split(string(out), "\n") {
		if idx := strings.Index(line, "/Volumes/"); idx >= 0 {
			mountPoint = strings.TrimSpace(line[idx:])
		}
	}
	if mountPoint == "" {
		return fmt.Errorf("hdiutil attach: no /Volumes/ mount point found in output: %s", out)
	}
	// Always detach, even on the error paths below — a failed extract must
	// not leave the update .dmg mounted (it'll just get re-downloaded and
	// re-attached next cycle otherwise, piling up mounted volumes).
	defer func() {
		if derr := exec.Command("hdiutil", "detach", mountPoint, "-quiet").Run(); derr != nil {
			fmt.Fprintf(os.Stderr, "update: hdiutil detach %s: %v\n", mountPoint, derr)
		}
	}()

	apps, err := filepath.Glob(filepath.Join(mountPoint, "*.app"))
	if err != nil || len(apps) == 0 {
		return fmt.Errorf("no .app bundle found in mounted %s", dmgPath)
	}
	srcBinary := filepath.Join(apps[0], "Contents", "MacOS", binaryName)

	src, err := os.Open(srcBinary)
	if err != nil {
		return fmt.Errorf("open %s: %v", srcBinary, err)
	}
	defer src.Close()

	dst, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("create %s: %v", destPath, err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		os.Remove(destPath) //nolint:errcheck
		return fmt.Errorf("copy %s: %v", srcBinary, err)
	}
	return dst.Close()
}

// ApplyTorrentDownloadedDMG stages a torrent-downloaded DMG at the path
// ApplyPendingUpdate expects (updateDMG in the same directory as the running
// exe). The torrent engine has already verified every piece against the
// magnet's btih, so no separate SHA-256 check is needed — same guarantee as
// ApplyTorrentDownloadedZip on Windows. ApplyPendingUpdate (called at the
// next launch) will mount the DMG via hdiutil and extract the real binary.
func ApplyTorrentDownloadedDMG(dmgPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("executable: %w", err)
	}
	dest := filepath.Join(filepath.Dir(exe), updateDMG)
	in, err := os.Open(dmgPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", dmgPath, err)
	}
	defer in.Close()
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("create %s: %w", dest, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dest) //nolint:errcheck
		return fmt.Errorf("copy: %w", err)
	}
	return out.Close()
}

// ApplyPendingUpdate checks for a downloaded update .dmg and, if found,
// extracts the real executable from it and replaces the current one,
// relaunching into it. Must be called before the single-instance lockfile is
// acquired.
func ApplyPendingUpdate() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	dir := filepath.Dir(exe)
	dmgPath := filepath.Join(dir, updateDMG)

	if _, err := os.Stat(dmgPath); os.IsNotExist(err) {
		return
	}

	// Pull the real Mach-O out of the disk image before touching anything
	// that's actually running — see extractBinaryFromDMG's doc comment for
	// why this step can't be skipped. extractedPath lands in the same
	// directory as exe so the swap-in below is a same-filesystem rename, not
	// a cross-volume copy.
	extractedPath := filepath.Join(dir, extractedBinary)
	if err := extractBinaryFromDMG(dmgPath, filepath.Base(exe), extractedPath); err != nil {
		fmt.Fprintf(os.Stderr, "update: extract from dmg: %v\n", err)
		// Drop the bad .dmg rather than retrying it forever unattended —
		// checkAndDownload() will simply fetch it fresh next cycle if the
		// remote version is still newer than ours.
		os.Remove(dmgPath) //nolint:errcheck
		return
	}

	oldPath := filepath.Join(dir, oldBinary)

	// Renaming a running binary on macOS is safe — the kernel keeps the inode
	// open by file descriptor, not by path.
	if err := os.Rename(exe, oldPath); err != nil {
		fmt.Fprintf(os.Stderr, "update: rename current exe: %v\n", err)
		os.Remove(extractedPath) //nolint:errcheck
		return
	}
	if err := os.Rename(extractedPath, exe); err != nil {
		fmt.Fprintf(os.Stderr, "update: rename extracted exe: %v\n", err)
		os.Rename(oldPath, exe) //nolint:errcheck
		return
	}
	os.Chmod(exe, 0755) //nolint:errcheck
	os.Remove(dmgPath)  //nolint:errcheck

	if UpdateSignalFunc != nil {
		UpdateSignalFunc()
	}

	cmd := exec.Command(exe, os.Args[1:]...)
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "update: relaunch: %v\n", err)
		os.Rename(exe, extractedPath) //nolint:errcheck
		os.Rename(oldPath, exe)       //nolint:errcheck
		return
	}

	os.Exit(0)
}

// UpdateCleanup removes leftovers from a previous update attempt: the stale
// .old binary, and a staging extractedBinary left behind if the process was
// killed between extractBinaryFromDMG succeeding and the final rename into
// exe's place (that window is brief, but not zero).
func UpdateCleanup() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	dir := filepath.Dir(exe)
	old := filepath.Join(dir, oldBinary)
	if err := os.Remove(old); err == nil {
		Log.Printf("updater: removed stale %s", oldBinary)
	}
	stale := filepath.Join(dir, extractedBinary)
	if err := os.Remove(stale); err == nil {
		Log.Printf("updater: removed stale %s", extractedBinary)
	}
}
