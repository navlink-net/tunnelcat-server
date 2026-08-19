// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

//go:build windows

package core

import (
	"archive/zip"
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
	"syscall"
	"time"
)

const (
	installerUpdateZip    = "shortnerdcat-installer-update.zip"
	installerUpdateBinary = "SncInstaller-pending.exe"

	clientUpdateZip    = "shortnerdcat-update.zip"
	clientUpdateBinary = "shortnerdcat-update.exe"
	clientOldBinary    = "shortnerdcat.exe.old"

	updatePort = "8090"
)

// Updater periodically checks for a newer client on any known control server.
// It has two update strategies, chosen fresh on every check via
// IsInstallerManaged:
//
//   - Not installer-managed (IsInstallerManaged is nil, or returns false --
//     a pre-installer install that manually unzipped shortnerdcat.exe
//     wherever the user liked): checks the *installer* package's version
//     (/client-windows-installer-version). If newer than core.Version,
//     downloads SncInstaller and hands off to it -- this process exits
//     without touching its own exe, and the installer (running as a
//     separate process once this one's file lock is released) finds and
//     removes this install as one of its "stale pre-installer copies",
//     then sets the "installed by installer" registry flag. A ONE-TIME
//     migration per machine.
//   - Installer-managed (flag present): checks the raw client's own version
//     (/client-windows-version). If newer, downloads it and self-replaces
//     in place (rename-swap + relaunch, the same mechanism every
//     pre-installer client always used) -- the installer is never touched
//     again. This is what keeps future client-only fixes from requiring an
//     installer redeploy just so already-migrated machines notice there's
//     an update (see the 2026-08-10 DPI-manifest incident: shipping a
//     client fix required bumping the installer's version too, purely to
//     get existing installs to look; that coupling is exactly what
//     IsInstallerManaged removes).
type Updater struct {
	// getControls returns the current list of control base URLs
	// (e.g. "https://1.2.3.4:443").  Called fresh on every check so that
	// newly discovered controls are used automatically.
	getControls func() []string

	// IsInstallerManaged reports whether this install was set up by
	// SncInstaller. Checked once per update cycle. nil is treated as false
	// (pre-installer behavior) -- the safe default: a client that mistakenly
	// took the direct-update path here would never get offered the one-time
	// migration to the installer at all.
	IsInstallerManaged func() bool

	// OnReady is called (from a goroutine) when a new binary has been
	// downloaded and verified.  The argument is the remote version string.
	// Set before calling Start.
	OnReady func(version string)
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
	// First check after 60 s to let discovery settle.
	time.Sleep(60 * time.Second)
	u.checkAndDownload()

	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		u.checkAndDownload()
	}
}

// updateHTTPClient fetches updates over HTTPS on port 8090. Cert verification is
// skipped because controls are addressed by IP, not hostname.
var updateHTTPClient = &http.Client{
	Timeout: 60 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	},
}

// updateBase extracts the host from a control base URL (e.g. "https://1.2.3.4:443")
// and returns the HTTPS update base URL on port 8090.
func updateBase(controlBase string) string {
	u, err := url.Parse(strings.TrimRight(controlBase, "/"))
	if err != nil {
		return ""
	}
	return "https://" + u.Hostname() + ":" + updatePort
}

func (u *Updater) checkAndDownload() {
	installerManaged := u.IsInstallerManaged != nil && u.IsInstallerManaged()

	// slug picks which OTA distributable this check/download targets --
	// see the two-strategy doc comment on Updater above.
	slug := "windows-installer"
	if installerManaged {
		slug = "windows"
	}

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
		resp, err := updateHTTPClient.Get(upBase + "/client-" + slug + "-version")
		if err != nil {
			Log.Printf("updater: version check %s: %v", upBase, err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		remoteVersion := strings.TrimSpace(string(body))
		if remoteVersion == "" {
			continue
		}
		// Reject server-side placeholders like "updates not configured".
		// Valid version strings are purely numeric (YYYYMMDDHHMMSS format).
		if !isNumericVersion(remoteVersion) {
			Log.Printf("updater: ignoring non-numeric version %q from %s", remoteVersion, upBase)
			continue
		}
		if remoteVersion <= Version {
			Log.Printf("updater: up to date (remote=%s current=%s slug=%s)", remoteVersion, Version, slug)
			return
		}
		Log.Printf("updater: new version %s available (current %s, slug=%s), downloading from %s",
			remoteVersion, Version, slug, upBase)

		// 2. Fetch expected SHA-256 of the ZIP.
		resp2, err := updateHTTPClient.Get(upBase + "/client-" + slug + ".sha256")
		if err != nil {
			Log.Printf("updater: sha256 fetch from %s: %v", upBase, err)
			continue
		}
		body2, _ := io.ReadAll(resp2.Body)
		resp2.Body.Close()
		fields := strings.Fields(string(body2))
		if len(fields) == 0 {
			Log.Printf("updater: empty sha256 from %s", upBase)
			continue
		}
		expectedHash := strings.ToLower(fields[0])

		exe, err := os.Executable()
		if err != nil {
			Log.Printf("updater: executable: %v", err)
			return
		}
		dir := filepath.Dir(exe)

		zipName, binName := installerUpdateZip, installerUpdateBinary
		if installerManaged {
			zipName, binName = clientUpdateZip, clientUpdateBinary
		}
		zipPath := filepath.Join(dir, zipName)
		updatePath := filepath.Join(dir, binName)

		// 3. Download ZIP and verify SHA-256; retry up to 3 times on failure.
		const maxAttempts = 3
		var actualHash string
		downloaded := false
		for attempt := 1; attempt <= maxAttempts; attempt++ {
			resp3, err := updateHTTPClient.Get(upBase + "/client-" + slug)
			if err != nil {
				Log.Printf("updater: download attempt %d/%d from %s: %v", attempt, maxAttempts, upBase, err)
				continue
			}
			f, err := os.OpenFile(zipPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if err != nil {
				resp3.Body.Close()
				Log.Printf("updater: create %s: %v", zipPath, err)
				return
			}
			h := sha256.New()
			_, copyErr := io.Copy(io.MultiWriter(f, h), resp3.Body)
			f.Close()
			resp3.Body.Close()
			if copyErr != nil {
				os.Remove(zipPath)
				Log.Printf("updater: download attempt %d/%d error from %s: %v", attempt, maxAttempts, upBase, copyErr)
				continue
			}
			actualHash = fmt.Sprintf("%x", h.Sum(nil))
			if actualHash != expectedHash {
				os.Remove(zipPath)
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

		// 4. Extract exe from ZIP.
		if err := extractExeFromZip(zipPath, updatePath); err != nil {
			os.Remove(zipPath)
			Log.Printf("updater: extract from zip (%s): %v", upBase, err)
			continue
		}
		os.Remove(zipPath)

		Log.Printf("updater: %s downloaded and verified (sha256=%.16s…), ready to install",
			remoteVersion, actualHash)
		if u.OnReady != nil {
			u.OnReady(remoteVersion)
		}
		return
	}
}

// extractExeFromZip finds the first .exe entry in the ZIP at zipPath and writes
// it to destPath.
func extractExeFromZip(zipPath, destPath string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()

	for _, f := range zr.File {
		if !strings.HasSuffix(strings.ToLower(f.Name), ".exe") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			rc.Close()
			return err
		}
		_, copyErr := io.Copy(out, rc)
		out.Close()
		rc.Close()
		return copyErr
	}
	return fmt.Errorf("no .exe entry found in archive")
}

// ApplyPendingUpdate checks for a downloaded update -- either an installer
// hand-off (pre-installer install) or a direct client self-replace
// (installer-managed install) -- and applies whichever is present. Must be
// called before the single-instance mutex is acquired so the freshly
// launched process (installer, or this same exe relaunched) is not blocked
// by it, but is ALSO called later, mid-session, whenever the user or the
// tray triggers an update manually (see tray.go's TriggerUpdateInstall) --
// this doc comment's "before the mutex" requirement only binds the
// startup call site.
//
// Returns true if a pending update file was actually found and an apply
// attempt was started (installer hand-off or client self-replace) -- false
// if neither expected filename existed on disk, i.e. there was genuinely
// nothing to apply. Before 2026-08-16 this returned nothing and logged
// nothing on the "found nothing" path either, so a manual trigger (the
// tray's "Update to X" item) that hit a stale ready-state -- the pending
// file already consumed by an earlier attempt, or never actually written --
// produced literally zero observable effect: no UI change, no log line,
// nothing. Callers that trigger this interactively should use the return
// value to tell the user (or at least log) that there was nothing to do,
// instead of leaving what looks like a broken button.
func ApplyPendingUpdate() bool {
	exe, err := os.Executable()
	if err != nil {
		Log.Printf("update: ApplyPendingUpdate: os.Executable: %v", err)
		return false
	}
	dir := filepath.Dir(exe)

	if installerPath := filepath.Join(dir, installerUpdateBinary); fileExists(installerPath) {
		Log.Printf("update: applying installer hand-off (%s)", installerPath)
		applyInstallerHandoff(installerPath)
		return true
	}
	if clientUpdatePath := filepath.Join(dir, clientUpdateBinary); fileExists(clientUpdatePath) {
		Log.Printf("update: applying client self-replace (%s)", clientUpdatePath)
		applyClientSelfReplace(exe, dir, clientUpdatePath)
		return true
	}
	Log.Printf("update: ApplyPendingUpdate called, no pending update file found in %s", dir)
	return false
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// applyInstallerHandoff launches the downloaded installer as a normal,
// visible, independent process (it has its own WPF UI with a banner/progress
// bar) and exits this process immediately. Unlike a client self-replace,
// this process does not touch its own executable at all — the installer
// (running as a separate process, once this one has exited and released its
// file lock) finds and removes this install itself, exactly as it does for
// any other pre-installer copy, then marks the machine installer-managed.
//
// The installer binary is moved to a temp path FIRST, before being launched.
// installerPath lives at filepath.Dir(exe) -- which is the exact same
// directory the installer extracts the new client INTO whenever the old
// install was already at the canonical path (i.e. any installer-managed
// machine re-triggering this path, or two hand-offs in a row). The installer
// only extracts what's in its zip (client + wintun.dll); it doesn't know
// this marker file exists and won't delete it. Left in place, the
// freshly-installed client's own first-run ApplyPendingUpdate call would
// find that same stale marker immediately and hand off to the installer
// again -- forever, at full speed, no network-timing gap to break it. Real
// incident, 2026-08-10: caught on a dev machine as "installer keeps
// launching in a loop", ~8.5MB re-downloaded every cycle. Moving the marker
// out first means ApplyPendingUpdate can never find it again after this
// point, no matter what the installer does or doesn't clean up.
func applyInstallerHandoff(installerPath string) {
	if UpdateSignalFunc != nil {
		UpdateSignalFunc()
	}

	runPath := installerPath
	tempPath := filepath.Join(os.TempDir(), fmt.Sprintf("%s-%d.exe", installerUpdateBinary, time.Now().UnixNano()))
	if err := os.Rename(installerPath, tempPath); err == nil {
		runPath = tempPath
	} else {
		fmt.Fprintf(os.Stderr, "update: move installer out of install dir (continuing anyway): %v\n", err)
	}

	cmd := exec.Command(runPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "update: launch installer: %v\n", err)
		return
	}

	os.Exit(0)
}

// applyClientSelfReplace performs an in-place update for installer-managed
// installs: swap the running exe for the freshly downloaded one and
// relaunch. Windows allows renaming a running executable because the file
// mapping is reference-counted by the kernel -- the same mechanism every
// pre-installer client used before the installer existed at all.
func applyClientSelfReplace(exe, dir, updatePath string) {
	oldPath := filepath.Join(dir, clientOldBinary)

	// Rename the running exe out of the way.
	if err := os.Rename(exe, oldPath); err != nil {
		fmt.Fprintf(os.Stderr, "update: rename current exe: %v\n", err)
		return
	}

	// Put the update in its place.
	if err := os.Rename(updatePath, exe); err != nil {
		fmt.Fprintf(os.Stderr, "update: rename update exe: %v\n", err)
		os.Rename(oldPath, exe) //nolint:errcheck
		return
	}

	// Signal the watchdog that a binary replacement is in progress so it
	// does not treat this os.Exit as an unclean crash and run cleanup.
	if UpdateSignalFunc != nil {
		UpdateSignalFunc()
	}

	// Relaunch the new binary (inheriting admin token — we are already elevated).
	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
		HideWindow:    true,
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "update: relaunch: %v\n", err)
		// Try to restore so the user can still run the old version.
		os.Rename(exe, updatePath) //nolint:errcheck
		os.Rename(oldPath, exe)    //nolint:errcheck
		return
	}

	os.Exit(0)
}

// isNumericVersion returns true when s consists entirely of ASCII digits and is
// at least 12 characters long (YYYYMMDDHHMMSS).  Rejects server-side
// placeholders like "updates not configured".
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

// UpdateCleanup removes leftover artifacts from a previous update attempt
// (e.g. a downloaded zip left behind by an interrupted extract, an installer
// that failed to launch, or a renamed-aside old exe from a self-replace).
// Call at startup after logging is initialised. Deliberately does NOT remove
// installerUpdateBinary/clientUpdateBinary here — that check happens
// earlier, in ApplyPendingUpdate, before this function ever runs.
func UpdateCleanup() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	dir := filepath.Dir(exe)
	for _, name := range []string{installerUpdateZip, clientUpdateZip, clientOldBinary} {
		if err := os.Remove(filepath.Join(dir, name)); err == nil {
			Log.Printf("updater: cleaned up %s", name)
		}
	}
}
