// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// clientBinaryTypes maps an upload binary_type to its canonical stored
// filename. Single source of truth for what's uploadable at all.
var clientBinaryTypes = map[string]string{
	"windows":           "shortnerdcat.zip",
	"windows-installer": "shortnerdcat-installer.zip",
	"android":           "shortnerdcat.apk",
	"linux":             "shortnerdcat.deb",
	"macos":             "shortnerdcat.dmg",
	"proekt-android":    "proekt.apk",
	"lisinder-android":  "lisinder.apk",
}

// otaSlugs is the subset of clientBinaryTypes that control nodes cache and
// relay to end-user VPN clients for OTA self-update (served at a control
// node's update port as /client-<slug>[-version|.sha256], sourced generically
// from /api/update/manifest — see apiUpdateManifest/apiUpdateDist below).
// proekt/lisinder are separate showcase apps distributed through the site's
// own download pages, not through this VPN-client OTA path.
//
// Adding a new type to this list is the ONLY change needed anywhere to start
// distributing it to clients — control nodes read the manifest at runtime
// and need no code changes or redeploy.
var otaSlugs = []string{"windows", "windows-installer", "android", "macos", "linux"}

type clientBinaryInfo struct {
	Hash    string
	Size    int64
	ModTime time.Time
	Version string
}

type downloadsPageData struct {
	Windows          clientBinaryInfo
	WindowsInstaller clientBinaryInfo
	Android          clientBinaryInfo
	Mac              clientBinaryInfo
	ProektAndroid    clientBinaryInfo
	LisinderAndroid  clientBinaryInfo
	Flash            string
}

func (h *handler) readClientBinaryInfo(filename string) clientBinaryInfo {
	if h.updateDir == "" {
		return clientBinaryInfo{}
	}
	fi, err := os.Stat(filepath.Join(h.updateDir, filename))
	if err != nil {
		return clientBinaryInfo{}
	}
	hash, _ := os.ReadFile(filepath.Join(h.updateDir, filename+".sha256"))
	ver, _ := os.ReadFile(filepath.Join(h.updateDir, filename+".version"))
	return clientBinaryInfo{
		Hash:    strings.TrimSpace(string(hash)),
		Size:    fi.Size(),
		ModTime: fi.ModTime(),
		Version: strings.TrimSpace(string(ver)),
	}
}

func (h *handler) adminDownloadsPage(w http.ResponseWriter, r *http.Request) {
	h.renderDownloadsPage(w, r, "")
}

func (h *handler) renderDownloadsPage(w http.ResponseWriter, r *http.Request, flash string) {
	u := h.currentUser(r)
	data := downloadsPageData{
		Windows:         h.readClientBinaryInfo("shortnerdcat.zip"),
		Android:         h.readClientBinaryInfo("shortnerdcat.apk"),
		Mac:             h.readClientBinaryInfo("shortnerdcat.dmg"),
		ProektAndroid:   h.readClientBinaryInfo("proekt.apk"),
		LisinderAndroid: h.readClientBinaryInfo("lisinder.apk"),
		Flash:           flash,
	}
	pd := pageData{User: u, Data: data, Flash: flash}
	h.renderPage(w, "admin_downloads.html", pd)
}

// checkUploadKey returns true if the request carries the configured upload key
// as a Bearer token. Falls through to true when no key is configured (route is
// already protected by requireAdmin for browser flows).
func (h *handler) checkUploadKey(r *http.Request) bool {
	if h.uploadKey == "" {
		return true
	}
	auth := r.Header.Get("Authorization")
	return auth == "Bearer "+h.uploadKey
}

// adminDownloadsUpload handles POST /admin/downloads/upload.
// Accepts either an authenticated admin session (browser) or
// Authorization: Bearer <upload-key> (deploy scripts).
// Form fields: binary_type ("windows" or "android"), version (optional), file.
//
// The upload is streamed directly to a temp file — the multipart body is drained
// as fast as the network allows without buffering 256 MB in RAM — then the final
// rename + hash write happen in a background goroutine so this handler returns
// immediately and never blocks auth or other API calls.
func (h *handler) adminDownloadsUpload(w http.ResponseWriter, r *http.Request) {
	// isReplica: this upload is itself a peer-replication push (see
	// replicateToPeers below) -- must not trigger a second round of
	// replication, or the two-node cluster would ping-pong the same file
	// back and forth forever.
	isReplica := r.Header.Get("X-No-Replicate") == "1"
	remote := r.RemoteAddr
	cl := r.Header.Get("Content-Length")
	te := r.Header.Get("Transfer-Encoding")
	ct := r.Header.Get("Content-Type")
	logInfof("upload: request from %s method=%s content-length=%s transfer-encoding=%q content-type=%.80s",
		remote, r.Method, cl, te, ct)

	if !h.checkUploadKey(r) {
		logWarnf("upload: auth rejected from %s authorization=%q", remote, r.Header.Get("Authorization"))
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	logInfof("upload: auth OK from %s", remote)

	if h.updateDir == "" {
		logWarnf("upload: update-dir not configured")
		h.renderDownloadsPage(w, r, "Update directory not configured (--update-dir flag missing).")
		return
	}

	logInfof("upload: parsing multipart form")
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		logWarnf("upload: ParseMultipartForm error: %v", err)
		h.renderDownloadsPage(w, r, "Request too large or malformed.")
		return
	}
	logInfof("upload: multipart parsed OK")

	binaryType := r.FormValue("binary_type")
	version := strings.TrimSpace(r.FormValue("version"))
	logInfof("upload: binary_type=%q version=%q", binaryType, version)

	canonicalName, ok := clientBinaryTypes[binaryType]
	if !ok {
		logWarnf("upload: unknown binary_type=%q", binaryType)
		h.renderDownloadsPage(w, r, fmt.Sprintf("Unknown binary type %q.", binaryType))
		return
	}

	f, fh, err := r.FormFile("file")
	if err != nil {
		logWarnf("upload: FormFile error: %v", err)
		h.renderDownloadsPage(w, r, "No file received.")
		return
	}
	defer f.Close()
	logInfof("upload: file part received filename=%q size=%d", fh.Filename, fh.Size)

	tmp, err := os.CreateTemp(h.updateDir, "upload-*.tmp")
	if err != nil {
		logWarnf("upload: create temp: %v", err)
		h.renderDownloadsPage(w, r, "Server error: could not create temp file.")
		return
	}
	tmpName := tmp.Name()
	logInfof("upload: streaming to temp file %s", tmpName)

	t0 := time.Now()
	h256 := sha256.New()
	size, err := io.Copy(io.MultiWriter(tmp, h256), f)
	tmp.Close()
	elapsed := time.Since(t0)

	if err != nil {
		logWarnf("upload: copy error after %dB in %v: %v", size, elapsed, err)
		os.Remove(tmpName)
		h.renderDownloadsPage(w, r, "Upload failed: could not write file.")
		return
	}
	if size == 0 {
		logWarnf("upload: received empty file")
		os.Remove(tmpName)
		h.renderDownloadsPage(w, r, "Uploaded file is empty.")
		return
	}

	hexHash := fmt.Sprintf("%x", h256.Sum(nil))
	logInfof("upload: received %dB in %v (%.1f KB/s) sha256=%.16s…",
		size, elapsed, float64(size)/elapsed.Seconds()/1024, hexHash)

	dst := filepath.Join(h.updateDir, canonicalName)
	go func() {
		defer os.Remove(tmpName)
		if err := os.Rename(tmpName, dst); err != nil {
			logWarnf("upload: rename to %s: %v", dst, err)
			return
		}
		logInfof("upload: renamed to %s", dst)
		if err := os.WriteFile(dst+".sha256", []byte(hexHash+"\n"), 0644); err != nil {
			logWarnf("upload: write sha256: %v", err)
		}
		if version != "" {
			if err := os.WriteFile(dst+".version", []byte(version+"\n"), 0644); err != nil {
				logWarnf("upload: write version: %v", err)
			}
		}
		logInfof("upload: installed %s size=%d sha256=%.16s… version=%q", canonicalName, size, hexHash, version)
		// Notify all live controls so they pull the new client binary immediately
		// instead of waiting for their 15-minute polling cycle.
		if h.notifier != nil {
			h.notifier.NotifyAll()
		}
		if !isReplica {
			h.replicateToPeers(binaryType, version, dst, canonicalName)
		}
	}()

	logInfof("upload: responding to %s", remote)
	if r.Header.Get("Authorization") != "" && !strings.Contains(r.Header.Get("Accept"), "text/html") {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"ok":true,"size":%d,"sha256":%q}`, size, hexHash)
	} else {
		http.Redirect(w, r, "/admin/downloads?uploaded=1", http.StatusSeeOther)
	}
}

// replicateToPeers pushes the just-installed client binary at diskPath to
// every configured fellow arbiter node (h.peerArbiters), so a binary
// uploaded to whichever node deploy.sh happened to hit doesn't only exist on
// that one node's disk -- see h.peerArbiters' doc comment for why this
// matters given the cluster's round-robin Load Balancer and lack of shared
// storage for updateDir. Best-effort: a peer that's down or slow just keeps
// serving its previous (stale but not missing) copy until the next upload;
// never blocks or fails the original upload response, which has already
// been sent by the time this runs (called from the same background
// goroutine that does the local install).
func (h *handler) replicateToPeers(binaryType, version, diskPath, canonicalName string) {
	for _, peer := range h.peerArbiters {
		if err := h.replicateOneUpload(peer, binaryType, version, diskPath); err != nil {
			logWarnf("upload: replicate %s to peer %s failed: %v", canonicalName, peer, err)
			continue
		}
		logInfof("upload: replicated %s to peer %s", canonicalName, peer)
	}
}

func (h *handler) replicateOneUpload(peerBaseURL, binaryType, version, diskPath string) error {
	f, err := os.Open(diskPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", diskPath, err)
	}
	defer f.Close()

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("binary_type", binaryType); err != nil {
		return err
	}
	if version != "" {
		if err := mw.WriteField("version", version); err != nil {
			return err
		}
	}
	fw, err := mw.CreateFormFile("file", filepath.Base(diskPath))
	if err != nil {
		return err
	}
	if _, err := io.Copy(fw, f); err != nil {
		return fmt.Errorf("copy file into form: %w", err)
	}
	if err := mw.Close(); err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(peerBaseURL, "/")+"/admin/downloads/upload", &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-No-Replicate", "1")
	if h.uploadKey != "" {
		req.Header.Set("Authorization", "Bearer "+h.uploadKey)
	}

	// InsecureSkipVerify: each arbiter node's TLS cert is issued for its own
	// bare IP (see docs/ARBITER_FAILOVER.md), not its peer's -- a strict
	// verify would reject every peer connection.
	client := &http.Client{
		Timeout: 5 * time.Minute,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("peer status %d: %s", resp.StatusCode, respBody)
	}
	return nil
}
