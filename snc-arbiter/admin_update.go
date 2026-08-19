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
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// updateBinaryInfo holds display info about a currently stored binary.
type updateBinaryInfo struct {
	Version string
	Hash    string
	Size    int64
	ModTime time.Time
}

// updatePageData is passed to admin_update.html.
type updatePageData struct {
	Control updateBinaryInfo
}

var validVersion = regexp.MustCompile(`^[0-9A-Za-z._-]+$`)

// adminUpdatePage renders GET /admin/update.
func (h *handler) adminUpdatePage(w http.ResponseWriter, r *http.Request) {
	h.renderUpdatePage(w, r, "")
}

func (h *handler) renderUpdatePage(w http.ResponseWriter, r *http.Request, flash string) {
	u := h.currentUser(r)
	data := updatePageData{
		Control: h.readBinaryInfo("snc-control", "version"),
	}
	pd := pageData{User: u, Data: data, Flash: flash}
	h.renderPage(w, "admin_update.html", pd)
}

// adminUpdateUpload handles POST /admin/update/upload.
// Form fields: binary_type (currently only "control"), version, file.
func (h *handler) adminUpdateUpload(w http.ResponseWriter, r *http.Request) {
	if h.updateDir == "" {
		h.renderUpdatePage(w, r, "Update directory not configured on this server (--update-dir flag missing).")
		return
	}

	if err := r.ParseMultipartForm(128 << 20); err != nil { // 128 MB max
		h.renderUpdatePage(w, r, "Request too large or malformed.")
		return
	}

	binaryType := r.FormValue("binary_type")
	version := strings.TrimSpace(r.FormValue("version"))

	if binaryType != "control" {
		h.renderUpdatePage(w, r, fmt.Sprintf("Unknown binary type %q.", binaryType))
		return
	}
	if !validVersion.MatchString(version) || version == "" {
		h.renderUpdatePage(w, r, "Invalid version string (allowed: letters, digits, '.', '-', '_').")
		return
	}

	// Determine destination filenames.
	binFile := "snc-control"
	hashFile := "snc-control.sha256"
	verFile := "version"

	f, _, err := r.FormFile("file")
	if err != nil {
		h.renderUpdatePage(w, r, "No file received.")
		return
	}
	defer f.Close()

	// Stream to a temp file while computing SHA-256.
	tmp, err := os.CreateTemp(h.updateDir, "upload-*.tmp")
	if err != nil {
		logWarnf("admin-update: create temp: %v", err)
		h.renderUpdatePage(w, r, "Server error: could not create temp file.")
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // cleaned up on error; on success the rename removes it from temp name

	h256 := sha256.New()
	size, err := io.Copy(io.MultiWriter(tmp, h256), f)
	tmp.Close()
	if err != nil {
		logWarnf("admin-update: write temp: %v", err)
		h.renderUpdatePage(w, r, "Upload failed: could not write file.")
		return
	}
	if size == 0 {
		h.renderUpdatePage(w, r, "Uploaded file is empty.")
		return
	}

	hexHash := fmt.Sprintf("%x", h256.Sum(nil))

	// Atomically put the binary in place.
	dst := filepath.Join(h.updateDir, binFile)
	if err := os.Rename(tmpName, dst); err != nil {
		logWarnf("admin-update: rename to %s: %v", dst, err)
		h.renderUpdatePage(w, r, "Server error: could not install binary.")
		return
	}

	// Write hash and version files.
	if err := os.WriteFile(filepath.Join(h.updateDir, hashFile), []byte(hexHash+"\n"), 0644); err != nil {
		logWarnf("admin-update: write hash: %v", err)
	}
	if err := os.WriteFile(filepath.Join(h.updateDir, verFile), []byte(version+"\n"), 0644); err != nil {
		logWarnf("admin-update: write version: %v", err)
	}

	logInfof("admin-update: uploaded %s version=%s size=%d sha256=%.16s…",
		binFile, version, size, hexHash)

	// Notify all live exits so they pull immediately.
	if h.notifier != nil {
		h.notifier.NotifyAll()
	}

	http.Redirect(w, r, "/admin/update?uploaded=1", http.StatusSeeOther)
}

// readBinaryInfo reads version/hash/size for a stored binary from updateDir.
func (h *handler) readBinaryInfo(binFile, verFile string) updateBinaryInfo {
	if h.updateDir == "" {
		return updateBinaryInfo{}
	}
	ver, _ := os.ReadFile(filepath.Join(h.updateDir, verFile))
	hash, _ := os.ReadFile(filepath.Join(h.updateDir, binFile+".sha256"))
	fi, err := os.Stat(filepath.Join(h.updateDir, binFile))
	if err != nil {
		return updateBinaryInfo{}
	}
	return updateBinaryInfo{
		Version: strings.TrimSpace(string(ver)),
		Hash:    strings.TrimSpace(string(hash)),
		Size:    fi.Size(),
		ModTime: fi.ModTime(),
	}
}
