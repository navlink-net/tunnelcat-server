// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"io"
	"net/http"
	"time"
)

// ratatoskDownloader is the upstream host for Ratatosk client binaries.
// The arbiter fetches from this host and streams the file to the browser so
// the direct downloader URL is never exposed to clients.
const ratatoskDownloader = "https://downloader.multi-portal.org"

var ratatoskHTTPClient = &http.Client{Timeout: 5 * time.Minute}

// ratatoskPage, ratatoskSupportPage/Submit, and ratatoskPrivacyPage
// (GET /ratatosk, GET+POST /ratatosk/support, GET /ratatosk/privacy) were
// removed 2026-08-25 -- migrated to static pages (Web/navlink/ratatosk/)
// + the shared POST /api/contact (see contact.go). Only the binary
// downloads below stay on the arbiter.

func (h *handler) ratatoskDownloadApk(w http.ResponseWriter, r *http.Request) {
	ratatoskProxy(w, r, ratatoskDownloader+"/ratatosk.apk", "ratatosk.apk",
		"application/vnd.android.package-archive")
}

func (h *handler) ratatoskDownloadZip(w http.ResponseWriter, r *http.Request) {
	ratatoskProxy(w, r, ratatoskDownloader+"/ratatosk.zip", "ratatosk.zip",
		"application/zip")
}

func (h *handler) ratatoskDownloadDmg(w http.ResponseWriter, r *http.Request) {
	ratatoskProxy(w, r, ratatoskDownloader+"/Ratatosk.dmg", "Ratatosk.dmg",
		"application/x-apple-diskimage")
}

// ratatoskProxy fetches url from the upstream downloader and streams it to w.
// Content-Disposition is set so the browser saves the file as filename.
func ratatoskProxy(w http.ResponseWriter, r *http.Request, url, filename, contentType string) {
	resp, err := ratatoskHTTPClient.Get(url) //nolint:noctx
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		http.NotFound(w, r)
		return
	}
	if resp.StatusCode != http.StatusOK {
		http.Error(w, "upstream error", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		w.Header().Set("Content-Length", cl)
	}
	w.WriteHeader(http.StatusOK)
	io.Copy(w, resp.Body) //nolint:errcheck
}
