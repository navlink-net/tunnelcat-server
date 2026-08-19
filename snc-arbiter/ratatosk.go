// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ratatoskDownloader is the upstream host for Ratatosk client binaries.
// The arbiter fetches from this host and streams the file to the browser so
// the direct downloader URL is never exposed to clients.
const ratatoskDownloader = "https://downloader.multi-portal.org"

var ratatoskHTTPClient = &http.Client{Timeout: 5 * time.Minute}

func (h *handler) ratatoskPage(w http.ResponseWriter, r *http.Request) {
	if setLangCookie(w, r) {
		return
	}
	lang := detectLang(r)
	h.renderPageR(w, r, "ratatosk.html", pageData{User: h.currentUser(r), Lang: lang})
}

func (h *handler) ratatoskSupportPage(w http.ResponseWriter, r *http.Request) {
	if setLangCookie(w, r) {
		return
	}
	lang := detectLang(r)
	h.renderPageR(w, r, "ratatosk_support.html", pageData{
		Lang: lang, Path: r.URL.Path,
		Data: supportPageData{},
	})
}

func (h *handler) ratatoskSupportSubmit(w http.ResponseWriter, r *http.Request) {
	lang := detectLang(r)
	if err := r.ParseForm(); err != nil {
		h.renderPageR(w, r, "ratatosk_support.html", pageData{
			Lang: lang, Path: r.URL.Path,
			Data: supportPageData{Flash: "Invalid form data"},
		})
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	subject := strings.TrimSpace(r.FormValue("subject"))
	message := strings.TrimSpace(r.FormValue("message"))
	if email == "" || subject == "" || message == "" {
		h.renderPageR(w, r, "ratatosk_support.html", pageData{
			Lang: lang, Path: r.URL.Path,
			Data: supportPageData{Flash: "Email, subject, and message are required"},
		})
		return
	}
	if !h.checkSupportRateLimit(r, email) {
		h.renderPageR(w, r, "ratatosk_support.html", pageData{
			Lang: lang, Path: r.URL.Path,
			Data: supportPageData{Flash: "Too many requests. Please wait before submitting again."},
		})
		return
	}

	fullSubject := fmt.Sprintf("[Ratatosk Support] %s", subject)
	htmlBody := fmt.Sprintf(
		"<p><strong>From:</strong> %s</p><p><strong>Subject:</strong> %s</p><hr><pre style=\"font-family:monospace;white-space:pre-wrap\">%s</pre>",
		email, subject, message)

	if err := h.auth.sendEmail("kk@partners.solutions", fullSubject, htmlBody); err != nil {
		logWarnf("ratatosk-support: sendEmail from=%s: %v", email, err)
		h.renderPageR(w, r, "ratatosk_support.html", pageData{
			Lang: lang, Path: r.URL.Path,
			Data: supportPageData{Flash: "Failed to send message. Please try again."},
		})
		return
	}

	logInfof("ratatosk-support: message sent from=%s subject=%s", email, subject)
	h.renderPageR(w, r, "ratatosk_support.html", pageData{
		Lang: lang, Path: r.URL.Path,
		Data: supportPageData{OK: true},
	})
}

func (h *handler) ratatoskPrivacyPage(w http.ResponseWriter, r *http.Request) {
	if setLangCookie(w, r) {
		return
	}
	lang := detectLang(r)
	h.renderPageR(w, r, "ratatosk_privacy.html", pageData{User: h.currentUser(r), Lang: lang, Path: r.URL.Path})
}

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
