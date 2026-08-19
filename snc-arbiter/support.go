// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// checkSupportRateLimit enforces the shared cooldown/global cap for every
// support-form submission -- /support and /ratatosk/support both funnel
// through here (same limiter namespace) so an attacker can't double their
// effective rate by splitting requests across the two forms. email is
// self-reported and unverified on this anonymous form, so it alone is not a
// reliable key -- see TODO.md's arbiter API flood audit -- hence the IP check
// alongside it, matching the 5s-IP/60s-email pattern already used for
// forgot-password/resend-confirmation/blackbadger-inquiry.
func (h *handler) checkSupportRateLimit(r *http.Request, email string) bool {
	if !h.supportGlobal.Allow() {
		return false
	}
	if !h.supportLimiter.Allow("ip:"+clientIP(r), limitTier{Window: 5 * time.Second, Max: 1}) {
		return false
	}
	if email != "" && !h.supportLimiter.Allow("email:"+email, limitTier{Window: 6 * time.Hour, Max: 1}) {
		return false
	}
	return true
}

// supportPageData is the template data for the public (no login required)
// support/contact page, used as the App Store "Support URL".
type supportPageData struct {
	Lang  string
	Path  string
	Flash string
	OK    bool
}

// GET /support — public contact form, no login required (unlike /my/support,
// which is gated behind a session). Apple's App Store listing needs a Support
// URL reachable without an account.
func (h *handler) supportPage(w http.ResponseWriter, r *http.Request) {
	if setLangCookie(w, r) {
		return
	}
	lang := detectLang(r)
	h.renderPageR(w, r, "support.html", pageData{
		Lang: lang, Path: r.URL.Path,
		Data: supportPageData{},
	})
}

// POST /support
func (h *handler) supportSubmit(w http.ResponseWriter, r *http.Request) {
	lang := detectLang(r)
	if err := r.ParseForm(); err != nil {
		h.renderPageR(w, r, "support.html", pageData{
			Lang: lang, Path: r.URL.Path,
			Data: supportPageData{Flash: "Invalid form data"},
		})
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	subject := strings.TrimSpace(r.FormValue("subject"))
	message := strings.TrimSpace(r.FormValue("message"))
	if email == "" || subject == "" || message == "" {
		h.renderPageR(w, r, "support.html", pageData{
			Lang: lang, Path: r.URL.Path,
			Data: supportPageData{Flash: "Email, subject, and message are required"},
		})
		return
	}
	if !h.checkSupportRateLimit(r, email) {
		h.renderPageR(w, r, "support.html", pageData{
			Lang: lang, Path: r.URL.Path,
			Data: supportPageData{Flash: "Too many requests. Please wait before submitting again."},
		})
		return
	}

	fullSubject := fmt.Sprintf("[ShortNerdCat Support] %s", subject)
	htmlBody := fmt.Sprintf(
		"<p><strong>From:</strong> %s</p><p><strong>Subject:</strong> %s</p><hr><pre style=\"font-family:monospace;white-space:pre-wrap\">%s</pre>",
		email, subject, message)

	if err := h.auth.sendEmail("kk@partners.solutions", fullSubject, htmlBody); err != nil {
		logWarnf("support: sendEmail from=%s: %v", email, err)
		h.renderPageR(w, r, "support.html", pageData{
			Lang: lang, Path: r.URL.Path,
			Data: supportPageData{Flash: "Failed to send message. Please try again."},
		})
		return
	}

	logInfof("support: message sent from=%s subject=%s", email, subject)
	h.renderPageR(w, r, "support.html", pageData{
		Lang: lang, Path: r.URL.Path,
		Data: supportPageData{OK: true},
	})
}
