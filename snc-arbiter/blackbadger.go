// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"time"
)

const (
	bbInquiryEmailCooldown = 60 * time.Second // min interval between inquiries from the same email
	bbInquiryIPCooldown    = 5 * time.Second  // min interval between submissions from the same IP
)

type bbInquiry struct {
	Name          string `json:"name"`
	Email         string `json:"email"`
	Company       string `json:"company"`
	CaptchaToken  string `json:"captcha_token"`
	CaptchaAnswer string `json:"captcha_answer"`
}

func (h *handler) blackbadgerPage(w http.ResponseWriter, r *http.Request) {
	if setLangCookie(w, r) {
		return
	}
	lang := detectLang(r)
	q, tok := h.newCaptcha()
	h.renderPage(w, "blackbadger.html", pageData{
		User: h.currentUser(r), Lang: lang, Path: r.URL.Path,
		CaptchaQ: q, CaptchaToken: tok,
	})
}

func (h *handler) blackbadgerInquiry(w http.ResponseWriter, r *http.Request) {
	var req bbInquiry
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	if !h.verifyCaptcha(req.CaptchaToken, req.CaptchaAnswer) {
		http.Error(w, `{"error":"captcha"}`, http.StatusBadRequest)
		return
	}
	if !h.bbInquiryLimiter.Allow("email:"+req.Email, bbInquiryEmailCooldown) ||
		!h.bbInquiryLimiter.Allow("ip:"+clientIP(r), bbInquiryIPCooldown) {
		http.Error(w, `{"error":"rate_limited"}`, http.StatusTooManyRequests)
		return
	}

	subject := "BlackBadger inquiry from " + req.Name
	body := fmt.Sprintf(`<p><b>Name:</b> %s</p><p><b>Email:</b> %s</p><p><b>Company:</b> %s</p>`,
		html.EscapeString(req.Name), html.EscapeString(req.Email), html.EscapeString(req.Company))

	// Best-effort — don't fail the user if email fails.
	if err := h.auth.sendEmail("kk@partners.solutions", subject, body); err != nil {
		logWarnf("blackbadger-inquiry: send email: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}
