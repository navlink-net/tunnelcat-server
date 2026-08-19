// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// genEmailToken generates a 32-byte hex token for email confirmation / password reset.
func genEmailToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// siteBase returns the scheme+host prefix for building absolute URLs in emails.
func (h *handler) siteBase(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
		scheme = "http"
	}
	host := r.Host
	if fwd := r.Header.Get("X-Forwarded-Host"); fwd != "" {
		host = fwd
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}

// ── Email confirmation ────────────────────────────────────────────────────────

// apiConfirmEmail handles POST /api/account/confirm-email {token}. Consumes
// the token from the confirmation email and, on success, issues the user's
// free key immediately (this is how the static-site signup flow completes
// registration -- see issueFreeKey's "email_confirm" source).
func (h *handler) apiConfirmEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		jsonErr(w, "invalid request", http.StatusBadRequest)
		return
	}
	username, err := h.db.consumeEmailToken(req.Token, "confirm")
	if err != nil || username == "" {
		jsonErr(w, "expired", http.StatusBadRequest)
		return
	}
	if err := h.db.setUserConfirmed(username); err != nil {
		logWarnf("apiConfirmEmail: setUserConfirmed %s: %v", username, err)
	}
	if _, err := h.db.getOrCreateUser(username); err != nil {
		logWarnf("apiConfirmEmail: getOrCreateUser %s: %v", username, err)
	}

	issued, err := h.issueFreeKey(r, username, "email_confirm")
	if err != nil {
		logWarnf("apiConfirmEmail: issueFreeKey %s: %v", username, err)
		jsonErr(w, "key generation failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"key": issued.KeyStr, "key_id": issued.KeyID, "client_id": issued.ClientID,
	})
}

const (
	resendConfirmEmailCooldown = 60 * time.Second // min interval between resends to the same address
	resendConfirmIPCooldown    = 5 * time.Second  // min interval between submissions from the same IP
)

// apiResendConfirmation handles POST /api/account/resend-confirmation
// {email, captcha_token, captcha_answer}.
func (h *handler) apiResendConfirmation(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email         string `json:"email"`
		CaptchaToken  string `json:"captcha_token"`
		CaptchaAnswer string `json:"captcha_answer"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request", http.StatusBadRequest)
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	lang := detectLang(r)

	if !h.verifyCaptcha(req.CaptchaToken, req.CaptchaAnswer) {
		jsonErr(w, "captcha", http.StatusBadRequest)
		return
	}
	if email == "" {
		jsonErr(w, "email required", http.StatusBadRequest)
		return
	}
	if !h.resendConfirmLimiter.Allow("email:"+email, resendConfirmEmailCooldown) ||
		!h.resendConfirmLimiter.Allow("ip:"+clientIP(r), resendConfirmIPCooldown) {
		jsonErr(w, "rate_limited", http.StatusTooManyRequests)
		return
	}

	confirmed, _ := h.db.isUserConfirmed(email)
	if confirmed {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`)) //nolint:errcheck
		return
	}
	h.db.deleteEmailTokensByUser(email, "confirm")
	if err := h.sendConfirmEmail(r, email, lang); err != nil {
		jsonErr(w, "send_failed", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`)) //nolint:errcheck
}

// sendConfirmEmail generates a confirmation token and emails it. Returns an
// error when the email genuinely could not be sent (bad token/token-store
// failure, or the mail server itself rejected it, e.g. an unknown mailbox) —
// callers must surface this to the user instead of claiming success, since a
// silently-failed confirmation email leaves the registration permanently
// stuck with no way for the user to know why (see the 2026-08-16 incident).
func (h *handler) sendConfirmEmail(r *http.Request, email, lang string) error {
	token, err := genEmailToken()
	if err != nil {
		logWarnf("sendConfirmEmail: genEmailToken: %v", err)
		return fmt.Errorf("internal error")
	}
	if err := h.db.createEmailToken(token, email, "confirm", time.Now().Add(24*time.Hour)); err != nil {
		logWarnf("sendConfirmEmail: createEmailToken %s: %v", email, err)
		return fmt.Errorf("internal error")
	}
	confirmURL := h.siteBase(r) + "/confirm-email.html?token=" + token
	subject := tr(lang, "Confirm your email — NavLink", "Подтвердите email — NavLink")
	if err := h.auth.sendEmail(email, subject, confirmEmailHTML(lang, confirmURL)); err != nil {
		logWarnf("sendConfirmEmail: sendEmail %s: %v", email, err)
		return fmt.Errorf("could not send confirmation email — please check the address is correct")
	}
	return nil
}

// ── Forgot / reset password ──────────────────────────────────────────────────

const (
	forgotPwEmailCooldown = 60 * time.Second // min interval between reset emails to the same address
	forgotPwIPCooldown    = 5 * time.Second  // min interval between submissions from the same IP
)

// apiForgotPassword handles POST /api/account/forgot-password
// {email, captcha_token, captcha_answer}. Always replies {"ok":true} once
// past the captcha/rate-limit gate, whether or not the address has an
// account, to avoid leaking which emails are registered.
func (h *handler) apiForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email         string `json:"email"`
		CaptchaToken  string `json:"captcha_token"`
		CaptchaAnswer string `json:"captcha_answer"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request", http.StatusBadRequest)
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	lang := detectLang(r)

	ok := func() {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`)) //nolint:errcheck
	}

	if !h.verifyCaptcha(req.CaptchaToken, req.CaptchaAnswer) {
		jsonErr(w, "captcha", http.StatusBadRequest)
		return
	}
	if email == "" || !strings.Contains(email, "@") {
		ok()
		return
	}
	if !h.forgotPwLimiter.Allow("email:"+email, forgotPwEmailCooldown) ||
		!h.forgotPwLimiter.Allow("ip:"+clientIP(r), forgotPwIPCooldown) {
		ok()
		return
	}

	h.db.deleteEmailTokensByUser(email, "reset")
	token, err := genEmailToken()
	if err == nil {
		if err := h.db.createEmailToken(token, email, "reset", time.Now().Add(time.Hour)); err == nil {
			resetURL := h.siteBase(r) + "/reset-password.html?token=" + token
			subject := tr(lang, "Reset your password — NavLink", "Сброс пароля — NavLink")
			if err := h.auth.sendEmail(email, subject, resetEmailHTML(lang, resetURL)); err != nil {
				logWarnf("forgotPassword: sendEmail %s: %v", email, err)
			}
		}
	}
	ok()
}

// apiResetPassword handles POST /api/account/reset-password {token, password}.
func (h *handler) apiResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request", http.StatusBadRequest)
		return
	}
	if req.Token == "" {
		jsonErr(w, "token required", http.StatusBadRequest)
		return
	}
	if len(req.Password) < 8 {
		jsonErr(w, "Password must be at least 8 characters.", http.StatusBadRequest)
		return
	}

	username, err := h.db.consumeEmailToken(req.Token, "reset")
	if err != nil || username == "" {
		jsonErr(w, "This reset link has expired or already been used. Please request a new one.", http.StatusBadRequest)
		return
	}
	if err := h.auth.forceChangePassword(username, req.Password); err != nil {
		logWarnf("apiResetPassword: forceChangePassword %s: %v", username, err)
		jsonErr(w, "Failed to reset password. Please try again.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`)) //nolint:errcheck
}

// sendAccountActivatedEmail notifies a user that their account was manually
// activated by an admin and they can now log in.
func (h *handler) sendAccountActivatedEmail(r *http.Request, email string) {
	loginURL := h.siteBase(r) + "/index.html#login"
	subject := "Your NavLink account is now active"
	body := buildEmailHTML(
		"Your account has been activated",
		"An administrator has confirmed your email address. You can now log in to your NavLink account.",
		"Log In",
		loginURL,
		"If you did not sign up for NavLink, please ignore this email.",
		"",
	)
	if err := h.auth.sendEmail(email, subject, body); err != nil {
		logWarnf("sendAccountActivatedEmail: %s: %v", email, err)
	}
}

// ── i18n helper ──────────────────────────────────────────────────────────────

// tr returns the Russian string when lang=="ru", otherwise the English one.
func tr(lang, en, ru string) string {
	if lang == "ru" {
		return ru
	}
	return en
}

// ── Email HTML templates ─────────────────────────────────────────────────────

func confirmEmailHTML(lang, confirmURL string) string {
	heading := tr(lang,
		"Confirm your email address",
		"Подтвердите адрес электронной почты")
	body := tr(lang,
		"Thank you for signing up for NavLink. Click the button below to confirm your email address and activate your account.",
		"Спасибо за регистрацию в NavLink. Нажмите кнопку ниже, чтобы подтвердить адрес электронной почты и активировать аккаунт.")
	btn := tr(lang, "Confirm Email", "Подтвердить email")
	note1 := tr(lang, "This link expires in 24 hours.", "Ссылка действительна 24 часа.")
	note2 := tr(lang,
		"If you did not sign up for NavLink, please ignore this email.",
		"Если вы не регистрировались в NavLink, проигнорируйте это письмо.")
	return buildEmailHTML(heading, body, btn, confirmURL, note1, note2)
}

func resetEmailHTML(lang, resetURL string) string {
	heading := tr(lang, "Reset your password", "Сброс пароля")
	body := tr(lang,
		"We received a request to reset the password for your NavLink account. Click the button below to set a new password.",
		"Мы получили запрос на сброс пароля для вашего аккаунта NavLink. Нажмите кнопку ниже, чтобы задать новый пароль.")
	btn := tr(lang, "Reset Password", "Сбросить пароль")
	note1 := tr(lang, "This link expires in 1 hour.", "Ссылка действительна 1 час.")
	note2 := tr(lang,
		"If you did not request a password reset, please ignore this email.",
		"Если вы не запрашивали сброс пароля, проигнорируйте это письмо.")
	return buildEmailHTML(heading, body, btn, resetURL, note1, note2)
}

func buildEmailHTML(heading, body, btnText, btnURL, note1, note2 string) string {
	return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#000010;font-family:'Helvetica Neue',Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#000010;padding:48px 0">
<tr><td align="center">
<table width="580" cellpadding="0" cellspacing="0" style="background:#08080f;border:1px solid rgba(125,220,255,.14);border-radius:12px;overflow:hidden;max-width:580px">
  <tr><td style="padding:32px 40px 24px;text-align:center;border-bottom:1px solid rgba(125,220,255,.07)">
    <span style="font-size:26px;font-weight:800;letter-spacing:-.02em;color:#7DDDFF">NavLink</span>
  </td></tr>
  <tr><td style="padding:36px 40px 28px">
    <h2 style="margin:0 0 14px;font-size:20px;font-weight:700;color:#e8ecf4;line-height:1.3">` + heading + `</h2>
    <p style="margin:0 0 32px;font-size:15px;line-height:1.75;color:rgba(232,236,244,.72)">` + body + `</p>
    <table cellpadding="0" cellspacing="0" style="margin:0 auto 32px">
      <tr><td style="border-radius:6px;background:linear-gradient(120deg,#4FC3F7,#7C4DFF)">
        <a href="` + btnURL + `" style="display:inline-block;padding:13px 38px;color:#fff;text-decoration:none;font-size:15px;font-weight:600;letter-spacing:.02em">` + btnText + `</a>
      </td></tr>
    </table>
    <p style="margin:0 0 6px;font-size:13px;color:rgba(232,236,244,.35)">` + note1 + `</p>
    <p style="margin:0;font-size:13px;color:rgba(232,236,244,.35)">` + note2 + `</p>
  </td></tr>
  <tr><td style="padding:14px 40px;text-align:center;border-top:1px solid rgba(125,220,255,.07)">
    <p style="margin:0;font-size:12px;color:rgba(232,236,244,.22)">&copy; AI Partners Solutions, 2026 &middot; <a href="https://navlink.net" style="color:rgba(125,220,255,.45);text-decoration:none">navlink.net</a></p>
  </td></tr>
</table>
</td></tr>
</table>
</body></html>`
}
