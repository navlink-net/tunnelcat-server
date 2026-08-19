// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"bytes"
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)


// webSession returns the full DB session for the current web request, or an
// error if the user is not logged in or the session is not found.
func (h *handler) webSession(r *http.Request) (*Session, error) {
	token := h.sessionToken(r)
	if token == "" {
		return nil, fmt.Errorf("no session token")
	}
	sess, err := h.db.getSession(token)
	if err != nil {
		return nil, fmt.Errorf("db: %w", err)
	}
	if sess == nil {
		return nil, fmt.Errorf("session not found")
	}
	return sess, nil
}

func setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400 * 7,
	})
}

// apiKeyFree handles POST /api/key/free — issues a brand-new perpetual key for
// the logged-in user and emails it. Never idempotent: a key is bound to one
// device, so pressing "Get key" again issues a fresh key for another device.
func (h *handler) apiKeyFree(w http.ResponseWriter, r *http.Request) {
	sess, err := h.webSession(r)
	if err != nil {
		jsonErr(w, "not logged in", http.StatusUnauthorized)
		return
	}
	// Per-account tiers: burst of 1 immediately, but capped well below what a
	// script could otherwise sustain -- see TODO.md's arbiter API flood audit.
	// Each key issuance is a real DB write + a real outbound email, so this
	// isn't just a UX nicety.
	if !h.keyLimiter.Allow(sess.Username,
		limitTier{Window: 10 * time.Second, Max: 1},
		limitTier{Window: 10 * time.Minute, Max: 3},
		limitTier{Window: 24 * time.Hour, Max: 10},
	) {
		jsonErr(w, "Too many key requests. Please wait before requesting another.", http.StatusTooManyRequests)
		return
	}
	issued, err := h.issueFreeKey(r, sess.Username, "get_key_page")
	if err != nil {
		logWarnf("key/free: issueKey for %s: %v", sess.Username, err)
		jsonErr(w, "key generation failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"key":       issued.KeyStr,
		"key_id":    issued.KeyID,
		"client_id": issued.ClientID,
	})
}

// issueFreeKey issues a perpetual key for username (region-biased by the
// request's origin IP) and emails it asynchronously. source records which
// page/endpoint triggered issuance (see KeyRow.Source).
func (h *handler) issueFreeKey(r *http.Request, username, source string) (*issuedKey, error) {
	region := h.regionOf(r.RemoteAddr)
	issued, err := h.issueKey(username, region, source)
	if err != nil {
		return nil, err
	}
	lang := detectLang(r)
	go func() {
		html, err := h.renderKeyEmail(lang, username, issued.KeyStr)
		if err != nil {
			logWarnf("issueFreeKey: render key email for %s: %v", username, err)
			return
		}
		subject := tr(lang, "Your Navlink key", "Ваш ключ Navlink")
		if err := h.auth.sendEmail(username, subject, html); err != nil {
			logWarnf("issueFreeKey: send key email for %s: %v", username, err)
		}
	}()
	return issued, nil
}

// renderKeyEmail renders the key-delivery email. Keys are always perpetual now.
func (h *handler) renderKeyEmail(lang, email, key string) (string, error) {
	tmpl, ok := h.emailTmpls["email_key_issued.html"]
	if !ok {
		return "", fmt.Errorf("email_key_issued.html template not loaded")
	}
	qrBase64 := h.auth.generateQRCodeBase64("navlink://activate?key=" + key)
	var buf bytes.Buffer
	err := tmpl.Execute(&buf, struct {
		Lang         string
		Email        string
		Key          string
		QRCodeBase64 string
	}{
		Lang:         lang,
		Email:        email,
		Key:          key,
		QRCodeBase64: qrBase64,
	})
	return buf.String(), err
}

// ── Account: start / login / set-password (logged-out /get-key flow) ──────────
//
// Camerlengo has no "does this user exist" command, so existence is detected
// by attempting addUser with a throwaway password:
//   - fails "already exists"  → account exists, ask for the real password (login)
//   - succeeds                → brand-new account; a confirmation email is sent
//     and the caller is asked to choose their real password via set-password,
//     which overwrites the throwaway one via forceChangePassword.

func randomThrowawayPassword() string {
	const charset = "ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789"
	buf := make([]byte, 20)
	crand.Read(buf) //nolint:errcheck
	out := make([]byte, 20)
	for i, b := range buf {
		out[i] = charset[int(b)%len(charset)]
	}
	return string(out)
}

func isEmailLike(s string) bool {
	return strings.Contains(s, "@") && strings.Contains(s, ".")
}

// apiAccountStart handles POST /api/account/start {email, captcha_token, captcha_answer}.
// captcha_token/captcha_answer come from GET /api/captcha -- required so this,
// the one unauthenticated endpoint that creates a real account, isn't open to
// unthrottled mass-registration scripts (see 2026-08-16 incident: ~1,300
// harvested-address signups with no server-side captcha check at all).
func (h *handler) apiAccountStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email         string `json:"email"`
		CaptchaToken  string `json:"captcha_token"`
		CaptchaAnswer string `json:"captcha_answer"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request", http.StatusBadRequest)
		return
	}
	if !h.verifyCaptcha(req.CaptchaToken, req.CaptchaAnswer) {
		jsonErr(w, "captcha", http.StatusBadRequest)
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if !isEmailLike(email) {
		jsonErr(w, "invalid email", http.StatusBadRequest)
		return
	}

	reply := func(exists, pending bool) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"exists": exists, "pending": pending}) //nolint:errcheck
	}

	if err := h.auth.addUser(email, randomThrowawayPassword()); err != nil {
		// Any failure is treated as "account already exists".
		pending, _ := h.db.isUserConfirmationPending(email)
		reply(true, pending)
		return
	}

	if err := h.db.setPendingConfirmation(email); err != nil {
		logWarnf("account/start: setPendingConfirmation %s: %v", email, err)
	}
	lang := detectLang(r)
	if err := h.sendConfirmEmail(r, email, lang); err != nil {
		logWarnf("account/start: sendConfirmEmail %s: %v", email, err)
		jsonErr(w, tr(lang, "We could not send a confirmation email to this address. Please check it's correct and try again.",
			"Не удалось отправить письмо с подтверждением на этот адрес. Проверьте правильность адреса и попробуйте ещё раз."), http.StatusBadGateway)
		return
	}
	logInfof("account/start: new pending account %s", email)
	reply(false, true)
}

// apiAccountLogin handles POST /api/account/login {email, password}.
func (h *handler) apiAccountLogin(w http.ResponseWriter, r *http.Request) {
	// Sitewide cap first (cheapest check, protects the shared Camerlengo
	// backend every login proxies to) -- token bucket with burst so one
	// steady-drip caller can't permanently starve every other user's logins.
	if !h.loginGlobal.Allow() {
		jsonErr(w, "Service is busy, please try again in a moment.", http.StatusTooManyRequests)
		return
	}
	ip := clientIP(r)
	if !h.loginIPLimiter.Allow(ip,
		limitTier{Window: 5 * time.Second, Max: 1},
		limitTier{Window: time.Hour, Max: 10},
	) {
		jsonErr(w, "Too many login attempts. Please wait before trying again.", http.StatusTooManyRequests)
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request", http.StatusBadRequest)
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if !isEmailLike(email) || req.Password == "" {
		jsonErr(w, "email and password are required", http.StatusBadRequest)
		return
	}

	if _, err := h.auth.login(email, req.Password); err != nil {
		logInfof("account/login: failed for %s: %v", email, err)
		jsonErr(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}
	if pending, _ := h.db.isUserConfirmationPending(email); pending {
		jsonErr(w, "Please confirm your email address first", http.StatusForbidden)
		return
	}
	if err := h.db.setUserConfirmed(email); err != nil {
		logWarnf("account/login: setUserConfirmed %s: %v", email, err)
	}
	token, err := h.sessions.Login(email, req.Password, nil)
	if err != nil {
		logWarnf("account/login: sessions.Login %s: %v", email, err)
		jsonErr(w, "Login failed. Please try again.", http.StatusInternalServerError)
		return
	}
	setSessionCookie(w, token)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck
}

// apiAccountLogout handles POST /api/account/logout -- clears the shared
// session cookie. JSON counterpart of the plain-redirect /logout (used
// directly by shortnerdcat/my.html's link); this one is for front-ends that
// want to stay on the same page and update their own UI state afterward.
func (h *handler) apiAccountLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   sessionCookieName,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck
}

// apiAccountSetPassword handles POST /api/account/set-password {email, password}.
// Only valid right after apiAccountStart created a brand-new pending account;
// replaces the throwaway password with the one the user chose.
func (h *handler) apiAccountSetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request", http.StatusBadRequest)
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if !isEmailLike(email) {
		jsonErr(w, "invalid email", http.StatusBadRequest)
		return
	}
	if len(req.Password) < 8 {
		jsonErr(w, "Password must be at least 8 characters.", http.StatusBadRequest)
		return
	}
	if err := h.auth.forceChangePassword(email, req.Password); err != nil {
		logWarnf("account/set-password: forceChangePassword %s: %v", email, err)
		jsonErr(w, "Failed to set password. Please try again.", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck
}
