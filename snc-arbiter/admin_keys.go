// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/json"
	"html"
	"net/http"
	"strings"
	"time"
)

// ── GET /admin/api/users/{username}/keys ─────────────────────────────────────

// apiAdminUserKeys returns the list of keys for a user as JSON.
// Path: /admin/api/users/{username}/keys
func (h *handler) apiAdminUserKeys(w http.ResponseWriter, r *http.Request) {
	// Extract username from path: /admin/api/users/<username>/keys
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/admin/api/users/"), "/")
	if len(parts) < 2 || parts[0] == "" {
		jsonErr(w, "bad path", http.StatusBadRequest)
		return
	}
	username := parts[0]

	keys, err := h.db.QueryUserKeys(username)
	if err != nil {
		logWarnf("apiAdminUserKeys %s: %v", username, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	if keys == nil {
		keys = []KeyRow{}
	}

	type keyJSON struct {
		KeyID            string `json:"key_id"`
		Username         string `json:"username"`
		DeviceID         string `json:"device_id"`
		DeviceName       string `json:"device_name"`
		Enabled          bool   `json:"enabled"`
		IssuedAt         string `json:"issued_at"`
		BoundAt          string `json:"bound_at"`
		LastSeen         string `json:"last_seen"`
		PaidUntil        string `json:"paid_until"` // "YYYY-MM-DD" or "" for perpetual
		UnlimitedDevices bool   `json:"unlimited_devices"`
		Source           string `json:"source"`
	}

	out := make([]keyJSON, len(keys))
	for i, k := range keys {
		ba := ""
		if k.BoundAt.Unix() > 0 {
			ba = k.BoundAt.UTC().Format("2006-01-02 15:04")
		}
		ls := ""
		if k.LastSeen.Unix() > 0 {
			ls = k.LastSeen.UTC().Format("2006-01-02 15:04")
		}
		pu := ""
		if k.PaidUntil != nil {
			pu = k.PaidUntil.UTC().Format("2006-01-02")
		}
		out[i] = keyJSON{
			KeyID:            k.KeyID,
			Username:         k.Username,
			DeviceID:         k.DeviceID,
			DeviceName:       k.DeviceName,
			Enabled:          k.Enabled,
			IssuedAt:         k.IssuedAt.UTC().Format("2006-01-02 15:04"),
			BoundAt:          ba,
			LastSeen:         ls,
			PaidUntil:        pu,
			UnlimitedDevices: k.UnlimitedDevices,
			Source:           k.Source,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out) //nolint:errcheck
}

// ── POST /admin/api/keys/{key_id}/enable|disable ──────────────────────────────

// apiAdminKeyEnable enables a key. Path: /admin/api/keys/{key_id}/enable
func (h *handler) apiAdminKeyEnable(w http.ResponseWriter, r *http.Request) {
	keyID := keyIDFromPath(r.URL.Path, "/enable")
	if keyID == "" {
		jsonErr(w, "bad path", http.StatusBadRequest)
		return
	}
	if err := h.db.SetKeyEnabled(keyID, true); err != nil {
		logWarnf("apiAdminKeyEnable %s: %v", keyID, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck
}

// apiAdminKeyDisable disables a key. Path: /admin/api/keys/{key_id}/disable
func (h *handler) apiAdminKeyDisable(w http.ResponseWriter, r *http.Request) {
	keyID := keyIDFromPath(r.URL.Path, "/disable")
	if keyID == "" {
		jsonErr(w, "bad path", http.StatusBadRequest)
		return
	}
	if err := h.db.SetKeyEnabled(keyID, false); err != nil {
		logWarnf("apiAdminKeyDisable %s: %v", keyID, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck
}

// keyIDFromPath extracts key_id from paths like /admin/api/keys/<key_id>/enable.
func keyIDFromPath(path, suffix string) string {
	path = strings.TrimSuffix(path, suffix)
	parts := strings.Split(strings.TrimPrefix(path, "/admin/api/keys/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		return ""
	}
	return parts[0]
}

// ── POST /admin/api/users/{username}/enable|disable ───────────────────────────

// apiAdminUserEnable enables a user account. Path: /admin/api/users/{username}/enable
func (h *handler) apiAdminUserEnable(w http.ResponseWriter, r *http.Request) {
	username := usernameFromAdminPath(r.URL.Path, "/enable")
	if username == "" {
		jsonErr(w, "bad path", http.StatusBadRequest)
		return
	}
	if err := h.db.SetUserEnabled(username, true); err != nil {
		logWarnf("apiAdminUserEnable %s: %v", username, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck
}

// apiAdminUserDisable disables a user account. Path: /admin/api/users/{username}/disable
func (h *handler) apiAdminUserDisable(w http.ResponseWriter, r *http.Request) {
	username := usernameFromAdminPath(r.URL.Path, "/disable")
	if username == "" {
		jsonErr(w, "bad path", http.StatusBadRequest)
		return
	}
	if err := h.db.SetUserEnabled(username, false); err != nil {
		logWarnf("apiAdminUserDisable %s: %v", username, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck
}

// usernameFromAdminPath extracts username from /admin/api/users/<username>/<suffix>.
func usernameFromAdminPath(path, suffix string) string {
	path = strings.TrimSuffix(path, suffix)
	parts := strings.Split(strings.TrimPrefix(path, "/admin/api/users/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		return ""
	}
	return parts[0]
}

// ── POST /api/admin/keys ──────────────────────────────────────────────────────

// apiRegisterKey registers a key_id→username mapping.
// Called by the key-issuance script (snc_issue_key.py) after generating a key.
// Auth: X-Admin-Token header must match the system setting "admin_api_token",
// OR the caller must have an active admin session cookie.
func (h *handler) apiRegisterKey(w http.ResponseWriter, r *http.Request) {
	// Allow admin session (browser) OR X-Admin-Token header (scripts).
	if !h.checkAdminAPIToken(r) {
		u := h.currentUser(r)
		if u == nil || u.Role != "admin" {
			jsonErr(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	var req struct {
		KeyID    string `json:"key_id"`
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.KeyID == "" || req.Username == "" {
		jsonErr(w, "key_id and username required", http.StatusBadRequest)
		return
	}

	if err := h.db.RegisterKey(req.KeyID, req.Username, "external_register"); err != nil {
		logWarnf("apiRegisterKey %s/%s: %v", req.KeyID, req.Username, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}

	logInfof("keys: registered key_id=%.8s… user=%s", req.KeyID, req.Username)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck
}

// ── POST /admin/api/users/{username}/issue-key ────────────────────────────────

// apiAdminIssueKey generates a new V2 signed activation key for a user.
// Delegates to issueKey — identical path to CLI /admin/key/generate.
func (h *handler) apiAdminIssueKey(w http.ResponseWriter, r *http.Request) {
	username := usernameFromAdminPath(r.URL.Path, "/issue-key")
	if username == "" {
		jsonErr(w, "bad path", http.StatusBadRequest)
		return
	}

	issued, err := h.issueKey(username, "", "admin_dashboard")
	if err != nil {
		logWarnf("apiAdminIssueKey: issueKey %s: %v", username, err)
		status := http.StatusInternalServerError
		if err.Error() == "no live control nodes" {
			status = http.StatusServiceUnavailable
		}
		jsonErr(w, err.Error(), status)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"ok": "true", "key": issued.KeyStr, "key_id": issued.KeyID}) //nolint:errcheck
}

// ── POST /admin/api/keys/{key_id}/unbind ─────────────────────────────────────

// apiAdminKeyUnbind clears the device binding for a key (admin version of myUnbindKey).
func (h *handler) apiAdminKeyUnbind(w http.ResponseWriter, r *http.Request) {
	keyID := keyIDFromPath(r.URL.Path, "/unbind")
	if keyID == "" {
		jsonErr(w, "bad path", http.StatusBadRequest)
		return
	}
	if err := h.db.UnbindKey(keyID); err != nil {
		logWarnf("apiAdminKeyUnbind %s: %v", keyID, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck
}

// ── GET /admin/api/users/pending ─────────────────────────────────────────────

// apiAdminPendingUsers returns navlink.net registrations where email is not yet confirmed.
func (h *handler) apiAdminPendingUsers(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	like := "%"
	if q != "" {
		like = "%" + q + "%"
	}
	pending, err := h.db.listPendingConfirmations(like)
	if err != nil {
		logWarnf("apiAdminPendingUsers: %v", err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	type row struct {
		Username   string `json:"username"`
		CreatedAt  string `json:"created_at"`
		PromoCodes string `json:"promo_codes"`
		SubStatus  string `json:"sub_status"`
		PaidUntil  string `json:"paid_until"`
	}
	out := make([]row, len(pending))
	for i, p := range pending {
		paidUntil := ""
		if !p.PaidUntil.IsZero() {
			paidUntil = p.PaidUntil.UTC().Format("2006-01-02")
		}
		out[i] = row{
			Username:   p.Username,
			CreatedAt:  p.CreatedAt.UTC().Format("2006-01-02 15:04"),
			PromoCodes: p.PromoCodes,
			SubStatus:  p.SubStatus,
			PaidUntil:  paidUntil,
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out) //nolint:errcheck
}

// ── POST /admin/api/users/{username}/confirm-email ────────────────────────────

// apiAdminConfirmEmail manually confirms a user's email, creates their account,
// and sends them a notification email so they know they can log in.
func (h *handler) apiAdminConfirmEmail(w http.ResponseWriter, r *http.Request) {
	username := usernameFromAdminPath(r.URL.Path, "/confirm-email")
	if username == "" {
		jsonErr(w, "bad path", http.StatusBadRequest)
		return
	}
	if err := h.db.setUserConfirmed(username); err != nil {
		logWarnf("apiAdminConfirmEmail setUserConfirmed %s: %v", username, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	if _, err := h.db.getOrCreateUser(username); err != nil {
		logWarnf("apiAdminConfirmEmail getOrCreateUser %s: %v", username, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	h.sendAccountActivatedEmail(r, username)
	logInfof("admin: manually confirmed email for %s", username)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck
}

// ── POST /admin/api/keys/{key_id}/set-paid-until ──────────────────────────────

// apiAdminKeySetPaidUntil sets the expiry date for a key.
// Body: {"paid_until":"2026-05-05"} (YYYY-MM-DD, interpreted as end of that day UTC).
// An empty string clears the expiry (makes the key perpetual).
func (h *handler) apiAdminKeySetPaidUntil(w http.ResponseWriter, r *http.Request) {
	keyID := keyIDFromPath(r.URL.Path, "/set-paid-until")
	if keyID == "" {
		jsonErr(w, "bad path", http.StatusBadRequest)
		return
	}
	var req struct {
		PaidUntil string `json:"paid_until"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.PaidUntil == "" {
		if err := h.db.ClearKeyPaidUntil(keyID); err != nil {
			logWarnf("apiAdminKeySetPaidUntil clear %s: %v", keyID, err)
			jsonErr(w, "internal error", http.StatusInternalServerError)
			return
		}
	} else {
		t, err := time.Parse("2006-01-02", req.PaidUntil)
		if err != nil {
			jsonErr(w, "invalid date, use YYYY-MM-DD", http.StatusBadRequest)
			return
		}
		t = time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 59, 0, time.UTC)
		k, _ := h.db.GetKey(keyID)
		planPia := int64(0)
		if k != nil {
			planPia = k.PlanPia
		}
		if err := h.db.SetKeyPaidUntil(keyID, t, planPia); err != nil {
			logWarnf("apiAdminKeySetPaidUntil %s: %v", keyID, err)
			jsonErr(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	logInfof("admin: set paid_until=%s for key=%.8s…", req.PaidUntil, keyID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck
}

// ── POST /admin/api/keys/{key_id}/set-unlimited ───────────────────────────────

// apiAdminKeySetUnlimited sets or clears the unlimited_devices flag for a key.
// Body: {"unlimited": true}
func (h *handler) apiAdminKeySetUnlimited(w http.ResponseWriter, r *http.Request) {
	keyID := keyIDFromPath(r.URL.Path, "/set-unlimited")
	if keyID == "" {
		jsonErr(w, "bad path", http.StatusBadRequest)
		return
	}
	var req struct {
		Unlimited bool `json:"unlimited"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := h.db.SetKeyUnlimitedDevices(keyID, req.Unlimited); err != nil {
		logWarnf("apiAdminKeySetUnlimited %s: %v", keyID, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	logInfof("admin: unlimited_devices=%v for key=%.8s…", req.Unlimited, keyID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck
}

// ── POST /admin/api/users/{username}/email ────────────────────────────────────

// apiAdminEmailUser sends a custom email to a user from "The Tunnel Cat <cat@partners.solutions>".
// Body: { "subject": "...", "body": "..." }
func (h *handler) apiAdminEmailUser(w http.ResponseWriter, r *http.Request) {
	username := usernameFromAdminPath(r.URL.Path, "/email")
	if username == "" {
		jsonErr(w, "bad path", http.StatusBadRequest)
		return
	}
	var req struct {
		Subject string `json:"subject"`
		Body    string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	req.Subject = strings.TrimSpace(req.Subject)
	req.Body = strings.TrimSpace(req.Body)
	if req.Subject == "" || req.Body == "" {
		jsonErr(w, "subject and body required", http.StatusBadRequest)
		return
	}
	const senderFrom = "The Tunnel Cat <cat@partners.solutions>"
	if err := h.auth.sendEmailFrom(username, senderFrom, req.Subject, adminEmailHTML(req.Subject, req.Body)); err != nil {
		logWarnf("apiAdminEmailUser %s: %v", username, err)
		jsonErr(w, "send failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	logInfof("admin: email sent to %s subject=%q", username, req.Subject)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck
}

// adminEmailHTML wraps admin-composed plain text in the Tunnel Cat HTML email template.
func adminEmailHTML(subject, body string) string {
	paras := strings.ReplaceAll(html.EscapeString(body), "\n", "<br>")
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>` + html.EscapeString(subject) + `</title>
</head>
<body style="margin:0;padding:0;background:#000010;font-family:'Helvetica Neue',Arial,sans-serif">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#000010;padding:48px 0">
<tr><td align="center">
<table width="580" cellpadding="0" cellspacing="0" style="background:#08080f;border:1px solid rgba(125,220,255,.14);border-radius:12px;overflow:hidden;max-width:580px">
  <tr><td style="padding:28px 40px 22px;text-align:center;border-bottom:1px solid rgba(125,220,255,.07)">
    <span style="font-size:26px;font-weight:800;letter-spacing:-.02em;color:#7DDDFF">Tunnel Cat</span>
  </td></tr>
  <tr><td style="padding:36px 40px 28px">
    <h2 style="margin:0 0 20px;font-size:18px;font-weight:700;color:#e8ecf4;line-height:1.3">` + html.EscapeString(subject) + `</h2>
    <p style="margin:0;font-size:15px;line-height:1.75;color:rgba(232,236,244,.72)">` + paras + `</p>
  </td></tr>
  <tr><td style="padding:14px 40px;text-align:center;border-top:1px solid rgba(125,220,255,.07)">
    <p style="margin:0;font-size:12px;color:rgba(232,236,244,.22)">&copy; AI Partners Solutions, 2026 &middot; <a href="https://navlink.net" style="color:rgba(125,220,255,.45);text-decoration:none">navlink.net</a></p>
  </td></tr>
</table>
</td></tr>
</table>
</body>
</html>`
}

// checkAdminAPIToken validates the X-Admin-Token header against the DB setting.
func (h *handler) checkAdminAPIToken(r *http.Request) bool {
	token := r.Header.Get("X-Admin-Token")
	if token == "" {
		return false
	}
	stored, ok, err := h.db.getSetting("admin_api_token")
	if err != nil || !ok {
		return false
	}
	return stored != "" && stored == token
}
