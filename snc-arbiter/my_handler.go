// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// ── /my cabinet ───────────────────────────────────────────────────────────────
//
// The HTML personal cabinet used to be rendered here; it now lives entirely
// on the static site (shortnerdcat.navlink.net/my.html), which calls the
// JSON endpoints below (session-authenticated via the same snc_session
// cookie, credentials:"include"). /my, /my/keys, /my/subscription just
// redirect there for anyone hitting the old arbiter URLs directly.

const myCabinetURL = "https://shortnerdcat.navlink.net/my.html"

func (h *handler) myCabinetRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, myCabinetURL, http.StatusMovedPermanently)
}

// ── GET /my/api/keys ───────────────────────────────────────────────────────────
//
// Public (session-authenticated) JSON listing of the logged-in user's own
// keys, for the static personal-cabinet front-end. Read-only.

type myKeyJSON struct {
	KeyID      string `json:"key_id"`
	DeviceName string `json:"device_name,omitempty"`
	Enabled    bool   `json:"enabled"`
	IssuedAt   string `json:"issued_at"`
}

func (h *handler) myApiKeysList(w http.ResponseWriter, r *http.Request) {
	sess, err := h.webSession(r)
	if err != nil {
		jsonErr(w, "not logged in", http.StatusUnauthorized)
		return
	}
	keys, err := h.db.QueryUserKeys(sess.Username)
	if err != nil {
		logWarnf("myApiKeysList %s: %v", sess.Username, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	out := make([]myKeyJSON, 0, len(keys))
	for _, k := range keys {
		out = append(out, myKeyJSON{
			KeyID:      k.KeyID,
			DeviceName: k.DeviceName,
			Enabled:    k.Enabled,
			IssuedAt:   k.IssuedAt.Format("2006-01-02"),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out) //nolint:errcheck
}

// ── GET /my/api/whoami ────────────────────────────────────────────────────────
//
// Minimal session-identity check for external services (e.g. navmail, see
// tunnel_cat/mailapi) that need to know which NavLink account a forwarded
// session cookie belongs to, without giving them any other account data.

type myWhoamiJSON struct {
	OK       bool   `json:"ok"`
	Username string `json:"username"`
}

func (h *handler) myApiWhoami(w http.ResponseWriter, r *http.Request) {
	sess, err := h.webSession(r)
	if err != nil {
		jsonErr(w, "not logged in", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(myWhoamiJSON{OK: true, Username: sess.Username}) //nolint:errcheck
}

// ── POST /my/api/keys/{key_id}/unbind ─────────────────────────────────────────

func (h *handler) myUnbindKey(w http.ResponseWriter, r *http.Request) {
	sess, err := h.webSession(r)
	if err != nil {
		jsonErr(w, "not logged in", http.StatusUnauthorized)
		return
	}

	path := strings.TrimSuffix(r.URL.Path, "/unbind")
	keyID := strings.TrimPrefix(path, "/my/api/keys/")
	if keyID == "" || strings.Contains(keyID, "/") {
		jsonErr(w, "bad path", http.StatusBadRequest)
		return
	}

	key, err := h.db.GetKey(keyID)
	if err != nil {
		logWarnf("myUnbindKey GetKey %s: %v", keyID, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	if key == nil || key.Username != sess.Username {
		jsonErr(w, "not found", http.StatusNotFound)
		return
	}

	if err := h.db.UnbindKey(keyID); err != nil {
		logWarnf("myUnbindKey %s: %v", keyID, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}

	logInfof("my-cabinet: user=%s unbound key=%.8s…", sess.Username, keyID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck
}

// ── GET /my/api/keys/{key_id}/download ────────────────────────────────────────
//
// Re-builds and returns the full signed key string for the given key_id.
// The key is re-signed with current control nodes so it always has fresh bootstrap addresses.
// Only accessible to the key's owner.

func (h *handler) myDownloadKey(w http.ResponseWriter, r *http.Request) {
	sess, err := h.webSession(r)
	if err != nil {
		jsonErr(w, "not logged in", http.StatusUnauthorized)
		return
	}

	path := strings.TrimSuffix(r.URL.Path, "/download")
	keyID := strings.TrimPrefix(path, "/my/api/keys/")
	if keyID == "" || strings.Contains(keyID, "/") {
		jsonErr(w, "bad path", http.StatusBadRequest)
		return
	}

	key, err := h.db.GetKey(keyID)
	if err != nil {
		logWarnf("myDownloadKey GetKey %s: %v", keyID, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	if key == nil || key.Username != sess.Username {
		jsonErr(w, "not found", http.StatusNotFound)
		return
	}

	// Re-build the signed key with current control nodes and a fresh session password.
	// V2 keys authenticate via AuthSig (which doesn't include the password), so the
	// new key is fully functional even though its password differs from the original.
	u, err := h.db.getOrCreateUser(sess.Username)
	if err != nil {
		logWarnf("myDownloadKey getUser %s: %v", sess.Username, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	controls, err := h.db.bootstrapNodes("control")
	if err != nil || len(controls) == 0 {
		jsonErr(w, "no live control nodes", http.StatusServiceUnavailable)
		return
	}
	region := h.regionOf(r.RemoteAddr)
	nodes := h.pickBootstrapControls(controls, region)
	p := &keyPayload{
		Username:      sess.Username,
		ControlNodes:  nodes,
		ArbiterPubkey: h.signer.pubkeyHex(),
		ClientID:      u.ClientID,
		KeyID:         keyID,
		IsAdmin:       u.Role == "admin",
	}
	ks, err := buildSignedKey(p, h.signer.priv)
	if err != nil {
		logWarnf("myDownloadKey buildKey %s: %v", keyID, err)
		jsonErr(w, "key build failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"key": ks}) //nolint:errcheck
}

// ── POST /my/api/keys/new ─────────────────────────────────────────────────────
//
// Issues a brand-new perpetual key for the logged-in user. Never idempotent —
// a key is bound to one device, so this is used both for a first key and for
// adding another device.

func (h *handler) myNewKey(w http.ResponseWriter, r *http.Request) {
	sess, err := h.webSession(r)
	if err != nil {
		jsonErr(w, "not logged in", http.StatusUnauthorized)
		return
	}

	issued, err := h.issueFreeKey(r, sess.Username, "my_account")
	if err != nil {
		logWarnf("my-new-key: issueKey for %s: %v", sess.Username, err)
		jsonErr(w, "key generation failed", http.StatusInternalServerError)
		return
	}

	logInfof("my-new-key: user=%s issued key=%.8s…", sess.Username, issued.KeyID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"key":       issued.KeyStr,
		"key_id":    issued.KeyID,
		"client_id": issued.ClientID,
	})
}

// ── GET /my/subscription ─────────────────────────────────────────────────────
//
// Shows the logged-in user's keys and lets them get another one.

// ── POST /my/api/support ────────────────────────────────────────────────────

// apiMySupportSubmit handles POST /my/api/support {subject, message} --
// JSON counterpart of the old my_support.html form, for the static
// my-support.html page.
func (h *handler) apiMySupportSubmit(w http.ResponseWriter, r *http.Request) {
	sess, err := h.webSession(r)
	if err != nil {
		jsonErr(w, "not logged in", http.StatusUnauthorized)
		return
	}
	var req struct {
		Subject string `json:"subject"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request", http.StatusBadRequest)
		return
	}
	subject := strings.TrimSpace(req.Subject)
	message := strings.TrimSpace(req.Message)
	if subject == "" || message == "" {
		jsonErr(w, "Subject and message are required", http.StatusBadRequest)
		return
	}

	fullSubject := fmt.Sprintf("[NavLink Support] %s", subject)
	htmlBody := fmt.Sprintf(
		"<p><strong>From:</strong> %s</p><p><strong>Subject:</strong> %s</p><hr><pre style=\"font-family:monospace;white-space:pre-wrap\">%s</pre>",
		sess.Username, subject, message)

	if err := h.auth.sendEmail("kk@partners.solutions", fullSubject, htmlBody); err != nil {
		logWarnf("my-support: sendEmail user=%s: %v", sess.Username, err)
		jsonErr(w, "Failed to send message. Please try again.", http.StatusInternalServerError)
		return
	}

	logInfof("my-support: user=%s sent: %s", sess.Username, subject)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck
}

// ── GET /logout-my ────────────────────────────────────────────────────────────

func (h *handler) myLogout(w http.ResponseWriter, r *http.Request) {
	// Clear the main session cookie (same one used everywhere).
	http.SetCookie(w, &http.Cookie{
		Name:   sessionCookieName,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

// userCanRecommend reports whether username currently has access to Cat
// Club (directly, or via a subsuming club like Elite Cat Club) — gates
// whether the "Recommend new Cat Club members" nav item is shown.
// Best-effort: any lookup error is treated as "no", never blocks page render.
func (h *handler) userCanRecommend(username string) bool {
	if username == "" {
		return false
	}
	user, err := h.db.getOrCreateUser(username)
	if err != nil {
		return false
	}
	catClub, err := h.db.ClubBySlug("cat_club")
	if err != nil {
		return false
	}
	ok, err := h.db.HasClubAccess(catClub.ID, user.ID)
	if err != nil {
		return false
	}
	return ok
}
