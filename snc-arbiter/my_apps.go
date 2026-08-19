// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Publisher-facing side of the apps.navlink.net app store: profile-completeness
// gating, listing submission/editing, and the user's own listing history.
// Moderation (approve/reject) lives in admin_apps.go; the public read API in
// apps_api.go. See TunnelCat/TODO.md "Apps showcase → dynamic, admin-published
// app store" for the full plan this implements.

// defaultAppCopyright and defaultAppPrivacy are the standard boilerplate the
// submission form pre-fills — the submitter can edit either before posting
// (decided 2026-08-07: Claude drafts the default, per-app text stays editable).
const (
	defaultAppCopyright = "© {{YEAR}} {{AUTHOR}}. All rights reserved."
	defaultAppPrivacy   = `This application may collect information necessary to provide its core ` +
		`functionality (such as account credentials, usage data, or content you submit within the app). ` +
		`Data is not sold to third parties. Contact the developer listed on this page for questions ` +
		`about what data is collected or to request its deletion.`
)

// ── GET /my/api/profile ──────────────────────────────────────────────────────

type myProfileJSON struct {
	FullName string `json:"fullName"`
	Contact  string `json:"contact"`
	Complete bool   `json:"complete"`
}

func (h *handler) myApiProfileGet(w http.ResponseWriter, r *http.Request) {
	sess, err := h.webSession(r)
	if err != nil {
		jsonErr(w, "not logged in", http.StatusUnauthorized)
		return
	}
	u, err := h.db.getOrCreateUser(sess.Username)
	if err != nil {
		logWarnf("myApiProfileGet %s: %v", sess.Username, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	fullName, contact, err := h.db.getUserProfile(u.ID)
	if err != nil {
		logWarnf("myApiProfileGet %s: %v", sess.Username, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(myProfileJSON{ //nolint:errcheck
		FullName: fullName,
		Contact:  contact,
		Complete: strings.TrimSpace(fullName) != "" && strings.TrimSpace(contact) != "",
	})
}

// ── POST /my/api/profile ─────────────────────────────────────────────────────
//
// Full name + contact are required before /my/api/apps will accept a
// submission — see requireCompleteProfile below. This endpoint is how a user
// fills them in.

func (h *handler) myApiProfileSet(w http.ResponseWriter, r *http.Request) {
	sess, err := h.webSession(r)
	if err != nil {
		jsonErr(w, "not logged in", http.StatusUnauthorized)
		return
	}
	r.ParseForm()
	fullName := strings.TrimSpace(r.FormValue("fullName"))
	contact := strings.TrimSpace(r.FormValue("contact"))
	if fullName == "" || contact == "" {
		jsonErr(w, "fullName and contact are both required", http.StatusBadRequest)
		return
	}
	u, err := h.db.getOrCreateUser(sess.Username)
	if err != nil {
		logWarnf("myApiProfileSet %s: %v", sess.Username, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := h.db.setUserProfile(u.ID, fullName, contact); err != nil {
		logWarnf("myApiProfileSet %s: %v", sess.Username, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck
}

// ── GET /my/api/apps ──────────────────────────────────────────────────────────
//
// The submitter's own listings, any status — powers a "my submissions" view
// distinct from the public storefront (which only ever shows "published").

type myAppListingJSON struct {
	ID           int64    `json:"id"`
	Name         string   `json:"name"`
	Status       string   `json:"status"`
	RejectReason string   `json:"rejectReason,omitempty"`
	Category     string   `json:"category"`
	Platforms    []string `json:"platforms"`
	SubmittedAt  int64    `json:"submittedAt"`
}

func (h *handler) myApiAppsList(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		h.myApiAppsSubmit(w, r)
		return
	}
	sess, err := h.webSession(r)
	if err != nil {
		jsonErr(w, "not logged in", http.StatusUnauthorized)
		return
	}
	u, err := h.db.getOrCreateUser(sess.Username)
	if err != nil {
		logWarnf("myApiAppsList %s: %v", sess.Username, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	listings, err := h.db.listAppListingsByOwner(u.ID)
	if err != nil {
		logWarnf("myApiAppsList %s: %v", sess.Username, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	out := make([]myAppListingJSON, 0, len(listings))
	for _, l := range listings {
		out = append(out, myAppListingJSON{
			ID: l.ID, Name: l.Name, Status: l.Status, RejectReason: l.RejectReason,
			Category: l.Category, Platforms: l.Platforms, SubmittedAt: l.SubmittedAt.Unix(),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out) //nolint:errcheck
}

// ── POST /my/api/apps (submit) and /my/api/apps/{id} (edit) ─────────────────
//
// Multipart form fields:
//   name, description, category   — text
//   platforms                     — comma-separated platform tags (see appPlatforms)
//   copyright, privacy            — text; frontend pre-fills with the defaults above
//   icon                          — file, optional on edit (keeps existing icon if omitted)
//   download_<platform>_url       — text, OR
//   download_<platform>_file      — file, per selected platform (one or the other)

func (h *handler) myApiAppsSubmit(w http.ResponseWriter, r *http.Request) {
	h.saveAppListing(w, r, 0)
}

func (h *handler) myApiAppEdit(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/my/api/apps/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		jsonErr(w, "bad id", http.StatusBadRequest)
		return
	}
	h.saveAppListing(w, r, id)
}

// saveAppListing handles both submit (id==0) and edit (id!=0), sharing the same
// validation, upload, and profile-completeness gate. On edit, ownership is
// checked before anything else -- a user may only edit their own listings.
func (h *handler) saveAppListing(w http.ResponseWriter, r *http.Request, id int64) {
	sess, err := h.webSession(r)
	if err != nil {
		jsonErr(w, "not logged in", http.StatusUnauthorized)
		return
	}
	u, err := h.db.getOrCreateUser(sess.Username)
	if err != nil {
		logWarnf("saveAppListing %s: %v", sess.Username, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	complete, err := h.db.isProfileComplete(u.ID)
	if err != nil {
		logWarnf("saveAppListing %s: %v", sess.Username, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !complete {
		jsonErr(w, "profile incomplete: fill in full name and contact details first (POST /my/api/profile)", http.StatusForbidden)
		return
	}

	var existing *AppListing
	if id != 0 {
		existing, err = h.db.getAppListing(id)
		if err != nil {
			logWarnf("saveAppListing %s: %v", sess.Username, err)
			jsonErr(w, "internal error", http.StatusInternalServerError)
			return
		}
		if existing == nil || existing.OwnerID != u.ID {
			jsonErr(w, "not found", http.StatusNotFound)
			return
		}
	}

	if h.appsAssetsDir == "" {
		jsonErr(w, "app submissions are not configured on this server", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil { // 32MB of form fields; files stream separately below
		jsonErr(w, "request too large or malformed", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	description := strings.TrimSpace(r.FormValue("description"))
	category := strings.TrimSpace(r.FormValue("category"))
	copyrightText := strings.TrimSpace(r.FormValue("copyright"))
	privacyText := strings.TrimSpace(r.FormValue("privacy"))
	platforms := splitCSV(r.FormValue("platforms"))
	if name == "" || len(platforms) == 0 {
		jsonErr(w, "name and at least one platform are required", http.StatusBadRequest)
		return
	}
	for _, p := range platforms {
		if !validAppPlatform(p) {
			jsonErr(w, "unknown platform: "+p, http.StatusBadRequest)
			return
		}
	}

	iconPath := ""
	if existing != nil {
		iconPath = existing.IconPath
	}
	if uploaded, ok, err := h.saveAppUpload(r, "icon", "icons"); err != nil {
		jsonErr(w, "icon upload failed: "+err.Error(), http.StatusInternalServerError)
		return
	} else if ok {
		iconPath = uploaded
	}

	var existingDL map[string]AppListingDownload
	if existing != nil {
		existingDL = make(map[string]AppListingDownload, len(existing.Downloads))
		for _, dl := range existing.Downloads {
			existingDL[dl.Platform] = dl
		}
	}
	var downloads []AppListingDownload
	for _, p := range platforms {
		dl := AppListingDownload{Platform: p}
		if url := strings.TrimSpace(r.FormValue("download_" + p + "_url")); url != "" {
			dl.URL = url
		} else if uploaded, ok, err := h.saveAppUpload(r, "download_"+p+"_file", "binaries"); err != nil {
			jsonErr(w, "download upload failed for "+p+": "+err.Error(), http.StatusInternalServerError)
			return
		} else if ok {
			dl.FilePath = uploaded
		} else if prev, hadPrev := existingDL[p]; hadPrev {
			dl = prev // neither a new URL nor a new file on edit -- keep what was there
		} else {
			jsonErr(w, "no download URL or file provided for platform: "+p, http.StatusBadRequest)
			return
		}
		downloads = append(downloads, dl)
	}

	if existing == nil {
		newID, err := h.db.submitAppListing(u.ID, name, description, category, platforms,
			iconPath, copyrightText, privacyText, downloads)
		if err != nil {
			logWarnf("submitAppListing %s: %v", sess.Username, err)
			jsonErr(w, "internal error", http.StatusInternalServerError)
			return
		}
		logInfof("apps: %s submitted new listing %d (%s)", sess.Username, newID, name)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "id": newID}) //nolint:errcheck
		return
	}

	if err := h.db.updateAppListing(id, name, description, category, platforms,
		iconPath, copyrightText, privacyText, downloads); err != nil {
		logWarnf("updateAppListing %s: %v", sess.Username, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	logInfof("apps: %s resubmitted listing %d (%s) for review", sess.Username, id, name)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "id": id}) //nolint:errcheck
}

func validAppPlatform(p string) bool {
	for _, ap := range appPlatforms {
		if ap == p {
			return true
		}
	}
	return false
}

// saveAppUpload streams an optional multipart file field to h.appsAssetsDir under
// the given subdirectory, returning its path relative to appsAssetsDir. Returns
// ok=false (no error) when the field is simply absent -- most upload fields here
// are optional (e.g. an edit that doesn't replace the icon).
func (h *handler) saveAppUpload(r *http.Request, field, subdir string) (relPath string, ok bool, err error) {
	f, fh, err := r.FormFile(field)
	if err != nil {
		return "", false, nil // field not present -- not an error
	}
	defer f.Close()

	dir := filepath.Join(h.appsAssetsDir, subdir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", false, fmt.Errorf("create %s: %w", dir, err)
	}

	nameBytes := make([]byte, 16)
	if _, err := rand.Read(nameBytes); err != nil {
		return "", false, err
	}
	ext := filepath.Ext(fh.Filename)
	fileName := hex.EncodeToString(nameBytes) + ext
	dst := filepath.Join(dir, fileName)

	out, err := os.Create(dst)
	if err != nil {
		return "", false, fmt.Errorf("create %s: %w", dst, err)
	}
	defer out.Close()
	if _, err := io.Copy(out, f); err != nil {
		os.Remove(dst) //nolint:errcheck
		return "", false, fmt.Errorf("write %s: %w", dst, err)
	}
	return filepath.ToSlash(filepath.Join(subdir, fileName)), true, nil
}
