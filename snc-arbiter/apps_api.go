// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Public, unauthenticated JSON API for apps.navlink.net's storefront. Only ever
// returns "published" listings — pending/rejected drafts are visible solely
// through /admin/apps (moderation) and /my/apps (the submitter's own view).
// See TunnelCat/TODO.md "Apps showcase → dynamic, admin-published app store".

// appListingJSON is the wire shape for one listing — deliberately its own type
// rather than reusing AppListing directly, so the DB row shape (OwnerID,
// RejectReason, etc.) never leaks into the public API by accident.
type appListingJSON struct {
	ID            int64                    `json:"id"`
	Name          string                   `json:"name"`
	Description   string                   `json:"description"`
	Category      string                   `json:"category"`
	Platforms     []string                 `json:"platforms"`
	IconURL       string                   `json:"iconUrl"`
	Author        string                   `json:"author"`
	CopyrightText string                   `json:"copyright"`
	PrivacyText   string                   `json:"privacy"`
	PublishedAt   int64                    `json:"publishedAt"`
	Downloads     []appListingDownloadJSON `json:"downloads"`
}

type appListingDownloadJSON struct {
	Platform string `json:"platform"`
	URL      string `json:"url"`
	Version  string `json:"version,omitempty"`
}

// downloadURLSlugs maps a locally-served download path to its OTA slug (see
// clientBinaryTypes in admin_downloads.go) so the storefront can show a live
// version number for our own apps without the submitter having to enter one
// by hand. Only covers paths backed by readClientBinaryInfo's version
// sidecar file -- external URLs (most third-party listings, and Ratatosk's
// downloader.multi-portal.org proxy) simply get no version badge.
var downloadURLSlugs = map[string]string{
	"/download/zip-installer":         "windows-installer",
	"/download/zip":                   "windows",
	"/download/apk":                   "android",
	"/download/dmg":                   "macos",
	"/download/deb":                   "linux",
	"/partners/download/apk":          "proekt-android",
	"/partners/lisinder/download/apk": "lisinder-android",
}

// downloadVersionFor returns the live OTA version for a download URL that
// points at one of our own locally-served binaries, or "" if the URL is
// external or unrecognized.
func (h *handler) downloadVersionFor(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	slug, ok := downloadURLSlugs[u.Path]
	if !ok {
		return ""
	}
	canonicalName, ok := clientBinaryTypes[slug]
	if !ok {
		return ""
	}
	return h.readClientBinaryInfo(canonicalName).Version
}

// appsAssetURL turns a stored relative path (e.g. "myicon.png") into the public
// URL under the shared sshfs-mounted assets tree that both the arbiter and the
// static host serve from (see TODO.md's storage-location decision). The static
// host serves these directly; this is only used when the arbiter itself renders
// a URL (JSON responses, the dynamic detail-page template).
func appsAssetURL(relPath string) string {
	if relPath == "" {
		return ""
	}
	return "https://apps.navlink.net/assets/" + strings.TrimPrefix(relPath, "/")
}

func (h *handler) toAppListingJSON(l AppListing) appListingJSON {
	out := appListingJSON{
		ID:            l.ID,
		Name:          l.Name,
		Description:   l.Description,
		Category:      l.Category,
		Platforms:     l.Platforms,
		IconURL:       appsAssetURL(l.IconPath),
		Author:        l.OwnerUsername,
		CopyrightText: l.CopyrightText,
		PrivacyText:   l.PrivacyText,
	}
	if l.PublishedAt != nil {
		out.PublishedAt = l.PublishedAt.Unix()
	}
	for _, dl := range l.Downloads {
		u := dl.URL
		if u == "" && dl.FilePath != "" {
			u = appsAssetURL(dl.FilePath)
		}
		out.Downloads = append(out.Downloads, appListingDownloadJSON{
			Platform: dl.Platform,
			URL:      u,
			Version:  h.downloadVersionFor(u),
		})
	}
	return out
}

// apiAppsMeta handles GET /api/apps/meta — static info the submission form and
// OS filter both need: the fixed platform list and the default Copyright/Privacy
// boilerplate text (editable per listing, see my_apps.go's defaultAppCopyright/
// defaultAppPrivacy).
func (h *handler) apiAppsMeta(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
		"platforms":        appPlatforms,
		"defaultCopyright": defaultAppCopyright,
		"defaultPrivacy":   defaultAppPrivacy,
	})
}

// apiAppsList handles GET /api/apps/list?q=&os= — the storefront grid's data
// source. Both filters are optional and ANDed; q matches name/description
// (case-insensitive substring), os matches one platform tag exactly.
func (h *handler) apiAppsList(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	os := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("os")))
	listings, err := h.db.listPublishedAppListings(q, os)
	if err != nil {
		logWarnf("apiAppsList: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	out := make([]appListingJSON, 0, len(listings))
	for _, l := range listings {
		out = append(out, h.toAppListingJSON(l))
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out) //nolint:errcheck
}

// apiAppGet handles GET /api/apps/{id} — a single published listing, for the
// dynamic per-app detail page. 404s for anything not published (pending/
// rejected listings aren't public, even by direct ID).
func (h *handler) apiAppGet(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/apps/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	l, err := h.db.getAppListing(id)
	if err != nil {
		logWarnf("apiAppGet %d: %v", id, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if l == nil || l.Status != "published" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(h.toAppListingJSON(*l)) //nolint:errcheck
}
