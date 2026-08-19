// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"net/http"
	"strconv"
	"strings"
)

// Admin moderation for the apps.navlink.net app store. Publishing is two-step (see
// TunnelCat/TODO.md "Apps showcase → dynamic, admin-published app store"): a
// registered user submits via /my/api/apps (my_handler.go), an admin approves or
// rejects here. Admins never author listings themselves.

type adminAppsData struct {
	Tab     string
	Pending []AppListing
	All     []AppListing
}

func (h *handler) adminAppsPage(w http.ResponseWriter, r *http.Request) {
	tab := r.URL.Query().Get("tab")
	if tab != "all" {
		tab = "pending"
	}
	data := adminAppsData{Tab: tab}
	if tab == "all" {
		data.All, _ = h.db.listAllAppListings()
	} else {
		data.Pending, _ = h.db.listPendingAppListings()
	}
	h.render(w, r, "admin_apps.html", data)
}

// adminAppAction handles /admin/apps/{id}/approve|reject|delete, mirroring
// adminNodeAction's single-dispatcher-per-resource shape.
func (h *handler) adminAppAction(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// parts: ["admin","apps","{id}","action"]
	if len(parts) != 4 {
		http.NotFound(w, r)
		return
	}
	id, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	switch parts[3] {
	case "approve":
		if err := h.db.approveAppListing(id); err != nil {
			logWarnf("adminAppAction approve %d: %v", id, err)
			http.Error(w, "error", http.StatusInternalServerError)
			return
		}
		logInfof("admin: published app listing %d", id)
	case "reject":
		r.ParseForm()
		if err := h.db.rejectAppListing(id, r.FormValue("reason")); err != nil {
			logWarnf("adminAppAction reject %d: %v", id, err)
			http.Error(w, "error", http.StatusInternalServerError)
			return
		}
		logInfof("admin: rejected app listing %d", id)
	case "delete":
		if err := h.db.deleteAppListing(id); err != nil {
			logWarnf("adminAppAction delete %d: %v", id, err)
			http.Error(w, "error", http.StatusInternalServerError)
			return
		}
		logInfof("admin: deleted app listing %d", id)
	default:
		http.NotFound(w, r)
		return
	}
	ref := r.Header.Get("Referer")
	if ref == "" {
		ref = "/admin/apps"
	}
	http.Redirect(w, r, ref, http.StatusSeeOther)
}
