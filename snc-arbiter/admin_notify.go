// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"net/http"
	"net/url"
	"strings"
	"time"
)

type notifyPageData struct {
	Notifications []notificationView
	Flash         string
}

type notificationView struct {
	ID           string
	Message      string
	CreatedAtFmt string
	CreatedBy    string
}

func toNotificationViews(entries []NotificationEntry) []notificationView {
	out := make([]notificationView, len(entries))
	for i, e := range entries {
		out[i] = notificationView{
			ID:           e.ID,
			Message:      e.Message,
			CreatedAtFmt: time.Unix(e.CreatedAt, 0).UTC().Format("2006-01-02 15:04 UTC"),
			CreatedBy:    e.CreatedBy,
		}
	}
	return out
}

// adminNotifyPage renders GET /admin/notify.
func (h *handler) adminNotifyPage(w http.ResponseWriter, r *http.Request) {
	entries, err := h.db.activeNotifications("")
	if err != nil {
		logWarnf("notify page: %v", err)
	}
	u := h.currentUser(r)
	h.renderPage(w, "admin_notify.html", pageData{
		User:    u,
		Flash:   r.URL.Query().Get("flash"),
		FlashOK: r.URL.Query().Get("flashok"),
		Data: notifyPageData{
			Notifications: toNotificationViews(entries),
		},
	})
}

// adminNotifyAdd handles POST /admin/notify/add.
func (h *handler) adminNotifyAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	message := strings.TrimSpace(r.FormValue("message"))
	if message == "" {
		http.Redirect(w, r, "/admin/notify?flash="+url.QueryEscape("Message cannot be empty"), http.StatusFound)
		return
	}
	id := newNotificationID()
	createdBy := ""
	if u := h.currentUser(r); u != nil {
		createdBy = u.Username
	}
	if err := h.db.addNotification(id, message, createdBy); err != nil {
		logWarnf("notify add: %v", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	h.loadNotificationsFromDB()
	logInfof("notify: admin %s added notification id=%s", createdBy, id)
	http.Redirect(w, r, "/admin/notify?flashok="+url.QueryEscape("Notification sent"), http.StatusFound)
}

// adminNotifyDelete handles POST /admin/notify/delete.
func (h *handler) adminNotifyDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id := r.FormValue("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	deletedBy := ""
	if u := h.currentUser(r); u != nil {
		deletedBy = u.Username
	}
	if err := h.db.deleteNotification(id); err != nil {
		logWarnf("notify delete: %v", err)
		http.Error(w, "database error", http.StatusInternalServerError)
		return
	}
	h.loadNotificationsFromDB()
	logInfof("notify: admin %s deleted notification id=%s", deletedBy, id)
	http.Redirect(w, r, "/admin/notify?flash="+url.QueryEscape("Notification removed"), http.StatusFound)
}
