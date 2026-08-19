// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// my_club.go — "Recommend new Cat Club members" JSON API for the /my
// cabinet, now served entirely by the static my-club.html page.
// Only usable by users who already have Cat Club access themselves
// (h.userCanRecommend, checked here server-side — a client-side check
// alone is not the enforcement).

// apiMyClubStatus handles GET /my/api/club -- whether the logged-in user can
// recommend new Cat Club members.
func (h *handler) apiMyClubStatus(w http.ResponseWriter, r *http.Request) {
	sess, err := h.webSession(r)
	if err != nil {
		jsonErr(w, "not logged in", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{ //nolint:errcheck
		"can_recommend": h.userCanRecommend(sess.Username),
	})
}

// apiMyClubRecommend handles POST /my/api/club/recommend {target_username}.
func (h *handler) apiMyClubRecommend(w http.ResponseWriter, r *http.Request) {
	sess, err := h.webSession(r)
	if err != nil {
		jsonErr(w, "not logged in", http.StatusUnauthorized)
		return
	}
	if !h.userCanRecommend(sess.Username) {
		jsonErr(w, "forbidden", http.StatusForbidden)
		return
	}
	var req struct {
		TargetUsername string `json:"target_username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "invalid request", http.StatusBadRequest)
		return
	}
	target := strings.TrimSpace(req.TargetUsername)
	if target == "" {
		jsonErr(w, "Enter the username to recommend", http.StatusBadRequest)
		return
	}
	if strings.EqualFold(target, sess.Username) {
		jsonErr(w, "You can't recommend yourself", http.StatusBadRequest)
		return
	}

	recommender, err := h.db.getOrCreateUser(sess.Username)
	if err != nil {
		jsonErr(w, "Internal error", http.StatusInternalServerError)
		return
	}
	targetUser, err := h.db.findUser(target)
	if err != nil {
		jsonErr(w, "Internal error", http.StatusInternalServerError)
		return
	}
	if targetUser == nil {
		jsonErr(w, "No account with that username", http.StatusNotFound)
		return
	}
	catClub, err := h.db.ClubBySlug("cat_club")
	if err != nil {
		jsonErr(w, "Internal error", http.StatusInternalServerError)
		return
	}
	if err := h.db.RecommendClubMembership(catClub.ID, targetUser.ID, recommender.ID); err != nil {
		logWarnf("my-club: recommend %s -> %s: %v", sess.Username, target, err)
		jsonErr(w, "Failed to record recommendation", http.StatusInternalServerError)
		return
	}

	logInfof("my-club: %s recommended %s for Cat Club", sess.Username, target)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck
}
