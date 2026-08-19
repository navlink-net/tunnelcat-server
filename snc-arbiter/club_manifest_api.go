// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
)

// club_manifest_api.go — the parallel, encrypted club-manifest channel.
// Sibling to apiManifest (handler.go) and its NodeEntry-based signing —
// deliberately not a variant of it, so the existing general-population
// manifest pipeline is never touched by this feature. See
// tunnel_cat/docs/club-membership.md for the full design.
//
// Clubs are addressed by their stable slug ("cat_club", "elite_cat_club"),
// not their DB-internal numeric id — the slug is a small, fixed, known-in-
// advance set shared as a constant across arbiter/exit/control/client
// (see clubSlugs in snc-exit and snc-control), so no discovery endpoint is
// needed for "what clubs exist" before fetching a manifest.
//
// Two separate endpoints, two separate audiences:
//   - apiClubManifest: exit-token gated, same as apiManifest — the
//     encrypted manifest bytes are not sensitive on their own (confidentiality
//     comes from the club's symmetric key, not from access control on the
//     fetch), so this mirrors the existing public-to-any-exit shape.
//   - apiClubKey: session gated — proves the *caller* currently has access
//     to the club before handing back the symmetric key that decrypts it.

// apiClubManifest returns the signed+encrypted manifest for the club given
// by the "club" (slug) query parameter. Only exit nodes (identified by
// their token) may call this, same restriction as apiManifest.
func (h *handler) apiClubManifest(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Node-Token")
	if token == "" {
		jsonErr(w, "X-Node-Token required", http.StatusUnauthorized)
		return
	}
	node, err := h.db.nodeByToken(token)
	if err != nil || node == nil || node.Type != "exit" {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	club, err := h.db.ClubBySlug(r.URL.Query().Get("club"))
	if err != nil {
		jsonErr(w, "unknown club", http.StatusBadRequest)
		return
	}

	nodes, err := h.db.ClubNodes(club.ID, "control")
	if err != nil {
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	key, err := h.db.ClubManifestKey(club.ID)
	if err != nil {
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	keyBytes, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}

	data, err := h.signer.signClubManifest(club.ID, keyBytes, nodes)
	if err != nil {
		jsonErr(w, "signing error", http.StatusInternalServerError)
		return
	}
	logInfof("club-manifest: serving club=%s token=%.8s… node=%s nodes=%d", club.Slug, token, node.Addr, len(nodes))
	w.Header().Set("Content-Type", "application/json")
	w.Write(data) //nolint:errcheck
}

// apiClubKey returns the requesting user's club symmetric key for the club
// given by "club" (slug), gated on an active membership check (direct
// grant, or a grant in a club that subsumes this one — see
// DB.HasClubAccess). Authenticated via the same X-Session token used
// elsewhere (e.g. apiManifest's per-user notifications), not X-Node-Token —
// this is a per-user check, not a per-node one.
// apiWhoAmI reports the caller's *current* admin status, looked up live by
// username on every call — deliberately NOT baked into the signed key blob
// the way keyPayload.IsAdmin is. That field is only ever set at key-issuance
// time (see admin_keygen.go/my_handler.go), so a role change (promoted to or
// demoted from admin) never reaches an already-issued key without the user
// re-authenticating for a brand new one — confirmed as a real, confusing gap
// 2026-08-14: an admin who'd been using an older key saw no club-theme
// preview menu at all, with no way to tell why short of re-keying blind.
// Clients poll this endpoint periodically (same cadence as ClubDiscoverer)
// and update the admin-only UI (theme preview menu, etc.) live, instead of
// only ever checking once at process start from the static key field.
func (h *handler) apiWhoAmI(w http.ResponseWriter, r *http.Request) {
	tok := r.Header.Get("X-Session")
	if tok == "" {
		jsonErr(w, "X-Session required", http.StatusUnauthorized)
		return
	}
	username, _, _, denied := h.sessions.Validate(tok)
	if username == "" || denied {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	user, err := h.db.findUser(username)
	if err != nil {
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	isAdmin := user != nil && user.Role == "admin"
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"is_admin": isAdmin}) //nolint:errcheck
}

func (h *handler) apiClubKey(w http.ResponseWriter, r *http.Request) {
	tok := r.Header.Get("X-Session")
	if tok == "" {
		jsonErr(w, "X-Session required", http.StatusUnauthorized)
		return
	}
	username, _, _, denied := h.sessions.Validate(tok)
	if username == "" || denied {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	club, err := h.db.ClubBySlug(r.URL.Query().Get("club"))
	if err != nil {
		jsonErr(w, "unknown club", http.StatusBadRequest)
		return
	}

	user, err := h.db.getOrCreateUser(username)
	if err != nil {
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	ok, err := h.db.HasClubAccess(club.ID, user.ID)
	if err != nil {
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		jsonErr(w, "not a member", http.StatusForbidden)
		return
	}

	key, err := h.db.ClubManifestKey(club.ID)
	if err != nil {
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Membership number belongs to whichever club actually granted this
	// user access -- for a direct grant that's club.ID itself; for access
	// via subsumption (e.g. an Elite member reading Cat Club's key) it's
	// the *subsuming* club's number, since that's the membership that
	// actually exists for this user (they may hold no direct Cat Club
	// grant at all). membership_club in the response tells the client
	// which of the two it actually is, so the badge shows the right tier.
	respClub := club
	num, hasNum, err := h.db.MembershipNumber(club.ID, user.ID)
	if err != nil {
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !hasNum {
		clubs, cerr := h.db.AllClubs()
		if cerr != nil {
			jsonErr(w, "internal error", http.StatusInternalServerError)
			return
		}
		for _, c := range clubs {
			if !c.SubsumesClubID.Valid || c.SubsumesClubID.Int64 != club.ID {
				continue
			}
			if n, ok, merr := h.db.MembershipNumber(c.ID, user.ID); merr == nil && ok {
				num, hasNum, respClub = n, true, &c
				break
			}
		}
	}

	resp := map[string]interface{}{"club": club.Slug, "key": key}
	if hasNum {
		resp["membership_number"] = num
		resp["membership_club"] = respClub.Slug
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

// apiClubRecommend handles POST /api/club-recommend — the client-app
// equivalent of the /my/club/recommend web form (see my_club.go), for
// callers that only have a tunnel session token (X-Session), not a browser
// cookie. Body: {"target_username": "..."}. Always recommends for Cat Club
// (the only club with a recommendation path today — same restriction the
// web form has, see db_clubs.go's RecThresholdCat/RecThresholdElite).
// Gated on the caller already having Cat Club access themselves, same as
// the web form's userCanRecommend check.
func (h *handler) apiClubRecommend(w http.ResponseWriter, r *http.Request) {
	tok := r.Header.Get("X-Session")
	if tok == "" {
		jsonErr(w, "X-Session required", http.StatusUnauthorized)
		return
	}
	username, _, _, denied := h.sessions.Validate(tok)
	if username == "" || denied {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var body struct {
		TargetUsername string `json:"target_username"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	target := body.TargetUsername
	if target == "" {
		jsonErr(w, "target_username required", http.StatusBadRequest)
		return
	}
	if strings.EqualFold(target, username) {
		jsonErr(w, "cannot recommend yourself", http.StatusBadRequest)
		return
	}

	recommender, err := h.db.getOrCreateUser(username)
	if err != nil {
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	catClub, err := h.db.ClubBySlug("cat_club")
	if err != nil {
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	if ok, err := h.db.HasClubAccess(catClub.ID, recommender.ID); err != nil {
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	} else if !ok {
		jsonErr(w, "not a member", http.StatusForbidden)
		return
	}

	targetUser, err := h.db.findUser(target)
	if err != nil {
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	if targetUser == nil {
		jsonErr(w, "no account with that username", http.StatusNotFound)
		return
	}
	if err := h.db.RecommendClubMembership(catClub.ID, targetUser.ID, recommender.ID); err != nil {
		logWarnf("club-recommend: %s -> %s: %v", username, target, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	logInfof("club-recommend: %s recommended %s for Cat Club", username, target)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck
}
