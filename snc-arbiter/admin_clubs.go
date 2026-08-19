// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"net/http"
	"strconv"
	"strings"
)

// clubAdminView bundles one club's admin-panel data: its config, current
// members (with permanent membership numbers), pending recommendation
// candidates, and the nodes currently dedicated to its manifest.
type clubAdminView struct {
	Club       Club
	Members    []clubMemberRow
	Candidates []PendingRecommendationCandidate
	Nodes      []Node
}

type clubMemberRow struct {
	Username         string
	MembershipNumber int64
}

type clubsPageData struct {
	Clubs        []clubAdminView
	GeneralNodes []Node // nodes with no club_id — the common pool, shown so admin can move one into a club
}

// adminClubsPage renders GET /admin/clubs.
func (h *handler) adminClubsPage(w http.ResponseWriter, r *http.Request) {
	clubs, err := h.db.AllClubs()
	if err != nil {
		logWarnf("admin clubs page: %v", err)
	}
	var views []clubAdminView
	for _, c := range clubs {
		members, err := h.db.ClubMembers(c.ID)
		if err != nil {
			logWarnf("admin clubs page: members for club %d: %v", c.ID, err)
		}
		var rows []clubMemberRow
		for _, username := range members {
			user, err := h.db.getOrCreateUser(username)
			if err != nil {
				continue
			}
			num, ok, err := h.db.MembershipNumber(c.ID, user.ID)
			if err != nil || !ok {
				continue
			}
			rows = append(rows, clubMemberRow{Username: username, MembershipNumber: num})
		}
		candidates, err := h.db.PendingCandidates(c.ID)
		if err != nil {
			logWarnf("admin clubs page: candidates for club %d: %v", c.ID, err)
		}
		nodes, err := h.db.ClubNodesAllStatuses(c.ID)
		if err != nil {
			logWarnf("admin clubs page: nodes for club %d: %v", c.ID, err)
		}
		views = append(views, clubAdminView{Club: c, Members: rows, Candidates: candidates, Nodes: nodes})
	}
	generalNodes, err := h.db.listAllNodes()
	if err != nil {
		logWarnf("admin clubs page: general nodes: %v", err)
	}
	var unassigned []Node
	for _, n := range generalNodes {
		if !n.ClubID.Valid && (n.Type == "control" || n.Type == "exit") {
			unassigned = append(unassigned, n)
		}
	}

	u := h.currentUser(r)
	h.renderPage(w, "admin_clubs.html", pageData{User: u, Data: clubsPageData{Clubs: views, GeneralNodes: unassigned}})
}

// adminClubsInvite handles POST /admin/clubs/invite.
func (h *handler) adminClubsInvite(w http.ResponseWriter, r *http.Request) {
	h.adminClubsAction(w, r, func(clubID, targetID, adminID int64) error {
		return h.db.InviteToClub(clubID, targetID, adminID)
	})
}

// adminClubsGrant handles POST /admin/clubs/grant — the admin's unilateral
// override, usable for either club regardless of the recommendation path.
func (h *handler) adminClubsGrant(w http.ResponseWriter, r *http.Request) {
	h.adminClubsAction(w, r, func(clubID, targetID, adminID int64) error {
		return h.db.GrantClubMembership(clubID, targetID, adminID)
	})
}

// adminClubsRevoke handles POST /admin/clubs/revoke.
func (h *handler) adminClubsRevoke(w http.ResponseWriter, r *http.Request) {
	h.adminClubsAction(w, r, func(clubID, targetID, adminID int64) error {
		return h.db.RevokeClubMembership(clubID, targetID, adminID)
	})
}

// adminClubsAction is the shared body for invite/grant/revoke: parse
// club_id + target_username from the form, resolve the admin's own user
// row for actor_user, run fn, redirect back to /admin/clubs.
func (h *handler) adminClubsAction(w http.ResponseWriter, r *http.Request, fn func(clubID, targetID, adminID int64) error) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	clubID, err := strconv.ParseInt(r.FormValue("club_id"), 10, 64)
	if err != nil {
		http.Error(w, "bad club_id", http.StatusBadRequest)
		return
	}
	target := strings.TrimSpace(r.FormValue("target_username"))
	if target == "" {
		http.Redirect(w, r, "/admin/clubs", http.StatusFound)
		return
	}
	targetUser, err := h.db.getOrCreateUser(target)
	if err != nil {
		logWarnf("admin clubs action: lookup target %s: %v", target, err)
		http.Redirect(w, r, "/admin/clubs", http.StatusFound)
		return
	}
	admin := h.currentUser(r)
	var adminID int64
	adminUsername := "?"
	if admin != nil {
		adminID = admin.ID
		adminUsername = admin.Username
	}
	if err := fn(clubID, targetUser.ID, adminID); err != nil {
		logWarnf("admin clubs action club=%d target=%s: %v", clubID, target, err)
	} else {
		logInfof("admin clubs: club=%d target=%s actor=%s", clubID, target, adminUsername)
	}
	http.Redirect(w, r, "/admin/clubs", http.StatusFound)
}

// adminClubsAssignNode handles POST /admin/clubs/assign-node — moves a node
// into a club's dedicated pool, or back to the general pool (club_id=0).
func (h *handler) adminClubsAssignNode(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	nodeID, err := strconv.ParseInt(r.FormValue("node_id"), 10, 64)
	if err != nil {
		http.Error(w, "bad node_id", http.StatusBadRequest)
		return
	}
	clubID, _ := strconv.ParseInt(r.FormValue("club_id"), 10, 64) // 0 = general pool, deliberately ignoring parse error
	if err := h.db.setNodeClub(nodeID, clubID); err != nil {
		logWarnf("admin clubs: assign node %d to club %d: %v", nodeID, clubID, err)
	} else {
		logInfof("admin clubs: node %d -> club %d", nodeID, clubID)
	}
	http.Redirect(w, r, "/admin/clubs", http.StatusFound)
}
