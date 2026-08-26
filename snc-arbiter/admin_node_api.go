// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// apiAdminNodeRegister handles POST /api/admin/node.
// Creates a node, immediately approves it, and optionally SSH-deploys it.
// Requires admin session.
func (h *handler) apiAdminNodeRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type                string `json:"type"`
		SSHHost             string `json:"ssh_host"`    // IP for SSH deploy; addr = ssh_host:443
		SSHUser             string `json:"ssh_user"`    // SSH login account; empty = "root"
		Addr                string `json:"addr"`        // explicit addr (used when ssh_host is empty)
		Fingerprint         string `json:"fingerprint"` // optional, manual flow
		Pubkey              string `json:"pubkey"`
		Description         string `json:"description"`
		AuthMethod          string `json:"auth_method"` // "password" | "key" | "" (no deploy)
		Password            string `json:"password"`
		PrivKey             string `json:"priv_key"`
		ProviderSlug        string `json:"provider_slug"`        // optional, e.g. "yandex-cloud" -- machine-readable, distinct from the human-entered "provider" display field
		ProviderInstanceID  string `json:"provider_instance_id"` // optional, hoster's own internal machine/instance id
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Type != "control" && req.Type != "exit" && req.Type != "navlink_mirror" {
		jsonErr(w, "type must be 'control', 'exit', or 'navlink_mirror'", http.StatusBadRequest)
		return
	}

	u := h.currentUser(r)
	var ownerID int64
	if u != nil {
		ownerID = u.ID
	} else {
		// X-Admin-Token auth: no session user; assign to the first admin account.
		ownerID = h.db.firstAdminUserID()
	}
	var id int64
	var err error
	addr := req.Addr

	if req.SSHHost != "" {
		// SSH-provisioned path: create node with ssh_host; addr derived automatically.
		id, err = h.db.submitNodeSSH(ownerID, req.Type, req.SSHHost, req.SSHUser, req.Description, req.ProviderSlug, req.ProviderInstanceID)
		addr = req.SSHHost + ":443"
	} else {
		if addr == "" {
			jsonErr(w, "ssh_host or addr required", http.StatusBadRequest)
			return
		}
		id, err = h.db.submitNode(ownerID, req.Type, addr, req.Fingerprint, req.Pubkey, req.Description, req.ProviderSlug, req.ProviderInstanceID)
	}
	if err != nil {
		logWarnf("apiAdminNodeRegister: submitNode: %v", err)
		jsonErr(w, "database error", http.StatusInternalServerError)
		return
	}

	token, err := h.db.approveNode(id)
	if err != nil {
		logWarnf("apiAdminNodeRegister: approveNode %d: %v", id, err)
		jsonErr(w, "approval failed", http.StatusInternalServerError)
		return
	}

	// Bind this node to a country the moment it exists, not by hand afterward.
	// RegionOverride is what country-scoped policy actually reads
	// (service_region_blocks, geo-filtered exit picking, PickForClient's
	// same-country exclusion) -- location/provider below are display-only.
	// Doing this here, server-side, means it fires for every registration
	// path (deploy.sh --setup, the admin dashboard's manual "add node" form,
	// any future automation) instead of living in one particular client tool.
	// regionOf uses the arbiter's own CIDR/ASN buckets (RU/EU/US/CN/IR/OTHER
	// -- see admin_service_blocks.go's allowed set), the same source
	// PickForClient's region filter already trusts, so this can't disagree
	// with the rest of the system the way a second, external geoip source
	// (e.g. deploy.sh's old ip-api.com call) occasionally would.
	// Best-effort: an empty/unknown region or a DB error here must not fail
	// registration -- the node still works, just without country-scoped
	// policy applying to it until someone sets RegionOverride by hand.
	if region := h.regionOf(addr); region != "" {
		if err := h.db.setNodeRegionOverride(id, region); err != nil {
			logWarnf("apiAdminNodeRegister: setNodeRegionOverride %d region=%s: %v", id, region, err)
		} else {
			logInfof("admin: node %d auto-bound to region=%s (CIDR/ASN lookup on %s)", id, region, addr)
		}
	} else {
		logWarnf("admin: node %d addr=%s — no CIDR/ASN match, RegionOverride not auto-set (non-fatal)", id, addr)
	}

	if h.notifier != nil {
		h.notifier.NotifyAll()
	}

	// Kick off SSH deploy if credentials were provided.
	if req.SSHHost != "" && req.AuthMethod != "" && h.provisioner != nil {
		h.provisioner.EnqueueFull(id, req.AuthMethod, req.Password, []byte(req.PrivKey))
	}

	logInfof("admin: registered+approved node id=%d type=%s addr=%s token=%.8s...", id, req.Type, addr, token)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
		"id":        id,
		"token":     token,
		"type":      req.Type,
		"addr":      addr,
		"deploying": req.SSHHost != "" && req.AuthMethod != "",
	})
}

// apiAdminNodeApprove handles POST /api/admin/node/{id}/approve.
// Approves a pending node and returns its token.
// Requires admin session.
func (h *handler) apiAdminNodeApprove(w http.ResponseWriter, r *http.Request) {
	// Path: /api/admin/node/{id}/approve
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 5 || parts[4] != "approve" {
		http.NotFound(w, r)
		return
	}
	nodeID, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		jsonErr(w, "bad node id", http.StatusBadRequest)
		return
	}
	token, err := h.db.approveNode(nodeID)
	if err != nil {
		logWarnf("apiAdminNodeApprove %d: %v", nodeID, err)
		jsonErr(w, "approval failed: node not found or not pending", http.StatusNotFound)
		return
	}
	if h.notifier != nil {
		h.notifier.NotifyAll()
	}
	// If the node was SSH-provisioned and is waiting for a token, push it now.
	if h.provisioner != nil {
		h.provisioner.EnqueueTokenPush(nodeID)
	}
	logInfof("admin: approved node %d token=%.8s...", nodeID, token)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token}) //nolint:errcheck
}

// apiAdminNodeUpdate handles POST /api/admin/node/{id}/update.
// Updates addr and/or description of an existing node.
// Requires admin session or X-Admin-Token header.
func (h *handler) apiAdminNodeUpdate(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// parts: ["api","admin","node","{id}","update"]
	if len(parts) != 5 || parts[4] != "update" {
		jsonErr(w, "not found", http.StatusNotFound)
		return
	}
	nodeID, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		jsonErr(w, "bad node id", http.StatusBadRequest)
		return
	}
	var req struct {
		Addr               string `json:"addr"`
		Description        string `json:"description"`
		Location           string `json:"location"` // "country, city" -- shown next to the address everywhere
		Provider           string `json:"provider"` // hosting company (human-entered display string)
		ProviderSlug       string `json:"provider_slug"`        // optional, machine-readable, e.g. "yandex-cloud"
		ProviderInstanceID string `json:"provider_instance_id"` // optional, hoster's own internal machine/instance id
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Addr == "" {
		jsonErr(w, "addr required", http.StatusBadRequest)
		return
	}
	if err := h.db.updateNode(nodeID, req.Addr, req.Description, req.Location, req.Provider, req.ProviderSlug, req.ProviderInstanceID); err != nil {
		logWarnf("apiAdminNodeUpdate %d: %v", nodeID, err)
		jsonErr(w, "database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if h.notifier != nil {
		h.notifier.NotifyAll()
	}
	logInfof("admin: updated node %d addr=%s desc=%q location=%q provider=%q", nodeID, req.Addr, req.Description, req.Location, req.Provider)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck
}

// apiAdminNodeDelete handles POST /api/admin/node/{id}/delete.
// Deletes a node by ID. Returns JSON {"ok":true} on success.
// Requires admin session or X-Admin-Token header.
func (h *handler) apiAdminNodeDelete(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// parts: ["api","admin","node","{id}","delete"]
	if len(parts) != 5 || parts[4] != "delete" {
		jsonErr(w, "not found", http.StatusNotFound)
		return
	}
	nodeID, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		jsonErr(w, "bad node id", http.StatusBadRequest)
		return
	}
	// Best-effort SSH teardown (stop+disable the service) before the DB row disappears.
	// Snapshot the fields the teardown job needs — the row is gone by the time it runs.
	if h.provisioner != nil {
		if info, infoErr := h.db.getNodeProvisionInfo(nodeID); infoErr == nil {
			h.provisioner.EnqueueTeardown(nodeID, info.SSHHost, info.SSHUser, info.Type)
		}
	}
	if err := h.db.deleteNode(nodeID); err != nil {
		logWarnf("apiAdminNodeDelete %d: %v", nodeID, err)
		jsonErr(w, "database error", http.StatusInternalServerError)
		return
	}
	if h.notifier != nil {
		h.notifier.NotifyAll()
	}
	logInfof("admin: deleted node %d via JSON API", nodeID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck
}

// apiAdminNodeDecommission handles POST /api/admin/node/{id}/decommission.
// Stops+disables the node's service (same SSH teardown as delete) but marks
// the row status='decommissioned' instead of removing it — preserving its
// history for network-wide stats attribution. See db.decommissionNode's
// comment for why hard-deleting a node with real traffic history is wrong.
// Use this for any node that has actually been live (has real node_traffic
// samples); reserve apiAdminNodeDelete for cleaning up bogus/never-deployed
// registrations with nothing worth preserving.
// Requires admin session or X-Admin-Token header.
func (h *handler) apiAdminNodeDecommission(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// parts: ["api","admin","node","{id}","decommission"]
	if len(parts) != 5 || parts[4] != "decommission" {
		jsonErr(w, "not found", http.StatusNotFound)
		return
	}
	nodeID, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		jsonErr(w, "bad node id", http.StatusBadRequest)
		return
	}
	if h.provisioner != nil {
		if info, infoErr := h.db.getNodeProvisionInfo(nodeID); infoErr == nil {
			h.provisioner.EnqueueTeardown(nodeID, info.SSHHost, info.SSHUser, info.Type)
		}
	}
	if err := h.db.decommissionNode(nodeID); err != nil {
		logWarnf("apiAdminNodeDecommission %d: %v", nodeID, err)
		jsonErr(w, "database error", http.StatusInternalServerError)
		return
	}
	if h.notifier != nil {
		h.notifier.NotifyAll()
	}
	logInfof("admin: decommissioned node %d via JSON API", nodeID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck
}

// apiGeoIP handles GET /api/geoip?ip=<addr>.
// Returns the ISO region code for the given IP using the loaded CIDR buckets.
// Authenticated by X-Node-Token (any approved node may call this).
func (h *handler) apiGeoIP(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Node-Token")
	node, err := h.db.nodeByToken(token)
	if err != nil || node == nil {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		jsonErr(w, "ip required", http.StatusBadRequest)
		return
	}
	region := h.regionOf(ip)
	logInfof("geoip: ip=%s region=%q caller=%s", ip, region, node.Addr)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"region": region}) //nolint:errcheck
}

// apiNodeValidate handles POST /api/node/validate.
// An exit node posts another node's token; the arbiter confirms whether it belongs
// to a live approved node and returns its type and address.
// Used by Exit2 to authenticate peer forwarding requests from Exit1.
func (h *handler) apiNodeValidate(w http.ResponseWriter, r *http.Request) {
	// Caller must itself be an approved node.
	callerToken := r.Header.Get("X-Node-Token")
	caller, err := h.db.nodeByToken(callerToken)
	if err != nil || caller == nil {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		jsonErr(w, "token required", http.StatusBadRequest)
		return
	}

	peer, err := h.db.nodeByToken(req.Token)
	if err != nil || peer == nil || !peer.IsOnline() {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"valid": false}) //nolint:errcheck
		return
	}

	logInfof("node-validate: caller=%.8s… peer=%.8s… type=%s addr=%s", callerToken, req.Token, peer.Type, peer.Addr)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
		"valid": true,
		"type":  peer.Type,
		"addr":  peer.Addr,
	})
}

// apiAdminNodeList handles GET /api/admin/nodes.
// Returns all nodes (all statuses) with full details including tokens.
// Requires admin session.
func (h *handler) apiAdminNodeList(w http.ResponseWriter, r *http.Request) {
	all, err := h.db.listAllNodes()
	if err != nil {
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	type nodeOut struct {
		ID          int64   `json:"id"`
		Type        string  `json:"type"`
		Addr        string  `json:"addr"`
		Status      string  `json:"status"`
		Token       string  `json:"token,omitempty"`
		Fingerprint string  `json:"fingerprint,omitempty"`
		Description string  `json:"description,omitempty"`
		Location    string  `json:"location,omitempty"`
		Provider    string  `json:"provider,omitempty"`
		Online      bool    `json:"online"`
		RTTms       float64 `json:"rtt_ms,omitempty"`
		Pinned      bool    `json:"pinned,omitempty"`
		NodeUID             string `json:"node_uid,omitempty"`
		ProviderSlug        string `json:"provider_slug,omitempty"`
		ProviderInstanceID  string `json:"provider_instance_id,omitempty"`
	}
	out := make([]nodeOut, 0, len(all))
	for _, n := range all {
		// IsOnline() only checks heartbeat freshness, not status -- fine for
		// every other caller (they all pre-filter to approved/suspended
		// nodes upstream), but this endpoint returns EVERY status including
		// decommissioned/rejected. Without this guard a decommissioned node
		// whose service kept sending heartbeats right up to the moment it
		// was torn down could show a green "online" dot in the dashboard
		// next to the word "decommissioned" for up to heartbeatTTL after
		// teardown -- confirmed live 2026-08-19 during a Yandex node
		// destroy+recreate rotation.
		online := (n.Status == "approved" || n.Status == "suspended") && n.IsOnline()
		out = append(out, nodeOut{
			ID:          n.ID,
			Type:        n.Type,
			Addr:        n.Addr,
			Status:      n.Status,
			Token:       n.Token,
			Fingerprint: n.Fingerprint,
			Description: n.Description,
			Location:    n.Location,
			Provider:    n.Provider,
			Online:      online,
			RTTms:       n.RTTms,
			Pinned:      n.Pinned,
			NodeUID:             n.NodeUID,
			ProviderSlug:        n.ProviderSlug,
			ProviderInstanceID:  n.ProviderInstanceID,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"nodes": out}) //nolint:errcheck
}

// apiNodeDeployStatus handles GET /api/nodes/{id}/deploy-status.
// Returns deploy status for nodes owned by the current user.
func (h *handler) apiNodeDeployStatus(w http.ResponseWriter, r *http.Request) {
	u := h.currentUser(r)
	var ownerID int64
	if u != nil {
		ownerID = u.ID
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 {
		jsonErr(w, "bad path", http.StatusBadRequest)
		return
	}
	nodeID, err := strconv.ParseInt(parts[len(parts)-2], 10, 64)
	if err != nil {
		jsonErr(w, "bad node id", http.StatusBadRequest)
		return
	}
	status, log, err := h.db.getDeployStatus(nodeID, ownerID)
	if err != nil {
		jsonErr(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
		"status": status,
		"log":    log,
		"done":   status == "done" || status == "failed" || status == "token_pending",
	})
}

// apiAdminNodeDeployStatus handles GET /admin/api/nodes/{id}/deploy-status.
// Admin can view deploy status of any node.
func (h *handler) apiAdminNodeDeployStatus(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 {
		jsonErr(w, "bad path", http.StatusBadRequest)
		return
	}
	nodeID, err := strconv.ParseInt(parts[len(parts)-2], 10, 64)
	if err != nil {
		jsonErr(w, "bad node id", http.StatusBadRequest)
		return
	}
	status, log, err := h.db.getDeployStatusAdmin(nodeID)
	if err != nil {
		jsonErr(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
		"status": status,
		"log":    log,
		"done":   status == "done" || status == "failed" || status == "token_pending",
	})
}

// ── POST /admin/api/nodes/{id}/sni-list ──────────────────────────────────────

// apiAdminNodeSetSNIList sets the SNI rotation list for a control node.
// Body: {"snis": ["example.com", "other.com"]}
// Send an empty array to clear.
func (h *handler) apiAdminNodeSetSNIList(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	logInfof("apiAdminNodeSetSNIList: path=%s parts=%v", r.URL.Path, parts)
	if len(parts) < 2 {
		jsonErr(w, "bad path", http.StatusBadRequest)
		return
	}
	nodeID, err := strconv.ParseInt(parts[len(parts)-2], 10, 64)
	if err != nil {
		jsonErr(w, "bad node id", http.StatusBadRequest)
		return
	}
	var req struct {
		SNIs []string `json:"snis"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	var clean []string
	for _, s := range req.SNIs {
		if v := strings.TrimSpace(s); v != "" {
			clean = append(clean, v)
		}
	}
	sniList := strings.Join(clean, ",")
	if err := h.db.setNodeSNIList(nodeID, sniList); err != nil {
		logWarnf("apiAdminNodeSetSNIList node=%d: %v", nodeID, err)
		jsonErr(w, "database error", http.StatusInternalServerError)
		return
	}
	logInfof("admin: SNI list for node %d set to %q", nodeID, sniList)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck
}
