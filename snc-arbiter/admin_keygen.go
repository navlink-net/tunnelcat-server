// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

const maxKeyControls = 10

type keygenPageData struct {
	Username string
	Region   string
	Regions  []string // known region codes for dropdown
	FullKey  bool
	ClientID string
	Key      string
	Error    string
}

// adminKeygenPage renders GET /admin/key.
func (h *handler) adminKeygenPage(w http.ResponseWriter, r *http.Request) {
	h.renderKeygenPage(w, r, keygenPageData{})
}

// adminKeygenPageSubmit handles POST /admin/key/generate-page (form submit).
// It calls the JSON API internally and renders the result inline.
func (h *handler) adminKeygenPageSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderKeygenPage(w, r, keygenPageData{Error: "bad request"})
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	region := strings.ToUpper(strings.TrimSpace(r.FormValue("region")))
	fullKey := r.FormValue("full_key") != ""
	if username == "" {
		h.renderKeygenPage(w, r, keygenPageData{Error: "username is required", Region: region, FullKey: fullKey})
		return
	}

	source := "admin_keygen_page"
	if fullKey {
		source = "admin_keygen_page_full"
	}
	issued, err := h.issueKeyOpts(username, region, fullKey, source)
	if err != nil {
		logWarnf("keygen-page: issueKey for %s: %v", username, err)
		msg := "key generation failed"
		if err.Error() == "no live control nodes" {
			msg = "no live control nodes — make sure at least one control is online"
		}
		h.renderKeygenPage(w, r, keygenPageData{Error: msg, Username: username, Region: region, FullKey: fullKey})
		return
	}

	h.renderKeygenPage(w, r, keygenPageData{
		Username: username,
		Region:   region,
		FullKey:  fullKey,
		ClientID: issued.ClientID,
		Key:      issued.KeyStr,
	})
}

// pickBootstrapControls returns up to maxKeyControls addresses from nodes,
// applying regional preference when region is non-empty:
//   - Regional controls are always included first (shuffled).
//   - Remaining slots are filled with non-regional controls (shuffled).
//   - When no region is specified: maxKeyControls random nodes from all.
//
// This keeps key strings small at scale while ensuring clients bootstrap
// with controls close to them.
func (h *handler) pickBootstrapControls(nodes []Node, region string) []string {
	addrs := make([]string, len(nodes))
	for i, n := range nodes {
		addrs[i] = n.Addr
	}

	if region == "" {
		// No region preference: shuffle and cap.
		rand.Shuffle(len(addrs), func(i, j int) { addrs[i], addrs[j] = addrs[j], addrs[i] })
		if len(addrs) > maxKeyControls {
			addrs = addrs[:maxKeyControls]
		}
		return addrs
	}

	// Split into regional and non-regional pools.
	var regional, others []string
	for _, addr := range addrs {
		if h.regionOf(addr) == region {
			regional = append(regional, addr)
		} else {
			others = append(others, addr)
		}
	}
	rand.Shuffle(len(regional), func(i, j int) { regional[i], regional[j] = regional[j], regional[i] })
	rand.Shuffle(len(others), func(i, j int) { others[i], others[j] = others[j], others[i] })

	// Regional controls first; fill remaining slots from others.
	result := regional
	if len(result) > maxKeyControls {
		result = result[:maxKeyControls]
	}
	if len(result) < maxKeyControls {
		need := maxKeyControls - len(result)
		if len(others) < need {
			need = len(others)
		}
		result = append(result, others[:need]...)
	}
	return result
}

func (h *handler) renderKeygenPage(w http.ResponseWriter, r *http.Request, data keygenPageData) {
	u := h.currentUser(r)
	flash := data.Error
	data.Error = ""
	data.Regions = h.cidrSt.knownRegions()
	h.renderPage(w, "admin_keygen.html", pageData{User: u, Data: data, Flash: flash})
}

// issuedKey is the result of a successful key generation.
type issuedKey struct {
	KeyStr   string
	KeyID    string
	ClientID string
}

// issueKey generates, signs and registers a new key for username.
// region biases bootstrap control selection toward nearby nodes. source
// records which UI/endpoint triggered issuance (see KeyRow.Source).
func (h *handler) issueKey(username, region, source string) (*issuedKey, error) {
	return h.issueKeyOpts(username, region, false, source)
}

// issueKeyOpts is issueKey with the option to embed every live control node
// instead of the usual region-biased, maxKeyControls-capped subset. Used for
// admin-issued "full" keys (e.g. for staff/monitoring accounts that should
// never be stranded if their regional controls go down).
func (h *handler) issueKeyOpts(username, region string, fullKey bool, source string) (*issuedKey, error) {
	u, err := h.db.getOrCreateUser(username)
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	controls, err := h.db.bootstrapNodes("control")
	if err != nil || len(controls) == 0 {
		return nil, fmt.Errorf("no live control nodes")
	}
	var nodes []string
	if fullKey {
		nodes = make([]string, len(controls))
		for i, n := range controls {
			nodes[i] = n.Addr
		}
	} else {
		nodes = h.pickBootstrapControls(controls, region)
	}
	keyID := uuid.New().String()
	p := &keyPayload{
		Username:      username,
		ControlNodes:  nodes,
		ArbiterPubkey: h.signer.pubkeyHex(),
		ClientID:      u.ClientID,
		KeyID:         keyID,
		IsAdmin:       u.Role == "admin",
	}
	ks, err := buildSignedKey(p, h.signer.priv)
	if err != nil {
		return nil, fmt.Errorf("build key: %w", err)
	}
	if err := h.db.RegisterKey(keyID, username, source); err != nil {
		logWarnf("issueKey: RegisterKey %s/%s: %v", keyID, username, err)
	}
	logInfof("issueKey: user=%s client_id=%s key_id=%.8s… region=%q", username, u.ClientID, keyID, region)
	return &issuedKey{KeyStr: ks, KeyID: keyID, ClientID: u.ClientID}, nil
}

// adminGenerateKey is the JSON API endpoint (called by curl / scripts).
// POST /admin/key/generate  →  {"key":"...","client_id":"...","key_id":"..."}
// Auth: admin session cookie OR X-Admin-Token header (same token as /api/admin/keys).
func (h *handler) adminGenerateKey(w http.ResponseWriter, r *http.Request) {
	isAdminToken := h.checkAdminAPIToken(r)
	if !isAdminToken {
		u := h.currentUser(r)
		if u == nil || u.Role != "admin" {
			jsonErr(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}
	var req struct {
		Username string `json:"username"`
		Region   string `json:"region"`
		FullKey  bool   `json:"full_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
		jsonErr(w, "username required", http.StatusBadRequest)
		return
	}
	req.Region = strings.ToUpper(strings.TrimSpace(req.Region))
	source := "admin_api"
	if req.FullKey {
		source = "admin_api_full"
	}
	issued, err := h.issueKeyOpts(req.Username, req.Region, req.FullKey, source)
	if err != nil {
		logWarnf("keygen: issueKey for %s: %v", req.Username, err)
		status := http.StatusInternalServerError
		if err.Error() == "no live control nodes" {
			status = http.StatusServiceUnavailable
		}
		jsonErr(w, err.Error(), status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"key": issued.KeyStr, "client_id": issued.ClientID, "key_id": issued.KeyID}) //nolint:errcheck
}
