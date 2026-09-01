// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"net/http"
	"time"
)

// manifest_topup_api.go — on-demand, one-node-at-a-time supplement to the
// manifest system. Added 2026-08-19 for clients that currently have fewer
// than their target live-control count (client-side threshold, today 12):
// rather than waiting on the next full manifest refresh, the client asks
// here for exactly one control it doesn't already have, checks it (e2e TCP
// probe, client-side), and asks again if still short -- until it either
// reaches the target or this endpoint reports the pool exhausted.
//
// Reachable at https://navlink.net/api/manifest/topup regardless of tunnel
// state -- same web-plane reachability model as apiManifestClientFetch
// (manifest_client_api.go), and for the same reason: a client that's short
// on live controls may have no tunnel at all to route a request through.
//
// State ("which nodes has this client already tried") lives entirely
// client-side, as a rolling 5-minute window -- the request re-sends its
// current exclude list every call, so the arbiter stays fully stateless
// here. A node the client excluded 5+ minutes ago will be sent again on a
// later call once the client's own window has aged it out, deliberately:
// conditions (rotation, a node coming back up) can change in that time.
//
// Deliberately a standalone file, not a variant of apiManifestClientFetch
// or handleKeyAuth -- same isolation rationale both of those already state
// in their own doc comments: a bug in this newer, less-tested endpoint
// should never be able to reach the general manifest pipeline or the real
// key-auth login path client connections depend on.
func (h *handler) apiManifestTopup(w http.ResponseWriter, r *http.Request) {
	if !h.manifestTopupLimiter.Allow(clientIP(r),
		limitTier{Window: 10 * time.Second, Max: 5},
		limitTier{Window: time.Hour, Max: 200},
	) {
		jsonErr(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	var req struct {
		Username      string   `json:"username"`
		Servers       []string `json:"servers"`
		ControlNodes  []string `json:"control_nodes"`
		ArbiterPubkey string   `json:"arbiter_pubkey"`
		NodeID        string   `json:"node_id"`
		APIKey        string   `json:"api_key"`
		ClientID      string   `json:"client_id"`
		KeyID         string   `json:"key_id"`
		AuthSig       string   `json:"auth_sig"`
		Exclude       []string `json:"exclude"` // control addrs tried in the client's trailing 5-minute window
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Username == "" || req.AuthSig == "" {
		jsonErr(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Same AuthSig verification as authenticateKey (handler.go's
	// handleKeyAuth) -- the client authenticates each topup call with the
	// same SNC key it uses to log in to a control, no session token needed
	// (a client with zero live controls has no session to reuse either).
	// Re-implemented rather than shared -- see file doc comment.
	authCanon, err := json.Marshal(keyPayloadAuthCanonical{
		Username:      req.Username,
		Servers:       req.Servers,
		ControlNodes:  req.ControlNodes,
		ArbiterPubkey: req.ArbiterPubkey,
		NodeID:        req.NodeID,
		APIKey:        req.APIKey,
		ClientID:      req.ClientID,
		KeyID:         req.KeyID,
	})
	if err != nil {
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(req.AuthSig)
	if err != nil || !ed25519.Verify(h.signer.pub, authCanon, sigBytes) {
		logInfof("manifest-topup: invalid AuthSig user=%s ip=%s", req.Username, clientIP(r))
		jsonErr(w, "invalid key", http.StatusUnauthorized)
		return
	}

	excluded := make(map[string]bool, len(req.Exclude))
	for _, a := range req.Exclude {
		excluded[a] = true
	}

	pool, err := h.db.liveNodes("control")
	if err != nil {
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Club members draw from their club's dedicated control set too --
	// additional to the general pool, never instead of it (see
	// docs/club-membership.md). A non-member's pool is exactly the general
	// population, same as the regular manifest.
	if user, uerr := h.db.getOrCreateUser(req.Username); uerr == nil && user != nil {
		if clubs, cerr := h.db.AllClubs(); cerr == nil {
			for _, c := range clubs {
				ok, aerr := h.db.HasClubAccess(c.ID, user.ID)
				if aerr != nil || !ok {
					continue
				}
				if clubNodes, nerr := h.db.ClubNodes(c.ID, "control"); nerr == nil {
					pool = append(pool, clubNodes...)
				}
			}
		}
	}

	var candidates []Node
	for _, n := range pool {
		if !excluded[n.Addr] {
			candidates = append(candidates, n)
		}
	}
	if len(candidates) == 0 {
		logInfof("manifest-topup: exhausted user=%s pool=%d excluded=%d", req.Username, len(pool), len(req.Exclude))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"exhausted": true}) //nolint:errcheck
		return
	}

	picked := candidates[rand.Intn(len(candidates))] //nolint:gosec // node selection, not a security decision
	logInfof("manifest-topup: serving user=%s node=%s (pool=%d excluded=%d)", req.Username, picked.Addr, len(pool), len(req.Exclude))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(NodeEntry{ //nolint:errcheck
		Addr:        picked.Addr,
		Fingerprint: picked.Fingerprint,
		RTTms:       picked.RTTms,
		Load:        picked.Load,
		DataPlaneOK: picked.DataPlaneOK,
	})
}
