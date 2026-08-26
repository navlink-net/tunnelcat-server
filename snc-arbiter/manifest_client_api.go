// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/json"
	"net/http"
	"time"
)

// checkManifestClientKey gates apiManifestClientFetch with the same shared
// bearer key every other client-facing telemetry endpoint uses (see
// client_telemetry_key.go / checkClientOrLegacyKey). The manifest content
// itself is self-authenticating (Ed25519 signature, verified client-side
// against the arbiter pubkey baked into the binary) -- this key isn't
// protecting the content, it's keeping the endpoint off generic scanner/
// search-engine reach, matching the threat model already documented for
// app-log/bananameter/log-upload/conn-stats.
func (h *handler) checkManifestClientKey(r *http.Request) bool {
	return h.checkClientOrLegacyKey(r, h.clientTelemetryKey)
}

// addNavlinkMirrors populates m.NavlinkMirrors from currently-live
// "navlink_mirror" nodes (see admin_node_api.go's apiAdminNodeRegister and
// the snc-navlink-mirror forwarder binary). Shared by both manifest-serving
// endpoints (apiManifest in handler.go and apiManifestClientFetch below) so
// the field is populated identically regardless of which path a client used
// to fetch its manifest. Best-effort: a DB error here just means the field
// stays empty, same as every other advisory field in SignedList.
func (h *handler) addNavlinkMirrors(m *SignedList) {
	mirrors, err := h.db.liveNodes("navlink_mirror")
	if err != nil || len(mirrors) == 0 {
		return
	}
	addrs := make([]string, 0, len(mirrors))
	for _, n := range mirrors {
		addrs = append(addrs, n.Addr)
	}
	m.NavlinkMirrors = addrs
}

// apiManifestClientFetch handles GET /api/manifest/client -- a manifest
// source reachable at https://navlink.net/api/manifest/client (through the
// public nginx proxy, on the web plane), for clients whose usual path (fetch
// through whichever exit their active tunnel happens to route through, see
// snc-exit's own /api/manifest proxy) is unavailable or exhausted.
//
// Added 2026-08-14 alongside the manifest cert-pinning fix and the
// DialerPool-as-extra-fetch-source change (Discoverer.SetExtraURLsProvider)
// -- same root problem, one more angle: a client stuck with an entirely
// stale/dead cached control list has no exit to route a manifest fetch
// through at all. This endpoint gives it one more independent path that
// doesn't depend on any particular control or exit being reachable --
// only on navlink.net itself, which every client already trusts and talks
// to directly for login/key issuance.
//
// Deliberately mirrors apiManifest's output shape (same maxManifestNodes
// cap, same advisory fields) rather than duplicating it via a shared helper
// -- apiManifest is the exit-facing path real client traffic depends on
// today; this file stays fully separate so a bug here can never touch it.
func (h *handler) apiManifestClientFetch(w http.ResponseWriter, r *http.Request) {
	if !h.checkManifestClientKey(r) {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	ip := clientIP(r)
	if !h.manifestClientLimiter.Allow(ip,
		limitTier{Window: 10 * time.Second, Max: 3},
		limitTier{Window: time.Hour, Max: 60},
	) {
		jsonErr(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	controls, err := h.db.liveNodes("control")
	if err != nil {
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	selected := selectManifestNodes(controls, maxManifestNodes)
	logInfof("manifest-client: serving ip=%s total=%d selected=%d", ip, len(controls), len(selected))

	data, err := h.signer.signList("manifest", selected, h.regionFnWithOverrides(controls))
	if err != nil {
		jsonErr(w, "signing error", http.StatusInternalServerError)
		return
	}

	h.notifMu.RLock()
	notifs := make([]NotificationEntry, len(h.notifCache))
	copy(notifs, h.notifCache)
	h.notifMu.RUnlock()
	if tok := r.Header.Get("X-Session"); tok != "" {
		if username, _, _, _ := h.sessions.Validate(tok); username != "" {
			if userNotifs, err := h.db.activeNotifications(username); err == nil {
				notifs = userNotifs
			}
		}
	}

	var nodeSNIs map[string][]string
	for _, n := range selected {
		if n.SNIList == "" {
			continue
		}
		snis := splitSNIList(n.SNIList)
		if len(snis) == 0 {
			continue
		}
		if nodeSNIs == nil {
			nodeSNIs = make(map[string][]string)
		}
		nodeSNIs[n.Addr] = snis
	}

	var excludedAddrs []string
	if excl, err := h.db.listExcludedNodes(); err == nil && len(excl) > 0 {
		for _, e := range excl {
			excludedAddrs = append(excludedAddrs, e.Addr)
		}
	}

	wlwtpPorts, _ := h.db.allWLWTPPorts()
	var nodeWLWTPPorts map[string][]int
	for _, n := range selected {
		if pts, ok := wlwtpPorts[n.Addr]; ok && len(pts) > 0 {
			if nodeWLWTPPorts == nil {
				nodeWLWTPPorts = make(map[string][]int)
			}
			nodeWLWTPPorts[n.Addr] = pts
		}
	}

	h.loadIPv6State()
	ipv6On := h.ipv6Enabled()
	h.loadTorrentState()
	torrentOn := h.torrentFeatureEnabled()
	{
		var m SignedList
		if err := json.Unmarshal(data, &m); err == nil {
			m.IPv6Enabled = &ipv6On
			m.TorrentEnabled = &torrentOn
			m.TorrentMagnets = h.softwareTorrentMagnets()
			m.TorrentManifestMagnet = h.manifestTorrentMagnet()
			if len(notifs) > 0 {
				m.Notifications = notifs
			}
			if len(nodeSNIs) > 0 {
				m.NodeSNIs = nodeSNIs
			}
			if len(excludedAddrs) > 0 {
				m.Excluded = excludedAddrs
			}
			if len(nodeWLWTPPorts) > 0 {
				m.NodeWLWTPPorts = nodeWLWTPPorts
			}
			h.addNavlinkMirrors(&m)
			if out, err := json.Marshal(m); err == nil {
				data = out
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data) //nolint:errcheck
}
