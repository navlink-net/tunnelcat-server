// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// checkLogUploadClientKey mirrors checkBananameterClientKey's shape: a
// single shared secret embedded in every client build, deliberately
// separate from appLogKey/uploadKey/bananameterClientKey so a key extracted
// from a client binary can only ever write device logs, nothing else.
// Node identity (X-Node-ID/X-Node-Type) is self-reported, same trust model
// the old control-relayed /api/log/upload path already had -- that path
// never authenticated the originating client either, only the relaying
// control/exit's own node token.
func (h *handler) checkLogUploadClientKey(r *http.Request) bool {
	return h.checkClientOrLegacyKey(r, h.logUploadClientKey)
}

// apiLogClientUpload handles POST /api/log/client-upload -- a client's own
// device-log ring buffer, gzip-compressed, sent directly over its live
// tunnel dialer to navlink.net (see tunnel_cat/snc/core/log_upload.go).
//
// Replaces the old client -> control's relay-API channel -> a randomly
// picked exit -> arbiter path (snc-control/relay_api.go's logUpload,
// removed 2026-08-11): that path was hop-by-hop TLS only, so both the
// control and the exit that happened to relay a given upload saw the full
// decompressed log content in plaintext -- found after a raw third-party OAuth token
// turned up in cleartext in a real user's uploaded logs. Reaching the
// arbiter directly over the client's own tunnel is genuinely end-to-end:
// neither control nor exit ever holds the plaintext.
//
// Must be registered on the :8080 web plane (see the case in web_handler.go
// and its comment) -- end-user clients only ever reach the arbiter via
// https://navlink.net/..., never :443 directly. This is the exact same
// dual-listener trap that silently dropped every client bananameter result
// for a while (see that case's comment) before being caught; registering
// here proactively rather than discovering it the same way.
//
// 2026-08-15 binary log format transition: as of this date, uploads carry
// an X-Log-Format header ("bin1" for a bare binlog-framed gzip stream, see
// tunnel_cat/binlog and tunnel_cat/snc/core/log_upload.go; absent for
// legacy plain text). This handler deliberately does NOT decode, inspect,
// or otherwise touch the payload based on that header -- it's stored
// exactly as received, same as every upload before this transition existed.
//
// An earlier version of this handler *did* gunzip and re-encode bin1
// uploads here, specifically so a plain zcat/grep against any stored file
// would always show text, whether the originating client was old or new.
// That traded a real cost for that convenience: decompressing a client's
// gzip on the arbiter is new exposure that never existed before (Store()
// has always just written whatever bytes it's given, for any format),
// gated behind a key whose trust model already assumes it can leak from a
// client binary (see checkLogUploadClientKey above) -- i.e. an attacker
// with that key could target the arbiter's decompression step directly,
// on every single upload, on the hot ingest path. Bounding the
// decompressed size closed the immediate decompression-bomb risk but
// didn't remove the underlying question: why does the arbiter need to
// understand this payload's content at all, just to store it? It doesn't.
// Reading a bin1-framed file back to plain text is exactly what
// tools/decode_snc_log.py is for -- run on demand, off the ingest path,
// against a downloaded/mounted file, where a decode bug or an oversized
// payload costs nothing beyond that one investigation. See that script's
// docstring for usage; it gunzips its input automatically.
//
// 2026-08-16: "zip1" is the one deliberate, narrow exception to "never
// touch the payload" above. It's a two-member zip archive ("log" + small
// "stats", see LogUploader.upload) specifically so a caller here can open
// just the "stats" member via zip's central directory -- the "log" member's
// bytes are never read or decompressed, so the hot-path exposure this
// comment otherwise argues against never applies to it. "stats" itself is
// bounded tightly (see log_client_stats.go's maxStatsEntryBytes) and holds
// only small structured records, never arbitrary log content.
func (h *handler) apiLogClientUpload(w http.ResponseWriter, r *http.Request) {
	if !h.checkLogUploadClientKey(r) {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	nodeID := r.Header.Get("X-Node-ID")
	if nodeID == "" {
		jsonErr(w, "X-Node-ID required", http.StatusBadRequest)
		return
	}
	nodeType := r.Header.Get("X-Node-Type")
	if !validNodeType(nodeType) {
		nodeType = "android" // legacy fallback, matches apiLogUpload
	}
	logFormat := r.Header.Get("X-Log-Format")
	if logFormat == "" {
		logFormat = "text" // legacy client, no header at all
	}

	data, err := io.ReadAll(io.LimitReader(r.Body, int64(nodeLogMaxLen)+1))
	if err != nil {
		jsonErr(w, "read error", http.StatusBadRequest)
		return
	}

	// Best-effort: resolve the account this device belongs to (from
	// client_conn_stats, which self-reports username alongside the same
	// X-Node-ID) so storage is organized per user, not just per anonymous
	// device -- see nodeLogStore's doc comment. "" (unresolved) falls back
	// to the old nodeID-keyed layout; this never blocks or fails the
	// upload either way.
	username := h.db.usernameForDeviceID(nodeID)

	// Log-upload privacy toggles (global kill switch + per-user preference
	// + staff override, see db.go's logUploadAllowed) -- checked here, not
	// just left to the client's own judgment, so a client that uploads
	// anyway (stale build, bug, or deliberate bypass) still gets refused.
	// Local on-device logging and a manual Share-Logs export are NOT
	// gated by this -- only this automatic background path. See
	// docs/LOG_UPLOAD_PRIVACY.md.
	if !h.db.logUploadAllowed(username) {
		logInfof("log-client-upload: refused (log upload disabled) type=%s node=%.16s… user=%s", nodeType, nodeID, username)
		jsonErr(w, "log upload disabled for this account", http.StatusForbidden)
		return
	}

	if err := h.logs.Store(nodeType, nodeID, username, data); err != nil {
		logWarnf("log-client-upload: store type=%s node=%.16s…: %v", nodeType, nodeID, err)
		jsonErr(w, "store error", http.StatusInternalServerError)
		return
	}

	// zip1 uploads carry a small, separate "stats" member alongside the
	// main (untouched, never-decompressed) "log" one -- see
	// log_client_stats.go. Only that one small entry is opened here.
	if logFormat == "zip1" {
		if addrs := controlDeadAddrsFromClientUpload(data); len(addrs) > 0 {
			if err := h.db.recordUnreachableEvents("client", "control", addrs, time.Now().Unix()); err != nil {
				logWarnf("log-client-upload: record unreachable controls node=%.16s…: %v", nodeID, err)
			}
		}
	}

	logInfof("log-client-upload: stored type=%s node=%.16s… user=%s format=%s size=%d", nodeType, nodeID, username, logFormat, len(data))
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`)) //nolint:errcheck
}

// logUploadPrefResponse is the shared JSON shape for both the GET and POST
// handlers below, so a client reads exactly the same fields no matter which
// one it just called.
type logUploadPrefResponse struct {
	Enabled       bool `json:"enabled"`        // this user's own preference
	AdminDisabled bool `json:"admin_disabled"` // staff override, if any
	GlobalEnabled bool `json:"global_enabled"` // system-wide kill switch
	Effective     bool `json:"effective"`      // what actually happens right now (AND of all three)
}

// apiLogClientUploadPrefGet handles GET /api/log/client-upload/pref -- lets
// the app's own settings UI show the user their current log-upload
// preference and whether it's actually taking effect (e.g. a user might
// have it enabled but a staff override or the global switch still blocks
// it). Same auth/identity model as apiLogClientUpload: shared bearer key +
// self-reported X-Node-ID resolved to a username via client_conn_stats.
func (h *handler) apiLogClientUploadPrefGet(w http.ResponseWriter, r *http.Request) {
	if !h.checkLogUploadClientKey(r) {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	nodeID := r.Header.Get("X-Node-ID")
	if nodeID == "" {
		jsonErr(w, "X-Node-ID required", http.StatusBadRequest)
		return
	}
	username := h.db.usernameForDeviceID(nodeID)
	userEnabled, adminDisabled := h.db.userLogUploadPrefs(username)
	resp := logUploadPrefResponse{
		Enabled:       userEnabled,
		AdminDisabled: adminDisabled,
		GlobalEnabled: h.db.globalLogUploadEnabled(),
	}
	resp.Effective = resp.GlobalEnabled && resp.Enabled && !resp.AdminDisabled
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

// apiLogClientUploadPrefSet handles POST /api/log/client-upload/pref
// {"enabled": bool} -- the actual settings-UI toggle action. Only ever
// changes the user's OWN preference; a staff override (set via the admin
// API, see admin_log_upload.go) can't be cleared from here by design --
// otherwise "admin forces this account off" would mean nothing.
func (h *handler) apiLogClientUploadPrefSet(w http.ResponseWriter, r *http.Request) {
	if !h.checkLogUploadClientKey(r) {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	nodeID := r.Header.Get("X-Node-ID")
	if nodeID == "" {
		jsonErr(w, "X-Node-ID required", http.StatusBadRequest)
		return
	}
	username := h.db.usernameForDeviceID(nodeID)
	if username == "" {
		// No resolvable account for this device yet (e.g. no conn-stats
		// report has landed since the client last started) -- nothing to
		// persist a per-user preference against. The client should retry
		// once it has reported at least one conn-stats sample.
		jsonErr(w, "no account resolved for this device yet", http.StatusConflict)
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<10)).Decode(&req); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := h.db.setUserLogUploadEnabled(username, req.Enabled); err != nil {
		logWarnf("log-client-upload-pref: set user=%s enabled=%v: %v", username, req.Enabled, err)
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	logInfof("log-client-upload-pref: user=%s set enabled=%v", username, req.Enabled)

	userEnabled, adminDisabled := h.db.userLogUploadPrefs(username)
	resp := logUploadPrefResponse{
		Enabled:       userEnabled,
		AdminDisabled: adminDisabled,
		GlobalEnabled: h.db.globalLogUploadEnabled(),
	}
	resp.Effective = resp.GlobalEnabled && resp.Enabled && !resp.AdminDisabled
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}
