// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

const logUploadPrefPath = "/api/log/client-upload/pref"

// LogUploadPrefResponse mirrors snc-arbiter/log_upload_client_api.go's
// logUploadPrefResponse -- same field names, same meaning. Exported so a
// platform's native Settings UI can display it (see GetPref/SetPref below).
type LogUploadPrefResponse struct {
	Enabled       bool `json:"enabled"`        // this account's own preference
	AdminDisabled bool `json:"admin_disabled"` // staff override, if any
	GlobalEnabled bool `json:"global_enabled"` // system-wide kill switch
	Effective     bool `json:"effective"`      // what actually happens right now (AND of all three)
}

func (lu *LogUploader) prefClient(dialer *TunnelDialer) *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
				return dialer.Dial(addr)
			},
		},
	}
}

// GetPref fetches this account's current log-upload preference from the
// arbiter -- for a Settings screen to show the toggle's initial state (and
// to explain, via AdminDisabled/GlobalEnabled, why it might be off even
// though the user never turned it off themselves). Requires an active
// tunnel dialer; returns an error if not connected or the request fails --
// unlike checkLogUploadAllowed's internal use (which fails open so a
// network hiccup never silently blocks routine diagnostics), a Settings
// screen showing a stale/wrong toggle state to the user is worse than
// showing "couldn't check right now".
func (lu *LogUploader) GetPref(dialer *TunnelDialer) (LogUploadPrefResponse, error) {
	var pref LogUploadPrefResponse
	if dialer == nil {
		return pref, fmt.Errorf("log-upload: not connected")
	}
	req, err := http.NewRequest(http.MethodGet, logUploadArbiterURL+logUploadPrefPath, nil)
	if err != nil {
		return pref, err
	}
	req.Header.Set("Authorization", "Bearer "+DefaultClientTelemetryKey)
	req.Header.Set("X-Node-ID", lu.nodeID)
	req.Header.Set("X-Node-Type", lu.nodeType)

	resp, err := lu.prefClient(dialer).Do(req)
	if err != nil {
		return pref, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return pref, fmt.Errorf("log-upload: pref fetch status=%d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&pref); err != nil {
		return pref, err
	}
	return pref, nil
}

// SetPref sets this account's own log-upload preference (the self-service
// half of the three switches -- see docs/LOG_UPLOAD_PRIVACY.md; a staff
// override, if any, can't be cleared from here) -- called when the user
// flips the Settings-screen toggle. Requires an active tunnel dialer.
func (lu *LogUploader) SetPref(dialer *TunnelDialer, enabled bool) (LogUploadPrefResponse, error) {
	var pref LogUploadPrefResponse
	if dialer == nil {
		return pref, fmt.Errorf("log-upload: not connected")
	}
	body, err := json.Marshal(struct {
		Enabled bool `json:"enabled"`
	}{Enabled: enabled})
	if err != nil {
		return pref, err
	}
	req, err := http.NewRequest(http.MethodPost, logUploadArbiterURL+logUploadPrefPath, bytes.NewReader(body))
	if err != nil {
		return pref, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+DefaultClientTelemetryKey)
	req.Header.Set("X-Node-ID", lu.nodeID)
	req.Header.Set("X-Node-Type", lu.nodeType)

	resp, err := lu.prefClient(dialer).Do(req)
	if err != nil {
		return pref, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return pref, fmt.Errorf("log-upload: pref set status=%d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&pref); err != nil {
		return pref, err
	}
	return pref, nil
}

// checkLogUploadAllowed asks the arbiter whether this device's automatic log
// upload should run right now (global kill switch AND this account's own
// preference AND no staff override) -- called once per upload tick, before
// touching the disk log at all, so a user (or an admin) who turned this off
// doesn't even have their log content read/zipped locally, let alone sent.
//
// Fails open (true) on any request/decode error: a transient network hiccup
// on this specific check must not silently stop diagnostics for a user who
// never asked for that. The actual upload endpoint enforces the real
// decision server-side regardless (see apiLogClientUpload) -- this check is
// an optimization to avoid doing the read/zip/send work and generating the
// traffic pattern at all when we already know the answer is no, not the
// security boundary itself. Settings-screen code should use GetPref/SetPref
// above instead, which surface real errors rather than failing open.
func checkLogUploadAllowed(dialer *TunnelDialer, nodeID, nodeType string) bool {
	lu := &LogUploader{nodeID: nodeID, nodeType: nodeType}
	pref, err := lu.GetPref(dialer)
	if err != nil {
		Log.Printf("log-upload: pref check failed (assuming allowed): %v", err)
		return true
	}
	return pref.Effective
}
