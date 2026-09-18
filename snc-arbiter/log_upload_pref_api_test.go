// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	testTelemetryKey = "test-telemetry-key"
	testDeviceID     = "dev-1234"
	testUser         = "dave@example.com"
)

// newLogUploadTestHandler returns a handler whose DB has one account
// (testUser) and one conn-stats row mapping testDeviceID to it -- the same
// device -> username link usernameForDeviceID resolves in production. h.logs
// is deliberately left nil: every test below either expects the request to be
// refused before storage is ever reached, or only exercises the pref
// endpoints, so a nil store proves nothing gets written on the refusal paths
// (a nil-pointer panic here would mean a refused upload still tried to
// store).
func newLogUploadTestHandler(t *testing.T) *handler {
	t.Helper()
	h := &handler{db: newTestDB(t), clientTelemetryKey: testTelemetryKey}
	if _, err := h.db.getOrCreateUser(testUser); err != nil {
		t.Fatal(err)
	}
	if err := h.db.insertConnStats(connStatsReport{
		Ts: 1, Username: testUser, DeviceID: testDeviceID, NodeType: "windows",
	}); err != nil {
		t.Fatal(err)
	}
	return h
}

func prefRequest(method, body string) *http.Request {
	r := httptest.NewRequest(method, "/api/log/client-upload/pref", bytes.NewBufferString(body))
	r.Header.Set("Authorization", "Bearer "+testTelemetryKey)
	r.Header.Set("X-Node-ID", testDeviceID)
	r.Header.Set("X-Node-Type", "windows")
	return r
}

func decodePref(t *testing.T, rec *httptest.ResponseRecorder) logUploadPrefResponse {
	t.Helper()
	var p logUploadPrefResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode pref response %q: %v", rec.Body.String(), err)
	}
	return p
}

// The actual privacy boundary: a client that uploads anyway (stale build,
// bug, or deliberate bypass of its own client-side check) must be refused
// server-side with 403 and nothing stored.
func TestApiLogClientUpload_RefusedWhenUserOptedOut(t *testing.T) {
	h := newLogUploadTestHandler(t)
	if err := h.db.setUserLogUploadEnabled(testUser, false); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/log/client-upload", bytes.NewBufferString("payload"))
	r.Header.Set("Authorization", "Bearer "+testTelemetryKey)
	r.Header.Set("X-Node-ID", testDeviceID)
	rec := httptest.NewRecorder()
	h.apiLogClientUpload(rec, r) // h.logs == nil: panics if a refused upload reaches storage
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
}

func TestApiLogClientUpload_RefusedByAdminOverride(t *testing.T) {
	h := newLogUploadTestHandler(t)
	if err := h.db.setUserLogUploadAdminDisabled(testUser, true); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/log/client-upload", bytes.NewBufferString("payload"))
	r.Header.Set("Authorization", "Bearer "+testTelemetryKey)
	r.Header.Set("X-Node-ID", testDeviceID)
	rec := httptest.NewRecorder()
	h.apiLogClientUpload(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
}

func TestApiLogClientUpload_RefusedByGlobalKillSwitch(t *testing.T) {
	h := newLogUploadTestHandler(t)
	if err := h.db.setGlobalLogUploadEnabled(false, "test"); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/log/client-upload", bytes.NewBufferString("payload"))
	r.Header.Set("Authorization", "Bearer "+testTelemetryKey)
	r.Header.Set("X-Node-ID", testDeviceID)
	rec := httptest.NewRecorder()
	h.apiLogClientUpload(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
}

func TestApiAppLogUpload_RefusedByGlobalKillSwitch(t *testing.T) {
	h := newLogUploadTestHandler(t)
	h.appLogKey = "app-log-key"
	if err := h.db.setGlobalLogUploadEnabled(false, "test"); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/log/app-upload", bytes.NewBufferString("payload"))
	r.Header.Set("Authorization", "Bearer app-log-key")
	r.Header.Set("X-App-ID", "com.navlink.lisinder")
	r.Header.Set("X-Device-ID", "abc123")
	rec := httptest.NewRecorder()
	h.apiAppLogUpload(rec, r) // h.logs == nil: panics if a refused upload reaches storage
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
}

func TestApiLogClientUploadPref_RequiresKey(t *testing.T) {
	h := newLogUploadTestHandler(t)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		r := prefRequest(method, `{"enabled":false}`)
		r.Header.Set("Authorization", "Bearer wrong")
		rec := httptest.NewRecorder()
		if method == http.MethodGet {
			h.apiLogClientUploadPrefGet(rec, r)
		} else {
			h.apiLogClientUploadPrefSet(rec, r)
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s with a wrong key: status = %d, want 401", method, rec.Code)
		}
	}
}

func TestApiLogClientUploadPref_GetDefaults(t *testing.T) {
	h := newLogUploadTestHandler(t)
	rec := httptest.NewRecorder()
	h.apiLogClientUploadPrefGet(rec, prefRequest(http.MethodGet, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	p := decodePref(t, rec)
	if !p.Enabled || p.AdminDisabled || !p.GlobalEnabled || !p.Effective {
		t.Fatalf("defaults should read as fully enabled, got %+v", p)
	}
}

func TestApiLogClientUploadPref_SetRoundTrip(t *testing.T) {
	h := newLogUploadTestHandler(t)

	rec := httptest.NewRecorder()
	h.apiLogClientUploadPrefSet(rec, prefRequest(http.MethodPost, `{"enabled":false}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("set: status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if p := decodePref(t, rec); p.Enabled || p.Effective {
		t.Fatalf("after opting out, got %+v", p)
	}

	rec = httptest.NewRecorder()
	h.apiLogClientUploadPrefGet(rec, prefRequest(http.MethodGet, ""))
	if p := decodePref(t, rec); p.Enabled || p.Effective {
		t.Fatalf("the opt-out should persist and be readable back, got %+v", p)
	}

	rec = httptest.NewRecorder()
	h.apiLogClientUploadPrefSet(rec, prefRequest(http.MethodPost, `{"enabled":true}`))
	if p := decodePref(t, rec); !p.Enabled || !p.Effective {
		t.Fatalf("after opting back in, got %+v", p)
	}
}

// A staff override must survive the user re-enabling their own preference, and
// the pref response must say so (enabled=true but effective=false) so a
// Settings screen can explain why the toggle isn't doing anything.
func TestApiLogClientUploadPref_AdminOverrideVisibleAndNotClearableByUser(t *testing.T) {
	h := newLogUploadTestHandler(t)
	if err := h.db.setUserLogUploadAdminDisabled(testUser, true); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.apiLogClientUploadPrefSet(rec, prefRequest(http.MethodPost, `{"enabled":true}`))
	p := decodePref(t, rec)
	if !p.Enabled || !p.AdminDisabled || p.Effective {
		t.Fatalf("user opted in but staff override is set: want enabled=true admin_disabled=true effective=false, got %+v", p)
	}
}

// A device with no resolved account can't have a per-user preference stored
// against it -- the client must be told to retry later, not have its request
// silently "succeed" against nobody.
func TestApiLogClientUploadPref_SetUnresolvedDeviceConflicts(t *testing.T) {
	h := newLogUploadTestHandler(t)
	r := prefRequest(http.MethodPost, `{"enabled":false}`)
	r.Header.Set("X-Node-ID", "unknown-device")
	rec := httptest.NewRecorder()
	h.apiLogClientUploadPrefSet(rec, r)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
}

func TestAdminLogUploadEndpoints(t *testing.T) {
	h := newLogUploadTestHandler(t)
	if err := h.db.setSetting("admin_api_token", "adm-token", "test"); err != nil {
		t.Fatal(err)
	}
	do := func(fn func(http.ResponseWriter, *http.Request), method, body, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/admin/api/log-upload/x", bytes.NewBufferString(body))
		if token != "" {
			r.Header.Set("X-Admin-Token", token)
		}
		rec := httptest.NewRecorder()
		fn(rec, r)
		return rec
	}

	// No credentials -> refused.
	if rec := do(h.adminLogUploadGlobalSet, http.MethodPost, `{"enabled":false}`, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("global set without a token: status = %d, want 401", rec.Code)
	}
	if !h.db.globalLogUploadEnabled() {
		t.Fatal("an unauthorized request must not have flipped the global switch")
	}

	// Global kill switch off, then back on.
	if rec := do(h.adminLogUploadGlobalSet, http.MethodPost, `{"enabled":false}`, "adm-token"); rec.Code != http.StatusOK {
		t.Fatalf("global set: status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if h.db.globalLogUploadEnabled() {
		t.Fatal("global switch should now be off")
	}
	do(h.adminLogUploadGlobalSet, http.MethodPost, `{"enabled":true}`, "adm-token")

	// Per-user override: set, visible via status, refused for unknown users.
	if rec := do(h.adminLogUploadUserOverride, http.MethodPost, `{"username":"`+testUser+`","disabled":true}`, "adm-token"); rec.Code != http.StatusOK {
		t.Fatalf("override set: status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if h.db.logUploadAllowed(testUser) {
		t.Fatal("the override should now block this account")
	}
	if rec := do(h.adminLogUploadUserOverride, http.MethodPost, `{"username":"ghost@example.com","disabled":true}`, "adm-token"); rec.Code != http.StatusNotFound {
		t.Fatalf("override for a nonexistent user: status = %d, want 404", rec.Code)
	}
	r := httptest.NewRequest(http.MethodGet, "/admin/api/log-upload/status?username="+testUser, nil)
	r.Header.Set("X-Admin-Token", "adm-token")
	rec := httptest.NewRecorder()
	h.adminLogUploadStatus(rec, r)
	var st map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st["admin_disabled"] != true || st["effective"] != false || st["global_enabled"] != true {
		t.Fatalf("status = %v", st)
	}
}
