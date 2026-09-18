// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import "testing"

// TestLogUploadAllowed covers every combination of the three switches (global
// kill switch, the user's own preference, the staff override) -- see
// docs/LOG_UPLOAD_PRIVACY.md. Allowed only when the global switch is on AND
// the user hasn't opted out AND no staff override is set.
func TestLogUploadAllowed(t *testing.T) {
	db := newTestDB(t)
	if _, err := db.getOrCreateUser("alice@example.com"); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name          string
		global        bool
		userEnabled   bool
		adminDisabled bool
		want          bool
	}{
		{"all defaults: uploads happen", true, true, false, true},
		{"user opted out", true, false, false, false},
		{"admin override forces off even though user is opted in", true, true, true, false},
		{"admin override AND user opted out", true, false, true, false},
		{"global kill switch off, user opted in", false, true, false, false},
		{"global kill switch off overrides everything", false, true, true, false},
		{"global off AND user opted out AND admin override (all-false is a real state)", false, false, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := db.setGlobalLogUploadEnabled(c.global, "test"); err != nil {
				t.Fatal(err)
			}
			if err := db.setUserLogUploadEnabled("alice@example.com", c.userEnabled); err != nil {
				t.Fatal(err)
			}
			if err := db.setUserLogUploadAdminDisabled("alice@example.com", c.adminDisabled); err != nil {
				t.Fatal(err)
			}
			if got := db.logUploadAllowed("alice@example.com"); got != c.want {
				t.Fatalf("logUploadAllowed = %v, want %v", got, c.want)
			}
		})
	}
}

// TestLogUploadAllowed_DefaultsToAllowed confirms that a fresh DB (nothing
// configured) allows uploads -- this feature only adds control, it must not
// silently change anyone's current behavior.
func TestLogUploadAllowed_DefaultsToAllowed(t *testing.T) {
	db := newTestDB(t)
	if _, err := db.getOrCreateUser("bob@example.com"); err != nil {
		t.Fatal(err)
	}
	if !db.globalLogUploadEnabled() {
		t.Fatal("global switch should default to enabled")
	}
	if !db.logUploadAllowed("bob@example.com") {
		t.Fatal("a fresh account should be allowed to upload")
	}
}

// TestLogUploadAllowed_UnresolvedUsername confirms an upload whose device
// couldn't be resolved to an account (username == "") is governed by the
// global switch only -- there's no per-user information to check.
func TestLogUploadAllowed_UnresolvedUsername(t *testing.T) {
	db := newTestDB(t)
	if !db.logUploadAllowed("") {
		t.Fatal("unresolved username should be allowed while the global switch is on")
	}
	if err := db.setGlobalLogUploadEnabled(false, "test"); err != nil {
		t.Fatal(err)
	}
	if db.logUploadAllowed("") {
		t.Fatal("unresolved username must still respect the global kill switch")
	}
}

// TestLogUploadAllowed_UnknownUserFallsBackToAllowed confirms a username with
// no row at all (never created) doesn't silently block uploads -- a lookup
// failure must never be the reason uploads across the fleet suddenly stop.
func TestLogUploadAllowed_UnknownUserFallsBackToAllowed(t *testing.T) {
	db := newTestDB(t)
	if !db.logUploadAllowed("nobody@example.com") {
		t.Fatal("a username with no users row should fall back to allowed")
	}
}

// TestAdminOverrideSurvivesUserToggle is the whole point of the override:
// once staff force a user's uploads off, the user re-enabling their own
// preference must NOT turn them back on.
func TestAdminOverrideSurvivesUserToggle(t *testing.T) {
	db := newTestDB(t)
	if _, err := db.getOrCreateUser("carol@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := db.setUserLogUploadAdminDisabled("carol@example.com", true); err != nil {
		t.Fatal(err)
	}
	if err := db.setUserLogUploadEnabled("carol@example.com", true); err != nil {
		t.Fatal(err)
	}
	if db.logUploadAllowed("carol@example.com") {
		t.Fatal("user re-enabling their own preference must not clear a staff override")
	}
	// Clearing the override hands control back to the user's own setting.
	if err := db.setUserLogUploadAdminDisabled("carol@example.com", false); err != nil {
		t.Fatal(err)
	}
	if !db.logUploadAllowed("carol@example.com") {
		t.Fatal("clearing the override should return control to the user's own (enabled) preference")
	}
}
