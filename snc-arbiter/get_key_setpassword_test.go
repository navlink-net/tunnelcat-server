// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPendingSignupWithin(t *testing.T) {
	db := newTestDB(t)
	const window = 10 * time.Minute

	// No user_confirmations row at all: a legacy / never-signed-up-via-start
	// account. Must never be eligible.
	if ok, err := db.pendingSignupWithin("legacy@example.com", window); err != nil || ok {
		t.Fatalf("legacy account: ok=%v err=%v, want false/nil", ok, err)
	}

	if err := db.resetPendingConfirmation("new@example.com"); err != nil {
		t.Fatalf("resetPendingConfirmation: %v", err)
	}
	if ok, err := db.pendingSignupWithin("new@example.com", window); err != nil || !ok {
		t.Fatalf("fresh pending sign-up: ok=%v err=%v, want true/nil", ok, err)
	}

	// Window expired.
	old := time.Now().Add(-window - time.Minute).Unix()
	if _, err := db.db.Exec(`UPDATE user_confirmations SET created_at=? WHERE username=?`, old, "new@example.com"); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	if ok, _ := db.pendingSignupWithin("new@example.com", window); ok {
		t.Fatal("expired window still eligible")
	}

	// Re-registering the same address restarts the window.
	if err := db.resetPendingConfirmation("new@example.com"); err != nil {
		t.Fatalf("resetPendingConfirmation (again): %v", err)
	}
	if ok, _ := db.pendingSignupWithin("new@example.com", window); !ok {
		t.Fatal("re-registration did not restart the window")
	}

	// Once confirmed, never eligible again -- even inside the window.
	if err := db.setUserConfirmed("new@example.com"); err != nil {
		t.Fatalf("setUserConfirmed: %v", err)
	}
	if ok, _ := db.pendingSignupWithin("new@example.com", window); ok {
		t.Fatal("confirmed account eligible for initial-password set")
	}
}

// TestAccountSetPassword_RefusesUnlessFreshSignup is the regression test for
// the unauthenticated set-password takeover: h.auth is deliberately nil, so a
// request that got past the gate would panic on the forceChangePassword call.
func TestAccountSetPassword_RefusesUnlessFreshSignup(t *testing.T) {
	db := newTestDB(t)
	h := &handler{db: db}

	if err := db.setUserConfirmed("confirmed@example.com"); err != nil {
		t.Fatal(err)
	}
	if err := db.resetPendingConfirmation("stale@example.com"); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour).Unix()
	if _, err := db.db.Exec(`UPDATE user_confirmations SET created_at=? WHERE username=?`, old, "stale@example.com"); err != nil {
		t.Fatal(err)
	}

	for _, email := range []string{"nobody@example.com", "confirmed@example.com", "stale@example.com"} {
		body := `{"email":"` + email + `","password":"attacker-chosen-pw"}`
		req := httptest.NewRequest(http.MethodPost, "/api/account/set-password", strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.apiAccountSetPassword(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403 (body %q)", email, rec.Code, rec.Body.String())
		}
	}
}
