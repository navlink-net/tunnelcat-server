// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"net"
	"sync"
	"testing"
	"time"
)

// testPostgresDSN points at a throwaway local Postgres used only for manual
// verification during the SQLite -> Postgres migration (Phase 3 wiring
// smoke test). Skips itself when nothing is listening there, so this
// never fails a normal `go test ./...` run on a machine without Docker --
// Phase 4 is where real, always-on Postgres integration tests get added.
const testPostgresDSN = "postgres://postgres:test@127.0.0.1:15432/arbiter_apptest?sslmode=disable"

func postgresReachable(t *testing.T) bool {
	t.Helper()
	conn, err := net.DialTimeout("tcp", "127.0.0.1:15432", 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// TestOpenDB_PostgresDSN_EndToEnd proves openDB's DSN-scheme dispatch
// (db.go) and openPostgresDB (db_postgres.go) work through the real
// application code path, not just the goose CLI used to hand-verify the
// migration file itself: connect, run embedded migrations, exercise one
// real read/write path (getOrCreateUser, the same function Phase 2 fixed
// for concurrency) against a live Postgres.
func TestOpenDB_PostgresDSN_EndToEnd(t *testing.T) {
	if !postgresReachable(t) {
		t.Skip("no Postgres listening on 127.0.0.1:15432 -- skipping (see Phase 4 for always-on integration tests)")
	}

	db, err := openDB(testPostgresDSN)
	if err != nil {
		t.Fatalf("openDB(postgres DSN): %v", err)
	}
	defer db.db.Close()

	u, err := db.getOrCreateUser("smoketest@example.com")
	if err != nil {
		t.Fatalf("getOrCreateUser: %v", err)
	}
	if u.Username != "smoketest@example.com" {
		t.Fatalf("got username %q", u.Username)
	}

	// Re-running openDB against the same DSN must be idempotent (goose
	// no-ops on an already-migrated database, and getOrCreateUser must
	// find the existing row rather than erroring or creating a duplicate --
	// this is exactly the race-fix from Phase 2, now proven against real
	// Postgres instead of just SQLite).
	db2, err := openDB(testPostgresDSN)
	if err != nil {
		t.Fatalf("openDB (second run): %v", err)
	}
	defer db2.db.Close()
	u2, err := db2.getOrCreateUser("smoketest@example.com")
	if err != nil {
		t.Fatalf("getOrCreateUser (second run): %v", err)
	}
	if u2.ID != u.ID {
		t.Fatalf("expected the same user row (id=%d), got id=%d -- duplicate created", u.ID, u2.ID)
	}
}

// TestExtendKeyPaidUntil_Postgres_ConcurrentDoesNotLoseUpdates is the
// Postgres counterpart to the SQLite version in db_keys_test.go -- proves
// the "SELECT ... FOR UPDATE" row lock added during the strftime->Postgres
// rewrite actually closes the lost-update race against a real Postgres
// connection pool, not just in theory.
func TestExtendKeyPaidUntil_Postgres_ConcurrentDoesNotLoseUpdates(t *testing.T) {
	if !postgresReachable(t) {
		t.Skip("no Postgres listening on 127.0.0.1:15432 -- skipping (see Phase 4 for always-on integration tests)")
	}
	db, err := openDB(testPostgresDSN)
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.db.Close()

	keyID := "pg-concurrent-test-key"
	if err := db.RegisterKey(keyID, "pgtest@example.com", "test"); err != nil {
		t.Fatalf("RegisterKey: %v", err)
	}

	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := db.ExtendKeyPaidUntil(keyID, 100)
			errs[i] = err
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: ExtendKeyPaidUntil: %v", i, err)
		}
	}

	k, err := db.GetKey(keyID)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if k.PaidUntil == nil {
		t.Fatal("paid_until is nil after concurrent extends")
	}
	gotMonths := int(k.PaidUntil.Sub(time.Now().UTC()).Hours() / (24 * 30))
	if gotMonths < n-1 {
		t.Fatalf("expected all %d concurrent extends to stack (~%d months out), got only ~%d months -- lost update", n, n, gotMonths)
	}
}
