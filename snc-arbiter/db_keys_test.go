// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := openDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	t.Cleanup(func() { db.db.Close() })
	return db
}

// TestExtendKeyPaidUntil_StacksFromNil confirms a perpetual (paid_until IS
// NULL) key extends to roughly one month from now.
func TestExtendKeyPaidUntil_StacksFromNil(t *testing.T) {
	db := newTestDB(t)
	if err := db.RegisterKey("k1", "user@example.com", "test"); err != nil {
		t.Fatalf("RegisterKey: %v", err)
	}
	before := time.Now().UTC()
	got, err := db.ExtendKeyPaidUntil("k1", 100)
	if err != nil {
		t.Fatalf("ExtendKeyPaidUntil: %v", err)
	}
	want := before.AddDate(0, 1, 0)
	if diff := got.Sub(want); diff < -time.Minute || diff > time.Minute {
		t.Fatalf("got %v, want ~%v (diff %v)", got, want, diff)
	}
}

// TestExtendKeyPaidUntil_StacksFromFuture confirms extending a key that
// already has a future paid_until adds another month ON TOP of it, not from
// now -- this is the exact behavior a lost-update race would silently break.
func TestExtendKeyPaidUntil_StacksFromFuture(t *testing.T) {
	db := newTestDB(t)
	if err := db.RegisterKey("k1", "user@example.com", "test"); err != nil {
		t.Fatalf("RegisterKey: %v", err)
	}
	first, err := db.ExtendKeyPaidUntil("k1", 100)
	if err != nil {
		t.Fatalf("first extend: %v", err)
	}
	second, err := db.ExtendKeyPaidUntil("k1", 100)
	if err != nil {
		t.Fatalf("second extend: %v", err)
	}
	gotMonths := second.Sub(first)
	wantMonths := first.AddDate(0, 1, 0).Sub(first)
	if diff := gotMonths - wantMonths; diff < -time.Minute || diff > time.Minute {
		t.Fatalf("second extend should add ~1 month on top of the first: got delta %v, want ~%v", gotMonths, wantMonths)
	}
}

// TestExtendKeyPaidUntil_ConcurrentDoesNotLoseUpdates is the actual
// concurrency-audit test: N concurrent extensions of the SAME key must all
// be reflected (N months stacked), not silently collapsed to fewer months
// by a read-compute-write race. This is exactly the scenario (duplicate
// payment webhook, double-clicked renew) that motivated the fix.
func TestExtendKeyPaidUntil_ConcurrentDoesNotLoseUpdates(t *testing.T) {
	db := newTestDB(t)
	if err := db.RegisterKey("k1", "user@example.com", "test"); err != nil {
		t.Fatalf("RegisterKey: %v", err)
	}

	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := db.ExtendKeyPaidUntil("k1", 100)
			errs[i] = err
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: ExtendKeyPaidUntil: %v", i, err)
		}
	}

	k, err := db.GetKey("k1")
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if k.PaidUntil == nil {
		t.Fatal("paid_until is nil after concurrent extends")
	}
	gotMonths := int(k.PaidUntil.Sub(time.Now().UTC()).Hours() / (24 * 30))
	if gotMonths < n-1 { // -1 for rounding slack across variable month lengths
		t.Fatalf("expected all %d concurrent extends to stack (~%d months out), got only ~%d months -- lost update", n, n, gotMonths)
	}
}
