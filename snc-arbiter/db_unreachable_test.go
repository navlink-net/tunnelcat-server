// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"testing"
	"time"
)

// insertTestNode inserts a minimal approved node directly, bypassing the
// registration API -- sufficient for exercising nodeIDByAddr/
// recordUnreachableEvents/typeUnreachabilityBreakdown without pulling in
// the whole node-registration flow.
func insertTestNode(t *testing.T, db *DB, nodeType, addr string) int64 {
	t.Helper()
	if _, err := db.db.Exec(`INSERT INTO users(username) VALUES('owner@example.com')`); err != nil {
		// Fine if it already exists from a prior call in the same test.
	}
	var ownerID int64
	if err := db.db.QueryRow(`SELECT id FROM users WHERE username='owner@example.com'`).Scan(&ownerID); err != nil {
		t.Fatalf("lookup owner: %v", err)
	}
	res, err := db.db.Exec(
		`INSERT INTO nodes(owner_id, type, addr, status) VALUES (?,?,?,'approved')`,
		ownerID, nodeType, addr,
	)
	if err != nil {
		t.Fatalf("insert node: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("LastInsertId: %v", err)
	}
	return id
}

func TestNodeIDByAddr(t *testing.T) {
	db := newTestDB(t)
	id := insertTestNode(t, db, "control", "1.2.3.4:443")

	got, ok := db.nodeIDByAddr("1.2.3.4:443")
	if !ok || got != id {
		t.Fatalf("nodeIDByAddr(known) = (%d, %v), want (%d, true)", got, ok, id)
	}

	if _, ok := db.nodeIDByAddr("9.9.9.9:443"); ok {
		t.Fatal("nodeIDByAddr(unknown addr) should return ok=false")
	}
}

// TestRecordUnreachableEvents_ResolvesKnownAndKeepsUnknown confirms both
// halves of recordUnreachableEvents' contract: a recognized address is
// resolved to its node_id, and an unrecognized one is still recorded (with
// a NULL target_node_id) rather than silently dropped.
func TestRecordUnreachableEvents_ResolvesKnownAndKeepsUnknown(t *testing.T) {
	db := newTestDB(t)
	id := insertTestNode(t, db, "control", "1.2.3.4:443")

	if err := db.recordUnreachableEvents("client", "control", []string{"1.2.3.4:443", "9.9.9.9:443"}, 1700000000); err != nil {
		t.Fatalf("recordUnreachableEvents: %v", err)
	}

	var total int
	if err := db.db.QueryRow(`SELECT COUNT(*) FROM node_unreachable_events`).Scan(&total); err != nil {
		t.Fatalf("count: %v", err)
	}
	if total != 2 {
		t.Fatalf("expected 2 rows (one resolved, one not), got %d", total)
	}

	var resolvedNodeID int64
	if err := db.db.QueryRow(`SELECT target_node_id FROM node_unreachable_events WHERE target_addr='1.2.3.4:443'`).Scan(&resolvedNodeID); err != nil {
		t.Fatalf("query resolved row: %v", err)
	}
	if resolvedNodeID != id {
		t.Fatalf("resolved target_node_id = %d, want %d", resolvedNodeID, id)
	}

	var unresolvedNodeID *int64
	if err := db.db.QueryRow(`SELECT target_node_id FROM node_unreachable_events WHERE target_addr='9.9.9.9:443'`).Scan(&unresolvedNodeID); err != nil {
		t.Fatalf("query unresolved row: %v", err)
	}
	if unresolvedNodeID != nil {
		t.Fatalf("expected NULL target_node_id for unresolved addr, got %v", *unresolvedNodeID)
	}
}

// TestTypeUnreachabilityBreakdown_SurvivesAddrChange is the core
// requirement this feature was built for: a node's unreachability history
// must stay attributed to it across an address change (IP rotation), not
// fragment into two separate per-address histories.
func TestTypeUnreachabilityBreakdown_SurvivesAddrChange(t *testing.T) {
	db := newTestDB(t)
	id := insertTestNode(t, db, "control", "1.2.3.4:443")

	// Two events reported while the node was still at its old address.
	if err := db.recordUnreachableEvents("client", "control", []string{"1.2.3.4:443"}, 1000); err != nil {
		t.Fatalf("record (old addr): %v", err)
	}
	if err := db.recordUnreachableEvents("client", "control", []string{"1.2.3.4:443"}, 1000); err != nil {
		t.Fatalf("record (old addr): %v", err)
	}

	// Rotate: same node id, new address (mirrors updateNode after a real rotation).
	if err := db.updateNode(id, "5.6.7.8:443", "", "", "", "", ""); err != nil {
		t.Fatalf("updateNode (rotate): %v", err)
	}

	// A third event reported after rotation, at the new address.
	if err := db.recordUnreachableEvents("client", "control", []string{"5.6.7.8:443"}, 1000); err != nil {
		t.Fatalf("record (new addr): %v", err)
	}

	breakdown, err := db.typeUnreachabilityBreakdown("control", time.Unix(0, 0))
	if err != nil {
		t.Fatalf("typeUnreachabilityBreakdown: %v", err)
	}
	if len(breakdown.Nodes) != 1 {
		t.Fatalf("expected exactly 1 node series (all 3 events attributed to the same node), got %d", len(breakdown.Nodes))
	}
	got := breakdown.Nodes[0]
	if got.NodeID != id {
		t.Fatalf("series NodeID = %d, want %d", got.NodeID, id)
	}
	total := 0
	for _, b := range got.Buckets {
		total += b.Count
	}
	if total != 3 {
		t.Fatalf("expected all 3 events (pre- and post-rotation) counted for node %d, got %d", id, total)
	}
}
