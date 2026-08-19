// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"testing"
	"time"
)

func TestUpdateNodeRecordsAddrRotation(t *testing.T) {
	db := newTestDB(t)

	owner, err := db.getOrCreateUser("rotation-test-owner")
	if err != nil {
		t.Fatalf("getOrCreateUser: %v", err)
	}
	nodeID, err := db.submitNode(owner.ID, "control", "1.2.3.4:443", "fp", "pk", "desc", "", "")
	if err != nil {
		t.Fatalf("submitNode: %v", err)
	}
	if _, err := db.db.Exec(`UPDATE nodes SET status='approved' WHERE id=?`, nodeID); err != nil {
		t.Fatalf("approve node: %v", err)
	}

	// First update changes the address -- should record one rotation row.
	if err := db.updateNode(nodeID, "5.6.7.8:443", "", "", "", "", ""); err != nil {
		t.Fatalf("updateNode: %v", err)
	}
	// Second update with an identical address must NOT record a duplicate row.
	if err := db.updateNode(nodeID, "5.6.7.8:443", "", "", "", "", ""); err != nil {
		t.Fatalf("updateNode (no-op addr): %v", err)
	}

	rotations, err := db.recentAddrRotations("control", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("recentAddrRotations: %v", err)
	}
	if len(rotations) != 1 {
		t.Fatalf("expected exactly 1 rotation, got %d: %+v", len(rotations), rotations)
	}
	r := rotations[0]
	if r.OldAddr != "1.2.3.4:443" || r.NewAddr != "5.6.7.8:443" {
		t.Fatalf("unexpected rotation values: %+v", r)
	}
	if r.NodeID != nodeID {
		t.Fatalf("expected node_id=%d, got %d", nodeID, r.NodeID)
	}

	// A different node type must not see this rotation.
	exitRotations, err := db.recentAddrRotations("exit", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("recentAddrRotations(exit): %v", err)
	}
	if len(exitRotations) != 0 {
		t.Fatalf("expected 0 exit rotations, got %d", len(exitRotations))
	}
}
