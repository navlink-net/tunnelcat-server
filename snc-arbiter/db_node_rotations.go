// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import "time"

// node_addr_rotations records every time a control/exit node's address
// changes (e.g. the yc_rotate.py/cloudru_rotate.py IP-rotation daemons
// running on navlink.net, or any other admin-initiated address update).
// The rotation daemons only ever report the *new* address to the arbiter
// (see POST /api/admin/node/{id}/update) -- the old value is never sent,
// so the only place both values are ever available together is here,
// server-side, at the moment updateNode is about to overwrite the
// previous addr. See recordAddrRotationIfChanged, called from updateNode.
const initNodeAddrRotationsSchemaSQL = `
CREATE TABLE IF NOT EXISTS node_addr_rotations (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	ts        INTEGER NOT NULL,
	node_id   INTEGER NOT NULL,
	node_type TEXT    NOT NULL,
	old_addr  TEXT    NOT NULL,
	new_addr  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS node_addr_rotations_type_ts ON node_addr_rotations(node_type, ts);
`

// initNodeAddrRotationsSchema creates node_addr_rotations on SQLite.
// Postgres gets the same table via
// migrations/postgres/00007_add_node_addr_rotations.sql instead --
// openDB's Postgres branch never calls this, matching every other
// initXSchema in this file.
func (d *DB) initNodeAddrRotationsSchema() error {
	_, err := d.db.Exec(initNodeAddrRotationsSchemaSQL)
	return err
}

// recordAddrRotationIfChanged inserts a rotation event when newAddr
// actually differs from oldAddr. A blank oldAddr (unresolved lookup) is
// never recorded -- there's nothing to show as the "old" side of the row.
func (d *DB) recordAddrRotationIfChanged(nodeID int64, nodeType, oldAddr, newAddr string, ts int64) error {
	if oldAddr == "" || newAddr == "" || oldAddr == newAddr {
		return nil
	}
	_, err := d.db.Exec(
		`INSERT INTO node_addr_rotations(ts, node_id, node_type, old_addr, new_addr) VALUES (?,?,?,?,?)`,
		ts, nodeID, nodeType, oldAddr, newAddr,
	)
	return err
}

// AddrRotation is one recorded address change, for the admin dashboard's
// Controls/Egresses "address rotations, last 24h" table.
type AddrRotation struct {
	Ts      int64
	NodeID  int64
	OldAddr string
	NewAddr string
}

// recentAddrRotations returns rotation events for the given node type
// ("control" | "exit") at or after since, newest first.
func (d *DB) recentAddrRotations(nodeType string, since time.Time) ([]AddrRotation, error) {
	rows, err := d.db.Query(
		`SELECT ts, node_id, old_addr, new_addr FROM node_addr_rotations
		 WHERE node_type=? AND ts>=? ORDER BY ts DESC`,
		nodeType, since.Unix(),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AddrRotation
	for rows.Next() {
		var r AddrRotation
		if err := rows.Scan(&r.Ts, &r.NodeID, &r.OldAddr, &r.NewAddr); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
