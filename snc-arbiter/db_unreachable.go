// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import "time"

// node_unreachable_events records, per observation, that one node was
// unreachable from another node's point of view -- resolved to a stable
// node_id at write time, not just the address the observer currently knows
// it by. This is what lets "which control/exit is unreachable more often"
// survive that node's own IP rotation instead of fragmenting into separate
// per-address histories (see the 2026-08-16 node rotation work earlier the
// same day this was requested -- the exact scenario this is designed to
// stay correct through).
//
// Two independent reporters feed this one table:
//   - end-user clients report which *controls* they personally can't reach
//     (already computed client-side, see snc/core/router.go's
//     UnreachableControls -- previously collapsed to a bare count before
//     upload, see conn_stats_client_api.go).
//   - control nodes report which *exits* they've marked dead (already
//     tracked locally by snc-control/exit_health.go, previously never
//     reported anywhere at all -- see snc-control/exits.go's heartbeat).
const initUnreachableSchemaSQL = `
CREATE TABLE IF NOT EXISTS node_unreachable_events (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	ts             INTEGER NOT NULL,
	reporter_type  TEXT    NOT NULL,
	target_type    TEXT    NOT NULL,
	target_node_id INTEGER,
	target_addr    TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS node_unreachable_events_target ON node_unreachable_events(target_type, target_node_id, ts);
CREATE INDEX IF NOT EXISTS node_unreachable_events_ts ON node_unreachable_events(ts);
`

// initUnreachableSchema creates node_unreachable_events on SQLite. Postgres
// gets the same table via migrations/postgres/00004_add_node_unreachable_events.sql
// instead -- openDB's Postgres branch never calls this (see openDB's early
// return for isPostgresDSN), matching every other initXSchema in this file.
func (d *DB) initUnreachableSchema() error {
	_, err := d.db.Exec(initUnreachableSchemaSQL)
	return err
}

// nodeIDByAddr resolves a node's current addr to its stable id. Returns
// (0, false) if no approved node currently has that address -- callers must
// still record the event (with a NULL target_node_id) rather than drop it,
// since "we don't recognize this address" is itself worth keeping for
// debugging, just not chartable per-node.
func (d *DB) nodeIDByAddr(addr string) (int64, bool) {
	var id int64
	if err := d.db.QueryRow(`SELECT id FROM nodes WHERE addr=? AND status='approved'`, addr).Scan(&id); err != nil {
		return 0, false
	}
	return id, true
}

// recordUnreachableEvents inserts one row per addr in addrs, resolving each
// to a node id best-effort. Never returns an error for an individual
// unresolved address -- only a real DB-level failure propagates, so one
// unrecognized address in a batch doesn't discard the rest. reporterType is
// "client" (reporting controls) or "control" (reporting exits); targetType
// is "control" or "exit" respectively.
func (d *DB) recordUnreachableEvents(reporterType, targetType string, addrs []string, ts int64) error {
	for _, addr := range addrs {
		var nodeID interface{} // nil -> SQL NULL when unresolved
		if id, ok := d.nodeIDByAddr(addr); ok {
			nodeID = id
		}
		if _, err := d.db.Exec(
			`INSERT INTO node_unreachable_events(ts, reporter_type, target_type, target_node_id, target_addr) VALUES (?,?,?,?,?)`,
			ts, reporterType, targetType, nodeID, addr,
		); err != nil {
			return err
		}
	}
	return nil
}

// unreachableNodeBucket is one time-bucketed unreachability count for a
// single node -- same 10-minute-bucket shape as bananameterNodeBucket
// (db_bananameter.go) so the Controls/Egresses tab charts can place this
// series alongside the existing throughput/ping ones using the same
// charting code.
type unreachableNodeBucket struct {
	Ts    int64 `json:"ts"`
	Count int   `json:"count"`
}

// unreachableNodeSeries is one node's own bucketed unreachability series,
// as part of a per-type breakdown.
type unreachableNodeSeries struct {
	NodeID  int64                   `json:"node_id"`
	Addr    string                  `json:"addr"`
	Buckets []unreachableNodeBucket `json:"buckets"`
}

// unreachableTypeBreakdown is everything the "which node is flaky" chart
// needs for one target type: the combined total plus each individual
// node's own series, both bucketed the same way -- mirrors
// bananameterTypeBreakdown's shape deliberately, see typeBananameterBreakdown.
type unreachableTypeBreakdown struct {
	Overall []unreachableNodeBucket `json:"overall"`
	Nodes   []unreachableNodeSeries `json:"nodes"`
}

// typeUnreachabilityBreakdown returns the combined "all nodes of this
// type" unreachability count plus each individual node's own series, both
// bucketed the same way, for the Controls/Egresses tab charts. Only events
// that resolved to a real node_id are broken out per-node (an unresolved
// address can't be attributed to a specific node's history); unresolved
// events still count toward Overall so the combined line isn't
// artificially low.
func (d *DB) typeUnreachabilityBreakdown(targetType string, since time.Time) (unreachableTypeBreakdown, error) {
	var result unreachableTypeBreakdown

	overallRows, err := d.db.Query(`
		SELECT (ts/600)*600 AS bucket, COUNT(*)
		FROM node_unreachable_events
		WHERE target_type=? AND ts>=?
		GROUP BY bucket
		ORDER BY bucket ASC`, targetType, since.Unix())
	if err != nil {
		return result, err
	}
	for overallRows.Next() {
		var b unreachableNodeBucket
		if err := overallRows.Scan(&b.Ts, &b.Count); err != nil {
			overallRows.Close()
			return result, err
		}
		result.Overall = append(result.Overall, b)
	}
	if err := overallRows.Err(); err != nil {
		overallRows.Close()
		return result, err
	}
	overallRows.Close()

	perNodeRows, err := d.db.Query(`
		SELECT (ts/600)*600 AS bucket, target_node_id, COUNT(*)
		FROM node_unreachable_events
		WHERE target_type=? AND ts>=? AND target_node_id IS NOT NULL
		GROUP BY bucket, target_node_id
		ORDER BY target_node_id ASC, bucket ASC`, targetType, since.Unix())
	if err != nil {
		return result, err
	}
	defer perNodeRows.Close()

	order := make([]int64, 0)
	byNode := make(map[int64][]unreachableNodeBucket)
	for perNodeRows.Next() {
		var nodeID int64
		var b unreachableNodeBucket
		if err := perNodeRows.Scan(&b.Ts, &nodeID, &b.Count); err != nil {
			return result, err
		}
		if _, ok := byNode[nodeID]; !ok {
			order = append(order, nodeID)
		}
		byNode[nodeID] = append(byNode[nodeID], b)
	}
	if err := perNodeRows.Err(); err != nil {
		return result, err
	}
	for _, nodeID := range order {
		addr := ""
		if n, err := d.nodeByID(nodeID); err == nil && n != nil {
			addr = n.Addr
		}
		result.Nodes = append(result.Nodes, unreachableNodeSeries{
			NodeID:  nodeID,
			Addr:    addr,
			Buckets: byNode[nodeID],
		})
	}
	return result, nil
}
