// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import "time"

// exit_rejected_sessions holds periodic counts of sessions an exit node gave
// up on because it couldn't deliver the user's data to the target or get a
// response back -- see snc-exit/stats.go's RecordRejectedSession. Reported
// once per exit's statsFlushInterval (5 min), same cadence as the rest of
// nodeStatsPayload -- this is the sole source of the admin dashboard's
// "rejected sessions" chart (see fleetRejectedSessionsHistory), a
// deliberate move away from the old client-reported version of this stat,
// which measured a much narrower (and, in production, apparently
// never-firing) client-side auth-rejection scenario instead of the actual
// delivery-failure case the chart was meant to show.
const rejectedSessionsSchemaSQL = `
CREATE TABLE IF NOT EXISTS exit_rejected_sessions (
	id      INTEGER PRIMARY KEY AUTOINCREMENT,
	ts      INTEGER NOT NULL,
	node_id INTEGER NOT NULL,
	count   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS exit_rejected_sessions_ts ON exit_rejected_sessions(ts);
`

// initRejectedSessionsSchema creates the exit_rejected_sessions table. Called from openDB.
func (d *DB) initRejectedSessionsSchema() error {
	_, err := d.db.Exec(rejectedSessionsSchemaSQL)
	return err
}

// insertRejectedSessions records one exit's rejected-session count since its
// last flush.
func (d *DB) insertRejectedSessions(nodeID, count, ts int64) error {
	_, err := d.db.Exec(
		`INSERT INTO exit_rejected_sessions(ts, node_id, count) VALUES(?,?,?)`,
		ts, nodeID, count)
	return err
}

// rejectedSessionsBucket is one 10-minute, fleet-wide point for the
// "rejected sessions" chart -- summed (not averaged) across every exit
// reporting in that window, since this is a count of real events, not a
// per-client gauge.
type rejectedSessionsBucket struct {
	Ts    int64 `json:"ts"`
	Count int64 `json:"count"`
}

// fleetRejectedSessionsHistory returns the system-wide, 10-min-bucketed sum
// of rejected sessions since the given time.
func (d *DB) fleetRejectedSessionsHistory(since time.Time) ([]rejectedSessionsBucket, error) {
	rows, err := d.db.Query(`
		SELECT (ts/600)*600 AS bucket, SUM(count)
		FROM exit_rejected_sessions
		WHERE ts >= ?
		GROUP BY bucket
		ORDER BY bucket ASC`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []rejectedSessionsBucket
	for rows.Next() {
		var b rejectedSessionsBucket
		if err := rows.Scan(&b.Ts, &b.Count); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// rejectedSessionsOlderThan / deleteRejectedSessionsOlderThan follow the same
// archive-then-delete pattern as connStatsOlderThan/deleteConnStatsOlderThan
// (see stats_archive.go).
type rejectedSessionsSample struct {
	Ts     int64 `json:"ts"`
	NodeID int64 `json:"node_id"`
	Count  int64 `json:"count"`
}

func (d *DB) rejectedSessionsOlderThan(cutoff int64) ([]rejectedSessionsSample, error) {
	rows, err := d.db.Query(
		`SELECT ts, node_id, count FROM exit_rejected_sessions WHERE ts < ? ORDER BY ts ASC`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []rejectedSessionsSample
	for rows.Next() {
		var s rejectedSessionsSample
		if err := rows.Scan(&s.Ts, &s.NodeID, &s.Count); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (d *DB) deleteRejectedSessionsOlderThan(cutoff int64) error {
	_, err := d.db.Exec(`DELETE FROM exit_rejected_sessions WHERE ts<?`, cutoff)
	return err
}
