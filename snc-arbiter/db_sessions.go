// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import "time"

// session_durations holds one row per completed user session, as reported
// post-factum by an exit's StatsCollector.sweep() (snc-exit/stats.go) once a
// user has gone sessionIdleTimeout without any traffic. There is no live
// "session in progress" row here by design -- only finished sessions, which
// is exactly what "average session duration" needs and avoids having to
// reconcile a half-open session against a node that later goes away.
const sessionsSchemaSQL = `
CREATE TABLE IF NOT EXISTS session_durations (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	username   TEXT    NOT NULL,
	node_id    INTEGER NOT NULL DEFAULT 0, -- exit that reported this session; 0 if unresolved
	seconds    INTEGER NOT NULL DEFAULT 0,
	ended_at   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS session_durations_ended_at ON session_durations(ended_at);
`

// initSessionsSchema creates the session_durations table. Called from openDB.
func (d *DB) initSessionsSchema() error {
	_, err := d.db.Exec(sessionsSchemaSQL)
	return err
}

// insertSessionDuration stores one completed session.
func (d *DB) insertSessionDuration(username string, nodeID int64, seconds, endedAt int64) error {
	_, err := d.db.Exec(
		`INSERT INTO session_durations(username, node_id, seconds, ended_at) VALUES(?,?,?,?)`,
		username, nodeID, seconds, endedAt)
	return err
}

// AvgSessionDuration returns the mean session length, in seconds, across
// every session that ended within window. Returns 0 if none did.
func (d *DB) AvgSessionDuration(window time.Duration) (float64, error) {
	cutoff := time.Now().Add(-window).Unix()
	var avg float64
	err := d.db.QueryRow(
		`SELECT COALESCE(AVG(seconds),0) FROM session_durations WHERE ended_at >= ?`, cutoff).Scan(&avg)
	return avg, err
}

// sessionDurationBucket is one 10-minute point for the avg-session-duration
// chart -- same bucketing convention as networkStatsBucket/connStatsFleetBucket,
// bucketed by ended_at (when the session was reported closed, not when it
// started) so a bucket's average reflects sessions that actually finished
// in that window.
type sessionDurationBucket struct {
	Ts         int64   `json:"ts"`
	AvgSeconds float64 `json:"avg_seconds"`
	Count      int     `json:"count"`
}

// AvgSessionDurationHistory returns 10-minute-bucketed average session
// duration for the chart on the Users tab, alongside AvgSessionDuration's
// single current-range figure.
func (d *DB) AvgSessionDurationHistory(since time.Time) ([]sessionDurationBucket, error) {
	rows, err := d.db.Query(`
		SELECT (ended_at/600)*600 AS bucket, AVG(seconds), COUNT(*)
		FROM session_durations
		WHERE ended_at >= ?
		GROUP BY bucket
		ORDER BY bucket ASC`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []sessionDurationBucket
	for rows.Next() {
		var b sessionDurationBucket
		if err := rows.Scan(&b.Ts, &b.AvgSeconds, &b.Count); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// sessionDurationsOlderThan / deleteSessionDurationsOlderThan follow the same
// archive-then-delete pattern as connStatsOlderThan/deleteConnStatsOlderThan
// (see stats_archive.go).
type sessionDurationSample struct {
	Username string `json:"username"`
	NodeID   int64  `json:"node_id"`
	Seconds  int64  `json:"seconds"`
	EndedAt  int64  `json:"ended_at"`
}

func (d *DB) sessionDurationsOlderThan(cutoff int64) ([]sessionDurationSample, error) {
	rows, err := d.db.Query(
		`SELECT username, node_id, seconds, ended_at FROM session_durations WHERE ended_at < ? ORDER BY ended_at ASC`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []sessionDurationSample
	for rows.Next() {
		var s sessionDurationSample
		if err := rows.Scan(&s.Username, &s.NodeID, &s.Seconds, &s.EndedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (d *DB) deleteSessionDurationsOlderThan(cutoff int64) error {
	_, err := d.db.Exec(`DELETE FROM session_durations WHERE ended_at<?`, cutoff)
	return err
}
