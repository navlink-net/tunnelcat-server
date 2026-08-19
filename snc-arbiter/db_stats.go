// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"time"
)

const statsSchema = `
CREATE TABLE IF NOT EXISTS user_stats (
	username     TEXT    PRIMARY KEY,
	first_seen   INTEGER NOT NULL DEFAULT 0,
	last_seen    INTEGER NOT NULL DEFAULT 0,
	bytes_up     INTEGER NOT NULL DEFAULT 0,
	bytes_down   INTEGER NOT NULL DEFAULT 0,
	country      TEXT    NOT NULL DEFAULT '',
	conns        INTEGER NOT NULL DEFAULT 0
);
`

// initStatsSchema creates the stats tables. Called from openDB.
func (db *DB) initStatsSchema() error {
	_, err := db.db.Exec(statsSchema)
	return err
}

// UpsertUserStats merges incremental stats reported by an exit node for one user.
// All byte/conn values are additive; country is updated when non-empty.
func (db *DB) UpsertUserStats(username, country string, bytesUp, bytesDown, conns int64, lastSeen time.Time) error {
	now := lastSeen.Unix()
	_, err := db.db.Exec(`
		INSERT INTO user_stats(username, first_seen, last_seen, bytes_up, bytes_down, country, conns)
		VALUES(?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(username) DO UPDATE SET
			last_seen  = CASE WHEN user_stats.last_seen > excluded.last_seen THEN user_stats.last_seen ELSE excluded.last_seen END,
			first_seen = CASE WHEN user_stats.first_seen = 0 THEN excluded.first_seen WHEN user_stats.first_seen < excluded.first_seen THEN user_stats.first_seen ELSE excluded.first_seen END,
			bytes_up   = user_stats.bytes_up   + excluded.bytes_up,
			bytes_down = user_stats.bytes_down + excluded.bytes_down,
			conns      = user_stats.conns      + excluded.conns,
			country    = CASE WHEN excluded.country != '' THEN excluded.country ELSE user_stats.country END
	`, username, now, now, bytesUp, bytesDown, country, conns)
	return err
}

// UserStatRow is one row returned by QueryUserStats.
type UserStatRow struct {
	Username  string
	FirstSeen time.Time
	LastSeen  time.Time
	BytesUp   int64
	BytesDown int64
	Country   string
	Conns     int64
	Suspended bool // true when user_enabled=0
}

// QueryUserStats returns all users whose username matches the LIKE pattern (% wildcards).
// Pass "%" to return all users.
func (db *DB) QueryUserStats(like string) ([]UserStatRow, error) {
	rows, err := db.db.Query(`
		SELECT us.username, us.first_seen, us.last_seen,
		       us.bytes_up, us.bytes_down, us.country, us.conns,
		       COALESCE(u.user_enabled, 1)
		FROM user_stats us
		LEFT JOIN users u ON u.username = us.username
		WHERE us.username LIKE ?
		ORDER BY us.last_seen DESC
		LIMIT 500
	`, like)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserStatRow
	for rows.Next() {
		var r UserStatRow
		var first, last int64
		var userEnabled int
		if err := rows.Scan(&r.Username, &first, &last, &r.BytesUp, &r.BytesDown, &r.Country, &r.Conns, &userEnabled); err != nil {
			return nil, err
		}
		r.FirstSeen = time.Unix(first, 0)
		r.LastSeen = time.Unix(last, 0)
		r.Suspended = userEnabled == 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// CountActiveUsers returns the number of users seen within the last window.
func (db *DB) CountActiveUsers(window time.Duration) (int, error) {
	cutoff := time.Now().Add(-window).Unix()
	var n int
	err := db.db.QueryRow(`SELECT COUNT(*) FROM user_stats WHERE last_seen >= ?`, cutoff).Scan(&n)
	return n, err
}

// CountActiveSessions returns the number of distinct users with a non-expired SNC session.
// Uses sessionStaleTTL as the expiry boundary (3 h without re-validation → session dead).
func (db *DB) CountActiveSessions() (int, error) {
	cutoff := time.Now().Add(-sessionStaleTTL).Unix()
	var n int
	err := db.db.QueryRow(
		`SELECT COUNT(DISTINCT username) FROM sessions WHERE validated_at >= ?`, cutoff).Scan(&n)
	return n, err
}

// CountTotalUsers returns the total number of unique users ever seen (i.e.
// that have generated at least one user_stats row via actual exit traffic).
// Not the same as CountAllAccounts -- see that doc comment.
func (db *DB) CountTotalUsers() (int, error) {
	var n int
	err := db.db.QueryRow(`SELECT COUNT(*) FROM user_stats`).Scan(&n)
	return n, err
}

// CountAllAccounts returns every registered account, including ones that
// have never connected (and so have no user_stats row at all -- unlike
// CountTotalUsers, which only counts users exit nodes have actually seen
// traffic from).
func (db *DB) CountAllAccounts() (int, error) {
	var n int
	err := db.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

