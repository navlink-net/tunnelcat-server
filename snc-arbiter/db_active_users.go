// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/json"
	"time"
)

// liveActiveUserFreshness is how old a node's most recent /api/node/stats
// snapshot can be before it's dropped from the live "Active users" count.
// Deliberately 2x statsFlushInterval (snc-exit/stats.go, 5 min): the old
// design compared a single per-user last_seen timestamp against a window
// exactly equal to the flush interval, with zero slack -- a genuinely
// connected user could fall in or out of the count purely because their
// specific exit's flush timer hadn't fired yet relative to the moment the
// count was read, causing the live card to visibly flicker/jump on a small
// user base. Freshness is now checked per NODE instead of per USER, so it
// can afford real margin without losing precision: a node's latest
// snapshot is either fully trusted (used whole) or fully dropped (node
// gone stale/dead), never partially decayed.
const liveActiveUserFreshness = 10 * time.Minute

const nodeActiveUsersSchemaSQL = `
CREATE TABLE IF NOT EXISTS node_active_users (
	node_id     INTEGER PRIMARY KEY,
	usernames   TEXT    NOT NULL,
	reported_at INTEGER NOT NULL
);
`

// initNodeActiveUsersSchema creates the node_active_users table (SQLite path
// only -- the Postgres schema arrives via migrations/postgres, see
// 00006_add_node_active_users.sql). Called from openDB.
func (d *DB) initNodeActiveUsersSchema() error {
	_, err := d.db.Exec(nodeActiveUsersSchemaSQL)
	return err
}

// UpsertNodeActiveUsers replaces (not merges into) the given exit node's
// latest reported username list -- each /api/node/stats flush is a full
// snapshot of who that node saw traffic for since its previous flush, and
// this row always holds only the most recent one. See apiNodeStats
// (admin_stats.go).
func (d *DB) UpsertNodeActiveUsers(nodeID int64, usernames []string, reportedAt int64) error {
	// Never nil in the JSON output: an exit with zero currently-active users
	// still needs its "I checked in, and saw nobody" snapshot recorded, so
	// it doesn't linger showing a stale nonempty list from its previous
	// flush after everyone using it has actually disconnected.
	if usernames == nil {
		usernames = []string{}
	}
	raw, err := json.Marshal(usernames)
	if err != nil {
		return err
	}
	_, err = d.db.Exec(`
		INSERT INTO node_active_users(node_id, usernames, reported_at)
		VALUES(?,?,?)
		ON CONFLICT(node_id) DO UPDATE SET usernames=excluded.usernames, reported_at=excluded.reported_at`,
		nodeID, string(raw), reportedAt)
	return err
}

// activeUserSet returns the union of usernames across every node whose most
// recent node_active_users snapshot is no older than freshness -- the
// building block for both CountLiveActiveUsers and
// CountClubMembersOnlineLive. Done in Go rather than SQL-side JSON
// unnesting since the row count here is tiny (one per exit node) and the
// two engines' JSON functions don't share syntax, unlike everywhere else
// in this package where a plain rebindingDB query suffices.
func (d *DB) activeUserSet(freshness time.Duration) (map[string]struct{}, error) {
	cutoff := time.Now().Add(-freshness).Unix()
	rows, err := d.db.Query(`SELECT usernames FROM node_active_users WHERE reported_at >= ?`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	set := make(map[string]struct{})
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var names []string
		if err := json.Unmarshal([]byte(raw), &names); err != nil {
			continue // one node's malformed row shouldn't sink the whole count
		}
		for _, n := range names {
			set[n] = struct{}{}
		}
	}
	return set, rows.Err()
}

// CountLiveActiveUsers returns the number of distinct accounts seen active
// across every currently-fresh exit node's latest snapshot -- the "Active
// users" card and chart's live/right-now number. Not to be confused with
// CountActiveUsers (db_stats.go), which answers a different question ("how
// many distinct users appeared at all over a long range like 24h/7d/30d")
// that inherently needs the persisted per-user history this table doesn't
// keep -- that one is unaffected by the flicker this fixes and is left
// alone.
func (d *DB) CountLiveActiveUsers() (int, error) {
	set, err := d.activeUserSet(liveActiveUserFreshness)
	if err != nil {
		return 0, err
	}
	return len(set), nil
}

// CountClubMembersOnlineLive returns how many *directly granted* members of
// the given club are currently online, using the same live/fresh-node
// definition as CountLiveActiveUsers instead of the old per-user
// last_seen-vs-fixed-window comparison. Deliberately not subsumption-aware:
// an Elite Cat Club member who was never directly granted Cat Club doesn't
// count toward Cat Club's number here, even though they have access to its
// manifest (see clubs.subsumes_club_id) -- two independent per-club counts,
// by design. Membership is event-sourced (club_membership_events): a user's
// current state for a club is whatever their most recent event (by id)
// says: only "granted" counts as a member; "revoked" (or no events at all)
// doesn't.
func (d *DB) CountClubMembersOnlineLive(clubID int64) (int, error) {
	active, err := d.activeUserSet(liveActiveUserFreshness)
	if err != nil {
		return 0, err
	}
	if len(active) == 0 {
		return 0, nil
	}

	rows, err := d.db.Query(`
		SELECT u.username FROM (
			SELECT e.target_user
			FROM club_membership_events e
			WHERE e.club_id = ?
			  AND e.id = (
				SELECT MAX(e2.id) FROM club_membership_events e2
				WHERE e2.club_id = e.club_id AND e2.target_user = e.target_user
			  )
			  AND e.kind = 'granted'
		) members
		JOIN users u ON u.id = members.target_user`, clubID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var username string
		if err := rows.Scan(&username); err != nil {
			return 0, err
		}
		if _, ok := active[username]; ok {
			n++
		}
	}
	return n, rows.Err()
}
