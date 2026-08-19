// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"time"
)

// Club membership schema: two tables, not one per club-related concept —
// `clubs` holds static tier config (admin-managed, rarely changes),
// `club_membership_events` is a single append-only event log covering
// invites, recommendations, and the resulting grants/revokes,
// distinguished by `kind`. Current membership is derived from the latest
// granted/revoked row per (club, target_user) rather than tracked as a
// separate boolean column, so the history (who recommended whom, when
// something was revoked) is never lost.
const clubsSchema = `
CREATE TABLE IF NOT EXISTS clubs (
	id                  INTEGER PRIMARY KEY AUTOINCREMENT,
	slug                TEXT    NOT NULL UNIQUE,
	name                TEXT    NOT NULL,
	rec_threshold_cat   INTEGER NOT NULL DEFAULT 0, -- recommendations needed from current Cat Club members for auto-grant; 0 = no auto path
	rec_threshold_elite INTEGER NOT NULL DEFAULT 0, -- recommendations needed from current Elite Cat Club members for auto-grant
	subsumes_club_id    INTEGER REFERENCES clubs(id), -- e.g. Elite Cat Club subsumes Cat Club: membership in this club implies access to subsumes_club_id's manifest too
	manifest_key        TEXT    NOT NULL DEFAULT '', -- base64 symmetric key for this club's manifest; generated lazily on first access
	created_at          INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS club_membership_events (
	id                 INTEGER PRIMARY KEY AUTOINCREMENT,
	club_id            INTEGER NOT NULL REFERENCES clubs(id),
	target_user        INTEGER NOT NULL REFERENCES users(id),
	kind               TEXT    NOT NULL CHECK(kind IN ('invite','recommendation','granted','revoked')),
	actor_user         INTEGER REFERENCES users(id), -- who recommended, or which admin invited/granted/revoked; NULL for system-triggered 'granted' (auto path)
	membership_number  INTEGER, -- set only on 'granted' rows: this member's permanent per-club membership number (see assignMembershipNumber)
	created_at         INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
CREATE INDEX IF NOT EXISTS club_membership_events_target_idx ON club_membership_events(club_id, target_user);
CREATE INDEX IF NOT EXISTS club_membership_events_actor_idx ON club_membership_events(club_id, actor_user);
`

// Club is one membership tier's static configuration.
type Club struct {
	ID                int64
	Slug              string
	Name              string
	RecThresholdCat   int
	RecThresholdElite int
	SubsumesClubID    sql.NullInt64
	ManifestKey       string // base64; may be empty until first lazily generated
}

// ClubMembershipEvent is one row of the append-only club event log.
type ClubMembershipEvent struct {
	ID               int64
	ClubID           int64
	TargetUser       int64
	Kind             string // 'invite' | 'recommendation' | 'granted' | 'revoked'
	ActorUser        sql.NullInt64
	MembershipNumber sql.NullInt64 // set only on 'granted' rows
	ActorUsername    string        // joined for display, not a DB column
	TargetUsername   string        // joined for display, not a DB column
	CreatedAt        int64
}

func (d *DB) initClubsSchema() error {
	if _, err := d.db.Exec(clubsSchema); err != nil {
		return err
	}
	// club_id references clubs(id) via application logic, not a DB-enforced FK
	// (SQLite doesn't support adding a REFERENCES constraint via ALTER TABLE).
	// NULL = general/common pool, unaffected by any of this.
	d.db.Exec(`ALTER TABLE nodes ADD COLUMN club_id INTEGER`) //nolint:errcheck // fails on duplicate column, which is fine
	return d.seedDefaultClubs()
}

// ClubNodes returns live, approved nodes of nodeType dedicated to clubID's
// extra pool — used to build that club's manifest. Mirrors liveNodesTTL but
// scoped to club_id instead of the general/common pool (club_id IS NULL).
func (d *DB) ClubNodes(clubID int64, nodeType string) ([]Node, error) {
	cutoff := time.Now().Add(-heartbeatTTL).Unix()
	rows, err := d.db.Query(`
		SELECT n.id, n.owner_id, u.username, n.type, n.addr, n.fingerprint, n.pubkey,
		       n.description, COALESCE(n.token,''), n.status,
		       n.submitted_at, n.approved_at, n.last_heartbeat,
		       n.rtt_ms, n.load, n.bandwidth_mbps, n.data_plane_ok,
		       COALESCE(n.region_override,''), COALESCE(n.sni_list,''),
		       COALESCE(n.capabilities,''), COALESCE(n.location,''), COALESCE(n.provider,''), n.pinned, n.club_id,
		       COALESCE(n.node_uid,''), COALESCE(n.provider_slug,''), COALESCE(n.provider_instance_id,'')
		FROM nodes n JOIN users u ON u.id=n.owner_id
		WHERE n.type=? AND n.status='approved' AND n.last_heartbeat>=? AND n.club_id=?
		ORDER BY n.rtt_ms ASC`, nodeType, cutoff, clubID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNodes(rows)
}

// seedDefaultClubs creates the two known tiers if they don't exist yet.
// Safe to call on every startup — ON CONFLICT DO NOTHING keyed on the unique slug.
func (d *DB) seedDefaultClubs() error {
	if _, err := d.db.Exec(
		`INSERT INTO clubs (slug, name, rec_threshold_cat, rec_threshold_elite) VALUES ('cat_club', 'Cat Club', 3, 2) ON CONFLICT(slug) DO NOTHING`,
	); err != nil {
		return fmt.Errorf("seed cat_club: %w", err)
	}
	// Elite Cat Club has no auto-recommendation path (thresholds 0) and
	// subsumes Cat Club — granted once cat_club exists so the FK resolves.
	var catClubID int64
	if err := d.db.QueryRow(`SELECT id FROM clubs WHERE slug='cat_club'`).Scan(&catClubID); err != nil {
		return fmt.Errorf("lookup cat_club id: %w", err)
	}
	if _, err := d.db.Exec(
		`INSERT INTO clubs (slug, name, rec_threshold_cat, rec_threshold_elite, subsumes_club_id) VALUES ('elite_cat_club', 'Elite Cat Club', 0, 0, ?) ON CONFLICT(slug) DO NOTHING`,
		catClubID,
	); err != nil {
		return fmt.Errorf("seed elite_cat_club: %w", err)
	}
	return nil
}

// ClubBySlug looks up a club by its stable slug ("cat_club", "elite_cat_club").
func (d *DB) ClubBySlug(slug string) (*Club, error) {
	var c Club
	err := d.db.QueryRow(
		`SELECT id, slug, name, rec_threshold_cat, rec_threshold_elite, subsumes_club_id, manifest_key FROM clubs WHERE slug=?`, slug,
	).Scan(&c.ID, &c.Slug, &c.Name, &c.RecThresholdCat, &c.RecThresholdElite, &c.SubsumesClubID, &c.ManifestKey)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// AllClubs returns every configured club, ordered by id.
func (d *DB) AllClubs() ([]Club, error) {
	rows, err := d.db.Query(
		`SELECT id, slug, name, rec_threshold_cat, rec_threshold_elite, subsumes_club_id, manifest_key FROM clubs ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Club
	for rows.Next() {
		var c Club
		if err := rows.Scan(&c.ID, &c.Slug, &c.Name, &c.RecThresholdCat, &c.RecThresholdElite, &c.SubsumesClubID, &c.ManifestKey); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ClubManifestKey returns the club's symmetric manifest key, generating and
// persisting a new random 32-byte key on first access if none exists yet.
func (d *DB) ClubManifestKey(clubID int64) (string, error) {
	var key string
	if err := d.db.QueryRow(`SELECT manifest_key FROM clubs WHERE id=?`, clubID).Scan(&key); err != nil {
		return "", err
	}
	if key != "" {
		return key, nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("gen club manifest key: %w", err)
	}
	key = base64.RawURLEncoding.EncodeToString(b)
	if _, err := d.db.Exec(`UPDATE clubs SET manifest_key=? WHERE id=? AND manifest_key=''`, key, clubID); err != nil {
		return "", fmt.Errorf("persist club manifest key: %w", err)
	}
	// Re-read in case of a concurrent generator winning the race — the
	// WHERE manifest_key='' guard means at most one write actually lands;
	// whichever generator ran second must return the persisted winner.
	if err := d.db.QueryRow(`SELECT manifest_key FROM clubs WHERE id=?`, clubID).Scan(&key); err != nil {
		return "", err
	}
	return key, nil
}

// IsClubMember reports whether targetUser currently holds a direct grant for
// clubID — the latest granted/revoked event for that pair, if any, was
// 'granted'. Does not account for subsumption (see HasClubAccess).
func (d *DB) IsClubMember(clubID, targetUser int64) (bool, error) {
	var kind string
	err := d.db.QueryRow(
		`SELECT kind FROM club_membership_events
		 WHERE club_id=? AND target_user=? AND kind IN ('granted','revoked')
		 ORDER BY id DESC LIMIT 1`, clubID, targetUser,
	).Scan(&kind)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return kind == "granted", nil
}

// HasClubAccess reports whether targetUser can read clubID's manifest —
// either a direct grant, or a direct grant in a club that subsumes clubID
// (e.g. Elite Cat Club membership implies Cat Club access).
func (d *DB) HasClubAccess(clubID, targetUser int64) (bool, error) {
	if ok, err := d.IsClubMember(clubID, targetUser); err != nil || ok {
		return ok, err
	}
	rows, err := d.db.Query(`SELECT id FROM clubs WHERE subsumes_club_id=?`, clubID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	var supersets []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return false, err
		}
		supersets = append(supersets, id)
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	for _, id := range supersets {
		if ok, err := d.IsClubMember(id, targetUser); err != nil {
			return false, err
		} else if ok {
			return true, nil
		}
	}
	return false, nil
}

// GrantClubMembership records a 'granted' event. actorUser is the admin's
// user ID for a manual grant, or 0 for a system-triggered auto-grant via
// the recommendation threshold.
func (d *DB) GrantClubMembership(clubID, targetUser, actorUser int64) error {
	num, err := d.assignMembershipNumber(clubID, targetUser)
	if err != nil {
		return fmt.Errorf("assign membership number: %w", err)
	}
	return d.insertClubEventWithNumber(clubID, targetUser, "granted", actorUser, num)
}

// assignMembershipNumber returns this user's permanent per-club membership
// number, reusing a prior number if they were granted membership before
// (e.g. revoked and re-granted) rather than issuing a new one each time —
// the number identifies the member's history in the club, not a single
// grant event. Numbers are sequential per club, starting at 1.
func (d *DB) assignMembershipNumber(clubID, targetUser int64) (int64, error) {
	var existing sql.NullInt64
	err := d.db.QueryRow(
		`SELECT membership_number FROM club_membership_events
		 WHERE club_id=? AND target_user=? AND kind='granted' AND membership_number IS NOT NULL
		 ORDER BY id ASC LIMIT 1`, clubID, targetUser,
	).Scan(&existing)
	if err != nil && err != sql.ErrNoRows {
		return 0, err
	}
	if existing.Valid {
		return existing.Int64, nil
	}
	var next sql.NullInt64
	if err := d.db.QueryRow(
		`SELECT MAX(membership_number) FROM club_membership_events WHERE club_id=? AND kind='granted'`, clubID,
	).Scan(&next); err != nil {
		return 0, err
	}
	if next.Valid {
		return next.Int64 + 1, nil
	}
	return 1, nil
}

// RevokeClubMembership records a 'revoked' event. Always an explicit admin
// action — there is no automatic revoke path.
func (d *DB) RevokeClubMembership(clubID, targetUser, actorUser int64) error {
	return d.insertClubEvent(clubID, targetUser, "revoked", actorUser)
}

// InviteToClub records an admin invite. Recorded for visibility/history;
// does not by itself grant membership (an admin invite is expected to be
// followed by a GrantClubMembership call once accepted — kept as two
// separate events rather than folded together, so "invited but never
// joined" stays visible in the log).
func (d *DB) InviteToClub(clubID, targetUser, actorUser int64) error {
	return d.insertClubEvent(clubID, targetUser, "invite", actorUser)
}

// RecommendClubMembership records a recommendation from recommenderUser for
// targetUser joining clubID, then checks whether the recommendation
// threshold has now been crossed and auto-grants if so. Only meaningful for
// clubs with a nonzero recommendation threshold (Cat Club today).
func (d *DB) RecommendClubMembership(clubID, targetUser, recommenderUser int64) error {
	if err := d.insertClubEvent(clubID, targetUser, "recommendation", recommenderUser); err != nil {
		return err
	}
	return d.maybeAutoGrant(clubID, targetUser)
}

// maybeAutoGrant checks the recommendation counts for targetUser against
// clubID's thresholds and grants membership if either is met and the user
// isn't already a member. Recommenders are counted only if they currently
// hold the required membership themselves (a recommendation from someone
// since revoked doesn't count).
func (d *DB) maybeAutoGrant(clubID, targetUser int64) error {
	var club Club
	if err := d.db.QueryRow(
		`SELECT id, rec_threshold_cat, rec_threshold_elite FROM clubs WHERE id=?`, clubID,
	).Scan(&club.ID, &club.RecThresholdCat, &club.RecThresholdElite); err != nil {
		return err
	}
	if club.RecThresholdCat <= 0 && club.RecThresholdElite <= 0 {
		return nil // no auto path for this club
	}
	if already, err := d.IsClubMember(clubID, targetUser); err != nil {
		return err
	} else if already {
		return nil
	}

	catClub, err := d.ClubBySlug("cat_club")
	if err != nil {
		return fmt.Errorf("lookup cat_club for threshold check: %w", err)
	}
	eliteClub, err := d.ClubBySlug("elite_cat_club")
	if err != nil {
		return fmt.Errorf("lookup elite_cat_club for threshold check: %w", err)
	}

	if club.RecThresholdCat > 0 {
		n, err := d.countQualifyingRecommenders(clubID, targetUser, catClub.ID)
		if err != nil {
			return err
		}
		if n >= club.RecThresholdCat {
			return d.GrantClubMembership(clubID, targetUser, 0)
		}
	}
	if club.RecThresholdElite > 0 {
		n, err := d.countQualifyingRecommenders(clubID, targetUser, eliteClub.ID)
		if err != nil {
			return err
		}
		if n >= club.RecThresholdElite {
			return d.GrantClubMembership(clubID, targetUser, 0)
		}
	}
	return nil
}

// countQualifyingRecommenders counts the distinct recommenders of
// targetUser for clubID who currently hold membership in sourceClubID —
// a recommendation from someone since revoked doesn't count.
func (d *DB) countQualifyingRecommenders(clubID, targetUser, sourceClubID int64) (int, error) {
	rows, err := d.db.Query(
		`SELECT DISTINCT actor_user FROM club_membership_events
		 WHERE club_id=? AND target_user=? AND kind='recommendation' AND actor_user IS NOT NULL`,
		clubID, targetUser)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var actor int64
		if err := rows.Scan(&actor); err != nil {
			return 0, err
		}
		if ok, err := d.IsClubMember(sourceClubID, actor); err != nil {
			return 0, err
		} else if ok {
			n++
		}
	}
	return n, rows.Err()
}

// PendingRecommendationCandidate is a user recommended for a club but not
// yet a member, with their current qualifying recommendation counts from
// each source club — for the admin panel's "who's close to joining" view.
type PendingRecommendationCandidate struct {
	TargetUser     int64
	TargetUsername string
	CatCount       int
	EliteCount     int
}

// PendingCandidates lists non-member users who have at least one
// recommendation on file for clubID, with their current counts.
func (d *DB) PendingCandidates(clubID int64) ([]PendingRecommendationCandidate, error) {
	rows, err := d.db.Query(`
		SELECT DISTINCT e.target_user, t.username FROM club_membership_events e
		JOIN users t ON t.id = e.target_user
		WHERE e.club_id=? AND e.kind='recommendation'
		ORDER BY t.username`, clubID)
	if err != nil {
		return nil, err
	}
	var candidates []PendingRecommendationCandidate
	for rows.Next() {
		var c PendingRecommendationCandidate
		if err := rows.Scan(&c.TargetUser, &c.TargetUsername); err != nil {
			rows.Close()
			return nil, err
		}
		candidates = append(candidates, c)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	catClub, err := d.ClubBySlug("cat_club")
	if err != nil {
		return nil, err
	}
	eliteClub, err := d.ClubBySlug("elite_cat_club")
	if err != nil {
		return nil, err
	}

	out := make([]PendingRecommendationCandidate, 0, len(candidates))
	for _, c := range candidates {
		if already, err := d.IsClubMember(clubID, c.TargetUser); err != nil {
			return nil, err
		} else if already {
			continue
		}
		if c.CatCount, err = d.countQualifyingRecommenders(clubID, c.TargetUser, catClub.ID); err != nil {
			return nil, err
		}
		if c.EliteCount, err = d.countQualifyingRecommenders(clubID, c.TargetUser, eliteClub.ID); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// ClubNodesAllStatuses returns every node (any status, any type) currently
// dedicated to clubID's pool — for the admin panel, which needs to show
// pending/suspended nodes too, unlike ClubNodes (manifest-building, live
// approved only).
func (d *DB) ClubNodesAllStatuses(clubID int64) ([]Node, error) {
	rows, err := d.db.Query(`
		SELECT n.id, n.owner_id, u.username, n.type, n.addr, n.fingerprint, n.pubkey,
		       n.description, COALESCE(n.token,''), n.status,
		       n.submitted_at, n.approved_at, n.last_heartbeat,
		       n.rtt_ms, n.load, n.bandwidth_mbps, n.data_plane_ok,
		       COALESCE(n.region_override,''), COALESCE(n.sni_list,''),
		       COALESCE(n.capabilities,''), COALESCE(n.location,''), COALESCE(n.provider,''), n.pinned, n.club_id,
		       COALESCE(n.node_uid,''), COALESCE(n.provider_slug,''), COALESCE(n.provider_instance_id,'')
		FROM nodes n JOIN users u ON u.id=n.owner_id
		WHERE n.club_id=?
		ORDER BY n.type, n.addr`, clubID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNodes(rows)
}

// setNodeClub assigns nodeID to clubID's dedicated pool, or clears it back
// to the general/common pool if clubID is 0.
func (d *DB) setNodeClub(nodeID, clubID int64) error {
	if clubID <= 0 {
		_, err := d.db.Exec(`UPDATE nodes SET club_id=NULL WHERE id=?`, nodeID)
		return err
	}
	_, err := d.db.Exec(`UPDATE nodes SET club_id=? WHERE id=?`, clubID, nodeID)
	return err
}

func (d *DB) insertClubEvent(clubID, targetUser int64, kind string, actorUser int64) error {
	return d.insertClubEventWithNumber(clubID, targetUser, kind, actorUser, 0)
}

// insertClubEventWithNumber is insertClubEvent plus an optional membership
// number (only meaningful for kind='granted'; pass 0 for every other kind).
func (d *DB) insertClubEventWithNumber(clubID, targetUser int64, kind string, actorUser, membershipNumber int64) error {
	var actor sql.NullInt64
	if actorUser > 0 {
		actor = sql.NullInt64{Int64: actorUser, Valid: true}
	}
	var num sql.NullInt64
	if membershipNumber > 0 {
		num = sql.NullInt64{Int64: membershipNumber, Valid: true}
	}
	_, err := d.db.Exec(
		`INSERT INTO club_membership_events (club_id, target_user, kind, actor_user, membership_number) VALUES (?,?,?,?,?)`,
		clubID, targetUser, kind, actor, num)
	return err
}

// ClubEventsForTarget returns the full event history for one candidate in
// one club, oldest first — used by the admin panel to show the
// recommendation graph ("who recommended whom") alongside invites and
// grant/revoke history.
func (d *DB) ClubEventsForTarget(clubID, targetUser int64) ([]ClubMembershipEvent, error) {
	rows, err := d.db.Query(
		`SELECT e.id, e.club_id, e.target_user, e.kind, e.actor_user, e.membership_number, e.created_at,
		        COALESCE(a.username, ''), t.username
		 FROM club_membership_events e
		 LEFT JOIN users a ON a.id = e.actor_user
		 JOIN users t ON t.id = e.target_user
		 WHERE e.club_id=? AND e.target_user=?
		 ORDER BY e.id ASC`, clubID, targetUser)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ClubMembershipEvent
	for rows.Next() {
		var ev ClubMembershipEvent
		if err := rows.Scan(&ev.ID, &ev.ClubID, &ev.TargetUser, &ev.Kind, &ev.ActorUser, &ev.MembershipNumber, &ev.CreatedAt, &ev.ActorUsername, &ev.TargetUsername); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// MembershipNumber returns the user's permanent membership number for
// clubID, if they currently hold a direct grant. ok=false if not a member.
func (d *DB) MembershipNumber(clubID, targetUser int64) (num int64, ok bool, err error) {
	member, err := d.IsClubMember(clubID, targetUser)
	if err != nil || !member {
		return 0, false, err
	}
	var n sql.NullInt64
	err = d.db.QueryRow(
		`SELECT membership_number FROM club_membership_events
		 WHERE club_id=? AND target_user=? AND kind='granted' AND membership_number IS NOT NULL
		 ORDER BY id ASC LIMIT 1`, clubID, targetUser,
	).Scan(&n)
	if err != nil {
		return 0, false, err
	}
	return n.Int64, n.Valid, nil
}

// ClubMembers returns the usernames of every current direct member of
// clubID (latest event per target_user is 'granted'), for the admin
// member-list screen.
func (d *DB) ClubMembers(clubID int64) ([]string, error) {
	rows, err := d.db.Query(`
		SELECT u.username FROM users u
		WHERE EXISTS (
			SELECT 1 FROM club_membership_events e
			WHERE e.club_id=? AND e.target_user=u.id AND e.kind IN ('granted','revoked')
			AND e.id = (
				SELECT MAX(id) FROM club_membership_events e2
				WHERE e2.club_id=e.club_id AND e2.target_user=e.target_user AND e2.kind IN ('granted','revoked')
			)
			AND e.kind='granted'
		)
		ORDER BY u.username`, clubID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
