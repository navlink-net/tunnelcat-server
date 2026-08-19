// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite"
)

const schema = `
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	username   TEXT    NOT NULL UNIQUE,
	role       TEXT    NOT NULL DEFAULT 'user',  -- 'user' | 'admin'
	client_id  TEXT    NOT NULL DEFAULT ''       -- immutable billing identifier, set on first key generation
);

CREATE TABLE IF NOT EXISTS nodes (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	owner_id       INTEGER NOT NULL REFERENCES users(id),
	type           TEXT    NOT NULL,   -- 'control' | 'exit'
	addr           TEXT    NOT NULL,   -- host:port
	fingerprint    TEXT    NOT NULL DEFAULT '',
	pubkey         TEXT    NOT NULL DEFAULT '',
	description    TEXT    NOT NULL DEFAULT '',
	token          TEXT    UNIQUE,     -- assigned on approval; NULL until approved
	status         TEXT    NOT NULL DEFAULT 'pending',  -- 'pending'|'approved'|'rejected'|'suspended'
	submitted_at   INTEGER NOT NULL DEFAULT (strftime('%s','now')),
	approved_at    INTEGER,
	last_heartbeat INTEGER,
	rtt_ms         REAL    NOT NULL DEFAULT 0,
	load           REAL    NOT NULL DEFAULT 0,
	bandwidth_mbps REAL    NOT NULL DEFAULT 0,
	data_plane_ok  INTEGER             -- NULL = not yet reporting; 0 = false; 1 = true
);

CREATE TABLE IF NOT EXISTS whitelist_entries (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	type       TEXT    NOT NULL CHECK(type IN ('domain','wildcard','cidr')),
	value      TEXT    NOT NULL UNIQUE,
	created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

-- Keyless bootstrap: destinations reachable through the tunnel without a
-- valid per-user session, gated on a single shared token baked into the
-- client apps (see snc-exit's anonBootstrapCache) rather than on "no token
-- presented" -- so it flows through the exact same session-check code path
-- as a real user, no new wire shape, nothing for DPI to key on differently.
-- Exists so a brand-new user with no key yet can still reach the site that
-- sells one (shortnerdcat.navlink.net / navlink.net) from inside the app,
-- in a threat model where direct (non-tunneled) access to that site is
-- assumed blocked. Same shape as whitelist_entries deliberately.
CREATE TABLE IF NOT EXISTS anon_allowlist_entries (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	type       TEXT    NOT NULL CHECK(type IN ('domain','wildcard','cidr')),
	value      TEXT    NOT NULL UNIQUE,
	created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

-- Per-service region blocks: "this domain/wildcard/cidr must not be dialed
-- directly by an exit whose own region is one of blocked_regions" -- e.g.
-- Telegram voice CIDRs blocked for region=RU, since RU-hosted exits can't
-- reach them (RKN blocking) no matter how healthy the exit otherwise is.
-- Same shape as whitelist_entries deliberately -- same admin mental model,
-- same signed-manifest distribution to exits (see signServiceBlocks).
CREATE TABLE IF NOT EXISTS service_region_blocks (
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	type            TEXT    NOT NULL CHECK(type IN ('domain','wildcard','cidr')),
	value           TEXT    NOT NULL,
	blocked_regions TEXT    NOT NULL, -- CSV of region codes, e.g. "RU" or "RU,CN,IR"
	reason          TEXT    NOT NULL DEFAULT '',
	created_at      INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS blacklist_entries (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	addr       TEXT    NOT NULL UNIQUE,
	reason     TEXT    NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

-- Exit addresses NOT allowed to let BitTorrent peer connections egress
-- directly. Blacklist model (deliberately matching service_region_blocks'
-- mental model): torrent egress is allowed everywhere by default, including
-- newly onboarded exits, and an admin opts specific exits OUT here rather
-- than opting exits in. Arbiter-controlled (admin adds/removes here, exits
-- fetch the signed list) -- deliberately NOT a local per-exit flag/env-var,
-- so this is togglable from one place without SSHing into and restarting
-- individual exit nodes.
CREATE TABLE IF NOT EXISTS torrent_blocked_entries (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	addr       TEXT    NOT NULL UNIQUE,
	reason     TEXT    NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS excluded_nodes (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	addr       TEXT    NOT NULL UNIQUE,
	reason     TEXT    NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS user_confirmations (
	username   TEXT    PRIMARY KEY,
	confirmed  INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS email_tokens (
	token      TEXT    PRIMARY KEY,
	username   TEXT    NOT NULL,
	type       TEXT    NOT NULL CHECK(type IN ('confirm','reset')),
	expires_at INTEGER NOT NULL,
	created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS sessions (
	token        TEXT    PRIMARY KEY,
	username     TEXT    NOT NULL,
	client_id    TEXT    NOT NULL DEFAULT '',
	device_id    TEXT    NOT NULL DEFAULT '',
	device_name  TEXT    NOT NULL DEFAULT '',
	enc_password BLOB    NOT NULL,
	cam_session  TEXT    NOT NULL DEFAULT '',
	validated_at INTEGER NOT NULL DEFAULT 0,
	last_attempt INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS subscription_plans (
	region        TEXT    NOT NULL,   -- ISO country code or '*' for default
	duration_days INTEGER NOT NULL DEFAULT 30,
	price_pia     INTEGER NOT NULL,
	updated_at    INTEGER NOT NULL DEFAULT (strftime('%s','now')),
	updated_by    TEXT    NOT NULL DEFAULT '',
	PRIMARY KEY (region, duration_days)
);

CREATE TABLE IF NOT EXISTS system_settings (
	key        TEXT PRIMARY KEY,
	value      TEXT NOT NULL,
	updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
	updated_by TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS subscriptions (
	key_id          TEXT    PRIMARY KEY REFERENCES keys(key_id) ON DELETE CASCADE,
	client_id       TEXT    NOT NULL DEFAULT '',
	user_email      TEXT    NOT NULL,
	plan_pia        INTEGER NOT NULL,                         -- minor units at time of last charge
	paid_until      INTEGER NOT NULL,                         -- unix timestamp
	status          TEXT    NOT NULL DEFAULT 'active',        -- 'active' | 'paused'
	last_charged_at INTEGER,
	created_at      INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

CREATE TABLE IF NOT EXISTS notifications (
	id         TEXT    PRIMARY KEY,
	message    TEXT    NOT NULL,
	created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
	created_by TEXT    NOT NULL DEFAULT ''
);

`

// migrations runs ALTER TABLE statements that are safe to call on existing
// databases (SQLite ignores duplicate-column errors via IF NOT EXISTS).
const migrations = `
ALTER TABLE users    ADD COLUMN client_id TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN client_id TEXT NOT NULL DEFAULT '';
`

// DB wraps a *rebindingDB (db_rebind.go) -- itself a thin layer over
// *sqlx.DB, which embeds the standard *sql.DB -- rather than a bare
// *sql.DB. This is a deliberate chokepoint: every call site still goes
// through the same Query/Exec/QueryRow/Begin method names it always has,
// but they now transparently rebind "?"-style placeholders to whatever the
// underlying driver needs (a no-op for SQLite, "$1,$2,..." for Postgres),
// so nothing else in the package needs to change regardless of which
// engine openDB actually opened.
type DB struct{ db *rebindingDB }

// migratePlansTable upgrades subscription_plans from the old schema
// (region TEXT PRIMARY KEY) to the new composite PK (region, duration_days).
// Safe to call on both old and already-migrated databases.
func migratePlansTable(db *sql.DB) error {
	// Check whether duration_days column already exists.
	rows, err := db.Query(`PRAGMA table_info(subscription_plans)`)
	if err != nil {
		return err
	}
	hasDuration := false
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		if name == "duration_days" {
			hasDuration = true
		}
	}
	rows.Close()
	if hasDuration {
		return nil // already migrated
	}
	// Recreate table with composite PK, preserving existing rows as 30-day plans.
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS subscription_plans_v2 (
			region        TEXT    NOT NULL,
			duration_days INTEGER NOT NULL DEFAULT 30,
			price_pia     INTEGER NOT NULL,
			updated_at    INTEGER NOT NULL DEFAULT (strftime('%s','now')),
			updated_by    TEXT    NOT NULL DEFAULT '',
			PRIMARY KEY (region, duration_days)
		)`,
		`INSERT OR IGNORE INTO subscription_plans_v2 (region, duration_days, price_pia, updated_at, updated_by)
		 SELECT region, 30, price_pia, updated_at, updated_by FROM subscription_plans`,
		`DROP TABLE IF EXISTS subscription_plans`,
		`ALTER TABLE subscription_plans_v2 RENAME TO subscription_plans`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return fmt.Errorf("migrate plans: %w", err)
		}
	}
	return nil
}

// migrateSubscriptionsTable converts the old schema (client_id PRIMARY KEY, one row
// per user) to the new schema (key_id PRIMARY KEY, one row per key). Safe to call
// on an already-migrated database.
func migrateSubscriptionsTable(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(subscriptions)`)
	if err != nil {
		return err
	}
	hasKeyID := false
	for rows.Next() {
		var cid int
		var name, typ string
		var notNull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		if name == "key_id" {
			hasKeyID = true
		}
	}
	rows.Close()
	if hasKeyID {
		return nil // already migrated
	}

	// Recreate with key_id as primary key. One row per billed key; derive values
	// from the key's own paid_until/plan_pia and fall back to the user's legacy
	// subscription row for last_charged_at and created_at.
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS subscriptions_v2 (
			key_id          TEXT    PRIMARY KEY REFERENCES keys(key_id) ON DELETE CASCADE,
			client_id       TEXT    NOT NULL DEFAULT '',
			user_email      TEXT    NOT NULL,
			plan_pia        INTEGER NOT NULL,
			paid_until      INTEGER NOT NULL,
			status          TEXT    NOT NULL DEFAULT 'active',
			last_charged_at INTEGER,
			created_at      INTEGER NOT NULL DEFAULT (strftime('%s','now'))
		)`,
		`INSERT OR IGNORE INTO subscriptions_v2
		     (key_id, client_id, user_email, plan_pia, paid_until, status, last_charged_at, created_at)
		 SELECT
		     k.key_id,
		     COALESCE(u.client_id, ''),
		     u.username,
		     k.plan_pia,
		     k.paid_until,
		     'active',
		     s.last_charged_at,
		     COALESCE(s.created_at, k.issued_at, strftime('%s','now'))
		 FROM keys k
		 JOIN users u ON k.username = u.username
		 LEFT JOIN subscriptions s ON s.client_id = u.client_id
		 WHERE k.paid_until IS NOT NULL`,
		`DROP TABLE IF EXISTS subscriptions`,
		`ALTER TABLE subscriptions_v2 RENAME TO subscriptions`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("migrate subscriptions: %w", err)
		}
	}
	return nil
}

// openDB opens the arbiter's database, dispatching on the shape of path:
// a Postgres DSN (postgres:// or postgresql://) goes through
// openPostgresDB (db_postgres.go), anything else is treated as a SQLite
// file path, unchanged from before this migration started. Every DB
// method elsewhere in the package (~280 call sites) operates on the
// resulting *DB the same way regardless of which branch ran.
func openDB(path string) (*DB, error) {
	if isPostgresDSN(path) {
		return openPostgresDB(path)
	}
	db, err := sqlx.Open("sqlite", path+"?_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", path, err)
	}
	db.SetMaxOpenConns(1) // SQLite likes single-writer
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	// keys' own CREATE TABLE lives in initKeysSchema (below), but several of
	// the ALTER TABLE ADD COLUMN statements right after this point target
	// keys too. Must run initKeysSchema first so the table actually exists
	// on a genuinely fresh database -- previously this ran at the end of
	// openDB, after those ALTERs, so every one of them silently no-op'd
	// (swallowed "no such table") on a brand-new install and keys ended up
	// permanently missing paid_until/plan_pia/reminder_sent/
	// preferred_duration_days/unlimited_devices/warn_count/last_warned_at.
	// Never manifested against the real production DB (that table has
	// existed since long before these columns were added), only found via
	// a fresh-database test (db_keys_test.go) -- fixed here rather than
	// carried into the from-scratch Postgres schema this system is moving to.
	d := &DB{db: &rebindingDB{db}}
	if err := d.initKeysSchema(); err != nil {
		return nil, fmt.Errorf("keys schema: %w", err)
	}
	// Run column-addition migrations; each ALTER TABLE may fail if the column
	// already exists (from the schema or a prior run) — that is expected and safe.
	for _, stmt := range []string{
		`ALTER TABLE users    ADD COLUMN client_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE sessions ADD COLUMN client_id TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE nodes    ADD COLUMN data_plane_ok INTEGER`,
		// device_id/device_name: arbiter.log's "session validate"/"login" lines
		// previously only identified the *account* (client_id), not which of
		// the account's devices made the request -- indistinguishable from each
		// other when a user is logged in on several devices at once. Confirmed
		// as a real diagnostic gap on 2026-08-09: a genuine per-device auth
		// failure was misdiagnosed as "mostly working" because other devices on
		// the same account were succeeding in the same log window.
		`ALTER TABLE sessions ADD COLUMN device_id   TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE sessions ADD COLUMN device_name TEXT NOT NULL DEFAULT ''`,
	} {
		db.Exec(stmt) //nolint:errcheck // fails on duplicate column, which is fine
	}
	// Run column-addition migrations for keys/user management features.
	for _, stmt := range []string{
		`ALTER TABLE users ADD COLUMN user_enabled INTEGER NOT NULL DEFAULT 1`,
		// Multi-device warning tracking per key.
		`ALTER TABLE keys ADD COLUMN warn_count     INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE keys ADD COLUMN last_warned_at INTEGER NOT NULL DEFAULT 0`,
		// Per-user notifications: NULL username = broadcast; non-NULL = specific user only.
		`ALTER TABLE notifications ADD COLUMN username TEXT`,
		// Registration source: 'navlink' for navlink.net signups; other values reserved.
		`ALTER TABLE user_confirmations ADD COLUMN source TEXT NOT NULL DEFAULT ''`,
	} {
		db.Exec(stmt) //nolint:errcheck // fails on duplicate column, which is fine
	}
	// Migrate subscription_plans to composite PK (region, duration_days) if needed.
	// The old schema had region TEXT PRIMARY KEY with no duration_days column.
	if err := migratePlansTable(db.DB); err != nil {
		return nil, fmt.Errorf("plans migration: %w", err)
	}

	// Migrate subscriptions from one-per-user (client_id PK) to one-per-key (key_id PK).
	if err := migrateSubscriptionsTable(db.DB); err != nil {
		return nil, fmt.Errorf("subscriptions migration: %w", err)
	}

	// promo_codes/promo_uses: the promo-code purchase feature is gone, but the
	// tables are kept (empty on fresh installs) because listPendingConfirmations
	// still LEFT JOINs promo_uses for the admin pending-users history column.
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS promo_codes (
	code         TEXT    PRIMARY KEY,
	type         TEXT    NOT NULL DEFAULT 'free',
	discount_val REAL    NOT NULL DEFAULT 0,
	max_uses     INTEGER NOT NULL DEFAULT 0,
	uses         INTEGER NOT NULL DEFAULT 0,
	per_user     INTEGER NOT NULL DEFAULT 1,
	valid_from   INTEGER NOT NULL DEFAULT 0,
	valid_until  INTEGER NOT NULL DEFAULT 0,
	enabled      INTEGER NOT NULL DEFAULT 1,
	description  TEXT    NOT NULL DEFAULT '',
	created_at   INTEGER NOT NULL DEFAULT (strftime('%s','now')),
	created_by   TEXT    NOT NULL DEFAULT '',
	allowed_duration_days INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS promo_uses (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	code        TEXT    NOT NULL,
	username    TEXT    NOT NULL,
	used_at     INTEGER NOT NULL DEFAULT (strftime('%s','now')),
	key_id      TEXT    NOT NULL DEFAULT '',
	charged_pia INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS promo_uses_code_user ON promo_uses(code, username);
`); err != nil {
		return nil, fmt.Errorf("promo tables: %w", err)
	}

	// SNI list per control node (comma-separated hostnames; "" = no SNI rotation).
	db.Exec(`ALTER TABLE nodes ADD COLUMN sni_list TEXT NOT NULL DEFAULT ''`) //nolint:errcheck

	// Per-key expiry, reminder tracking, and preferred renewal plan (NULL paid_until = perpetual key).
	for _, stmt := range []string{
		`ALTER TABLE keys ADD COLUMN paid_until               INTEGER`,
		`ALTER TABLE keys ADD COLUMN plan_pia                 INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE keys ADD COLUMN reminder_sent            INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE keys ADD COLUMN preferred_duration_days  INTEGER NOT NULL DEFAULT 30`,
	} {
		db.Exec(stmt) //nolint:errcheck // fails on duplicate column, which is fine
	}
	// Unlimited-devices flag for keys that should not be bound to a single device.
	db.Exec(`ALTER TABLE keys ADD COLUMN unlimited_devices INTEGER NOT NULL DEFAULT 0`) //nolint:errcheck
	// Issuance channel (website get-key page, my-account page, admin, ...) for keys.
	db.Exec(`ALTER TABLE keys ADD COLUMN source TEXT NOT NULL DEFAULT ''`) //nolint:errcheck
	// Grant unlimited-device access to the embedded admin key.
	db.Exec(`UPDATE keys SET unlimited_devices=1 WHERE username='admin@agents.media'`) //nolint:errcheck
	// Clear any multi-device warnings that accumulated before the flag was set.
	db.Exec(`DELETE FROM notifications WHERE username='admin@agents.media'`) //nolint:errcheck

	// Node provisioner columns.
	for _, stmt := range []string{
		`ALTER TABLE nodes ADD COLUMN ssh_host      TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE nodes ADD COLUMN deploy_status TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE nodes ADD COLUMN deploy_log    TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE nodes ADD COLUMN ssh_user      TEXT NOT NULL DEFAULT 'root'`,
	} {
		db.Exec(stmt) //nolint:errcheck // fails on duplicate column, which is fine
	}
	// Manual region override column ("" = auto-detect via CIDR; "OTHER" is an
	// explicit classification -- "not RU/CN/IR/EU/US" -- and must be treated
	// as a real value downstream, never collapsed to "" / unknown).
	db.Exec(`ALTER TABLE nodes ADD COLUMN region_override TEXT NOT NULL DEFAULT ''`) //nolint:errcheck
	// Whitelist capability JSON reported by exit nodes via heartbeat.
	db.Exec(`ALTER TABLE nodes ADD COLUMN capabilities TEXT NOT NULL DEFAULT ''`) //nolint:errcheck
	// Human-entered "where is this box and who hosts it" — shown next to the
	// address on every admin screen that lists nodes. Nothing auto-detects
	// this (unlike region_override/CIDRRegion); an admin fills it in once via
	// /admin/infra, same edit surface as address/description.
	db.Exec(`ALTER TABLE nodes ADD COLUMN location TEXT NOT NULL DEFAULT ''`) //nolint:errcheck // country/city, e.g. "Germany, Falkenstein"
	db.Exec(`ALTER TABLE nodes ADD COLUMN provider TEXT NOT NULL DEFAULT ''`) //nolint:errcheck // hosting company, e.g. "Hetzner Online GmbH"
	// Long-lived anchor control nodes: always included in every manifest
	// (apiManifest) and skipped by the IP-rotation daemons (yc_rotate.py /
	// cloudru_rotate.py, via /api/admin/nodes). Exists so a client that's been
	// offline long enough for every OTHER control in its cached manifest to
	// have rotated away still has at least one address that's still alive.
	db.Exec(`ALTER TABLE nodes ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0`) //nolint:errcheck
	// Stable node identity, independent of the node's current addr (which now
	// rotates for control nodes via yc_rotate.py/cloudru_rotate.py, and will
	// for exit nodes too). node_uid is generated once and never changes.
	// provider_slug/provider_instance_id are the machine-readable hosting
	// provider + that provider's own internal machine/instance id (e.g. a
	// Yandex Cloud instance id) -- deliberately separate from the existing
	// human-entered `provider` column above (free-text display string like
	// "Hetzner Online GmbH"), which keeps its current meaning unchanged.
	for _, stmt := range []string{
		`ALTER TABLE nodes ADD COLUMN node_uid             TEXT`,
		`ALTER TABLE nodes ADD COLUMN provider_slug        TEXT`,
		`ALTER TABLE nodes ADD COLUMN provider_instance_id TEXT`,
	} {
		db.Exec(stmt) //nolint:errcheck // fails on duplicate column, which is fine
	}
	db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_uid ON nodes(node_uid) WHERE node_uid IS NOT NULL`)                                                                                    //nolint:errcheck
	db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_nodes_provider_instance ON nodes(provider_slug, provider_instance_id) WHERE provider_slug IS NOT NULL AND provider_instance_id IS NOT NULL`) //nolint:errcheck
	// Backfill node_uid for every row that predates this column (all existing
	// nodes, on first run after this migration) -- new rows get one at
	// creation time (submitNode/submitNodeSSH), so this only ever needs to
	// run once per row.
	if err := backfillNodeUIDs(db.DB); err != nil {
		return nil, fmt.Errorf("node_uid backfill: %w", err)
	}
	// torrent_allowed_entries (whitelist model) was replaced by
	// torrent_blocked_entries (blacklist model, see its schema comment) --
	// the two have inverted meaning, so old rows cannot be carried forward.
	db.Exec(`DROP TABLE IF EXISTS torrent_allowed_entries`) //nolint:errcheck
	// user_failures (per-connection-failure log) removed entirely -- grew to
	// millions of rows with no admin action ever taken on individual rows
	// (the UI only ever showed a recent-N list and an hourly count, both
	// low-value relative to the storage/migration cost of keeping this
	// table around). Dropped rather than kept empty, unlike
	// torrent_allowed_entries above, since nothing references this table's
	// shape going forward.
	db.Exec(`DROP TABLE IF EXISTS user_failures`) //nolint:errcheck
	if err := d.initStatsSchema(); err != nil {
		return nil, fmt.Errorf("stats schema: %w", err)
	}
	if err := d.initTrafficSchema(); err != nil {
		return nil, fmt.Errorf("traffic schema: %w", err)
	}
	if err := d.initUsageStatsSchema(); err != nil {
		return nil, fmt.Errorf("usage stats schema: %w", err)
	}
	if err := d.initNodeActiveUsersSchema(); err != nil {
		return nil, fmt.Errorf("node active users schema: %w", err)
	}
	if err := d.initAppsSchema(); err != nil {
		return nil, fmt.Errorf("apps schema: %w", err)
	}
	if err := d.initConnStatsSchema(); err != nil {
		return nil, fmt.Errorf("conn stats schema: %w", err)
	}
	if err := d.initSessionsSchema(); err != nil {
		return nil, fmt.Errorf("sessions schema: %w", err)
	}
	if err := d.initBananameterSchema(); err != nil {
		return nil, fmt.Errorf("bananameter schema: %w", err)
	}
	if err := d.seedAnonAllowlist(); err != nil {
		return nil, fmt.Errorf("anon allowlist seed: %w", err)
	}
	if err := d.initClubsSchema(); err != nil {
		return nil, fmt.Errorf("clubs schema: %w", err)
	}
	if err := d.initRejectedSessionsSchema(); err != nil {
		return nil, fmt.Errorf("rejected sessions schema: %w", err)
	}
	if err := d.initUnreachableSchema(); err != nil {
		return nil, fmt.Errorf("unreachable events schema: %w", err)
	}
	if err := d.initNodeAddrRotationsSchema(); err != nil {
		return nil, fmt.Errorf("node addr rotations schema: %w", err)
	}
	return d, nil
}

// ── users ─────────────────────────────────────────────────────────────────────

type User struct {
	ID       int64
	Username string
	Role     string
	ClientID string // immutable billing identifier; generated once by arbiter
}

// findUser returns the local user record for username, or nil if no such
// account exists — unlike getOrCreateUser, never creates one. Use this
// wherever a caller-supplied username names *someone else* (e.g. a club
// recommendation target) rather than the caller's own identity, so a typo
// or an arbitrary string can't silently mint a phantom user row.
func (d *DB) findUser(username string) (*User, error) {
	var u User
	err := d.db.QueryRow(
		`SELECT id, username, role, client_id FROM users WHERE username=?`, username).
		Scan(&u.ID, &u.Username, &u.Role, &u.ClientID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lookup user: %w", err)
	}
	return &u, nil
}

// getOrCreateUser returns the local user record for the given username,
// creating it if this is the first login. The first-ever user gets role=admin.
// A ClientID is generated on creation and never changes.
//
// Concurrency note: the create path below is a genuine check-then-act race
// under a real multi-connection pool (SQLite's forced single connection
// hid this) -- two simultaneous first-ever logins for the same brand-new
// username could both see "not found" and both attempt to create the row.
// users.username is UNIQUE, so the loser's INSERT would previously surface
// as an unhandled constraint-violation error instead of the caller just
// getting the row the winner created. Fixed with INSERT ... ON CONFLICT DO
// NOTHING followed by an unconditional re-read, which is race-free
// regardless of which goroutine's insert (if any) actually won.
//
// The "assign admin to the very first user" COUNT(*) check a few lines
// below is a separate, much lower-stakes check-then-act race (two
// concurrent *first-ever* registrations could theoretically both become
// admin) -- left as-is: this system already has its first admin user, so
// this path can never actually execute again in production.
func (d *DB) getOrCreateUser(username string) (*User, error) {
	var u User
	err := d.db.QueryRow(
		`SELECT id, username, role, client_id FROM users WHERE username=?`, username).
		Scan(&u.ID, &u.Username, &u.Role, &u.ClientID)
	if err == nil {
		// Backfill client_id for legacy rows that have an empty one.
		if u.ClientID == "" {
			cid, cerr := genClientID()
			if cerr == nil {
				d.db.Exec(`UPDATE users SET client_id=? WHERE id=?`, cid, u.ID) //nolint:errcheck
				u.ClientID = cid
			}
		}
		return &u, nil
	}
	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("lookup user: %w", err)
	}

	// Assign admin role to very first user.
	var count int
	d.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	role := "user"
	if count == 0 {
		role = "admin"
	}

	clientID, err := genClientID()
	if err != nil {
		return nil, fmt.Errorf("gen client_id: %w", err)
	}

	if _, err := d.db.Exec(
		`INSERT INTO users (username, role, client_id) VALUES (?,?,?) ON CONFLICT(username) DO NOTHING`,
		username, role, clientID); err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	// Unconditional re-read: whether this goroutine's own insert won the
	// race or a concurrent caller's did, the row exists now either way --
	// this is what makes the create path above race-free instead of just
	// race-free-looking.
	var u2 User
	if err := d.db.QueryRow(
		`SELECT id, username, role, client_id FROM users WHERE username=?`, username).
		Scan(&u2.ID, &u2.Username, &u2.Role, &u2.ClientID); err != nil {
		return nil, fmt.Errorf("read back created user: %w", err)
	}
	return &u2, nil
}

// genClientID generates a new unique ClientID: "clt_" + 24 random hex chars.
func genClientID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("clt_%x", b), nil
}

// ── nodes ─────────────────────────────────────────────────────────────────────

type Node struct {
	ID                 int64
	OwnerID            int64
	OwnerUsername      string
	Type               string // "control" | "exit"
	Addr               string
	Fingerprint        string
	Pubkey             string
	Description        string
	Token              string
	Status             string
	SubmittedAt        time.Time
	ApprovedAt         *time.Time
	LastHeartbeat      *time.Time
	RTTms              float64
	Load               float64
	BandwidthMbps      float64
	BWFresh            bool            // true if BandwidthMbps is from the latest heartbeat interval
	DataPlaneOK        *bool           // nil = not yet reporting
	HourlyBytes        int64           // populated at dashboard render time, not stored
	RegionOverride     string          // "" = no override (CIDR auto); "OTHER" = rest-of-world; else explicit code
	CIDRRegion         string          // CIDR-detected region; "" if not in any CIDR bucket (populated at render time)
	Location           string          // human-entered "country, city" -- "" if never filled in
	Provider           string          // human-entered hosting company -- "" if never filled in
	SNIList            string          // comma-separated SNI hostnames for client-side TLS SNI rotation; "" = disabled
	Capabilities       map[string]bool // whitelist domain → reachable; nil = not yet reported (exit nodes only)
	Pinned             bool            // long-lived anchor control: always included in manifests, never IP-rotated (see setNodePinned)
	ClubID             sql.NullInt64   // NULL = general/common pool; set = dedicated to that club's manifest only (see db_clubs.go)
	NodeUID            string          // stable identity, independent of addr; generated once, never changes
	ProviderSlug       string          // machine-readable hosting provider, e.g. "yandex-cloud" -- distinct from the human-entered Provider field above
	ProviderInstanceID string          // hoster's own internal machine/instance id -- "" if never set (legacy nodes, manual deploys)
}

// firstAdminUserID returns the ID of the first admin user, or 0 if none exists.
// Used as a fallback owner when registering nodes via API token (no browser session).
func (d *DB) firstAdminUserID() int64 {
	var id int64
	d.db.QueryRow(`SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1`).Scan(&id) //nolint:errcheck
	return id
}

// userCount returns the total number of registered users -- used by the
// admin broadcast form to show a real recipient count before sending.
func (d *DB) userCount() (int, error) {
	var n int
	err := d.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// allUsernames returns every registered username, for the admin broadcast
// send loop (see admin_broadcast.go). Usernames double as email addresses
// throughout this codebase (Camerlengo's sendEmail "to" field).
func (d *DB) allUsernames() ([]string, error) {
	rows, err := d.db.Query(`SELECT username FROM users ORDER BY id`)
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

func (d *DB) submitNode(ownerID int64, nodeType, addr, fingerprint, pubkey, description, providerSlug, providerInstanceID string) (int64, error) {
	// RETURNING id, not res.LastInsertId(): the Postgres driver doesn't
	// implement LastInsertId at all ("LastInsertId is not supported by this
	// driver") -- discovered live when this broke node registration after
	// the arbiter's move off SQLite. RETURNING works on both engines
	// (modernc.org/sqlite supports it since SQLite 3.35).
	var id int64
	err := d.db.QueryRow(`
		INSERT INTO nodes (owner_id, type, addr, fingerprint, pubkey, description, node_uid, provider_slug, provider_instance_id)
		VALUES (?,?,?,?,?,?,?,?,?) RETURNING id`,
		ownerID, nodeType, addr, fingerprint, pubkey, description, uuid.New().String(), nullIfEmpty(providerSlug), nullIfEmpty(providerInstanceID)).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("submit node: %w", err)
	}
	return id, nil
}

// nullIfEmpty turns "" into a real SQL NULL so provider_slug/provider_instance_id
// stay NULL (not "") when unset -- required for the partial unique index on
// (provider_slug, provider_instance_id), which only applies to non-NULL pairs.
func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func (d *DB) approveNode(nodeID int64) (token string, err error) {
	token, err = genToken()
	if err != nil {
		return "", err
	}
	now := time.Now().Unix()
	_, err = d.db.Exec(`
		UPDATE nodes SET status='approved', token=?, approved_at=?, last_heartbeat=?
		WHERE id=? AND status='pending'`,
		token, now, now, nodeID)
	return token, err
}

func (d *DB) setNodeStatus(nodeID int64, status string) error {
	_, err := d.db.Exec(`UPDATE nodes SET status=? WHERE id=?`, status, nodeID)
	return err
}

func (d *DB) updateHeartbeat(token string, rttMs, routingRTTms, bwMbps float64, bytesTotal int64, fingerprint string, dataPlaneOK *bool, capabilities map[string]bool, cpuPct, memPct, diskPct float64) (int64, error) {
	now := time.Now().Unix()
	var dpVal interface{} // nil → SQL NULL
	if dataPlaneOK != nil {
		if *dataPlaneOK {
			dpVal = int64(1)
		} else {
			dpVal = int64(0)
		}
	}
	var capsJSON string
	if len(capabilities) > 0 {
		if b, err := json.Marshal(capabilities); err == nil {
			capsJSON = string(b)
		}
	}
	var res sql.Result
	var err error
	if fingerprint != "" {
		res, err = d.db.Exec(`
			UPDATE nodes SET last_heartbeat=?, rtt_ms=?, bandwidth_mbps=?, fingerprint=?, data_plane_ok=?, capabilities=?
			WHERE token=? AND status='approved'`,
			now, rttMs, bwMbps, fingerprint, dpVal, capsJSON, token)
	} else {
		res, err = d.db.Exec(`
			UPDATE nodes SET last_heartbeat=?, rtt_ms=?, bandwidth_mbps=?, data_plane_ok=?, capabilities=?
			WHERE token=? AND status='approved'`,
			now, rttMs, bwMbps, dpVal, capsJSON, token)
	}
	if err != nil {
		return 0, err
	}
	rows, _ := res.RowsAffected()
	if rows > 0 {
		// Record a stat sample (traffic + RTT + CPU/mem/disk) for history/graphing.
		// node_type is captured here, at write time, so later network-wide
		// aggregates don't need to JOIN back to nodes to know what a sample
		// belongs to (see initTrafficSchema's node_type column comment).
		var nodeID int64
		var nodeType string
		d.db.QueryRow(`SELECT id, type FROM nodes WHERE token=?`, token).Scan(&nodeID, &nodeType) //nolint:errcheck
		if nodeID > 0 {
			d.recordNodeTrafficSample(nodeID, now, bytesTotal, nodeType, bwMbps, rttMs, routingRTTms, cpuPct, memPct, diskPct) //nolint:errcheck
		}
	}
	return rows, nil
}

const (
	// heartbeatTTL is the liveness window used for dashboard display, manifests,
	// and exit lists.  Keep it short so dead nodes disappear quickly.
	heartbeatTTL = 90 * time.Second

	// bootstrapTTL is the wider window used when selecting control nodes for
	// newly-issued key strings.  A node that was online recently is still a
	// valid bootstrap candidate even if it missed a few heartbeats.
	bootstrapTTL = 1800 * time.Second
)

// IsOnline reports whether the node has sent a heartbeat within the TTL window.
func (n *Node) IsOnline() bool {
	return n.LastHeartbeat != nil && time.Since(*n.LastHeartbeat) < heartbeatTTL
}

// listApprovedNodes returns approved and suspended nodes of the given type,
// ordered by address. Suspended nodes appear in the dashboard so admins can unsuspend them.
func (d *DB) listApprovedNodes(nodeType string) ([]Node, error) {
	rows, err := d.db.Query(`
		SELECT n.id, n.owner_id, u.username, n.type, n.addr, n.fingerprint, n.pubkey,
		       n.description, COALESCE(n.token,''), n.status,
		       n.submitted_at, n.approved_at, n.last_heartbeat,
		       n.rtt_ms, n.load, n.bandwidth_mbps, n.data_plane_ok,
		       COALESCE(n.region_override,''), COALESCE(n.sni_list,''),
		       COALESCE(n.capabilities,''), COALESCE(n.location,''), COALESCE(n.provider,''), n.pinned, n.club_id,
		       COALESCE(n.node_uid,''), COALESCE(n.provider_slug,''), COALESCE(n.provider_instance_id,'')
		FROM nodes n JOIN users u ON u.id=n.owner_id
		WHERE n.type=? AND n.status IN ('approved','suspended')
		ORDER BY n.addr ASC`, nodeType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNodes(rows)
}

// liveNodes returns approved nodes whose last heartbeat is within heartbeatTTL.
// Used for manifests, exit lists, and dashboard health.
func (d *DB) liveNodes(nodeType string) ([]Node, error) {
	return d.liveNodesTTL(nodeType, heartbeatTTL)
}

// bootstrapNodes returns approved nodes whose last heartbeat is within
// bootstrapTTL.  Used only when selecting bootstrap controls for key strings;
// the wider window ensures keys stay useful even when a node briefly goes quiet.
func (d *DB) bootstrapNodes(nodeType string) ([]Node, error) {
	return d.liveNodesTTL(nodeType, bootstrapTTL)
}

func (d *DB) liveNodesTTL(nodeType string, ttl time.Duration) ([]Node, error) {
	cutoff := time.Now().Add(-ttl).Unix()
	rows, err := d.db.Query(`
		SELECT n.id, n.owner_id, u.username, n.type, n.addr, n.fingerprint, n.pubkey,
		       n.description, COALESCE(n.token,''), n.status,
		       n.submitted_at, n.approved_at, n.last_heartbeat,
		       n.rtt_ms, n.load, n.bandwidth_mbps, n.data_plane_ok,
		       COALESCE(n.region_override,''), COALESCE(n.sni_list,''),
		       COALESCE(n.capabilities,''), COALESCE(n.location,''), COALESCE(n.provider,''), n.pinned, n.club_id,
		       COALESCE(n.node_uid,''), COALESCE(n.provider_slug,''), COALESCE(n.provider_instance_id,'')
		FROM nodes n JOIN users u ON u.id=n.owner_id
		WHERE n.type=? AND n.status='approved' AND n.last_heartbeat>=?
		ORDER BY n.rtt_ms ASC`, nodeType, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNodes(rows)
}

// nodeByToken returns the node with the given token, or nil if not found.
func (d *DB) nodeByToken(token string) (*Node, error) {
	rows, err := d.db.Query(`
		SELECT n.id, n.owner_id, u.username, n.type, n.addr, n.fingerprint, n.pubkey,
		       n.description, COALESCE(n.token,''), n.status,
		       n.submitted_at, n.approved_at, n.last_heartbeat,
		       n.rtt_ms, n.load, n.bandwidth_mbps, n.data_plane_ok,
		       COALESCE(n.region_override,''), COALESCE(n.sni_list,''),
		       COALESCE(n.capabilities,''), COALESCE(n.location,''), COALESCE(n.provider,''), n.pinned, n.club_id,
		       COALESCE(n.node_uid,''), COALESCE(n.provider_slug,''), COALESCE(n.provider_instance_id,'')
		FROM nodes n JOIN users u ON u.id=n.owner_id
		WHERE n.token=? AND n.status='approved'`, token)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	nodes, err := scanNodes(rows)
	if err != nil || len(nodes) == 0 {
		return nil, err
	}
	return &nodes[0], nil
}

// nodeByID returns the node with the given ID, or nil if not found.
func (d *DB) nodeByID(id int64) (*Node, error) {
	rows, err := d.db.Query(`
		SELECT n.id, n.owner_id, u.username, n.type, n.addr, n.fingerprint, n.pubkey,
		       n.description, COALESCE(n.token,''), n.status,
		       n.submitted_at, n.approved_at, n.last_heartbeat,
		       n.rtt_ms, n.load, n.bandwidth_mbps, n.data_plane_ok,
		       COALESCE(n.region_override,''), COALESCE(n.sni_list,''),
		       COALESCE(n.capabilities,''), COALESCE(n.location,''), COALESCE(n.provider,''), n.pinned, n.club_id,
		       COALESCE(n.node_uid,''), COALESCE(n.provider_slug,''), COALESCE(n.provider_instance_id,'')
		FROM nodes n JOIN users u ON u.id=n.owner_id
		WHERE n.id=?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	nodes, err := scanNodes(rows)
	if err != nil || len(nodes) == 0 {
		return nil, err
	}
	return &nodes[0], nil
}

// listAllNodes returns all nodes of all statuses ordered by id.
func (d *DB) listAllNodes() ([]Node, error) {
	rows, err := d.db.Query(`
		SELECT n.id, n.owner_id, u.username, n.type, n.addr, n.fingerprint, n.pubkey,
		       n.description, COALESCE(n.token,''), n.status,
		       n.submitted_at, n.approved_at, n.last_heartbeat,
		       n.rtt_ms, n.load, n.bandwidth_mbps, n.data_plane_ok,
		       COALESCE(n.region_override,''), COALESCE(n.sni_list,''),
		       COALESCE(n.capabilities,''), COALESCE(n.location,''), COALESCE(n.provider,''), n.pinned, n.club_id,
		       COALESCE(n.node_uid,''), COALESCE(n.provider_slug,''), COALESCE(n.provider_instance_id,'')
		FROM nodes n JOIN users u ON u.id=n.owner_id
		ORDER BY n.id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanNodes(rows)
}

func scanNodes(rows *sql.Rows) ([]Node, error) {
	var out []Node
	for rows.Next() {
		var n Node
		var submittedAt int64
		var approvedAt, lastHB, dpOK *int64
		var capsJSON string
		err := rows.Scan(
			&n.ID, &n.OwnerID, &n.OwnerUsername, &n.Type, &n.Addr,
			&n.Fingerprint, &n.Pubkey, &n.Description, &n.Token, &n.Status,
			&submittedAt, &approvedAt, &lastHB,
			&n.RTTms, &n.Load, &n.BandwidthMbps, &dpOK,
			&n.RegionOverride, &n.SNIList,
			&capsJSON, &n.Location, &n.Provider, &n.Pinned, &n.ClubID,
			&n.NodeUID, &n.ProviderSlug, &n.ProviderInstanceID,
		)
		if err != nil {
			return nil, err
		}
		n.SubmittedAt = time.Unix(submittedAt, 0)
		if approvedAt != nil {
			t := time.Unix(*approvedAt, 0)
			n.ApprovedAt = &t
		}
		if lastHB != nil {
			t := time.Unix(*lastHB, 0)
			n.LastHeartbeat = &t
		}
		if dpOK != nil {
			v := *dpOK != 0
			n.DataPlaneOK = &v
		}
		if capsJSON != "" {
			json.Unmarshal([]byte(capsJSON), &n.Capabilities) //nolint:errcheck
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// setNodeRegionOverride persists the manual region override for a node.
// Allowed values: "", "RU", "EU", "US", "CN", "IR", "OTHER".
func (d *DB) setNodeRegionOverride(nodeID int64, region string) error {
	_, err := d.db.Exec(`UPDATE nodes SET region_override=? WHERE id=?`, region, nodeID)
	return err
}

// setNodePinned persists the pinned (long-lived anchor) flag for a node.
// See the Node.Pinned doc comment for what this actually controls.
//
// pinned is converted to 0/1 before being passed to Exec -- the nodes.pinned
// column is BIGINT (every SQLite 0/1 "boolean" column stays BIGINT under
// Postgres too, see migrations/postgres/00001_initial_schema.sql's
// translation notes), and unlike SQLite's loose typing, pgx's binary
// protocol refuses to encode a Go bool into an int8 column outright
// ("unable to encode false into binary format for int8 (OID 20)") rather
// than coercing it -- confirmed live 2026-08-16 via a real 500 on
// POST /admin/api/nodes/{id}/pinned. SetKeyEnabled/SetUserEnabled
// (db_keys.go) already establish this exact bool -> int conversion for the
// same class of column; this just brings setNodePinned in line with them.
func (d *DB) setNodePinned(nodeID int64, pinned bool) error {
	v := 0
	if pinned {
		v = 1
	}
	_, err := d.db.Exec(`UPDATE nodes SET pinned=? WHERE id=?`, v, nodeID)
	return err
}

// setNodeSNIList persists the SNI rotation list for a node (comma-separated hostnames).
func (d *DB) setNodeSNIList(nodeID int64, sniList string) error {
	_, err := d.db.Exec(`UPDATE nodes SET sni_list=? WHERE id=?`, sniList, nodeID)
	return err
}

func genToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// backfillNodeUIDs assigns a node_uid to every row that doesn't have one yet
// -- runs once per row, ever (new rows get one at creation time instead, see
// submitNode/submitNodeSSH). Safe to call on every startup.
func backfillNodeUIDs(db *sql.DB) error {
	rows, err := db.Query(`SELECT id FROM nodes WHERE node_uid IS NULL`)
	if err != nil {
		return err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		if _, err := db.Exec(`UPDATE nodes SET node_uid=? WHERE id=?`, uuid.New().String(), id); err != nil {
			return fmt.Errorf("backfill node %d: %w", id, err)
		}
	}
	return nil
}

// ── node provisioner ──────────────────────────────────────────────────────────

// nodeProvisionInfo carries the data the provisioner needs for a deploy job.
type nodeProvisionInfo struct {
	ID           int64
	Type         string
	Addr         string
	Token        string
	SSHHost      string
	SSHUser      string
	DeployStatus string
	OwnerEmail   string // username == email in this system
}

// submitNodeSSH upserts a node record for SSH-provisioned deployment.
// If an existing node can be recognized as the same box, it's reset to
// pending so it can be re-deployed and re-approved, preventing duplicates.
// sshUser is the account used to connect; empty defaults to "root".
//
// Recognition prefers (providerSlug, providerInstanceID) when both are
// given -- that pairing survives IP rotation, unlike addr. Falls back to
// type+addr (the old behavior) when no provider info is available, e.g.
// manual/no-cloud-API deploys. Without this, re-provisioning the same
// logical box at a new IP silently created a brand-new row (new id, new
// token, lost history) instead of recognizing it as the same node.
// Concurrency note: the (providerSlug, providerInstanceID) lookup path is
// backed by a partial unique index (idx_nodes_provider_instance) so a losing
// concurrent insert surfaces as a clean constraint violation. The type+addr
// fallback path has no such index -- and deliberately can't have a simple
// one, since a decommissioned row is allowed to share its old addr with a
// newer, unrelated live row at the same address (observed in production:
// id=3 decommissioned and id=71 live both at 203.0.113.13). A real fix
// would need a partial unique index scoped to non-decommissioned rows,
// which first requires auditing prod for any existing live-row duplicates
// it would reject -- tracked as a follow-up, not done here. What IS done
// here: the whole check-then-act runs inside one transaction, which makes
// this fully race-free under SQLite (single-writer + transaction-level
// locking) and narrows (though doesn't perfectly close, absent that index)
// the race window under a real Postgres connection pool. In practice this
// path is only ever called from admin-triggered/deploy.sh provisioning,
// not a concurrent user-facing hot path, which is why this narrowing is an
// acceptable interim state rather than something blocking the migration.
func (d *DB) submitNodeSSH(ownerID int64, nodeType, sshHost, sshUser, description, providerSlug, providerInstanceID string) (int64, error) {
	if sshUser == "" {
		sshUser = "root"
	}
	addr := sshHost + ":443"

	tx, err := d.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful Commit

	var existing int64
	if providerSlug != "" && providerInstanceID != "" {
		err = tx.QueryRow(`SELECT id FROM nodes WHERE provider_slug=? AND provider_instance_id=? LIMIT 1`,
			providerSlug, providerInstanceID).Scan(&existing)
	} else {
		err = tx.QueryRow(`SELECT id FROM nodes WHERE type=? AND addr=? LIMIT 1`, nodeType, addr).Scan(&existing)
	}
	if err == nil {
		// Reset the existing node for re-deployment. submitted_at is bound
		// as a Go-side time.Now().Unix() rather than SQL-side
		// strftime('%s','now') -- the latter is SQLite-only and has no
		// Postgres equivalent, so this update outright failed with a syntax
		// error against Postgres before this fix.
		if _, err = tx.Exec(`
			UPDATE nodes SET owner_id=?, addr=?, ssh_host=?, ssh_user=?, description=?,
			                 provider_slug=?, provider_instance_id=?,
			                 status='pending', token=NULL, approved_at=NULL,
			                 deploy_status='', deploy_log='',
			                 submitted_at=?
			WHERE id=?`,
			ownerID, addr, sshHost, sshUser, description,
			nullIfEmpty(providerSlug), nullIfEmpty(providerInstanceID), time.Now().Unix(), existing); err != nil {
			return 0, fmt.Errorf("reset node: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return 0, fmt.Errorf("commit: %w", err)
		}
		return existing, nil
	}
	// RETURNING id, not res.LastInsertId(): the Postgres driver doesn't
	// implement LastInsertId at all -- see submitNode above, same fix.
	var id int64
	err = tx.QueryRow(`
		INSERT INTO nodes (owner_id, type, addr, ssh_host, ssh_user, description, node_uid, provider_slug, provider_instance_id)
		VALUES (?,?,?,?,?,?,?,?,?) RETURNING id`,
		ownerID, nodeType, addr, sshHost, sshUser, description,
		uuid.New().String(), nullIfEmpty(providerSlug), nullIfEmpty(providerInstanceID)).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("submit node: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return id, nil
}

func (d *DB) getNodeProvisionInfo(nodeID int64) (*nodeProvisionInfo, error) {
	var info nodeProvisionInfo
	err := d.db.QueryRow(`
		SELECT n.id, n.type, n.addr, COALESCE(n.token,''), n.ssh_host, n.ssh_user, n.deploy_status, u.username
		FROM nodes n JOIN users u ON u.id = n.owner_id
		WHERE n.id = ?`, nodeID).Scan(
		&info.ID, &info.Type, &info.Addr, &info.Token,
		&info.SSHHost, &info.SSHUser, &info.DeployStatus, &info.OwnerEmail)
	if err != nil {
		return nil, err
	}
	return &info, nil
}

func (d *DB) deleteNode(nodeID int64) error {
	_, err := d.db.Exec(`DELETE FROM nodes WHERE id=?`, nodeID)
	return err
}

// decommissionNode marks a node 'decommissioned' instead of hard-deleting its
// row. node_traffic has no node-type column of its own -- every network-wide
// aggregate query (networkStatsRange, networkBytesTotal, etc.) attributes a
// sample's type by JOINing node_traffic to nodes on node_id. Hard-deleting
// the nodes row therefore silently drops that node's entire history —
// including past periods — from every network-wide total, not just future
// ones. Keeping a status='decommissioned' row preserves that JOIN forever,
// at the cost of the row lingering in listAllNodes (callers that only want
// "live" nodes should filter status='approved' explicitly, as
// nodePeaksAndDistribution already does).
//
// Confirmed as a real, reproduced data-loss bug on 2026-08-09: hard-deleting
// node 30 (203.0.113.14, 5379 samples of real history) made its entire
// traffic contribution vanish from network-wide stats, including the
// cumulative total. Fixed there by re-inserting a decommissioned stub row
// with the same id; this method is the code-level fix so it doesn't recur.
func (d *DB) decommissionNode(nodeID int64) error {
	// Fetch addr first so the addr-keyed blacklist cleanup below still works
	// after the UPDATE (status changes, addr doesn't).
	node, err := d.nodeByID(nodeID)
	if err != nil {
		return err
	}

	res, err := d.db.Exec(`UPDATE nodes SET status='decommissioned' WHERE id=?`, nodeID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("node %d not found", nodeID)
	}

	// A decommissioned node's addr must not linger in addr-keyed exit-policy
	// lists: a stale row there silently reasserts a policy for the address
	// forever (up to and including if it's later reassigned to a new node),
	// and confirms nothing about the *now-dead* node it was written for.
	// service_region_blocks is deliberately NOT touched here — it keys off
	// region/provider tags, not individual node addrs, so it must keep
	// applying to any other live node sharing that region/provider.
	if node != nil {
		d.deleteBlacklistEntryByAddr(node.Addr)      //nolint:errcheck
		d.deleteTorrentBlockedEntryByAddr(node.Addr) //nolint:errcheck
	}
	return nil
}

// updateNode updates the always-provided display/network fields (addr,
// description, location, provider) unconditionally. providerSlug and
// providerInstanceID are updated only when non-empty (via NULLIF+COALESCE),
// so callers that don't know about them (e.g. the admin UI's edit form)
// don't clobber values a rotation daemon already set.
func (d *DB) updateNode(nodeID int64, addr, description, location, provider, providerSlug, providerInstanceID string) error {
	// Read the current type/addr before overwriting -- this is the only
	// place both the old and new address are ever available together (the
	// rotation daemons that call this via the admin API only ever send the
	// new address), so it's the single point that can record a rotation
	// event. Best-effort: if this lookup fails for any reason, the update
	// below still proceeds, it just won't have a rotation row to show for it.
	var nodeType, oldAddr string
	_ = d.db.QueryRow(`SELECT type, addr FROM nodes WHERE id=?`, nodeID).Scan(&nodeType, &oldAddr)

	// location/provider use the same "preserve on empty" COALESCE as
	// provider_slug/provider_instance_id below -- a caller that only wants to
	// change addr (e.g. yc_rotate.py's rotate-node updating the address after
	// an IP rotation) must not silently blank out previously-resolved geo
	// data just because it didn't re-send it. See 2026-08-14 incident: every
	// node touched by an addr-only update showed "Unknown" region afterward.
	res, err := d.db.Exec(`
		UPDATE nodes SET addr=?, description=?,
		                 location=COALESCE(NULLIF(?, ''), location),
		                 provider=COALESCE(NULLIF(?, ''), provider),
		                 provider_slug=COALESCE(NULLIF(?, ''), provider_slug),
		                 provider_instance_id=COALESCE(NULLIF(?, ''), provider_instance_id)
		WHERE id=?`,
		addr, description, location, provider, providerSlug, providerInstanceID, nodeID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("node %d not found", nodeID)
	}
	// Non-fatal: the address update itself already succeeded above --
	// losing a rotation-history row shouldn't fail the whole request.
	_ = d.recordAddrRotationIfChanged(nodeID, nodeType, oldAddr, addr, time.Now().Unix())
	return nil
}

func (d *DB) setDeployStatus(nodeID int64, status string) {
	_, _ = d.db.Exec(`UPDATE nodes SET deploy_status = ? WHERE id = ?`, status, nodeID)
}

func (d *DB) appendNodeDeployLog(nodeID int64, text string) {
	_, _ = d.db.Exec(`UPDATE nodes SET deploy_log = deploy_log || ? WHERE id = ?`, text, nodeID)
}

func (d *DB) getDeployStatus(nodeID int64, ownerID int64) (status, log string, err error) {
	err = d.db.QueryRow(
		`SELECT deploy_status, deploy_log FROM nodes WHERE id = ? AND owner_id = ?`,
		nodeID, ownerID).Scan(&status, &log)
	return
}

func (d *DB) getDeployStatusAdmin(nodeID int64) (status, log string, err error) {
	err = d.db.QueryRow(
		`SELECT deploy_status, deploy_log FROM nodes WHERE id = ?`,
		nodeID).Scan(&status, &log)
	return
}

// ── sessions ──────────────────────────────────────────────────────────────────

// Session represents a cached VPN client session managed by the arbiter.
type Session struct {
	Token       string
	Username    string
	ClientID    string // immutable billing identifier copied from users.client_id
	DeviceID    string // stable per-device UUID generated by the client; "" for legacy/proxy logins
	DeviceName  string // human-readable device label (e.g. "Windows PC", "Android")
	EncPassword []byte // ChaCha20-Poly1305 encrypted
	CamSession  string // current Camerlengo session token
	ValidatedAt time.Time
	LastAttempt time.Time
}

func (d *DB) createSession(token, username, clientID, deviceID, deviceName string, encPwd []byte, camSession string, now time.Time) error {
	_, err := d.db.Exec(
		`INSERT INTO sessions (token, username, client_id, device_id, device_name, enc_password, cam_session, validated_at, last_attempt)
		 VALUES (?,?,?,?,?,?,?,?,?)`,
		token, username, clientID, deviceID, deviceName, encPwd, camSession, now.Unix(), now.Unix())
	return err
}

func (d *DB) getSession(token string) (*Session, error) {
	var s Session
	var validated, attempt int64
	err := d.db.QueryRow(
		`SELECT token, username, client_id, device_id, device_name, enc_password, cam_session, validated_at, last_attempt
		 FROM sessions WHERE token=?`, token).
		Scan(&s.Token, &s.Username, &s.ClientID, &s.DeviceID, &s.DeviceName, &s.EncPassword, &s.CamSession, &validated, &attempt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	s.ValidatedAt = time.Unix(validated, 0)
	s.LastAttempt = time.Unix(attempt, 0)
	return &s, nil
}

// getRecentSessionByUsername returns the most recently validated web session
// with a non-empty cam_session for the given user. Used by the auto-renewer
// to charge wallets without a live HTTP request context.
func (d *DB) getRecentSessionByUsername(username string) (*Session, error) {
	var s Session
	var validated, attempt int64
	err := d.db.QueryRow(
		`SELECT token, username, client_id, device_id, device_name, enc_password, cam_session, validated_at, last_attempt
		 FROM sessions WHERE username=? AND cam_session != ''
		 ORDER BY validated_at DESC LIMIT 1`, username).
		Scan(&s.Token, &s.Username, &s.ClientID, &s.DeviceID, &s.DeviceName, &s.EncPassword, &s.CamSession, &validated, &attempt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getRecentSessionByUsername: %w", err)
	}
	s.ValidatedAt = time.Unix(validated, 0)
	s.LastAttempt = time.Unix(attempt, 0)
	return &s, nil
}

func (d *DB) updateCamSession(token, camSession string, now time.Time) error {
	_, err := d.db.Exec(
		`UPDATE sessions SET cam_session=?, validated_at=?, last_attempt=? WHERE token=?`,
		camSession, now.Unix(), now.Unix(), token)
	return err
}

func (d *DB) touchLastAttempt(token string, now time.Time) error {
	_, err := d.db.Exec(`UPDATE sessions SET last_attempt=? WHERE token=?`, now.Unix(), token)
	return err
}

// touchSession updates validated_at for an active session, keeping it alive
// as long as exit nodes are validating it.
func (d *DB) touchSession(token string, now time.Time) error {
	_, err := d.db.Exec(`UPDATE sessions SET validated_at=? WHERE token=?`, now.Unix(), token)
	return err
}

func (d *DB) deleteSession(token string) error {
	_, err := d.db.Exec(`DELETE FROM sessions WHERE token=?`, token)
	return err
}

func (d *DB) listSessions() ([]*Session, error) {
	rows, err := d.db.Query(
		`SELECT token, username, client_id, device_id, device_name, enc_password, cam_session, validated_at, last_attempt FROM sessions`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Session
	for rows.Next() {
		var s Session
		var validated, attempt int64
		if err := rows.Scan(&s.Token, &s.Username, &s.ClientID, &s.DeviceID, &s.DeviceName, &s.EncPassword, &s.CamSession, &validated, &attempt); err != nil {
			return nil, err
		}
		s.ValidatedAt = time.Unix(validated, 0)
		s.LastAttempt = time.Unix(attempt, 0)
		out = append(out, &s)
	}
	return out, rows.Err()
}

// ── whitelist ─────────────────────────────────────────────────────────────────

// WhitelistEntry is a single traffic whitelist entry (exit-to-exit peer-routing fallback).
type WhitelistEntry struct {
	ID        int64
	Type      string // "domain" | "wildcard" | "cidr"
	Value     string
	CreatedAt time.Time
}

func (d *DB) listWhitelistEntries() ([]WhitelistEntry, error) {
	rows, err := d.db.Query(`SELECT id, type, value, created_at FROM whitelist_entries ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WhitelistEntry
	for rows.Next() {
		var e WhitelistEntry
		var ts int64
		if err := rows.Scan(&e.ID, &e.Type, &e.Value, &ts); err != nil {
			return nil, err
		}
		e.CreatedAt = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (d *DB) addWhitelistEntry(entryType, value string) error {
	_, err := d.db.Exec(`INSERT INTO whitelist_entries (type, value) VALUES (?,?) ON CONFLICT(value) DO NOTHING`, entryType, value)
	return err
}

func (d *DB) deleteWhitelistEntry(id int64) error {
	_, err := d.db.Exec(`DELETE FROM whitelist_entries WHERE id=?`, id)
	return err
}

// ── anonymous bootstrap allowlist ───────────────────────────────────────────

// AnonAllowlistEntry is a single "reachable without a key" destination rule.
type AnonAllowlistEntry struct {
	ID        int64
	Type      string // "domain" | "wildcard" | "cidr"
	Value     string
	CreatedAt time.Time
}

// seedAnonAllowlist inserts the two domains the get-a-key flow itself needs
// (see Web/shortnerdcat/auth-modals.js: ARBITER_API/MY_API = "https://navlink.net")
// if the table is empty. Admin-editable afterward like any other entry --
// this only saves whoever deploys this feature from having to know that
// detail up front.
func (d *DB) seedAnonAllowlist() error {
	var count int
	if err := d.db.QueryRow(`SELECT COUNT(*) FROM anon_allowlist_entries`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	for _, v := range []string{"shortnerdcat.navlink.net", "navlink.net"} {
		if err := d.addAnonAllowlistEntry("domain", v); err != nil {
			return fmt.Errorf("seed anon allowlist %s: %w", v, err)
		}
	}
	return nil
}

func (d *DB) listAnonAllowlistEntries() ([]AnonAllowlistEntry, error) {
	rows, err := d.db.Query(`SELECT id, type, value, created_at FROM anon_allowlist_entries ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AnonAllowlistEntry
	for rows.Next() {
		var e AnonAllowlistEntry
		var ts int64
		if err := rows.Scan(&e.ID, &e.Type, &e.Value, &ts); err != nil {
			return nil, err
		}
		e.CreatedAt = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (d *DB) addAnonAllowlistEntry(entryType, value string) error {
	_, err := d.db.Exec(`INSERT INTO anon_allowlist_entries (type, value) VALUES (?,?) ON CONFLICT(value) DO NOTHING`, entryType, value)
	return err
}

func (d *DB) deleteAnonAllowlistEntry(id int64) error {
	_, err := d.db.Exec(`DELETE FROM anon_allowlist_entries WHERE id=?`, id)
	return err
}

const anonBootstrapTokenSettingKey = "anon_bootstrap_token"

// getOrCreateAnonBootstrapToken returns the current bootstrap token, minting
// a fresh random one on first use. Same value must be baked into the client
// apps out of band (there's no per-device provisioning for it -- it's a
// single shared secret, see the admin_anon_bootstrap.go page for the
// rotation/abuse tradeoffs that implies).
func (d *DB) getOrCreateAnonBootstrapToken() (string, error) {
	if v, ok, err := d.getSetting(anonBootstrapTokenSettingKey); err != nil {
		return "", err
	} else if ok && v != "" {
		return v, nil
	}
	tok, err := genToken()
	if err != nil {
		return "", err
	}
	if err := d.setSetting(anonBootstrapTokenSettingKey, tok, "system"); err != nil {
		return "", err
	}
	return tok, nil
}

// regenerateAnonBootstrapToken overwrites the current token with a fresh
// random one -- old copies (extracted from a previous APK build, say) stop
// working the moment exits next refresh their cache.
func (d *DB) regenerateAnonBootstrapToken(updatedBy string) (string, error) {
	tok, err := genToken()
	if err != nil {
		return "", err
	}
	if err := d.setSetting(anonBootstrapTokenSettingKey, tok, updatedBy); err != nil {
		return "", err
	}
	return tok, nil
}

// ── service region blocks ───────────────────────────────────────────────────

// ServiceRegionBlock is a single "don't dial this directly from these
// regions" rule -- see the service_region_blocks schema comment.
type ServiceRegionBlock struct {
	ID             int64
	Type           string // "domain" | "wildcard" | "cidr"
	Value          string
	BlockedRegions []string // parsed from the stored CSV
	Reason         string
	CreatedAt      time.Time
}

func (d *DB) listServiceRegionBlocks() ([]ServiceRegionBlock, error) {
	rows, err := d.db.Query(`SELECT id, type, value, blocked_regions, reason, created_at FROM service_region_blocks ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ServiceRegionBlock
	for rows.Next() {
		var e ServiceRegionBlock
		var ts int64
		var regionsCSV string
		if err := rows.Scan(&e.ID, &e.Type, &e.Value, &regionsCSV, &e.Reason, &ts); err != nil {
			return nil, err
		}
		e.CreatedAt = time.Unix(ts, 0)
		for _, r := range strings.Split(regionsCSV, ",") {
			if r = strings.TrimSpace(r); r != "" {
				e.BlockedRegions = append(e.BlockedRegions, r)
			}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (d *DB) addServiceRegionBlock(entryType, value string, blockedRegions []string, reason string) error {
	_, err := d.db.Exec(
		`INSERT INTO service_region_blocks (type, value, blocked_regions, reason) VALUES (?,?,?,?)`,
		entryType, value, strings.Join(blockedRegions, ","), reason)
	return err
}

func (d *DB) deleteServiceRegionBlock(id int64) error {
	_, err := d.db.Exec(`DELETE FROM service_region_blocks WHERE id=?`, id)
	return err
}

// ── blacklist ─────────────────────────────────────────────────────────────────

// BlacklistEntry is a single exit-node address blacklist entry.
type BlacklistEntry struct {
	ID        int64
	Addr      string
	Reason    string
	CreatedAt time.Time
}

func (d *DB) listBlacklistEntries() ([]BlacklistEntry, error) {
	rows, err := d.db.Query(`SELECT id, addr, reason, created_at FROM blacklist_entries ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BlacklistEntry
	for rows.Next() {
		var e BlacklistEntry
		var ts int64
		if err := rows.Scan(&e.ID, &e.Addr, &e.Reason, &ts); err != nil {
			return nil, err
		}
		e.CreatedAt = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (d *DB) addBlacklistEntry(addr, reason string) error {
	_, err := d.db.Exec(`INSERT INTO blacklist_entries (addr, reason) VALUES (?,?) ON CONFLICT(addr) DO NOTHING`, addr, reason)
	return err
}

func (d *DB) deleteBlacklistEntry(id int64) error {
	_, err := d.db.Exec(`DELETE FROM blacklist_entries WHERE id=?`, id)
	return err
}

// deleteBlacklistEntryByAddr removes addr's blacklist row, if any — called on
// node decommission so a dead exit doesn't leave a stale entry.
func (d *DB) deleteBlacklistEntryByAddr(addr string) error {
	_, err := d.db.Exec(`DELETE FROM blacklist_entries WHERE addr=?`, addr)
	return err
}

// ── torrent-blocked exits ───────────────────────────────────────────────────

// TorrentBlockedEntry is a single exit-node address opted OUT of carrying
// BitTorrent peer traffic directly (see torrent_blocked_entries schema
// comment — blacklist model, absence = allowed).
type TorrentBlockedEntry struct {
	ID        int64
	Addr      string
	Reason    string
	CreatedAt time.Time
}

func (d *DB) listTorrentBlockedEntries() ([]TorrentBlockedEntry, error) {
	rows, err := d.db.Query(`SELECT id, addr, reason, created_at FROM torrent_blocked_entries ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TorrentBlockedEntry
	for rows.Next() {
		var e TorrentBlockedEntry
		var ts int64
		if err := rows.Scan(&e.ID, &e.Addr, &e.Reason, &ts); err != nil {
			return nil, err
		}
		e.CreatedAt = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (d *DB) addTorrentBlockedEntry(addr, reason string) error {
	_, err := d.db.Exec(`INSERT INTO torrent_blocked_entries (addr, reason) VALUES (?,?) ON CONFLICT(addr) DO NOTHING`, addr, reason)
	return err
}

func (d *DB) deleteTorrentBlockedEntry(id int64) error {
	_, err := d.db.Exec(`DELETE FROM torrent_blocked_entries WHERE id=?`, id)
	return err
}

// deleteTorrentBlockedEntryByAddr removes addr's blocked-list row, if any —
// called on node decommission so a dead exit doesn't leave a stale entry
// (see deleteBlacklistEntryByAddr for the sibling cleanup).
func (d *DB) deleteTorrentBlockedEntryByAddr(addr string) error {
	_, err := d.db.Exec(`DELETE FROM torrent_blocked_entries WHERE addr=?`, addr)
	return err
}

// ── excluded control nodes ────────────────────────────────────────────────────

// ExcludedNodeEntry is one control-node address that clients must not use.
type ExcludedNodeEntry struct {
	ID        int64
	Addr      string
	Reason    string
	CreatedAt time.Time
}

func (d *DB) listExcludedNodes() ([]ExcludedNodeEntry, error) {
	rows, err := d.db.Query(`SELECT id, addr, reason, created_at FROM excluded_nodes ORDER BY id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExcludedNodeEntry
	for rows.Next() {
		var e ExcludedNodeEntry
		var ts int64
		if err := rows.Scan(&e.ID, &e.Addr, &e.Reason, &ts); err != nil {
			return nil, err
		}
		e.CreatedAt = time.Unix(ts, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (d *DB) addExcludedNode(addr, reason string) error {
	_, err := d.db.Exec(`INSERT INTO excluded_nodes (addr, reason) VALUES (?,?) ON CONFLICT(addr) DO NOTHING`, addr, reason)
	return err
}

func (d *DB) deleteExcludedNode(id int64) error {
	_, err := d.db.Exec(`DELETE FROM excluded_nodes WHERE id=?`, id)
	return err
}

// ── email confirmation & password reset ──────────────────────────────────────

// setPendingConfirmation records a new unconfirmed navlink.net user registration.
func (d *DB) setPendingConfirmation(username string) error {
	_, err := d.db.Exec(
		`INSERT INTO user_confirmations (username, confirmed, source) VALUES (?,0,'navlink')
		 ON CONFLICT(username) DO NOTHING`, username)
	return err
}

// setUserConfirmed marks a user's email address as confirmed.
func (d *DB) setUserConfirmed(username string) error {
	_, err := d.db.Exec(
		`INSERT INTO user_confirmations (username, confirmed) VALUES (?,1)
		 ON CONFLICT(username) DO UPDATE SET confirmed=1`, username)
	return err
}

// PendingUser is a navlink.net registration that was started but not yet email-confirmed.
type PendingUser struct {
	Username   string
	CreatedAt  time.Time
	PromoCodes string // comma-separated list of promo codes used by this email
	SubStatus  string // 'active'|'suspended'|'' (no subscription)
	PaidUntil  time.Time
}

// listPendingConfirmations returns navlink.net registrations where confirmed=0
// matching the LIKE pattern, newest first. Includes any promo codes and subscription
// data associated with the email so the admin can see context before confirming.
func (d *DB) listPendingConfirmations(like string) ([]PendingUser, error) {
	rows, err := d.db.Query(`
		SELECT uc.username, uc.created_at,
		       COALESCE(GROUP_CONCAT(DISTINCT pu.code), '') AS promo_codes,
		       COALESCE(s.status, '')                       AS sub_status,
		       COALESCE(s.paid_until, 0)                   AS paid_until
		FROM user_confirmations uc
		LEFT JOIN promo_uses   pu ON pu.username   = uc.username
		LEFT JOIN subscriptions s  ON s.user_email = uc.username
		WHERE uc.confirmed = 0
		  AND (uc.source = 'navlink' OR uc.source = '')
		  AND uc.username LIKE ?
		GROUP BY uc.username, uc.created_at, s.status, s.paid_until
		ORDER BY uc.created_at DESC
	`, like)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingUser
	for rows.Next() {
		var u PendingUser
		var ts, paidUntil int64
		if err := rows.Scan(&u.Username, &ts, &u.PromoCodes, &u.SubStatus, &paidUntil); err != nil {
			return nil, err
		}
		u.CreatedAt = time.Unix(ts, 0)
		if paidUntil > 0 {
			u.PaidUntil = time.Unix(paidUntil, 0)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// isUserConfirmationPending returns true only when a user_confirmations record
// exists with confirmed=0 (i.e. registration started but not yet confirmed).
// Returns false (not blocking) for pre-existing users with no record.
func (d *DB) isUserConfirmationPending(username string) (bool, error) {
	var confirmed int
	err := d.db.QueryRow(
		`SELECT confirmed FROM user_confirmations WHERE username=?`, username).Scan(&confirmed)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return confirmed == 0, nil
}

// isUserConfirmed returns true only when a confirmed=1 record exists.
// Used by forgot-password to verify the account is active.
func (d *DB) isUserConfirmed(username string) (bool, error) {
	var confirmed int
	err := d.db.QueryRow(
		`SELECT confirmed FROM user_confirmations WHERE username=?`, username).Scan(&confirmed)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return confirmed == 1, nil
}

// createEmailToken stores a one-time token of the given type for a user.
func (d *DB) createEmailToken(token, username, tokenType string, expiresAt time.Time) error {
	_, err := d.db.Exec(
		`INSERT INTO email_tokens (token, username, type, expires_at) VALUES (?,?,?,?)`,
		token, username, tokenType, expiresAt.Unix())
	return err
}

// consumeEmailToken validates and atomically deletes a token.
// Returns the username if the token is valid and not expired; "" otherwise.
func (d *DB) consumeEmailToken(token, tokenType string) (string, error) {
	var username string
	var expiresAt int64
	err := d.db.QueryRow(
		`SELECT username, expires_at FROM email_tokens WHERE token=? AND type=?`,
		token, tokenType).Scan(&username, &expiresAt)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if time.Now().Unix() > expiresAt {
		d.db.Exec(`DELETE FROM email_tokens WHERE token=?`, token) //nolint:errcheck
		return "", nil
	}
	if _, err := d.db.Exec(`DELETE FROM email_tokens WHERE token=?`, token); err != nil {
		return "", err
	}
	return username, nil
}

// deleteEmailTokensByUser removes all tokens of the given type for a user.
// Used before generating a replacement token (resend / new reset).
func (d *DB) deleteEmailTokensByUser(username, tokenType string) {
	d.db.Exec(`DELETE FROM email_tokens WHERE username=? AND type=?`, username, tokenType) //nolint:errcheck
}

// ── subscription_plans ────────────────────────────────────────────────────────

type SubscriptionPlan struct {
	Region       string
	DurationDays int
	PricePia     int64
	UpdatedAt    time.Time
	UpdatedBy    string
}

// PaidUntilFrom returns the paid_until time for this plan starting from base.
// Monthly plans use calendar-month arithmetic; others use exact day count.
func (p *SubscriptionPlan) PaidUntilFrom(base time.Time) time.Time {
	if p.DurationDays == 30 {
		return base.AddDate(0, 1, 0)
	}
	return base.AddDate(0, 0, p.DurationDays)
}

func (d *DB) listPlans() ([]SubscriptionPlan, error) {
	rows, err := d.db.Query(
		`SELECT region, duration_days, price_pia, updated_at, updated_by
		 FROM subscription_plans ORDER BY region, duration_days`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SubscriptionPlan
	for rows.Next() {
		var p SubscriptionPlan
		var ts int64
		if err := rows.Scan(&p.Region, &p.DurationDays, &p.PricePia, &ts, &p.UpdatedBy); err != nil {
			return nil, err
		}
		p.UpdatedAt = time.Unix(ts, 0).UTC()
		out = append(out, p)
	}
	return out, rows.Err()
}

func (d *DB) upsertPlan(region string, durationDays int, pricePia int64, updatedBy string) error {
	_, err := d.db.Exec(
		`INSERT INTO subscription_plans(region,duration_days,price_pia,updated_at,updated_by)
		 VALUES(?,?,?,strftime('%s','now'),?)
		 ON CONFLICT(region,duration_days) DO UPDATE SET
		   price_pia=excluded.price_pia,
		   updated_at=excluded.updated_at,
		   updated_by=excluded.updated_by`,
		region, durationDays, pricePia, updatedBy)
	return err
}

func (d *DB) deletePlan(region string, durationDays int) error {
	_, err := d.db.Exec(
		`DELETE FROM subscription_plans WHERE region=? AND duration_days=?`, region, durationDays)
	return err
}

// getPlansForRegion returns all plans for a region, falling back to '*'.
// Exact region match wins over '*' for each duration.
func (d *DB) getPlansForRegion(region string) ([]SubscriptionPlan, error) {
	rows, err := d.db.Query(
		`SELECT region, duration_days, price_pia, updated_at, updated_by
		 FROM subscription_plans
		 WHERE region=? OR region='*'
		 ORDER BY duration_days,
		          CASE WHEN region=? THEN 0 ELSE 1 END`,
		region, region)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := map[int]bool{}
	var out []SubscriptionPlan
	for rows.Next() {
		var p SubscriptionPlan
		var ts int64
		if err := rows.Scan(&p.Region, &p.DurationDays, &p.PricePia, &ts, &p.UpdatedBy); err != nil {
			return nil, err
		}
		p.UpdatedAt = time.Unix(ts, 0).UTC()
		if !seen[p.DurationDays] {
			seen[p.DurationDays] = true
			out = append(out, p)
		}
	}
	return out, rows.Err()
}

// getPlanForRegionAndDuration returns the plan for a specific region+duration,
// falling back to '*' for that duration. Returns nil if not found.
func (d *DB) getPlanForRegionAndDuration(region string, durationDays int) (*SubscriptionPlan, error) {
	var p SubscriptionPlan
	var ts int64
	err := d.db.QueryRow(
		`SELECT region, duration_days, price_pia, updated_at, updated_by
		 FROM subscription_plans
		 WHERE (region=? OR region='*') AND duration_days=?
		 ORDER BY CASE WHEN region=? THEN 0 ELSE 1 END LIMIT 1`,
		region, durationDays, region).
		Scan(&p.Region, &p.DurationDays, &p.PricePia, &ts, &p.UpdatedBy)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.UpdatedAt = time.Unix(ts, 0).UTC()
	return &p, nil
}

// getPlanForRegion returns the 30-day plan for a region (backward compat).
func (d *DB) getPlanForRegion(region string) (*SubscriptionPlan, error) {
	return d.getPlanForRegionAndDuration(region, 30)
}

// ── system_settings ───────────────────────────────────────────────────────────

func (d *DB) getSetting(key string) (value string, ok bool, err error) {
	err = d.db.QueryRow(`SELECT value FROM system_settings WHERE key=?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	return value, err == nil, err
}

func (d *DB) setSetting(key, value, updatedBy string) error {
	_, err := d.db.Exec(
		`INSERT INTO system_settings(key,value,updated_at,updated_by)
		 VALUES(?,?,strftime('%s','now'),?)
		 ON CONFLICT(key) DO UPDATE SET
		   value=excluded.value,
		   updated_at=excluded.updated_at,
		   updated_by=excluded.updated_by`,
		key, value, updatedBy)
	return err
}

// getPlanForRegion returns the plan for an ISO region code, falling back to '*'.
// Returns nil if no plan exists at all.
// ── subscriptions ─────────────────────────────────────────────────────────────

type Subscription struct {
	KeyID         string
	ClientID      string
	UserEmail     string
	PlanPia       int64 // minor units (e.g. 150000 = 1500.00 PIA)
	PaidUntil     time.Time
	Status        string // "active" | "paused"
	LastChargedAt *time.Time
	CreatedAt     time.Time
}

func (d *DB) getSubscription(keyID string) (*Subscription, error) {
	var s Subscription
	var paidUntil, createdAt int64
	var lastCharged *int64
	err := d.db.QueryRow(
		`SELECT key_id, client_id, user_email, plan_pia, paid_until, status, last_charged_at, created_at
		 FROM subscriptions WHERE key_id=?`, keyID).
		Scan(&s.KeyID, &s.ClientID, &s.UserEmail, &s.PlanPia, &paidUntil,
			&s.Status, &lastCharged, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	s.PaidUntil = time.Unix(paidUntil, 0)
	s.CreatedAt = time.Unix(createdAt, 0)
	if lastCharged != nil {
		t := time.Unix(*lastCharged, 0)
		s.LastChargedAt = &t
	}
	return &s, nil
}

func (d *DB) upsertSubscription(s *Subscription) error {
	now := time.Now().Unix()
	var lastCharged interface{}
	if s.LastChargedAt != nil {
		lastCharged = s.LastChargedAt.Unix()
	}
	_, err := d.db.Exec(
		`INSERT INTO subscriptions(key_id, client_id, user_email, plan_pia, paid_until, status, last_charged_at, created_at)
		 VALUES(?,?,?,?,?,?,?,?)
		 ON CONFLICT(key_id) DO UPDATE SET
		   client_id=excluded.client_id,
		   user_email=excluded.user_email,
		   plan_pia=excluded.plan_pia,
		   paid_until=excluded.paid_until,
		   status=excluded.status,
		   last_charged_at=excluded.last_charged_at`,
		s.KeyID, s.ClientID, s.UserEmail, s.PlanPia, s.PaidUntil.Unix(),
		s.Status, lastCharged, now)
	return err
}

// pauseKey disables a key and marks its subscription as paused.
func (d *DB) pauseKey(keyID string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.Exec(`UPDATE keys SET enabled=0 WHERE key_id=?`, keyID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE subscriptions SET status='paused' WHERE key_id=?`, keyID); err != nil {
		return err
	}
	return tx.Commit()
}

// resumeKey re-enables a paused key if its paid_until has not passed.
// Returns (true, nil) on success, (false, nil) if the subscription has expired.
func (d *DB) resumeKey(keyID string) (bool, error) {
	now := time.Now().Unix()
	var paidUntil sql.NullInt64
	if err := d.db.QueryRow(`SELECT paid_until FROM keys WHERE key_id=?`, keyID).Scan(&paidUntil); err != nil {
		return false, err
	}
	if !paidUntil.Valid || paidUntil.Int64 <= now {
		return false, nil
	}
	tx, err := d.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.Exec(`UPDATE keys SET enabled=1 WHERE key_id=?`, keyID); err != nil {
		return false, err
	}
	if _, err := tx.Exec(`UPDATE subscriptions SET status='active' WHERE key_id=?`, keyID); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// cancelKey permanently deletes the subscription and the key.
func (d *DB) cancelKey(keyID string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	// Delete subscription first (FK reference from subscriptions → keys).
	if _, err := tx.Exec(`DELETE FROM subscriptions WHERE key_id=?`, keyID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM keys WHERE key_id=?`, keyID); err != nil {
		return err
	}
	return tx.Commit()
}

// getSettingRow returns the full row including metadata.
func (d *DB) getSettingRow(key string) (value, updatedBy string, updatedAt time.Time, ok bool, err error) {
	var ts int64
	err = d.db.QueryRow(
		`SELECT value, updated_by, updated_at FROM system_settings WHERE key=?`, key,
	).Scan(&value, &updatedBy, &ts)
	if err == sql.ErrNoRows {
		return "", "", time.Time{}, false, nil
	}
	if err != nil {
		return "", "", time.Time{}, false, err
	}
	return value, updatedBy, time.Unix(ts, 0).UTC(), true, nil
}

// ── node traffic time-series ──────────────────────────────────────────────────

const trafficSchemaSQL = `
CREATE TABLE IF NOT EXISTS node_traffic (
	node_id     INTEGER NOT NULL,
	ts          INTEGER NOT NULL,
	bytes_total INTEGER NOT NULL DEFAULT 0,
	bw_mbps     REAL    NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS node_traffic_node_ts ON node_traffic(node_id, ts);

-- Per-node running state the arbiter uses to turn each node's raw, locally-
-- resetting bytes_total report into a true never-decreasing lifetime total.
-- Nodes don't (and shouldn't) track anything across their own restarts --
-- they just report "bytes moved since my process started". It's the
-- arbiter's job to notice when that counter drops (a restart) and keep
-- accumulating instead of losing everything before the reset.
CREATE TABLE IF NOT EXISTS node_counter_state (
	node_id  INTEGER PRIMARY KEY,
	offset   INTEGER NOT NULL DEFAULT 0, -- sum of every completed reset-epoch's final value
	last_raw INTEGER NOT NULL DEFAULT 0  -- last raw bytes_total this node reported
);
`

// initTrafficSchema creates the node_traffic table used for per-node historical
// stats (bandwidth, RTT, CPU/mem/disk load) and adds the stat columns that were
// introduced after the original bandwidth-only table.
func (d *DB) initTrafficSchema() error {
	if _, err := d.db.Exec(trafficSchemaSQL); err != nil {
		return err
	}
	for _, stmt := range []string{
		`ALTER TABLE node_traffic ADD COLUMN rtt_ms    REAL    NOT NULL DEFAULT 0`,
		`ALTER TABLE node_traffic ADD COLUMN cpu_pct   REAL    NOT NULL DEFAULT 0`,
		`ALTER TABLE node_traffic ADD COLUMN mem_pct   REAL    NOT NULL DEFAULT 0`,
		`ALTER TABLE node_traffic ADD COLUMN disk_pct  REAL    NOT NULL DEFAULT 0`,
		// bytes_cum is the arbiter-normalized, restart-proof cumulative total
		// (see recordNodeTrafficSample) -- every read of "how much traffic has
		// this node moved" should use this column, never raw bytes_total.
		`ALTER TABLE node_traffic ADD COLUMN bytes_cum INTEGER NOT NULL DEFAULT 0`,
		// routing_rtt_ms is a SEPARATE metric from rtt_ms, added 2026-08-10.
		// rtt_ms stays the original probe-only signal (control/exit -> real
		// internet target) it has always been -- that's the "Average RTT"
		// health chart's historical meaning and it must not silently change
		// again. routing_rtt_ms is the new value: the blended RTT a control
		// node's own routing logic (ExitRegistry.MinEffectiveRTT) actually
		// uses to pick an exit, which trends toward sub-millisecond
		// control<->exit dial time once real traffic flows -- a different,
		// also-useful fact, but not the same fact, so it gets its own column
		// and its own chart instead of overwriting rtt_ms.
		`ALTER TABLE node_traffic ADD COLUMN routing_rtt_ms REAL NOT NULL DEFAULT 0`,
		// node_type denormalizes nodes.type onto each sample at write time.
		// Every network-wide aggregate (networkStatsRange, networkBytesTotal)
		// used to attribute a sample's type by JOINing to nodes on node_id --
		// which means a hard-deleted nodes row (apiAdminNodeDelete) silently
		// dropped that node's entire history from every network-wide total,
		// not just future samples (this is exactly what happened to node 30
		// on 2026-08-09, and decommissionNode's doc comment explains the
		// same mechanism). Decommission (status='decommissioned', row kept)
		// already avoided this by keeping the row joinable -- this column
		// removes the dependency on the row existing at all, so the
		// network-wide totals are correct even after a hard delete, without
		// changing decommissionNode/deleteNode or anything about when either
		// gets used.
		`ALTER TABLE node_traffic ADD COLUMN node_type TEXT NOT NULL DEFAULT ''`,
	} {
		d.db.Exec(stmt) //nolint:errcheck // fails on duplicate column, which is fine
	}
	// One-time backfill for rows written before node_type existed: derive it
	// from nodes while the row is still there to join against (a node
	// hard-deleted *before* this migration ran is an unrecoverable gap --
	// nothing left to backfill from -- but every node whose row still exists,
	// approved or decommissioned, gets its history correctly typed here).
	d.db.Exec(`
		UPDATE node_traffic SET node_type = (
			SELECT n.type FROM nodes n WHERE n.id = node_traffic.node_id
		) WHERE node_type = '' AND EXISTS (
			SELECT 1 FROM nodes n WHERE n.id = node_traffic.node_id
		)`) //nolint:errcheck
	return nil
}

// recordNodeTrafficSample records one stat sample (bandwidth + RTT +
// CPU/mem/disk) for the given node, and folds its raw bytes_total report into
// node_counter_state to derive bytes_cum -- a lifetime total that keeps
// climbing across node restarts instead of following the node's own counter
// back down to zero. The node only ever reports "bytes since my process
// started"; recognizing and bridging a reset is the arbiter's job, done once
// here at ingestion, so every downstream query can just trust bytes_cum.
// Postgres follow-up (Phase 3 dialect pass): this SELECT should gain a
// `FOR UPDATE` clause once the driver targets Postgres. SQLite doesn't
// support that clause (would break the current build), and the practical
// risk today is low (concurrent heartbeats for the very same node_id are
// rare -- a node normally reports one at a time), but without it, two
// truly simultaneous heartbeats for one node under a real connection pool
// could both read the same offset/last_raw and produce an inconsistent
// bytes_cum. Flagging now rather than silently carrying it into Postgres.
func (d *DB) recordNodeTrafficSample(nodeID, ts, rawBytesTotal int64, nodeType string, bwMbps, rttMs, routingRTTms, cpuPct, memPct, diskPct float64) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	var offset, lastRaw int64
	// "offset" is quoted -- it's a reserved word in Postgres (see quoteCols's
	// comment in cmd/pgcutover/main.go, which already had to account for this
	// on the one-time data copy; this ongoing write path did not, and silently
	// syntax-errored on every call since the Postgres cutover, so no new
	// node_traffic/node_counter_state rows were written at all post-migration).
	err = tx.QueryRow(`SELECT "offset", last_raw FROM node_counter_state WHERE node_id=?`, nodeID).Scan(&offset, &lastRaw)
	switch {
	case err == sql.ErrNoRows:
		// First sample ever for this node: nothing to carry forward.
		offset, lastRaw = 0, 0
	case err != nil:
		return err
	case rawBytesTotal < lastRaw:
		// The node's own counter went backwards -- it restarted. Bank the
		// pre-reset total so this new, smaller count keeps adding on top of
		// it rather than replacing it.
		offset += lastRaw
	}
	cum := offset + rawBytesTotal

	if _, err := tx.Exec(`
		INSERT INTO node_counter_state(node_id, "offset", last_raw) VALUES(?,?,?)
		ON CONFLICT(node_id) DO UPDATE SET "offset"=excluded."offset", last_raw=excluded.last_raw
	`, nodeID, offset, rawBytesTotal); err != nil {
		return err
	}

	if _, err := tx.Exec(
		`INSERT INTO node_traffic(node_id, ts, bytes_total, bytes_cum, node_type, bw_mbps, rtt_ms, routing_rtt_ms, cpu_pct, mem_pct, disk_pct)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		nodeID, ts, rawBytesTotal, cum, nodeType, bwMbps, rttMs, routingRTTms, cpuPct, memPct, diskPct); err != nil {
		return err
	}
	return tx.Commit()
}

// nodeHourlyBytes returns the total bytes proxied by a node in the last hour,
// computed as MAX(bytes_cum) - MIN(bytes_cum) within the window (bytes_cum is
// restart-proof, so this stays correct across a node restart mid-window).
// Returns 0 if there is insufficient data (node just started or no traffic).
func (d *DB) nodeHourlyBytes(nodeID int64) int64 {
	cutoff := time.Now().Add(-time.Hour).Unix()
	var hi, lo int64
	err := d.db.QueryRow(
		`SELECT COALESCE(MAX(bytes_cum),0), COALESCE(MIN(bytes_cum),0)
		 FROM node_traffic WHERE node_id=? AND ts>=?`,
		nodeID, cutoff).Scan(&hi, &lo)
	if err != nil || hi <= lo {
		return 0
	}
	return hi - lo
}

// nodeLastBW returns the most recent non-zero bw_mbps from node_traffic within
// the last hour, and whether it is "fresh" (from the last ~60 s / 2 heartbeats).
func (d *DB) nodeLastBW(nodeID int64) (bw float64, fresh bool) {
	cutoff := time.Now().Add(-time.Hour).Unix()
	freshCutoff := time.Now().Add(-60 * time.Second).Unix()
	var ts int64
	err := d.db.QueryRow(
		`SELECT bw_mbps, ts FROM node_traffic
		 WHERE node_id=? AND bw_mbps>0 AND ts>=?
		 ORDER BY ts DESC LIMIT 1`,
		nodeID, cutoff).Scan(&bw, &ts)
	if err != nil {
		return 0, false
	}
	return bw, ts >= freshCutoff
}

// setNodeLoad overwrites the signed "load" bonus/malus coefficient for a node.
// Picked up automatically on the next manifest/exit-list signing (signing.go),
// which reads nodes.load directly. See load_factor.go for how this value is
// computed (relative last-hour traffic share within the node's type+region
// group) and load_factor.go's periodic ticker for the only caller.
func (d *DB) setNodeLoad(nodeID int64, load float64) error {
	_, err := d.db.Exec(`UPDATE nodes SET load=? WHERE id=?`, load, nodeID)
	return err
}

// populateNodeTraffic fills HourlyBytes and BandwidthMbps/BWFresh for each node.
func (d *DB) populateNodeTraffic(nodes []Node) {
	for i := range nodes {
		if !nodes[i].IsOnline() {
			continue
		}
		nodes[i].HourlyBytes = d.nodeHourlyBytes(nodes[i].ID)
		if nodes[i].BandwidthMbps > 0 {
			nodes[i].BWFresh = true
		} else {
			// Current heartbeat had no traffic — fetch last known non-zero value.
			bw, fresh := d.nodeLastBW(nodes[i].ID)
			if bw > 0 {
				nodes[i].BandwidthMbps = bw
				nodes[i].BWFresh = fresh
			}
		}
	}
}

// nodeStatSample is one row of the node_traffic time-series table.
type nodeStatSample struct {
	Ts           int64   `json:"ts"`
	BytesTotal   int64   `json:"bytes_total"` // raw, as reported by the node -- resets to 0 on node restart
	BytesCum     int64   `json:"bytes_cum"`   // arbiter-normalized lifetime total -- never decreases
	BWMbps       float64 `json:"bw_mbps"`
	RTTms        float64 `json:"rtt_ms"`
	RoutingRTTms float64 `json:"routing_rtt_ms"`
	CPUPct       float64 `json:"cpu_pct"`
	MemPct       float64 `json:"mem_pct"`
	DiskPct      float64 `json:"disk_pct"`
}

// nodeStatsBucket is one 10-minute aggregation point for the stats graphs.
// RTTms and RoutingRTTms are deliberately two separate fields, not one --
// see the routing_rtt_ms column comment in initTrafficSchema for why they
// must never be merged back into a single number again.
type nodeStatsBucket struct {
	Ts               int64   `json:"ts"`
	RTTms            float64 `json:"rtt_ms"`
	RoutingRTTms     float64 `json:"routing_rtt_ms"`
	BWMbps           float64 `json:"bw_mbps"`
	CPUPct           float64 `json:"cpu_pct"`
	MemPct           float64 `json:"mem_pct"`
	DiskPct          float64 `json:"disk_pct"`
	BytesTransferred int64   `json:"bytes_transferred"` // bytes delta within this bucket
}

// nodeStatsRange returns 10-minute-bucketed stat history for a node over the
// given lookback window, plus the node's current cumulative lifetime total.
// Everything here reads bytes_cum (see recordNodeTrafficSample), which stays
// correct across a node restart mid-window -- unlike raw bytes_total, it
// never decreases, so a bucket delta is never clamped to zero by a reset.
func (d *DB) nodeStatsRange(nodeID int64, since time.Time) ([]nodeStatsBucket, int64, error) {
	cutoff := since.Unix()
	rows, err := d.db.Query(`
		SELECT (ts/600)*600 AS bucket,
		       AVG(rtt_ms), AVG(routing_rtt_ms), AVG(bw_mbps), AVG(cpu_pct), AVG(mem_pct), AVG(disk_pct),
		       MAX(bytes_cum) - MIN(bytes_cum)
		FROM node_traffic
		WHERE node_id=? AND ts>=?
		GROUP BY bucket
		ORDER BY bucket ASC`,
		nodeID, cutoff)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var buckets []nodeStatsBucket
	for rows.Next() {
		var b nodeStatsBucket
		if err := rows.Scan(&b.Ts, &b.RTTms, &b.RoutingRTTms, &b.BWMbps, &b.CPUPct, &b.MemPct, &b.DiskPct, &b.BytesTransferred); err != nil {
			return nil, 0, err
		}
		buckets = append(buckets, b)
	}

	var totalBytes int64
	d.db.QueryRow(`SELECT COALESCE(MAX(bytes_cum),0)-COALESCE(MIN(bytes_cum),0) FROM node_traffic WHERE node_id=? AND ts>=?`, nodeID, cutoff).Scan(&totalBytes) //nolint:errcheck
	return buckets, totalBytes, rows.Err()
}

// networkStatsBucket is one 10-minute aggregation point across every node of
// a given type, for the network-wide stats tab.
type networkStatsBucket struct {
	Ts               int64   `json:"ts"`
	RTTms            float64 `json:"rtt_ms"`
	RoutingRTTms     float64 `json:"routing_rtt_ms"`
	CPUPct           float64 `json:"cpu_pct"`
	MemPct           float64 `json:"mem_pct"`
	DiskPct          float64 `json:"disk_pct"`
	OnlineCount      int     `json:"online_count"`      // distinct nodes that reported a sample in this bucket
	BytesTransferred int64   `json:"bytes_transferred"` // summed per-node bucket delta
}

// networkStatsRange returns 10-minute-bucketed stat history aggregated across
// every node of the given type ("control" | "exit") that has ever reported a
// sample -- live, decommissioned, or hard-deleted -- plus the network's
// current total cumulative bytes transferred (sum of each node's latest
// bytes_cum). Averages (RTT/CPU/mem/disk) and online-count come from one
// query; per-node byte deltas are summed in a second query because bytes_cum
// is a per-node monotonic counter that must be diffed per node before it can
// be summed across nodes.
// Filters on node_traffic's own node_type column, not a JOIN to nodes -- a
// node's history must keep counting toward the network-wide total no matter
// what later happens to its nodes row (see node_type's column comment in
// initTrafficSchema).
func (d *DB) networkStatsRange(nodeType string, since time.Time) ([]networkStatsBucket, int64, error) {
	cutoff := since.Unix()

	rows, err := d.db.Query(`
		SELECT (t.ts/600)*600 AS bucket,
		       AVG(t.rtt_ms), AVG(t.routing_rtt_ms), AVG(t.cpu_pct), AVG(t.mem_pct), AVG(t.disk_pct),
		       COUNT(DISTINCT t.node_id)
		FROM node_traffic t
		WHERE t.node_type=? AND t.ts>=?
		GROUP BY bucket
		ORDER BY bucket ASC`,
		nodeType, cutoff)
	if err != nil {
		return nil, 0, err
	}
	buckets := map[int64]*networkStatsBucket{}
	var order []int64
	for rows.Next() {
		var b networkStatsBucket
		if err := rows.Scan(&b.Ts, &b.RTTms, &b.RoutingRTTms, &b.CPUPct, &b.MemPct, &b.DiskPct, &b.OnlineCount); err != nil {
			rows.Close()
			return nil, 0, err
		}
		bCopy := b
		buckets[b.Ts] = &bCopy
		order = append(order, b.Ts)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	byteRows, err := d.db.Query(`
		SELECT bucket, SUM(delta) FROM (
			SELECT t.node_id, (t.ts/600)*600 AS bucket,
			       MAX(t.bytes_cum) - MIN(t.bytes_cum) AS delta
			FROM node_traffic t
			WHERE t.node_type=? AND t.ts>=?
			GROUP BY t.node_id, bucket
		)
		GROUP BY bucket`,
		nodeType, cutoff)
	if err != nil {
		return nil, 0, err
	}
	defer byteRows.Close()
	for byteRows.Next() {
		var ts, sum int64
		if err := byteRows.Scan(&ts, &sum); err != nil {
			return nil, 0, err
		}
		if b, ok := buckets[ts]; ok {
			b.BytesTransferred = sum
		}
	}
	if err := byteRows.Err(); err != nil {
		return nil, 0, err
	}

	out := make([]networkStatsBucket, 0, len(order))
	var totalBytes int64
	for _, ts := range order {
		b := *buckets[ts]
		out = append(out, b)
		totalBytes += b.BytesTransferred
	}

	return out, totalBytes, nil
}

// networkBytesTotal returns the current cumulative bytes transferred summed
// across every node of the given type that has ever reported a sample --
// live, decommissioned, or hard-deleted (sum of each node's latest bytes_cum
// sample -- restart-proof, unlike raw bytes_total). Filters on node_traffic's
// own node_type column, not a JOIN to nodes -- see networkStatsRange's doc
// comment for why.
func (d *DB) networkBytesTotal(nodeType string) int64 {
	var totalBytes int64
	d.db.QueryRow(`
		SELECT COALESCE(SUM(latest),0) FROM (
			SELECT MAX(t.bytes_cum) AS latest
			FROM node_traffic t
			WHERE t.node_type=?
			GROUP BY t.node_id
		)`, nodeType).Scan(&totalBytes) //nolint:errcheck
	return totalBytes
}

// nodePeakRow is one node's peak resource usage and total traffic over a
// selected range — used for the "peak load" / "load distribution" section of
// the network stats tab. Deliberately per-node rather than a fleet average,
// since an average across nodes hides which specific node is under load.
type nodePeakRow struct {
	NodeID      int64   `json:"node_id"`
	Addr        string  `json:"addr"` // port stripped for display
	PeakRTTms   float64 `json:"peak_rtt_ms"`
	PeakCPUPct  float64 `json:"peak_cpu_pct"`
	PeakMemPct  float64 `json:"peak_mem_pct"`
	PeakDiskPct float64 `json:"peak_disk_pct"`
	PeakBWMbps  float64 `json:"peak_bw_mbps"`
	// Avg* are the mean of the same samples the Peak* columns take the max
	// of, over the same lookback window -- added alongside peak (not instead
	// of) since peak alone doesn't show whether a node runs hot most of the
	// time or just spiked once.
	AvgCPUPct        float64 `json:"avg_cpu_pct"`
	AvgMemPct        float64 `json:"avg_mem_pct"`
	AvgDiskPct       float64 `json:"avg_disk_pct"`
	BytesTransferred int64   `json:"bytes_transferred"` // total over the whole range, not bucketed
}

// nodePeaksAndDistribution returns, for every approved node of the given
// type, its peak and average RTT/CPU/mem/disk/bandwidth and total bytes
// transferred over the given lookback window — sorted by bytes transferred
// descending, so the most heavily loaded nodes surface first.
func (d *DB) nodePeaksAndDistribution(nodeType string, since time.Time) ([]nodePeakRow, error) {
	cutoff := since.Unix()
	rows, err := d.db.Query(`
		SELECT n.id, n.addr,
		       COALESCE(MAX(t.rtt_ms),0), COALESCE(MAX(t.cpu_pct),0), COALESCE(MAX(t.mem_pct),0),
		       COALESCE(MAX(t.disk_pct),0), COALESCE(MAX(t.bw_mbps),0),
		       COALESCE(AVG(t.cpu_pct),0), COALESCE(AVG(t.mem_pct),0), COALESCE(AVG(t.disk_pct),0),
		       COALESCE(MAX(t.bytes_cum),0) - COALESCE(MIN(t.bytes_cum),0)
		FROM nodes n
		LEFT JOIN node_traffic t ON t.node_id = n.id AND t.ts >= ?
		WHERE n.type = ? AND n.status = 'approved'
		GROUP BY n.id
		ORDER BY 11 DESC`,
		cutoff, nodeType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []nodePeakRow
	for rows.Next() {
		var r nodePeakRow
		if err := rows.Scan(&r.NodeID, &r.Addr, &r.PeakRTTms, &r.PeakCPUPct, &r.PeakMemPct,
			&r.PeakDiskPct, &r.PeakBWMbps, &r.AvgCPUPct, &r.AvgMemPct, &r.AvgDiskPct,
			&r.BytesTransferred); err != nil {
			return nil, err
		}
		r.Addr = strings.TrimSuffix(r.Addr, ":443")
		out = append(out, r)
	}
	return out, rows.Err()
}

// nodeIDsWithStatsOlderThan returns distinct node_ids that have node_traffic
// rows older than cutoff (unix seconds) — candidates for archival.
func (d *DB) nodeIDsWithStatsOlderThan(cutoff int64) ([]int64, error) {
	rows, err := d.db.Query(`SELECT DISTINCT node_id FROM node_traffic WHERE ts<?`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// nodeStatsOlderThan returns all node_traffic samples for a node older than cutoff,
// oldest first — the batch about to be archived off-disk.
func (d *DB) nodeStatsOlderThan(nodeID, cutoff int64) ([]nodeStatSample, error) {
	rows, err := d.db.Query(`
		SELECT ts, bytes_total, bytes_cum, bw_mbps, rtt_ms, routing_rtt_ms, cpu_pct, mem_pct, disk_pct
		FROM node_traffic WHERE node_id=? AND ts<? ORDER BY ts ASC`,
		nodeID, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []nodeStatSample
	for rows.Next() {
		var s nodeStatSample
		if err := rows.Scan(&s.Ts, &s.BytesTotal, &s.BytesCum, &s.BWMbps, &s.RTTms, &s.RoutingRTTms, &s.CPUPct, &s.MemPct, &s.DiskPct); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// deleteNodeStatsOlderThan removes archived samples from the live table.
func (d *DB) deleteNodeStatsOlderThan(nodeID, cutoff int64) error {
	_, err := d.db.Exec(`DELETE FROM node_traffic WHERE node_id=? AND ts<?`, nodeID, cutoff)
	return err
}

