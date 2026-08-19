// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"database/sql"
	"fmt"
	"time"
)

// keysSchema defines the keys table and the index on username.
const keysSchema = `
CREATE TABLE IF NOT EXISTS keys (
	key_id      TEXT PRIMARY KEY,
	username    TEXT NOT NULL,
	device_id   TEXT,
	device_name TEXT,
	enabled     INTEGER NOT NULL DEFAULT 1,
	issued_at   INTEGER NOT NULL DEFAULT 0,
	bound_at    INTEGER NOT NULL DEFAULT 0,
	last_seen   INTEGER NOT NULL DEFAULT 0,
	source      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS keys_username ON keys(username);
`

// initKeysSchema creates the keys table. Called from openDB.
func (db *DB) initKeysSchema() error {
	_, err := db.db.Exec(keysSchema)
	return err
}

// KeyRow is one row from the keys table.
type KeyRow struct {
	KeyID                 string
	Username              string
	DeviceID              string
	DeviceName            string
	Enabled               bool
	IssuedAt              time.Time
	BoundAt               time.Time
	LastSeen              time.Time
	PaidUntil             *time.Time // nil = perpetual key
	PlanPia               int64      // price paid (minor units); 0 for perpetual/admin-issued
	ReminderSent          int        // bitmask: bit0=7d sent, bit1=1d sent, bit2=2h sent
	PreferredDurationDays int        // plan duration for auto-renewal (7 or 30); defaults to 30
	UnlimitedDevices      bool       // true = skip device binding and multi-device checks
	SubStatus             string     // subscription status from subscriptions table: "active"|"paused"; "" for perpetual keys
	Source                string     // issuance channel: "get_key_page"|"my_account"|"admin_dashboard"|"admin_keygen_page"|"admin_api"|"external_register"; "" for keys issued before this was tracked
}

// RegisterKey inserts a new key record with defaults if no record with key_id exists.
// Safe to call multiple times; ignores duplicate. source records which UI/endpoint
// issued the key (see KeyRow.Source), for distinguishing e.g. website vs admin-issued keys.
func (db *DB) RegisterKey(keyID, username, source string) error {
	now := time.Now().Unix()
	_, err := db.db.Exec(
		`INSERT INTO keys (key_id, username, enabled, issued_at, source) VALUES (?,?,1,?,?) ON CONFLICT(key_id) DO NOTHING`,
		keyID, username, now, source)
	return err
}

// UpsertKeyDevice binds device_id and device_name to a key that currently has
// no device bound (device_id IS NULL). If the key is already bound, this is a
// no-op (the caller should have checked first).
func (db *DB) UpsertKeyDevice(keyID, deviceID, deviceName string) error {
	now := time.Now().Unix()
	_, err := db.db.Exec(
		`UPDATE keys SET device_id=?, device_name=?, bound_at=?
		 WHERE key_id=? AND device_id IS NULL`,
		deviceID, deviceName, now, keyID)
	return err
}

// GetKey returns the KeyRow for keyID, or nil if not found.
func (db *DB) GetKey(keyID string) (*KeyRow, error) {
	var k KeyRow
	var deviceID, deviceName sql.NullString
	var enabled int
	var issuedAt, boundAt, lastSeen int64
	var paidUntil sql.NullInt64
	var unlimitedDevices int
	err := db.db.QueryRow(
		`SELECT key_id, username, device_id, device_name, enabled, issued_at, bound_at, last_seen,
		        paid_until, plan_pia, reminder_sent, preferred_duration_days, unlimited_devices
		 FROM keys WHERE key_id=?`, keyID).
		Scan(&k.KeyID, &k.Username, &deviceID, &deviceName, &enabled, &issuedAt, &boundAt, &lastSeen,
			&paidUntil, &k.PlanPia, &k.ReminderSent, &k.PreferredDurationDays, &unlimitedDevices)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get key: %w", err)
	}
	k.DeviceID = deviceID.String
	k.DeviceName = deviceName.String
	k.Enabled = enabled != 0
	k.UnlimitedDevices = unlimitedDevices != 0
	k.IssuedAt = time.Unix(issuedAt, 0)
	k.BoundAt = time.Unix(boundAt, 0)
	k.LastSeen = time.Unix(lastSeen, 0)
	if paidUntil.Valid {
		t := time.Unix(paidUntil.Int64, 0)
		k.PaidUntil = &t
	}
	return &k, nil
}

// SetKeyUnlimitedDevices sets whether a key bypasses per-device binding checks.
func (db *DB) SetKeyUnlimitedDevices(keyID string, unlimited bool) error {
	v := 0
	if unlimited {
		v = 1
	}
	_, err := db.db.Exec(`UPDATE keys SET unlimited_devices=? WHERE key_id=?`, v, keyID)
	return err
}

// SetKeyEnabled enables or disables a key by key_id.
func (db *DB) SetKeyEnabled(keyID string, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := db.db.Exec(`UPDATE keys SET enabled=? WHERE key_id=?`, v, keyID)
	return err
}

// SetUserEnabled enables or disables all VPN access for a user.
// Requires the user_enabled column (added via migration).
func (db *DB) SetUserEnabled(username string, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	_, err := db.db.Exec(`UPDATE users SET user_enabled=? WHERE username=?`, v, username)
	return err
}

// QueryUserKeys returns all key rows for a given username, including each key's
// subscription status (SubStatus) from the subscriptions table.
func (db *DB) QueryUserKeys(username string) ([]KeyRow, error) {
	rows, err := db.db.Query(
		`SELECT k.key_id, k.username, k.device_id, k.device_name, k.enabled, k.issued_at, k.bound_at, k.last_seen,
		        k.paid_until, k.plan_pia, k.reminder_sent, k.preferred_duration_days, k.unlimited_devices,
		        COALESCE(s.status, '') AS sub_status, k.source
		 FROM keys k
		 LEFT JOIN subscriptions s ON s.key_id = k.key_id
		 WHERE k.username=? ORDER BY k.issued_at DESC`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KeyRow
	for rows.Next() {
		var k KeyRow
		var deviceID, deviceName sql.NullString
		var enabled, unlimitedDevices int
		var issuedAt, boundAt, lastSeen int64
		var paidUntil sql.NullInt64
		if err := rows.Scan(&k.KeyID, &k.Username, &deviceID, &deviceName,
			&enabled, &issuedAt, &boundAt, &lastSeen,
			&paidUntil, &k.PlanPia, &k.ReminderSent, &k.PreferredDurationDays, &unlimitedDevices,
			&k.SubStatus, &k.Source); err != nil {
			return nil, err
		}
		k.DeviceID = deviceID.String
		k.DeviceName = deviceName.String
		k.Enabled = enabled != 0
		k.UnlimitedDevices = unlimitedDevices != 0
		k.IssuedAt = time.Unix(issuedAt, 0)
		k.BoundAt = time.Unix(boundAt, 0)
		k.LastSeen = time.Unix(lastSeen, 0)
		if paidUntil.Valid {
			t := time.Unix(paidUntil.Int64, 0)
			k.PaidUntil = &t
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// SetKeyPaidUntil sets paid_until and plan_pia for a key and clears reminder_sent.
func (db *DB) SetKeyPaidUntil(keyID string, paidUntil time.Time, planPia int64) error {
	_, err := db.db.Exec(
		`UPDATE keys SET paid_until=?, plan_pia=?, reminder_sent=0 WHERE key_id=?`,
		paidUntil.Unix(), planPia, keyID)
	return err
}

// ClearKeyPaidUntil removes the expiry from a key, making it perpetual.
func (db *DB) ClearKeyPaidUntil(keyID string) error {
	_, err := db.db.Exec(
		`UPDATE keys SET paid_until=NULL, plan_pia=0, reminder_sent=0 WHERE key_id=?`, keyID)
	return err
}

// ExtendKeyPaidUntil extends paid_until by one calendar month (from current
// paid_until if in the future, otherwise from now) and resets reminder_sent.
//
// This used to be a Go-level read-compute-write (GetKey, then compute
// base+1month, then SetKeyPaidUntil) -- a genuine lost-update race: two
// concurrent extensions for the same key (a duplicate payment webhook, a
// double-clicked renew button) would both read the same starting
// paid_until, both compute the same new value, and the second payment's
// month would be silently lost instead of stacking. SQLite's forced
// single-connection serialization happened to make this safe today (the
// second call's read would already see the first call's write); a real
// Postgres connection pool would not offer that accidental protection.
//
// An earlier version of this fix pushed the whole "+1 month" computation
// into one atomic SQL UPDATE using SQLite's strftime(...,'unixepoch','+1
// month') -- race-free, but Postgres has no strftime function at all
// (confirmed: fails outright, not just different syntax). Rewritten to
// keep the exact calendar-month arithmetic in Go (time.AddDate, so it
// still handles variable month lengths identically on both engines) but
// close the race with a row lock instead: SELECT ... FOR UPDATE on
// Postgres blocks a second concurrent extension until the first commits,
// so it reads the already-updated paid_until, not the stale value. SQLite
// doesn't support FOR UPDATE syntax at all (would break the build) and
// doesn't need it -- its own transaction/single-writer locking already
// serializes this.
func (db *DB) ExtendKeyPaidUntil(keyID string, planPia int64) (time.Time, error) {
	tx, err := db.db.Begin()
	if err != nil {
		return time.Time{}, err
	}
	defer tx.Rollback() //nolint:errcheck

	lockClause := ""
	if db.db.DriverName() == "pgx" {
		lockClause = " FOR UPDATE"
	}
	var paidUntil sql.NullInt64
	if err := tx.QueryRow(`SELECT paid_until FROM keys WHERE key_id=?`+lockClause, keyID).Scan(&paidUntil); err != nil {
		if err == sql.ErrNoRows {
			return time.Time{}, fmt.Errorf("key not found")
		}
		return time.Time{}, fmt.Errorf("read paid_until: %w", err)
	}

	base := time.Now().UTC()
	if paidUntil.Valid && paidUntil.Int64 > base.Unix() {
		base = time.Unix(paidUntil.Int64, 0).UTC()
	}
	newUntil := base.AddDate(0, 1, 0)

	if _, err := tx.Exec(
		`UPDATE keys SET paid_until=?, plan_pia=?, reminder_sent=0 WHERE key_id=?`,
		newUntil.Unix(), planPia, keyID); err != nil {
		return time.Time{}, fmt.Errorf("write extended paid_until: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return time.Time{}, fmt.Errorf("commit: %w", err)
	}
	return newUntil, nil
}

// GetKeysNeedingReminders returns enabled keys with paid_until set that fall within
// any of the given reminder windows but haven't had that reminder sent yet.
// Each threshold bit corresponds to: bit0 = longest (e.g. 7d), bit1, bit2 = shortest (e.g. 2h).
func (db *DB) GetKeysNeedingReminders(thresholds []time.Duration) ([]KeyRow, error) {
	now := time.Now().Unix()
	rows, err := db.db.Query(
		`SELECT key_id, username, device_id, device_name, enabled, issued_at, bound_at, last_seen,
		        paid_until, plan_pia, reminder_sent, preferred_duration_days, unlimited_devices
		 FROM keys WHERE enabled=1 AND paid_until IS NOT NULL AND paid_until > ?`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KeyRow
	for rows.Next() {
		var k KeyRow
		var deviceID, deviceName sql.NullString
		var enabled, unlimitedDevices int
		var issuedAt, boundAt, lastSeen int64
		var paidUntil sql.NullInt64
		if err := rows.Scan(&k.KeyID, &k.Username, &deviceID, &deviceName,
			&enabled, &issuedAt, &boundAt, &lastSeen,
			&paidUntil, &k.PlanPia, &k.ReminderSent, &k.PreferredDurationDays, &unlimitedDevices); err != nil {
			return nil, err
		}
		k.DeviceID = deviceID.String
		k.DeviceName = deviceName.String
		k.Enabled = enabled != 0
		k.UnlimitedDevices = unlimitedDevices != 0
		k.IssuedAt = time.Unix(issuedAt, 0)
		k.BoundAt = time.Unix(boundAt, 0)
		k.LastSeen = time.Unix(lastSeen, 0)
		if paidUntil.Valid {
			t := time.Unix(paidUntil.Int64, 0)
			k.PaidUntil = &t
		}
		if k.PaidUntil == nil {
			continue
		}
		timeLeft := time.Until(*k.PaidUntil)
		needsReminder := false
		for bit, thresh := range thresholds {
			if timeLeft <= thresh && k.ReminderSent&(1<<bit) == 0 {
				needsReminder = true
				break
			}
		}
		if needsReminder {
			out = append(out, k)
		}
	}
	return out, rows.Err()
}

// MarkReminderSent sets the given bit in reminder_sent for a key.
func (db *DB) MarkReminderSent(keyID string, bit int) error {
	_, err := db.db.Exec(
		`UPDATE keys SET reminder_sent = reminder_sent | ? WHERE key_id=?`,
		1<<bit, keyID)
	return err
}

// DisableExpiredKeys sets enabled=0 for all keys where paid_until < now.
// Returns the list of (keyID, username) pairs that were disabled.
func (db *DB) DisableExpiredKeys() ([]KeyRow, error) {
	now := time.Now().Unix()
	rows, err := db.db.Query(
		`SELECT key_id, username, paid_until FROM keys WHERE enabled=1 AND paid_until IS NOT NULL AND paid_until < ?`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var expired []KeyRow
	for rows.Next() {
		var k KeyRow
		var paidUntil int64
		if err := rows.Scan(&k.KeyID, &k.Username, &paidUntil); err != nil {
			return nil, err
		}
		t := time.Unix(paidUntil, 0)
		k.PaidUntil = &t
		expired = append(expired, k)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, k := range expired {
		db.db.Exec(`UPDATE keys SET enabled=0 WHERE key_id=?`, k.KeyID) //nolint:errcheck
	}
	return expired, nil
}

// IsUserEnabled returns false when the user has user_enabled=0.
// Returns true for users without the column (legacy rows default to enabled).
func (db *DB) IsUserEnabled(username string) (bool, error) {
	var enabled int
	err := db.db.QueryRow(`SELECT user_enabled FROM users WHERE username=?`, username).Scan(&enabled)
	if err == sql.ErrNoRows {
		// User does not exist yet; allow login (getOrCreateUser will create them).
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("is user enabled: %w", err)
	}
	return enabled != 0, nil
}

// GetKeyWarnState returns the current multi-device warning count and the unix
// timestamp of the last warning issued for keyID.  Returns zeros if not found.
func (db *DB) GetKeyWarnState(keyID string) (warnCount int, lastWarnedAt int64, err error) {
	err = db.db.QueryRow(
		`SELECT warn_count, last_warned_at FROM keys WHERE key_id=?`, keyID).
		Scan(&warnCount, &lastWarnedAt)
	if err == sql.ErrNoRows {
		return 0, 0, nil
	}
	return
}

// BumpKeyWarn increments warn_count and sets last_warned_at to now.
// Returns the new warn_count.
func (db *DB) BumpKeyWarn(keyID string) (int, error) {
	now := time.Now().Unix()
	_, err := db.db.Exec(
		`UPDATE keys SET warn_count=warn_count+1, last_warned_at=? WHERE key_id=?`,
		now, keyID)
	if err != nil {
		return 0, err
	}
	var newCount int
	db.db.QueryRow(`SELECT warn_count FROM keys WHERE key_id=?`, keyID).Scan(&newCount) //nolint:errcheck
	return newCount, nil
}

// TouchKeyLastSeen updates last_seen to now for the given key.
func (db *DB) TouchKeyLastSeen(keyID string) error {
	now := time.Now().Unix()
	_, err := db.db.Exec(`UPDATE keys SET last_seen=? WHERE key_id=?`, now, keyID)
	return err
}

// UnbindKey clears device_id and device_name for a key (allows re-activation on a new device).
func (db *DB) UnbindKey(keyID string) error {
	_, err := db.db.Exec(
		`UPDATE keys SET device_id=NULL, device_name=NULL, bound_at=0 WHERE key_id=?`, keyID)
	return err
}

// SetKeyPreferredDuration stores the user's preferred renewal plan duration for a key.
// Used for auto-renewal and as the default plan in the renewal UI.
func (db *DB) SetKeyPreferredDuration(keyID string, durationDays int) error {
	_, err := db.db.Exec(
		`UPDATE keys SET preferred_duration_days=? WHERE key_id=?`, durationDays, keyID)
	return err
}

// GetExpiredEnabledKeys returns enabled keys whose paid_until is in the past.
// Used by the auto-renewer to attempt charging before DisableExpiredKeys runs.
func (db *DB) GetExpiredEnabledKeys() ([]KeyRow, error) {
	now := time.Now().Unix()
	rows, err := db.db.Query(
		`SELECT key_id, username, device_id, device_name, enabled, issued_at, bound_at, last_seen,
		        paid_until, plan_pia, reminder_sent, preferred_duration_days, unlimited_devices
		 FROM keys WHERE enabled=1 AND paid_until IS NOT NULL AND paid_until < ?`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KeyRow
	for rows.Next() {
		var k KeyRow
		var deviceID, deviceName sql.NullString
		var enabled, unlimitedDevices int
		var issuedAt, boundAt, lastSeen int64
		var paidUntil sql.NullInt64
		if err := rows.Scan(&k.KeyID, &k.Username, &deviceID, &deviceName,
			&enabled, &issuedAt, &boundAt, &lastSeen,
			&paidUntil, &k.PlanPia, &k.ReminderSent, &k.PreferredDurationDays, &unlimitedDevices); err != nil {
			return nil, err
		}
		k.DeviceID = deviceID.String
		k.DeviceName = deviceName.String
		k.Enabled = enabled != 0
		k.UnlimitedDevices = unlimitedDevices != 0
		k.IssuedAt = time.Unix(issuedAt, 0)
		k.BoundAt = time.Unix(boundAt, 0)
		k.LastSeen = time.Unix(lastSeen, 0)
		if paidUntil.Valid {
			t := time.Unix(paidUntil.Int64, 0)
			k.PaidUntil = &t
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
