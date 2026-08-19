// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import "time"

// client_conn_stats holds periodic connection-health samples self-reported
// directly by end-user clients (see conn_stats_client_api.go /
// tunnel_cat/snc/core/conn_stats_upload.go), same cadence and trust model
// as bananameter_results' source_type='client' rows and log-upload's
// device reports: self-identified via X-Node-ID/X-Node-Type headers plus a
// self-reported username in the body, authenticated only by a shared
// bearer key (telemetry, not an auth boundary).
//
// Two different value shapes share this one row, matching node_traffic's
// convention (gauge columns like cpu_pct sit next to no equivalent "delta"
// column there because node_traffic has none -- here we do need both
// kinds, so the naming spells out which is which):
//   - "gauge" columns are the value AT the moment of the report (pool size,
//     unreachable-controls count, current session's elapsed seconds) --
//     MAX/AVG over a window is meaningful the same way it is for cpu_pct.
//   - "_delta" columns are event counts SINCE THE CLIENT'S LAST SUCCESSFUL
//     upload (the client zeroes its own counters after a send succeeds) --
//     summing deltas over a window gives "how many of this event happened
//     in this window", deliberately NOT a cumulative-since-install total
//     (unlike node_traffic's bytes_cum, which needs node_counter_state to
//     survive restarts -- event counts don't carry that same cost if a
//     single 5-minute window is lost to a crash, so the simpler delta
//     model was chosen over cumulative-with-server-side-diff).
const connStatsSchemaSQL = `
CREATE TABLE IF NOT EXISTS client_conn_stats (
	id                    INTEGER PRIMARY KEY AUTOINCREMENT,
	ts                    INTEGER NOT NULL,
	username              TEXT    NOT NULL,
	device_id             TEXT    NOT NULL DEFAULT '',
	node_type             TEXT    NOT NULL DEFAULT '', -- client platform: android/ios/windows/macos/linux
	client_version        TEXT    NOT NULL DEFAULT '',
	pool_tcp              INTEGER NOT NULL DEFAULT 0, -- gauge: TCP dialers in the pool right now
	pool_udp              INTEGER NOT NULL DEFAULT 0, -- gauge: UDP dialers in the pool right now
	unreachable_controls  INTEGER NOT NULL DEFAULT 0, -- gauge
	total_controls        INTEGER NOT NULL DEFAULT 0, -- gauge: known control count (denominator for unreachable)
	seconds_online        INTEGER NOT NULL DEFAULT 0, -- gauge: current session's elapsed time at report time
	avg_fail_ratio        REAL    NOT NULL DEFAULT 0,  -- gauge: mean TunnelDialer.FailRatio() across active dialers
	rejected_sessions     INTEGER NOT NULL DEFAULT 0, -- delta
	connects_manual       INTEGER NOT NULL DEFAULT 0, -- delta
	connects_auto         INTEGER NOT NULL DEFAULT 0, -- delta
	disconnects_manual    INTEGER NOT NULL DEFAULT 0, -- delta
	disconnects_auto      INTEGER NOT NULL DEFAULT 0, -- delta
	flap_events           INTEGER NOT NULL DEFAULT 0, -- delta
	evictions             INTEGER NOT NULL DEFAULT 0  -- delta
);
CREATE INDEX IF NOT EXISTS client_conn_stats_username_ts ON client_conn_stats(username, ts);
CREATE INDEX IF NOT EXISTS client_conn_stats_ts           ON client_conn_stats(ts);
`

// initConnStatsSchema creates the client_conn_stats table. Called from openDB.
func (d *DB) initConnStatsSchema() error {
	if _, err := d.db.Exec(connStatsSchemaSQL); err != nil {
		return err
	}
	return nil
}

// connStatsReport is one client-reported sample, as decoded from the
// upload payload (see conn_stats_client_api.go's clientConnStatsPayload)
// plus the identity fields resolved from headers/body by the handler.
type connStatsReport struct {
	Ts                    int64
	Username              string
	DeviceID              string
	NodeType              string
	ClientVersion         string
	PoolTCP               int
	PoolUDP               int
	UnreachableControls   int
	TotalControls         int
	SecondsOnline         int64
	AvgFailRatio          float64
	RejectedSessions      int
	ConnectsManual        int
	ConnectsAuto          int
	DisconnectsManual     int
	DisconnectsAuto       int
	FlapEvents            int
	Evictions             int
}

// usernameForDeviceID returns the most recently reported username for a
// device_id (X-Node-ID), used by log_store.go to organize log-upload
// storage by user instead of raw device id. Returns "" on any failure,
// including "not found" -- callers must treat that as "fall back to
// nodeID-keyed storage", not propagate an error: a device that has only
// ever sent logs and never a conn-stats sample yet legitimately has no
// known username server-side, and that's routine, not exceptional.
func (d *DB) usernameForDeviceID(deviceID string) string {
	if deviceID == "" {
		return ""
	}
	var username string
	err := d.db.QueryRow(
		`SELECT username FROM client_conn_stats WHERE device_id = ? ORDER BY ts DESC LIMIT 1`,
		deviceID,
	).Scan(&username)
	if err != nil {
		return ""
	}
	return username
}

// insertConnStats stores one client-reported connection-stats sample.
func (d *DB) insertConnStats(r connStatsReport) error {
	_, err := d.db.Exec(`
		INSERT INTO client_conn_stats(
			ts, username, device_id, node_type, client_version,
			pool_tcp, pool_udp, unreachable_controls, total_controls,
			seconds_online, avg_fail_ratio,
			rejected_sessions, connects_manual, connects_auto,
			disconnects_manual, disconnects_auto, flap_events, evictions
		) VALUES (?,?,?,?,?, ?,?,?,?, ?,?, ?,?,?, ?,?,?,?)`,
		r.Ts, r.Username, r.DeviceID, r.NodeType, r.ClientVersion,
		r.PoolTCP, r.PoolUDP, r.UnreachableControls, r.TotalControls,
		r.SecondsOnline, r.AvgFailRatio,
		r.RejectedSessions, r.ConnectsManual, r.ConnectsAuto,
		r.DisconnectsManual, r.DisconnectsAuto, r.FlapEvents, r.Evictions)
	return err
}

// connStatsDeviceBucket is one (time bucket, device) row of a per-user
// history query -- same pivot shape as bananameterUserDeviceBucket, so the
// admin_user_stats.html JS can reuse the identical pivot-by-device pattern.
type connStatsDeviceBucket struct {
	Ts                    int64   `json:"ts"`
	DeviceID              string  `json:"device_id"`
	PoolTCP               float64 `json:"pool_tcp"`
	PoolUDP               float64 `json:"pool_udp"`
	UnreachableControls   float64 `json:"unreachable_controls"`
	TotalControls         float64 `json:"total_controls"`
	SecondsOnline         float64 `json:"seconds_online"`
	AvgFailRatio          float64 `json:"avg_fail_ratio"`
	RejectedSessions      int64   `json:"rejected_sessions"`
	ConnectsManual        int64   `json:"connects_manual"`
	ConnectsAuto          int64   `json:"connects_auto"`
	DisconnectsManual     int64   `json:"disconnects_manual"`
	DisconnectsAuto       int64   `json:"disconnects_auto"`
	FlapEvents            int64   `json:"flap_events"`
	Evictions             int64   `json:"evictions"`
	Samples               int     `json:"samples"`
}

// userConnStatsHistory returns one user's connection-stats history,
// 10-min-bucketed and broken out per device_id -- mirrors
// userBananameterHistory's shape exactly (db_bananameter.go) so the same
// per-device pivot/chart JS pattern applies. Gauge columns are averaged
// per bucket; delta (event-count) columns are summed per bucket.
func (d *DB) userConnStatsHistory(username string, since time.Time) ([]connStatsDeviceBucket, error) {
	rows, err := d.db.Query(`
		SELECT (ts/600)*600 AS bucket, device_id,
		       AVG(pool_tcp), AVG(pool_udp), AVG(unreachable_controls), AVG(total_controls),
		       AVG(seconds_online), AVG(avg_fail_ratio),
		       SUM(rejected_sessions), SUM(connects_manual), SUM(connects_auto),
		       SUM(disconnects_manual), SUM(disconnects_auto), SUM(flap_events), SUM(evictions),
		       COUNT(*)
		FROM client_conn_stats
		WHERE username=? AND ts>=?
		GROUP BY bucket, device_id
		ORDER BY bucket ASC`, username, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []connStatsDeviceBucket
	for rows.Next() {
		var b connStatsDeviceBucket
		if err := rows.Scan(&b.Ts, &b.DeviceID,
			&b.PoolTCP, &b.PoolUDP, &b.UnreachableControls, &b.TotalControls,
			&b.SecondsOnline, &b.AvgFailRatio,
			&b.RejectedSessions, &b.ConnectsManual, &b.ConnectsAuto,
			&b.DisconnectsManual, &b.DisconnectsAuto, &b.FlapEvents, &b.Evictions,
			&b.Samples); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// connStatsFleetBucket is one time-bucketed, fleet-wide average row --
// mirrors bananameterNetworkBucket's shape (db_bananameter.go).
type connStatsFleetBucket struct {
	Ts                    int64   `json:"ts"`
	PoolTCP               float64 `json:"pool_tcp"`
	PoolUDP               float64 `json:"pool_udp"`
	UnreachableControls   float64 `json:"unreachable_controls"`
	TotalControls         float64 `json:"total_controls"`
	SecondsOnline         float64 `json:"seconds_online"`
	AvgFailRatio          float64 `json:"avg_fail_ratio"`
	RejectedSessions      float64 `json:"rejected_sessions"`
	ConnectsManual        float64 `json:"connects_manual"`
	ConnectsAuto          float64 `json:"connects_auto"`
	DisconnectsManual     float64 `json:"disconnects_manual"`
	DisconnectsAuto       float64 `json:"disconnects_auto"`
	FlapEvents            float64 `json:"flap_events"`
	Evictions             float64 `json:"evictions"`
	Samples               int     `json:"samples"`
}

// fleetConnStatsHistory returns the system-wide, 10-min-bucketed average
// across every reporting user/device, for the fleet-average chart on the
// Users tab -- mirrors networkBananameterHistory's shape and bucketing.
func (d *DB) fleetConnStatsHistory(since time.Time) ([]connStatsFleetBucket, error) {
	rows, err := d.db.Query(`
		SELECT (ts/600)*600 AS bucket,
		       AVG(pool_tcp), AVG(pool_udp), AVG(unreachable_controls), AVG(total_controls),
		       AVG(seconds_online), AVG(avg_fail_ratio),
		       AVG(rejected_sessions), AVG(connects_manual), AVG(connects_auto),
		       AVG(disconnects_manual), AVG(disconnects_auto), AVG(flap_events), AVG(evictions),
		       COUNT(*)
		FROM client_conn_stats
		WHERE ts>=?
		GROUP BY bucket
		ORDER BY bucket ASC`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []connStatsFleetBucket
	for rows.Next() {
		var b connStatsFleetBucket
		if err := rows.Scan(&b.Ts,
			&b.PoolTCP, &b.PoolUDP, &b.UnreachableControls, &b.TotalControls,
			&b.SecondsOnline, &b.AvgFailRatio,
			&b.RejectedSessions, &b.ConnectsManual, &b.ConnectsAuto,
			&b.DisconnectsManual, &b.DisconnectsAuto, &b.FlapEvents, &b.Evictions,
			&b.Samples); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// connStatsSample is a raw row, used only by the archiver (stats_archive.go).
type connStatsSample struct {
	Ts                    int64   `json:"ts"`
	Username              string  `json:"username"`
	DeviceID              string  `json:"device_id"`
	NodeType              string  `json:"node_type"`
	ClientVersion         string  `json:"client_version"`
	PoolTCP               int     `json:"pool_tcp"`
	PoolUDP               int     `json:"pool_udp"`
	UnreachableControls   int     `json:"unreachable_controls"`
	TotalControls         int     `json:"total_controls"`
	SecondsOnline         int64   `json:"seconds_online"`
	AvgFailRatio          float64 `json:"avg_fail_ratio"`
	RejectedSessions      int     `json:"rejected_sessions"`
	ConnectsManual        int     `json:"connects_manual"`
	ConnectsAuto          int     `json:"connects_auto"`
	DisconnectsManual     int     `json:"disconnects_manual"`
	DisconnectsAuto       int     `json:"disconnects_auto"`
	FlapEvents            int     `json:"flap_events"`
	Evictions             int     `json:"evictions"`
}

// connStatsOlderThan returns raw samples older than cutoff, oldest first --
// the batch about to be archived off-disk (same shape as usageStatsOlderThan).
func (d *DB) connStatsOlderThan(cutoff int64) ([]connStatsSample, error) {
	rows, err := d.db.Query(`
		SELECT ts, username, device_id, node_type, client_version,
		       pool_tcp, pool_udp, unreachable_controls, total_controls,
		       seconds_online, avg_fail_ratio,
		       rejected_sessions, connects_manual, connects_auto,
		       disconnects_manual, disconnects_auto, flap_events, evictions
		FROM client_conn_stats WHERE ts < ? ORDER BY ts ASC`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []connStatsSample
	for rows.Next() {
		var s connStatsSample
		if err := rows.Scan(&s.Ts, &s.Username, &s.DeviceID, &s.NodeType, &s.ClientVersion,
			&s.PoolTCP, &s.PoolUDP, &s.UnreachableControls, &s.TotalControls,
			&s.SecondsOnline, &s.AvgFailRatio,
			&s.RejectedSessions, &s.ConnectsManual, &s.ConnectsAuto,
			&s.DisconnectsManual, &s.DisconnectsAuto, &s.FlapEvents, &s.Evictions); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// deleteConnStatsOlderThan removes archived rows from the live table.
func (d *DB) deleteConnStatsOlderThan(cutoff int64) error {
	_, err := d.db.Exec(`DELETE FROM client_conn_stats WHERE ts<?`, cutoff)
	return err
}
