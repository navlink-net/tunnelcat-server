// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import "time"

const usageStatsSchemaSQL = `
CREATE TABLE IF NOT EXISTS network_usage_stats (
	ts           INTEGER PRIMARY KEY,
	active_users INTEGER NOT NULL DEFAULT 0,
	bytes_total  INTEGER NOT NULL DEFAULT 0
);
`

// usageSampleInterval is how often the network-wide usage snapshot is taken.
// Matches the 10-minute bucket granularity used throughout the stats UI.
const usageSampleInterval = 10 * time.Minute

// initUsageStatsSchema creates the network_usage_stats table used for the
// "users online" / "traffic per user" graphs on the network stats tab.
func (d *DB) initUsageStatsSchema() error {
	_, err := d.db.Exec(usageStatsSchemaSQL)
	return err
}

// insertUsageSnapshot records one network-wide usage sample: how many users
// were active and the network's cumulative exit-egress byte counter at ts.
// bytesTotal is cumulative (sum of every exit node's latest bytes_total), the
// same shape as node_traffic.bytes_total — per-window deltas are computed at
// query time in usageStatsRange.
func (d *DB) insertUsageSnapshot(ts int64, activeUsers int, bytesTotal int64) error {
	_, err := d.db.Exec(
		`INSERT INTO network_usage_stats(ts, active_users, bytes_total) VALUES(?,?,?)
		 ON CONFLICT(ts) DO UPDATE SET active_users=excluded.active_users, bytes_total=excluded.bytes_total`,
		ts, activeUsers, bytesTotal)
	return err
}

// usageBucket is one point in the users/traffic-per-user history.
type usageBucket struct {
	Ts              int64 `json:"ts"`
	ActiveUsers     int   `json:"active_users"`
	BytesPerUser    int64 `json:"bytes_per_user"`    // bytes transferred since the previous sample, divided by active_users
	BytesThisWindow int64 `json:"bytes_this_window"` // raw bytes transferred since the previous sample
}

// usageStatsRange returns the users-online / traffic-per-user history since
// the given time. Each returned point is the delta between two consecutive
// snapshots (there is one global snapshot per usageSampleInterval, not a
// per-node table, so no further bucketing is needed here).
func (d *DB) usageStatsRange(since time.Time) ([]usageBucket, error) {
	rows, err := d.db.Query(`
		SELECT ts, active_users, bytes_total FROM network_usage_stats
		WHERE ts >= ?
		ORDER BY ts ASC`,
		since.Add(-usageSampleInterval).Unix()) // one extra sample before the window so the first delta is real
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type raw struct {
		ts          int64
		activeUsers int
		bytesTotal  int64
	}
	var samples []raw
	for rows.Next() {
		var s raw
		if err := rows.Scan(&s.ts, &s.activeUsers, &s.bytesTotal); err != nil {
			return nil, err
		}
		samples = append(samples, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	cutoff := since.Unix()
	var out []usageBucket
	for i := 1; i < len(samples); i++ {
		if samples[i].ts < cutoff {
			continue
		}
		delta := samples[i].bytesTotal - samples[i-1].bytesTotal
		if delta < 0 {
			delta = 0 // counter reset (an exit node restarted) within this window
		}
		perUser := int64(0)
		if samples[i].activeUsers > 0 {
			perUser = delta / int64(samples[i].activeUsers)
		}
		out = append(out, usageBucket{
			Ts:              samples[i].ts,
			ActiveUsers:     samples[i].activeUsers,
			BytesThisWindow: delta,
			BytesPerUser:    perUser,
		})
	}
	return out, nil
}

// usageSnapshot is one raw row of network_usage_stats — used for archival.
type usageSnapshot struct {
	Ts          int64 `json:"ts"`
	ActiveUsers int   `json:"active_users"`
	BytesTotal  int64 `json:"bytes_total"`
}

// usageStatsOlderThan returns raw snapshots older than cutoff, oldest first —
// the batch about to be archived off-disk.
func (d *DB) usageStatsOlderThan(cutoff int64) ([]usageSnapshot, error) {
	rows, err := d.db.Query(`
		SELECT ts, active_users, bytes_total FROM network_usage_stats
		WHERE ts < ? ORDER BY ts ASC`, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []usageSnapshot
	for rows.Next() {
		var s usageSnapshot
		if err := rows.Scan(&s.Ts, &s.ActiveUsers, &s.BytesTotal); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// deleteUsageStatsOlderThan removes archived snapshots from the live table.
func (d *DB) deleteUsageStatsOlderThan(cutoff int64) error {
	_, err := d.db.Exec(`DELETE FROM network_usage_stats WHERE ts<?`, cutoff)
	return err
}

// startUsageSampler runs a snapshot every usageSampleInterval, feeding the
// network stats tab's "users online" / "traffic per user" graphs.
//
// Runs on every arbiter instance -- this was written assuming a single
// arbiter process (see the "one global snapshot per usageSampleInterval"
// comment on usageStatsRange below), an assumption the 2-node LB cluster
// broke: both nodes ran this goroutine independently and each inserted its
// own row a few seconds apart, doubling the point density and making
// bytes_per_user's delta-since-previous-sample math operate over an
// effective ~15s gap instead of the assumed 10 minutes -- confirmed live
// via paired rows 15s apart at matching values. Fixed by truncating ts to
// the usageSampleInterval boundary (aligned to the Unix epoch, so both
// nodes land on the identical boundary regardless of when each process
// started) before the insert, so the existing ON CONFLICT(ts) DO UPDATE
// naturally collapses both nodes' samples for the same window into one row
// instead of needing real leader election.
func (h *handler) startUsageSampler() {
	sample := func() {
		activeUsers, err := h.db.CountLiveActiveUsers() // same definition as the dashboard's "Active users" card
		if err != nil {
			logWarnf("usage-sampler: count active users: %v", err)
			return
		}
		bytesTotal := h.db.networkBytesTotal("exit") // user-facing egress traffic passes through exit nodes
		bucketTs := time.Now().Truncate(usageSampleInterval).Unix()
		if err := h.db.insertUsageSnapshot(bucketTs, activeUsers, bytesTotal); err != nil {
			logWarnf("usage-sampler: insert: %v", err)
		}
	}
	go func() {
		sample()
		t := time.NewTicker(usageSampleInterval)
		defer t.Stop()
		for range t.C {
			sample()
		}
	}()
}
