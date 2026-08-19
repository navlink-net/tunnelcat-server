// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import "time"

const bananameterSchemaSQL = `
-- Results from the periodic BananaMeter probe (client/control/exit each run
-- their own leg of the real tunnel path against bananameter.net -- see
-- TODO.md "BananaMeter-based tunnel diagnostics"). This table is the
-- TunnelCat-side system of record with real identity attribution; the
-- BananaMeter service itself only ever sees one shared node_id for all
-- three source types (it isn't designed for thousands of self-registering
-- client devices), so it is never the source of truth for "which node".
CREATE TABLE IF NOT EXISTS bananameter_results (
	id               INTEGER PRIMARY KEY AUTOINCREMENT,
	source_type      TEXT    NOT NULL,           -- 'client' | 'control' | 'exit'
	source_id        TEXT    NOT NULL,           -- client_id for client; node addr for control/exit
	username         TEXT    NOT NULL DEFAULT '', -- client only
	device_id        TEXT    NOT NULL DEFAULT '', -- client only
	via_exit         TEXT    NOT NULL DEFAULT '', -- control only: which exit this specific test used
	ts               INTEGER NOT NULL,
	duration_seconds REAL    NOT NULL,
	payload_bytes    INTEGER NOT NULL,
	ping_ms          REAL    NOT NULL DEFAULT 0,
	throughput_bps   REAL    NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_bananameter_source_ts ON bananameter_results(source_type, source_id, ts);
CREATE INDEX IF NOT EXISTS idx_bananameter_ts ON bananameter_results(ts);
`

func (d *DB) initBananameterSchema() error {
	_, err := d.db.Exec(bananameterSchemaSQL)
	return err
}

// bananameterResult is one row to insert -- shared shape for all three
// source types; fields that don't apply to a given source_type are left zero.
type bananameterResult struct {
	SourceType      string  `json:"source_type"`
	SourceID        string  `json:"source_id"`
	Username        string  `json:"username"`
	DeviceID        string  `json:"device_id"`
	ViaExit         string  `json:"via_exit"`
	Ts              int64   `json:"ts"`
	DurationSeconds float64 `json:"duration_seconds"`
	PayloadBytes    int64   `json:"payload_bytes"`
	PingMs          float64 `json:"ping_ms"`
	ThroughputBps   float64 `json:"throughput_bps"`
}

func (d *DB) insertBananameterResult(r bananameterResult) error {
	_, err := d.db.Exec(`
		INSERT INTO bananameter_results
			(source_type, source_id, username, device_id, via_exit, ts, duration_seconds, payload_bytes, ping_ms, throughput_bps)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		r.SourceType, r.SourceID, r.Username, r.DeviceID, r.ViaExit, r.Ts,
		r.DurationSeconds, r.PayloadBytes, r.PingMs, r.ThroughputBps)
	return err
}

// pruneOldBananameterResults deletes rows older than the given age.
func (d *DB) pruneOldBananameterResults(ageSeconds int64) error {
	_, err := d.db.Exec(`DELETE FROM bananameter_results WHERE ts < strftime('%s','now') - ?`, ageSeconds)
	return err
}

// ── Admin read queries: system-wide, per-node, per-user history ────────────

// bananameterNetworkBucket is one 10-minute point on the system-wide chart,
// with client/control/exit each as their own series -- these three
// measure different legs of the same real tunnel path (see
// TODO.md "BananaMeter-based tunnel diagnostics"), so pivoting them into one
// row per bucket lets the chart show all three lines against the same
// timeline without three separate round trips.
//
// The three Avg* fields are pointers, not plain float64: a bucket where,
// say, control reported but client didn't (very likely right after this
// feature shipped, when almost no client has the new build yet) must come
// back as null for client, never 0 -- a real 0 average and "nobody reported
// this window" are different facts, and collapsing them together is
// literally the bug reported 2026-08-10 ("для пользователей сейчас
// тождественно нули"): the chart looked like every user always gets zero
// throughput, when the truth was just "no client samples yet in most
// windows". json:",omitempty" is not enough here (it hides real 0.0
// values too) -- nil pointers marshal to JSON null, exactly the signal
// the frontend's spanGaps needs.
type bananameterNetworkBucket struct {
	Ts               int64    `json:"ts"`
	ClientAvgMbps    *float64 `json:"client_avg_mbps"`
	ClientAvgPingMs  *float64 `json:"client_avg_ping_ms"`
	ClientSamples    int      `json:"client_samples"`
	ControlAvgMbps   *float64 `json:"control_avg_mbps"`
	ControlAvgPingMs *float64 `json:"control_avg_ping_ms"`
	ControlSamples   int      `json:"control_samples"`
	ExitAvgMbps      *float64 `json:"exit_avg_mbps"`
	ExitAvgPingMs    *float64 `json:"exit_avg_ping_ms"`
	ExitSamples      int      `json:"exit_samples"`
}

// networkBananameterHistory returns the system-wide, 10-min-bucketed history
// since the given time, one row per bucket with all three source types
// pivoted into columns. A source type with no samples in a given bucket is
// left as nil (JSON null), never 0 -- see the struct doc comment.
func (d *DB) networkBananameterHistory(since time.Time) ([]bananameterNetworkBucket, error) {
	rows, err := d.db.Query(`
		SELECT (ts/600)*600 AS bucket, source_type,
		       AVG(throughput_bps), AVG(ping_ms), COUNT(*)
		FROM bananameter_results
		WHERE ts >= ?
		GROUP BY bucket, source_type
		ORDER BY bucket ASC`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	idx := make(map[int64]int)
	var out []bananameterNetworkBucket
	for rows.Next() {
		var bucket int64
		var sourceType string
		var avgBps, avgPing float64
		var n int
		if err := rows.Scan(&bucket, &sourceType, &avgBps, &avgPing, &n); err != nil {
			return nil, err
		}
		i, ok := idx[bucket]
		if !ok {
			out = append(out, bananameterNetworkBucket{Ts: bucket})
			i = len(out) - 1
			idx[bucket] = i
		}
		mbps := avgBps / 1e6
		switch sourceType {
		case "client":
			out[i].ClientAvgMbps, out[i].ClientAvgPingMs, out[i].ClientSamples = &mbps, &avgPing, n
		case "control":
			out[i].ControlAvgMbps, out[i].ControlAvgPingMs, out[i].ControlSamples = &mbps, &avgPing, n
		case "exit":
			out[i].ExitAvgMbps, out[i].ExitAvgPingMs, out[i].ExitSamples = &mbps, &avgPing, n
		}
	}
	return out, rows.Err()
}

// bananameterNodeBucket is one 10-minute point on a single node's chart.
type bananameterNodeBucket struct {
	Ts        int64   `json:"ts"`
	AvgMbps   float64 `json:"avg_mbps"`
	AvgPingMs float64 `json:"avg_ping_ms"`
	Samples   int     `json:"samples"`
}

// nodeBananameterHistory returns one node's own bucketed history (control:
// its control->exit probes averaged across every exit it tested through in
// that window; exit: its own direct probe).
func (d *DB) nodeBananameterHistory(sourceType, sourceID string, since time.Time) ([]bananameterNodeBucket, error) {
	rows, err := d.db.Query(`
		SELECT (ts/600)*600 AS bucket, AVG(throughput_bps), AVG(ping_ms), COUNT(*)
		FROM bananameter_results
		WHERE source_type=? AND source_id=? AND ts>=?
		GROUP BY bucket
		ORDER BY bucket ASC`, sourceType, sourceID, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []bananameterNodeBucket
	for rows.Next() {
		var b bananameterNodeBucket
		var avgBps float64
		if err := rows.Scan(&b.Ts, &avgBps, &b.AvgPingMs, &b.Samples); err != nil {
			return nil, err
		}
		b.AvgMbps = avgBps / 1e6
		out = append(out, b)
	}
	return out, rows.Err()
}

// bananameterNodeSeries is one node's own bucketed series, as part of a
// per-type breakdown (see typeBananameterBreakdown).
type bananameterNodeSeries struct {
	Addr    string                   `json:"addr"`
	Buckets []bananameterNodeBucket  `json:"buckets"`
}

// bananameterTypeBreakdown is everything a "which node is at fault" chart
// needs for one node type: the bold combined average, plus each node's own
// thin line, so a drop in the average can be traced to a specific node
// instead of staying an unexplained aggregate dip (see TODO.md
// "BananaMeter-based tunnel diagnostics" -- requested 2026-08-10 after the
// system-wide chart alone couldn't answer "throughput just dropped and
// ping just spiked for controls -- which one?").
type bananameterTypeBreakdown struct {
	Overall []bananameterNodeBucket `json:"overall"`
	Nodes   []bananameterNodeSeries `json:"nodes"`
}

// typeBananameterBreakdown returns the bold "all nodes of this type"
// average plus each individual node's own series, both bucketed the same
// way, for the Controls/Egresses tab charts.
func (d *DB) typeBananameterBreakdown(sourceType string, since time.Time) (bananameterTypeBreakdown, error) {
	var result bananameterTypeBreakdown

	overallRows, err := d.db.Query(`
		SELECT (ts/600)*600 AS bucket, AVG(throughput_bps), AVG(ping_ms), COUNT(*)
		FROM bananameter_results
		WHERE source_type=? AND ts>=?
		GROUP BY bucket
		ORDER BY bucket ASC`, sourceType, since.Unix())
	if err != nil {
		return result, err
	}
	for overallRows.Next() {
		var b bananameterNodeBucket
		var avgBps float64
		if err := overallRows.Scan(&b.Ts, &avgBps, &b.AvgPingMs, &b.Samples); err != nil {
			overallRows.Close()
			return result, err
		}
		b.AvgMbps = avgBps / 1e6
		result.Overall = append(result.Overall, b)
	}
	if err := overallRows.Err(); err != nil {
		overallRows.Close()
		return result, err
	}
	overallRows.Close()

	perNodeRows, err := d.db.Query(`
		SELECT (ts/600)*600 AS bucket, source_id, AVG(throughput_bps), AVG(ping_ms), COUNT(*)
		FROM bananameter_results
		WHERE source_type=? AND ts>=?
		GROUP BY bucket, source_id
		ORDER BY source_id ASC, bucket ASC`, sourceType, since.Unix())
	if err != nil {
		return result, err
	}
	defer perNodeRows.Close()

	order := make([]string, 0)
	byAddr := make(map[string][]bananameterNodeBucket)
	for perNodeRows.Next() {
		var addr string
		var b bananameterNodeBucket
		var avgBps float64
		if err := perNodeRows.Scan(&b.Ts, &addr, &avgBps, &b.AvgPingMs, &b.Samples); err != nil {
			return result, err
		}
		b.AvgMbps = avgBps / 1e6
		if _, ok := byAddr[addr]; !ok {
			order = append(order, addr)
		}
		byAddr[addr] = append(byAddr[addr], b)
	}
	if err := perNodeRows.Err(); err != nil {
		return result, err
	}
	for _, addr := range order {
		result.Nodes = append(result.Nodes, bananameterNodeSeries{Addr: addr, Buckets: byAddr[addr]})
	}
	return result, nil
}

// bananameterPeerRow is one row of a control node's per-exit breakdown --
// only meaningful for source_type="control" (exit's own probe has no peer).
type bananameterPeerRow struct {
	PeerAddr  string  `json:"peer_addr"`
	AvgMbps   float64 `json:"avg_mbps"`
	AvgPingMs float64 `json:"avg_ping_ms"`
	Samples   int     `json:"samples"`
}

// nodeBananameterPeers returns a control node's per-exit breakdown over the
// given window, so an admin can see which specific exit is dragging down
// this control's average.
func (d *DB) nodeBananameterPeers(sourceType, sourceID string, since time.Time) ([]bananameterPeerRow, error) {
	rows, err := d.db.Query(`
		SELECT via_exit, AVG(throughput_bps), AVG(ping_ms), COUNT(*)
		FROM bananameter_results
		WHERE source_type=? AND source_id=? AND ts>=? AND via_exit != ''
		GROUP BY via_exit
		ORDER BY via_exit ASC`, sourceType, sourceID, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []bananameterPeerRow
	for rows.Next() {
		var p bananameterPeerRow
		var avgBps float64
		if err := rows.Scan(&p.PeerAddr, &avgBps, &p.AvgPingMs, &p.Samples); err != nil {
			return nil, err
		}
		p.AvgMbps = avgBps / 1e6
		out = append(out, p)
	}
	return out, rows.Err()
}

// bananameterUserDeviceBucket is one 10-minute point for one of a user's
// devices -- the frontend pivots these into one line per device_id.
type bananameterUserDeviceBucket struct {
	Ts        int64   `json:"ts"`
	DeviceID  string  `json:"device_id"`
	AvgMbps   float64 `json:"avg_mbps"`
	AvgPingMs float64 `json:"avg_ping_ms"`
	Samples   int     `json:"samples"`
}

// userBananameterHistory returns a user's own client-side probe history,
// bucketed and broken out per device_id (a user with 3 devices gets 3
// interleaved series back, one row per device per bucket that has data).
func (d *DB) userBananameterHistory(username string, since time.Time) ([]bananameterUserDeviceBucket, error) {
	rows, err := d.db.Query(`
		SELECT (ts/600)*600 AS bucket, device_id, AVG(throughput_bps), AVG(ping_ms), COUNT(*)
		FROM bananameter_results
		WHERE source_type='client' AND username=? AND ts>=?
		GROUP BY bucket, device_id
		ORDER BY bucket ASC`, username, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []bananameterUserDeviceBucket
	for rows.Next() {
		var b bananameterUserDeviceBucket
		var avgBps float64
		if err := rows.Scan(&b.Ts, &b.DeviceID, &avgBps, &b.AvgPingMs, &b.Samples); err != nil {
			return nil, err
		}
		b.AvgMbps = avgBps / 1e6
		out = append(out, b)
	}
	return out, rows.Err()
}
