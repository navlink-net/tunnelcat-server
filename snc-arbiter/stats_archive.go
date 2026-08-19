// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const (
	remoteStatsBase = "/mnt/remote/snc/stats"
	statsRetention  = 30 * 24 * time.Hour
)

// archiveOldNodeStats moves node_traffic rows older than statsRetention to
// gzip'd JSONL files on the remote SSHFS mount (one file per node per
// calendar month, following the remoteLogBase convention in log_store.go),
// then deletes them from the DB. This keeps the SQLite table bounded to
// ~30 days of full-resolution samples while preserving history indefinitely
// off-disk for later inspection.
func (h *handler) archiveOldNodeStats() {
	cutoff := time.Now().Add(-statsRetention).Unix()
	nodeIDs, err := h.db.nodeIDsWithStatsOlderThan(cutoff)
	if err != nil {
		logWarnf("stats-archive: list nodes: %v", err)
		return
	}
	for _, nodeID := range nodeIDs {
		samples, err := h.db.nodeStatsOlderThan(nodeID, cutoff)
		if err != nil {
			logWarnf("stats-archive: node=%d read: %v", nodeID, err)
			continue
		}
		if len(samples) == 0 {
			continue
		}
		if err := appendStatsArchive(nodeID, samples); err != nil {
			logWarnf("stats-archive: node=%d write: %v", nodeID, err)
			continue // don't delete rows we failed to archive
		}
		if err := h.db.deleteNodeStatsOlderThan(nodeID, cutoff); err != nil {
			logWarnf("stats-archive: node=%d prune: %v", nodeID, err)
			continue
		}
		logInfof("stats-archive: node=%d archived %d samples older than %s", nodeID, len(samples), statsRetention)
	}
}

// appendStatsArchive groups samples by calendar month (UTC) and appends each
// group as gzip'd JSONL to <remoteStatsBase>/<nodeID>/<YYYY-MM>.jsonl.gz.
func appendStatsArchive(nodeID int64, samples []nodeStatSample) error {
	byMonth := map[string][]nodeStatSample{}
	for _, s := range samples {
		month := time.Unix(s.Ts, 0).UTC().Format("2006-01")
		byMonth[month] = append(byMonth[month], s)
	}
	dir := filepath.Join(remoteStatsBase, fmt.Sprintf("%d", nodeID))
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	for month, group := range byMonth {
		path := filepath.Join(dir, month+".jsonl.gz")
		if err := appendGzipJSONL(path, group); err != nil {
			return err
		}
	}
	return nil
}

// archiveOldUsageStats moves network_usage_stats rows older than
// statsRetention to <remoteStatsBase>/network/<YYYY-MM>.jsonl.gz, then
// deletes them from the DB — same policy as archiveOldNodeStats, applied to
// the (much smaller) network-wide usage snapshot table.
func (h *handler) archiveOldUsageStats() {
	cutoff := time.Now().Add(-statsRetention).Unix()
	samples, err := h.db.usageStatsOlderThan(cutoff)
	if err != nil {
		logWarnf("usage-archive: read: %v", err)
		return
	}
	if len(samples) == 0 {
		return
	}
	byMonth := map[string][]usageSnapshot{}
	for _, s := range samples {
		month := time.Unix(s.Ts, 0).UTC().Format("2006-01")
		byMonth[month] = append(byMonth[month], s)
	}
	dir := filepath.Join(remoteStatsBase, "network")
	if err := os.MkdirAll(dir, 0755); err != nil {
		logWarnf("usage-archive: mkdir: %v", err)
		return
	}
	for month, group := range byMonth {
		path := filepath.Join(dir, month+".jsonl.gz")
		if err := appendGzipJSONL(path, group); err != nil {
			logWarnf("usage-archive: write %s: %v", path, err)
			return // don't delete rows we failed to archive
		}
	}
	if err := h.db.deleteUsageStatsOlderThan(cutoff); err != nil {
		logWarnf("usage-archive: prune: %v", err)
		return
	}
	logInfof("usage-archive: archived %d samples older than %s", len(samples), statsRetention)
}

// archiveOldConnStats moves client_conn_stats rows older than statsRetention
// to <remoteStatsBase>/conn-stats/<YYYY-MM>.jsonl.gz, then deletes them from
// the DB -- same policy as archiveOldUsageStats, applied to the flat
// (not per-node) client-reported connection-stats table.
func (h *handler) archiveOldConnStats() {
	cutoff := time.Now().Add(-statsRetention).Unix()
	samples, err := h.db.connStatsOlderThan(cutoff)
	if err != nil {
		logWarnf("conn-stats-archive: read: %v", err)
		return
	}
	if len(samples) == 0 {
		return
	}
	byMonth := map[string][]connStatsSample{}
	for _, s := range samples {
		month := time.Unix(s.Ts, 0).UTC().Format("2006-01")
		byMonth[month] = append(byMonth[month], s)
	}
	dir := filepath.Join(remoteStatsBase, "conn-stats")
	if err := os.MkdirAll(dir, 0755); err != nil {
		logWarnf("conn-stats-archive: mkdir: %v", err)
		return
	}
	for month, group := range byMonth {
		path := filepath.Join(dir, month+".jsonl.gz")
		if err := appendGzipJSONL(path, group); err != nil {
			logWarnf("conn-stats-archive: write %s: %v", path, err)
			return // don't delete rows we failed to archive
		}
	}
	if err := h.db.deleteConnStatsOlderThan(cutoff); err != nil {
		logWarnf("conn-stats-archive: prune: %v", err)
		return
	}
	logInfof("conn-stats-archive: archived %d samples older than %s", len(samples), statsRetention)
}

// archiveOldRejectedSessions moves exit_rejected_sessions rows older than
// statsRetention to <remoteStatsBase>/rejected-sessions/<YYYY-MM>.jsonl.gz,
// then deletes them from the DB -- same policy as archiveOldConnStats.
func (h *handler) archiveOldRejectedSessions() {
	cutoff := time.Now().Add(-statsRetention).Unix()
	samples, err := h.db.rejectedSessionsOlderThan(cutoff)
	if err != nil {
		logWarnf("rejected-sessions-archive: read: %v", err)
		return
	}
	if len(samples) == 0 {
		return
	}
	byMonth := map[string][]rejectedSessionsSample{}
	for _, s := range samples {
		month := time.Unix(s.Ts, 0).UTC().Format("2006-01")
		byMonth[month] = append(byMonth[month], s)
	}
	dir := filepath.Join(remoteStatsBase, "rejected-sessions")
	if err := os.MkdirAll(dir, 0755); err != nil {
		logWarnf("rejected-sessions-archive: mkdir: %v", err)
		return
	}
	for month, group := range byMonth {
		path := filepath.Join(dir, month+".jsonl.gz")
		if err := appendGzipJSONL(path, group); err != nil {
			logWarnf("rejected-sessions-archive: write %s: %v", path, err)
			return // don't delete rows we failed to archive
		}
	}
	if err := h.db.deleteRejectedSessionsOlderThan(cutoff); err != nil {
		logWarnf("rejected-sessions-archive: prune: %v", err)
		return
	}
	logInfof("rejected-sessions-archive: archived %d samples older than %s", len(samples), statsRetention)
}

// appendGzipJSONL decompresses any existing file content, appends new JSONL
// lines, and rewrites the file (gzip streams cannot be appended to directly).
// Archive files roll monthly, so this stays bounded to one month of samples.
func appendGzipJSONL[T any](path string, samples []T) error {
	var body bytes.Buffer
	if existing, err := os.ReadFile(path); err == nil {
		if gr, err := gzip.NewReader(bytes.NewReader(existing)); err == nil {
			io.Copy(&body, gr) //nolint:errcheck
			gr.Close()
		}
	}
	for _, s := range samples {
		line, err := json.Marshal(s)
		if err != nil {
			continue
		}
		body.Write(line)
		body.WriteByte('\n')
	}

	var out bytes.Buffer
	gw := gzip.NewWriter(&out)
	if _, err := gw.Write(body.Bytes()); err != nil {
		gw.Close()
		return err
	}
	if err := gw.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, out.Bytes(), 0644)
}

// startStatsArchiver runs the archival passes once a day, plus once at
// startup so a restart doesn't wait a full day before the first archival pass.
func (h *handler) startStatsArchiver() {
	go func() {
		h.archiveOldNodeStats()
		h.archiveOldUsageStats()
		h.archiveOldConnStats()
		h.archiveOldRejectedSessions()
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for range t.C {
			h.archiveOldNodeStats()
			h.archiveOldUsageStats()
			h.archiveOldConnStats()
			h.archiveOldRejectedSessions()
		}
	}()
}
