// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"time"
)

const (
	connStatsUploadArbiterURL = "https://navlink.net"
	connStatsUploadPath       = "/api/conn-stats/client-upload"
)

// Auth uses DefaultClientTelemetryKey, the one shared key across every
// client-facing telemetry endpoint (see client_telemetry_key.go).

// ConnStatsUploader periodically snapshots a ConnStatsCollector and POSTs it
// to the arbiter over the client's own live tunnel dialer -- same channel
// shape, cadence, and rationale as LogUploader (see that type's doc
// comment): never a bypass, indistinguishable from the user's own tunneled
// traffic.
type ConnStatsUploader struct {
	collector *ConnStatsCollector
	pool      *DialerPool
	router    *Router
	nodeID    string
	nodeType  string
	username  string
	stop      chan struct{}
}

// NewConnStatsUploader creates an uploader for this device/session.
// pool/router are the same long-lived objects the client already
// constructed at startup (the ones ConnStatsCollector.Snapshot reads from);
// username is the account identity from the user's key (KeyData.Username),
// same self-reported field bananameter's client payload already uses.
func NewConnStatsUploader(collector *ConnStatsCollector, pool *DialerPool, router *Router, nodeID, nodeType, username string) *ConnStatsUploader {
	return &ConnStatsUploader{
		collector: collector,
		pool:      pool,
		router:    router,
		nodeID:    nodeID,
		nodeType:  nodeType,
		username:  username,
		stop:      make(chan struct{}),
	}
}

// Start launches the background upload goroutine, same tick interval as
// LogUploader (logUploadInterval, 5 minutes) so the two channels stay in
// lockstep for anyone correlating them. Non-blocking.
//
// pickDialer/wildcatActive have the exact same contract as LogUploader.Start.
func (cu *ConnStatsUploader) Start(pickDialer func() *TunnelDialer, wildcatActive func() bool) {
	go func() {
		t := time.NewTicker(logUploadInterval)
		defer t.Stop()
		for {
			select {
			case <-cu.stop:
				return
			case <-t.C:
				if wildcatActive != nil && wildcatActive() {
					Log.Printf("conn-stats-upload: skipping tick, WildCat active")
					continue
				}
				dialer := pickDialer()
				if dialer == nil {
					Log.Printf("conn-stats-upload: skipping tick, not connected")
					continue
				}
				cu.upload(dialer)
			}
		}
	}()
}

// Stop shuts down the upload goroutine.
func (cu *ConnStatsUploader) Stop() { close(cu.stop) }

// UploadOnce performs a single upload synchronously against the given
// dialer. Useful for testing.
func (cu *ConnStatsUploader) UploadOnce(dialer *TunnelDialer) { cu.upload(dialer) }

func (cu *ConnStatsUploader) upload(dialer *TunnelDialer) {
	snap := cu.collector.Snapshot(cu.pool, cu.router)

	body := struct {
		Username              string  `json:"username"`
		ClientVersion         string  `json:"client_version"`
		Ts                    int64   `json:"ts"`
		PoolTCP               int     `json:"pool_tcp"`
		PoolUDP               int     `json:"pool_udp"`
		UnreachableControls   int     `json:"unreachable_controls"`
		TotalControls         int     `json:"total_controls"`
		SecondsOnline         int64   `json:"seconds_online"`
		AvgFailRatio          float64 `json:"avg_fail_ratio"`
		ConnectsManual        int     `json:"connects_manual"`
		ConnectsAuto          int     `json:"connects_auto"`
		DisconnectsManual     int     `json:"disconnects_manual"`
		DisconnectsAuto       int     `json:"disconnects_auto"`
		FlapEvents            int     `json:"flap_events"`
		Evictions             int     `json:"evictions"`
		WildcatSessionsOK     int     `json:"wildcat_sessions_ok"`
		WildcatSessionsFailed int     `json:"wildcat_sessions_failed"`
		WildcatSecondsTotal   int64   `json:"wildcat_seconds_total"`
	}{
		Username:              cu.username,
		ClientVersion:         Version,
		Ts:                    time.Now().Unix(),
		PoolTCP:               snap.PoolTCP,
		PoolUDP:               snap.PoolUDP,
		UnreachableControls:   snap.UnreachableControls,
		TotalControls:         snap.TotalControls,
		SecondsOnline:         snap.SecondsOnline,
		AvgFailRatio:          snap.AvgFailRatio,
		ConnectsManual:        snap.ConnectsManual,
		ConnectsAuto:          snap.ConnectsAuto,
		DisconnectsManual:     snap.DisconnectsManual,
		DisconnectsAuto:       snap.DisconnectsAuto,
		FlapEvents:            snap.FlapEvents,
		Evictions:             snap.Evictions,
		WildcatSessionsOK:     snap.WildcatSessionsOK,
		WildcatSessionsFailed: snap.WildcatSessionsFailed,
		WildcatSecondsTotal:   snap.WildcatSecondsTotal,
	}

	payload, err := json.Marshal(body)
	if err != nil {
		Log.Printf("conn-stats-upload: marshal: %v", err)
		return
	}

	// Dial through the real active tunnel, same as any of the user's own
	// traffic -- never a bypass. See LogUploader.upload/BananameterProber.runOnce
	// for the same pattern and rationale.
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
				return dialer.Dial(addr)
			},
		},
	}

	req, err := http.NewRequest(http.MethodPost, connStatsUploadArbiterURL+connStatsUploadPath, bytes.NewReader(payload))
	if err != nil {
		Log.Printf("conn-stats-upload: build request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+DefaultClientTelemetryKey)
	req.Header.Set("X-Node-ID", cu.nodeID)
	req.Header.Set("X-Node-Type", cu.nodeType)

	resp, err := client.Do(req)
	if err != nil {
		Log.Printf("conn-stats-upload: post: %v", err)
		return
	}
	resp.Body.Close()
	Log.Printf("conn-stats-upload: sent, status=%d", resp.StatusCode)
}
