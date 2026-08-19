// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// This exit's own periodic probe against bananameter.net -- the "last hop"
// leg of the tunnel path, exactly like any real user's traffic reaching its
// target (a direct dial, not a bypass -- see TODO.md "BananaMeter-based
// tunnel diagnostics"). Compared against control's own control->exit->here
// probe and the client's full end-to-end probe, this localizes whether a
// slowdown is this exit's own egress/internet path specifically.
const (
	bananameterBaseURL    = "https://bananameter.net"
	bananameterPingPath   = "/measure_ping.dat"
	bananameterSmallPath  = "/measure_small.dat"
	bananameterProbeEvery = 10 * time.Minute
)

// bananameterProber owns this exit's periodic direct probe.
type bananameterProber struct {
	arbiterURL string
	nodeToken  string
	bmNodeID   string
	bmNodeKey  string
	client     *http.Client
}

func newBananameterProber(arbiterURL, nodeToken, bmNodeID, bmNodeKey string) *bananameterProber {
	return &bananameterProber{
		arbiterURL: arbiterURL,
		nodeToken:  nodeToken,
		bmNodeID:   bmNodeID,
		bmNodeKey:  bmNodeKey,
		client:     &http.Client{Timeout: 30 * time.Second},
	}
}

// Start launches the background probe loop. No-op (logs and returns) if the
// shared BananaMeter credentials aren't configured.
func (p *bananameterProber) Start() {
	if p.bmNodeID == "" || p.bmNodeKey == "" {
		logWarnf("bananameter: node id/key not configured, probe disabled")
		return
	}
	go func() {
		time.Sleep(30 * time.Second) // let the exit finish startup first
		p.safeRunOnce()
		t := time.NewTicker(bananameterProbeEvery)
		defer t.Stop()
		for range t.C {
			p.safeRunOnce()
		}
	}()
}

// safeRunOnce isolates this diagnostic feature from the rest of the process:
// an unrecovered panic in any goroutine kills the entire Go process, so a bug
// here must never be allowed to take down real tunnel traffic. Recovering
// per-tick (not just around the whole loop) means one bad iteration doesn't
// even kill future probes, only itself.
func (p *bananameterProber) safeRunOnce() {
	defer func() {
		if r := recover(); r != nil {
			logWarnf("bananameter: probe panic recovered: %v", r)
		}
	}()
	p.runOnce()
}

func (p *bananameterProber) fetchTimed(path string) (dur time.Duration, n int64, err error) {
	start := time.Now()
	resp, err := p.client.Get(bananameterBaseURL + path)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()
	n, err = io.Copy(io.Discard, resp.Body)
	if err != nil {
		return 0, 0, err
	}
	return time.Since(start), n, nil
}

func (p *bananameterProber) runOnce() {
	pingDur, _, err := p.fetchTimed(bananameterPingPath)
	if err != nil {
		logWarnf("bananameter: ping probe failed: %v", err)
		return
	}
	pingMs := float64(pingDur.Microseconds()) / 1000.0

	throughputDur, n, err := p.fetchTimed(bananameterSmallPath)
	if err != nil {
		logWarnf("bananameter: throughput probe failed: %v", err)
		return
	}
	durSec := throughputDur.Seconds()
	var bps float64
	if durSec > 0 {
		bps = float64(n*8) / durSec
	}

	logDebugf("bananameter: probe ping=%.1fms throughput=%.0fbps (%d bytes in %.3fs)", pingMs, bps, n, durSec)

	p.submitToBananameter(durSec, n, pingMs, bps)
	p.reportToArbiter("", durSec, n, pingMs, bps)
}

// submitToBananameter records this result in BananaMeter's own fleet DB
// under the one shared node_id every TunnelCat node/client uses -- see
// TODO.md: BananaMeter isn't designed for thousands of self-registering
// identities, so real per-node attribution lives only in the arbiter's own
// report (reportToArbiter), never here.
func (p *bananameterProber) submitToBananameter(durSec float64, payloadBytes int64, pingMs, bps float64) {
	body, _ := json.Marshal(map[string]interface{}{
		".command":          "bananameter:submitResult",
		"node_id":           p.bmNodeID,
		"key":               p.bmNodeKey,
		"test_type":         "exit-direct",
		"duration_seconds":  durSec,
		"payload_bytes":     payloadBytes,
		"average_speed_bps": bps,
		"ping_avg_ms":       pingMs,
	})
	resp, err := p.client.Post(bananameterBaseURL+"/api/", "application/json", bytes.NewReader(body))
	if err != nil {
		logWarnf("bananameter: submitResult: %v", err)
		return
	}
	resp.Body.Close()
}

type bananameterReportPayload struct {
	ViaExit         string  `json:"via_exit"`
	Ts              int64   `json:"ts"`
	DurationSeconds float64 `json:"duration_seconds"`
	PayloadBytes    int64   `json:"payload_bytes"`
	PingMs          float64 `json:"ping_ms"`
	ThroughputBps   float64 `json:"throughput_bps"`
}

// reportToArbiter sends the real, attributable copy of this result to the
// TunnelCat arbiter. viaExit is empty for an exit's own direct probe; control
// fills it in for its own control->exit probe (see snc-control/bananameter_probe.go).
func (p *bananameterProber) reportToArbiter(viaExit string, durSec float64, payloadBytes int64, pingMs, bps float64) {
	payload := bananameterReportPayload{
		ViaExit:         viaExit,
		Ts:              time.Now().Unix(),
		DurationSeconds: durSec,
		PayloadBytes:    payloadBytes,
		PingMs:          pingMs,
		ThroughputBps:   bps,
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, p.arbiterURL+"/api/node/bananameter-result", bytes.NewReader(body))
	if err != nil {
		logWarnf("bananameter: build arbiter report: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Node-Token", p.nodeToken)
	resp, err := p.client.Do(req)
	if err != nil {
		logWarnf("bananameter: report to arbiter: %v", err)
		return
	}
	resp.Body.Close()
}
