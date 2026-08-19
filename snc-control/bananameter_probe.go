// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"

	"tunnel_cat/snc/core"
)

// This control's own periodic probe against bananameter.net -- always
// routed through a real exit, using the exact same authenticated tunnel
// mechanism a real client uses (never a direct control->bananameter dial,
// per explicit instruction: "Контрол всегда шлет через экзит"). Control
// logs in once as a dedicated service account ("prober@navlink.net", see
// TODO.md "BananaMeter-based tunnel diagnostics") and re-uses that session
// token across every live exit it knows about -- one probe per exit per
// cycle, not just one random exit, so a bad exit can't hide behind a good
// one in the average.
const (
	bananameterProbeEvery = 10 * time.Minute
	bananameterBaseURL    = "https://bananameter.net"
	bananameterPingPath   = "/measure_ping.dat"
	bananameterSmallPath  = "/measure_small.dat"
	bananameterAPIKey     = "01Az8nB8mB4cCV" // same public Camerlengo API key embedded in every real client
)

// controlBananameterProber owns control's periodic per-exit probe.
type controlBananameterProber struct {
	exits          *ExitRegistry
	nodeToken      string
	bmNodeID       string
	bmNodeKey      string
	proberUsername string
	proberPassword string

	// httpClient is for the BananaMeter submitResult call ONLY -- that's a
	// real external service (bananameter.net), not the arbiter, so a plain
	// untunneled client is correct there. The arbiter report in
	// reportToArbiter below must NEVER use this client directly against an
	// arbiter URL: control has no business knowing or dialing the arbiter's
	// address under any circumstances, for any purpose, ever (see the
	// 2026-08-10 audit that found and fixed exactly that violation here --
	// this comment exists because it has had to be re-explained too many
	// times). Every arbiter-bound call from control goes through
	// exitProxyURL()+nodeProxyClient(), exactly like every other node API
	// call in this codebase (see exits.go, cidr_cache.go, content_manifest.go,
	// log_uploader.go, relay_api.go, probe_sites.go).
	httpClient *http.Client
	token      string // cached SNC session token for the prober account
}

func newControlBananameterProber(exits *ExitRegistry, nodeToken, bmNodeID, bmNodeKey, proberUsername, proberPassword string) *controlBananameterProber {
	return &controlBananameterProber{
		exits:          exits,
		nodeToken:      nodeToken,
		bmNodeID:       bmNodeID,
		bmNodeKey:      bmNodeKey,
		proberUsername: proberUsername,
		proberPassword: proberPassword,
		httpClient:     &http.Client{Timeout: 30 * time.Second},
	}
}

// Start launches the background probe loop. No-op if the prober account or
// shared BananaMeter credentials aren't configured.
func (p *controlBananameterProber) Start() {
	if p.proberUsername == "" || p.proberPassword == "" {
		logWarnf("bananameter: prober account not configured, control probe disabled")
		return
	}
	if p.bmNodeID == "" || p.bmNodeKey == "" {
		logWarnf("bananameter: node id/key not configured, control probe disabled")
		return
	}
	go func() {
		time.Sleep(45 * time.Second) // let exits registry populate first
		t := time.NewTicker(bananameterProbeEvery)
		defer t.Stop()
		p.safeRunOnce()
		for range t.C {
			p.safeRunOnce()
		}
	}()
}

// safeRunOnce isolates this diagnostic feature from the rest of the process:
// an unrecovered panic in any goroutine kills the entire Go process, so a bug
// here must never be allowed to take down real relay traffic.
func (p *controlBananameterProber) safeRunOnce() {
	defer func() {
		if r := recover(); r != nil {
			logWarnf("bananameter: probe cycle panic recovered: %v", r)
		}
	}()
	p.runOnce()
}

// ensureToken logs in as the prober account if there is no cached token yet.
// The token is validated by the arbiter (shared across all exits), so one
// login is reused for every exit's dialer -- see doProbeViaExit.
func (p *controlBananameterProber) ensureToken(exitAddr string) error {
	if p.token != "" {
		return nil
	}
	auth := core.NewAuthenticator("https://"+exitAddr, bananameterAPIKey, p.proberUsername, p.proberPassword)
	if err := auth.Login(); err != nil {
		return err
	}
	p.token = auth.Token()
	return nil
}

func (p *controlBananameterProber) runOnce() {
	live := p.exits.Exits()
	if len(live) == 0 {
		logDebugf("bananameter: no live exits to probe through")
		return
	}
	if err := p.ensureToken(live[0].Addr); err != nil {
		logWarnf("bananameter: prober login failed: %v", err)
		p.token = ""
		return
	}
	for _, exit := range live {
		p.safeProbeViaExit(exit.Addr)
	}
}

// safeProbeViaExit isolates one exit's probe from the rest of the cycle: a
// panic testing one exit must not skip every exit after it in the list.
func (p *controlBananameterProber) safeProbeViaExit(exitAddr string) {
	defer func() {
		if r := recover(); r != nil {
			logWarnf("bananameter: probe via exit=%s panic recovered: %v", exitAddr, r)
		}
	}()
	p.probeViaExit(exitAddr)
}

// probeViaExit runs the ping+throughput test through one specific exit,
// using the exact same authenticated tunnel path a real client's traffic
// takes through that exit -- not a bypass.
func (p *controlBananameterProber) probeViaExit(exitAddr string) {
	auth := core.NewAuthenticatorWithToken("https://"+exitAddr, bananameterAPIKey, p.token)
	dialer := core.NewTunnelDialer(auth)

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
				return dialer.Dial(addr)
			},
		},
	}

	pingDur, _, err := fetchTimed(client, bananameterPingPath)
	if err != nil {
		logWarnf("bananameter: ping via exit=%s failed: %v", exitAddr, err)
		// A tunnel-level auth failure likely means the cached token expired;
		// force a fresh login on the next cycle rather than fail silently
		// for the rest of this run's exits too.
		p.token = ""
		return
	}
	pingMs := float64(pingDur.Microseconds()) / 1000.0

	throughputDur, n, err := fetchTimed(client, bananameterSmallPath)
	if err != nil {
		logWarnf("bananameter: throughput via exit=%s failed: %v", exitAddr, err)
		return
	}
	durSec := throughputDur.Seconds()
	var bps float64
	if durSec > 0 {
		bps = float64(n*8) / durSec
	}

	logDebugf("bananameter: probe via exit=%s ping=%.1fms throughput=%.0fbps", exitAddr, pingMs, bps)

	p.submitToBananameter(durSec, n, pingMs, bps)
	p.reportToArbiter(exitAddr, durSec, n, pingMs, bps)
}

func fetchTimed(client *http.Client, path string) (dur time.Duration, n int64, err error) {
	start := time.Now()
	resp, err := client.Get(bananameterBaseURL + path)
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

func (p *controlBananameterProber) submitToBananameter(durSec float64, payloadBytes int64, pingMs, bps float64) {
	body, _ := json.Marshal(map[string]interface{}{
		".command":          "bananameter:submitResult",
		"node_id":           p.bmNodeID,
		"key":               p.bmNodeKey,
		"test_type":         "control-via-exit",
		"duration_seconds":  durSec,
		"payload_bytes":     payloadBytes,
		"average_speed_bps": bps,
		"ping_avg_ms":       pingMs,
	})
	resp, err := p.httpClient.Post(bananameterBaseURL+"/api/", "application/json", bytes.NewReader(body))
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

// reportToArbiter sends this result to the arbiter via the SAME exit that
// was just probed -- exitProxyURL()+nodeProxyClient(), never a direct dial.
// Control must never hold or use the arbiter's address for its own outbound
// requests; the exit is the only thing control ever talks to.
func (p *controlBananameterProber) reportToArbiter(viaExit string, durSec float64, payloadBytes int64, pingMs, bps float64) {
	payload := bananameterReportPayload{
		ViaExit:         viaExit,
		Ts:              time.Now().Unix(),
		DurationSeconds: durSec,
		PayloadBytes:    payloadBytes,
		PingMs:          pingMs,
		ThroughputBps:   bps,
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, exitProxyURL(viaExit, "/api/node/bananameter-result"), bytes.NewReader(body))
	if err != nil {
		logWarnf("bananameter: build arbiter report: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Node-Token", p.nodeToken)
	resp, err := nodeProxyClient().Do(req)
	if err != nil {
		logWarnf("bananameter: report to arbiter via exit=%s: %v", viaExit, err)
		return
	}
	resp.Body.Close()
}
