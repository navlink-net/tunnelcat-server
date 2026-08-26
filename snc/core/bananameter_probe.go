// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"
)

// BananameterProber runs this client's leg of the tunnel-diagnostics probe
// (see TODO.md "BananaMeter-based tunnel diagnostics"): every 10 minutes,
// while connected and not in WildCat mode, fetch a small payload from
// bananameter.net through the *real* active tunnel dialer -- the same path
// any of the user's own traffic takes, never a bypass -- and report the
// result both to BananaMeter's shared fleet account and to the TunnelCat
// arbiter with this device's real identity. WildCat is excluded by the
// caller (see Start's wildcatActive param): that transport is a disguised,
// bandwidth-constrained fallback, not the thing we want a synthetic
// background test competing with.
const (
	bananameterProbeEvery = 10 * time.Minute
	bananameterBaseURL    = "https://bananameter.net"
	bananameterPingPath   = "/measure_ping.dat"
	bananameterSmallPath  = "/measure_small.dat"
	bananameterArbiterURL = "https://navlink.net"
	bananameterReportPath = "/api/bananameter/client-result"
	bananameterSubmitPath = "/api/"
)

// BananameterCreds are the shared, build-embedded credentials every
// TunnelCat node/client uses to submit to BananaMeter's one fleet-wide
// account (it isn't designed for thousands of self-registering client
// identities -- real per-device attribution lives only in the arbiter
// report, see reportToArbiter) and to authenticate this client's own report
// to the TunnelCat arbiter.
type BananameterCreds struct {
	NodeID           string // shared BananaMeter node_id
	NodeKey          string // shared BananaMeter node_key
	ArbiterClientKey string // shared bearer key for /api/bananameter/client-result
}

// Default*BananameterCreds are the fleet-shared values every client build
// embeds directly -- same threat model as the Camerlengo API key already
// baked into every client (extractable from the binary, not meant to be a
// real secret boundary; per-device identity is what actually matters and
// that's carried separately in the arbiter report, not in these).
const (
	DefaultBananameterNodeID  = "c91441829ac7dfcfeed3613406aeeed3"
	DefaultBananameterNodeKey = "dJqWBk05HlAT-2sUaiziQugmSGDepOmQ6T3yHqdIEIY"
)

// DefaultBananameterCreds returns the fleet-shared BananaMeter credentials
// every platform's main entry point should pass to NewBananameterProber.
// ArbiterClientKey uses DefaultClientTelemetryKey, the one shared key across
// every client-facing telemetry endpoint (see client_telemetry_key.go).
func DefaultBananameterCreds() BananameterCreds {
	return BananameterCreds{
		NodeID:           DefaultBananameterNodeID,
		NodeKey:          DefaultBananameterNodeKey,
		ArbiterClientKey: DefaultClientTelemetryKey,
	}
}

// BananameterProber owns the periodic probe loop for one running client.
type BananameterProber struct {
	creds    BananameterCreds
	clientID string
	deviceID string
	username string
	stop     chan struct{}
}

// NewBananameterProber creates a prober for the given device/account
// identity. clientID/deviceID/username come from the same KeyData the
// client already parsed at login -- no new identity concept.
func NewBananameterProber(creds BananameterCreds, clientID, deviceID, username string) *BananameterProber {
	return &BananameterProber{
		creds:    creds,
		clientID: clientID,
		deviceID: deviceID,
		username: username,
		stop:     make(chan struct{}),
	}
}

// Start launches the background probe loop. pickDialer returns the
// currently active TunnelDialer (e.g. pool.Pick()), or nil if not
// connected right now -- checked fresh on every tick, not cached, since
// connection state changes over the life of this prober. wildcatActive
// reports whether WildCat transport is the active mode; when true, the
// tick is skipped entirely (see doc comment above for why).
func (b *BananameterProber) Start(pickDialer func() *TunnelDialer, wildcatActive func() bool) {
	if b.creds.NodeID == "" || b.creds.NodeKey == "" || b.creds.ArbiterClientKey == "" {
		Log.Printf("bananameter: credentials not configured, client probe disabled")
		return
	}
	go func() {
		t := time.NewTicker(bananameterProbeEvery)
		defer t.Stop()
		for {
			select {
			case <-b.stop:
				return
			case <-t.C:
				if wildcatActive != nil && wildcatActive() {
					Log.Printf("bananameter: skipping probe, WildCat active")
					continue
				}
				dialer := pickDialer()
				if dialer == nil {
					Log.Printf("bananameter: skipping probe, not connected")
					continue
				}
				b.safeRunOnce(dialer)
			}
		}
	}()
}

// Stop ends the probe loop.
func (b *BananameterProber) Stop() { close(b.stop) }

// safeRunOnce isolates this diagnostic feature from the rest of the app: an
// unrecovered panic in any goroutine kills the entire process, including the
// live tunnel -- a bug in this background probe must never be able to do
// that. Recovering per-tick means one bad iteration doesn't even kill future
// probes, only itself.
func (b *BananameterProber) safeRunOnce(dialer *TunnelDialer) {
	defer func() {
		if r := recover(); r != nil {
			Log.Printf("bananameter: probe panic recovered: %v", r)
		}
	}()
	b.runOnce(dialer)
}

func (b *BananameterProber) runOnce(dialer *TunnelDialer) {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
				return dialer.Dial(addr)
			},
		},
	}

	pingDur, _, err := bananameterFetchTimed(client, bananameterPingPath)
	if err != nil {
		Log.Printf("bananameter: ping probe failed: %v", err)
		return
	}
	pingMs := float64(pingDur.Microseconds()) / 1000.0

	throughputDur, n, err := bananameterFetchTimed(client, bananameterSmallPath)
	if err != nil {
		Log.Printf("bananameter: throughput probe failed: %v", err)
		return
	}
	durSec := throughputDur.Seconds()
	var bps float64
	if durSec > 0 {
		bps = float64(n*8) / durSec
	}

	Log.Printf("bananameter: probe ping=%.1fms throughput=%.0fbps (%d bytes in %.3fs)", pingMs, bps, n, durSec)

	// Both follow-up calls reuse the same tunneled client as the test
	// itself -- a direct/bypass connection here would defeat the whole
	// "no bypass, only real tunnel path" premise, and for submitResult it
	// would also be pointless: it's the same host we just tested.
	b.submitToBananameter(client, durSec, n, pingMs, bps)
	b.reportToArbiter(client, durSec, n, pingMs, bps)
}

func bananameterFetchTimed(client *http.Client, path string) (dur time.Duration, n int64, err error) {
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

func (b *BananameterProber) submitToBananameter(client *http.Client, durSec float64, payloadBytes int64, pingMs, bps float64) {
	body, _ := json.Marshal(map[string]interface{}{
		".command":          "bananameter:submitResult",
		"node_id":           b.creds.NodeID,
		"key":               b.creds.NodeKey,
		"test_type":         "client-e2e",
		"duration_seconds":  durSec,
		"payload_bytes":     payloadBytes,
		"average_speed_bps": bps,
		"ping_avg_ms":       pingMs,
	})
	// Deliberately posted through the same tunneled path as the test itself
	// (bananameter.net is already the request's own host) rather than a
	// second bypassing connection -- consistent with "we only care about
	// tunnel performance, no bypass".
	resp, err := client.Post(bananameterBaseURL+bananameterSubmitPath, "application/json", bytes.NewReader(body))
	if err != nil {
		Log.Printf("bananameter: submitResult: %v", err)
		return
	}
	resp.Body.Close()
}

type clientBananameterReportPayload struct {
	ClientID        string  `json:"client_id"`
	DeviceID        string  `json:"device_id"`
	Username        string  `json:"username"`
	Ts              int64   `json:"ts"`
	DurationSeconds float64 `json:"duration_seconds"`
	PayloadBytes    int64   `json:"payload_bytes"`
	PingMs          float64 `json:"ping_ms"`
	ThroughputBps   float64 `json:"throughput_bps"`
}

// reportToArbiter sends the real, attributable copy of this result to the
// TunnelCat arbiter -- unlike control's own probe, no via-exit tag is
// attached here (the client isn't supposed to know which exit it used in
// the first place; see TODO.md: "для клиентских никто ничего не
// дописывает"). Reached as a normal tunneled HTTPS call to navlink.net,
// same as any other client-initiated API call -- no special frame type.
func (b *BananameterProber) reportToArbiter(client *http.Client, durSec float64, payloadBytes int64, pingMs, bps float64) {
	payload := clientBananameterReportPayload{
		ClientID:        b.clientID,
		DeviceID:        b.deviceID,
		Username:        b.username,
		Ts:              time.Now().Unix(),
		DurationSeconds: durSec,
		PayloadBytes:    payloadBytes,
		PingMs:          pingMs,
		ThroughputBps:   bps,
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, bananameterArbiterURL+bananameterReportPath, bytes.NewReader(body))
	if err != nil {
		Log.Printf("bananameter: build arbiter report: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+b.creds.ArbiterClientKey)
	resp, err := client.Do(req)
	if err != nil {
		Log.Printf("bananameter: report to arbiter: %v", err)
		return
	}
	resp.Body.Close()
}
