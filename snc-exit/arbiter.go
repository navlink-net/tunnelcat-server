// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// fetchRegion asks the arbiter for the ISO region code of the given IP address.
// Returns "" if the arbiter has no CIDR data for that IP yet.
func (a *authClient) fetchRegion(ip string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, a.arbiterURL+"/api/geoip?ip="+ip, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Node-Token", a.nodeToken)
	resp, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("geoip: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("geoip: status %d", resp.StatusCode)
	}
	var result struct {
		Region string `json:"region"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("geoip: parse: %w", err)
	}
	return result.Region, nil
}

// fetchExitList retrieves the signed exit-node list from the arbiter and returns
// the peer entries with their regions, plus this exit's own effective region
// (selfRegion), resolved server-side by the arbiter from the caller's own
// X-Node-Token -- authoritative and RegionOverride-aware regardless of what
// this exit's own outbound-IP self-detection would find (see resolveRegionLoop:
// that detection breaks behind cloud-provider NAT, e.g. Yandex Cloud, where the
// local outbound IP is the internal NAT address, not the public one).
// The caller (this exit) is excluded from the returned peer list if its own
// address appears in it.
func (a *authClient) fetchExitList() ([]PeerEntry, string, error) {
	req, err := http.NewRequest(http.MethodGet, a.arbiterURL+"/api/exits", nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("X-Node-Token", a.nodeToken)
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("fetch exits: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("fetch exits: status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, "", fmt.Errorf("fetch exits: read: %w", err)
	}

	// SignedList wire format (advisory Regions/SelfRegion are unsigned, safe to read).
	var sl struct {
		Nodes []struct {
			Addr string `json:"addr"`
		} `json:"nodes"`
		Regions    map[string]string `json:"regions"` // addr → ISO code
		SelfRegion string            `json:"self_region"`
	}
	if err := json.Unmarshal(raw, &sl); err != nil {
		return nil, "", fmt.Errorf("fetch exits: parse: %w", err)
	}

	out := make([]PeerEntry, 0, len(sl.Nodes))
	for _, n := range sl.Nodes {
		out = append(out, PeerEntry{
			Addr:   n.Addr,
			Region: sl.Regions[n.Addr],
		})
	}
	return out, sl.SelfRegion, nil
}

// validatePeerToken asks the arbiter whether token belongs to a live approved exit node.
// Returns the peer's address on success, or an error if invalid/offline.
func (a *authClient) validatePeerToken(token string) (addr string, err error) {
	addr, nodeType, err := a.validateNodeToken(token)
	if err != nil {
		return "", err
	}
	if nodeType != "exit" {
		return "", fmt.Errorf("validate peer: not a valid exit node (type=%s)", nodeType)
	}
	return addr, nil
}

// validateNodeToken asks the arbiter whether token belongs to any live approved node.
// Returns the node's address and type. Used by wildcat relay to accept control tokens.
func (a *authClient) validateNodeToken(token string) (addr, nodeType string, err error) {
	body, _ := json.Marshal(map[string]string{"token": token})
	req, err := http.NewRequest(http.MethodPost, a.arbiterURL+"/api/node/validate", bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Node-Token", a.nodeToken)
	resp, err := a.client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("validate node: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("validate node: status %d", resp.StatusCode)
	}
	var result struct {
		Valid bool   `json:"valid"`
		Type  string `json:"type"`
		Addr  string `json:"addr"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", fmt.Errorf("validate node: parse: %w", err)
	}
	if !result.Valid {
		return "", "", fmt.Errorf("validate node: invalid or offline")
	}
	return result.Addr, result.Type, nil
}

// startArbiterHeartbeat sends periodic keepalives to the arbiter so this exit
// stays in the live list.  nodeID is an opaque label (first 8 chars of token).
// fingerprint is the SHA-256 of the server's leaf TLS cert (colon-hex), used
// by the arbiter to keep its DB in sync with cert renewals.
// probe, if non-nil, provides the whitelist capability snapshot sent with each heartbeat.
func startArbiterHeartbeat(arbiterURL, token, fingerprint string, probe *WhitelistProbe) {
	c := &http.Client{Timeout: 10 * time.Second}
	url := strings.TrimRight(arbiterURL, "/") + "/api/heartbeat"
	nodeID := token
	if len(nodeID) > 8 {
		nodeID = nodeID[:8]
	}

	var lastBytes int64
	var lastTime time.Time

	send := func() {
		now := time.Now()
		total := exitBytesTotal.Load()

		// Compute bandwidth from bytes delta since last heartbeat.
		var bwMbps float64
		if !lastTime.IsZero() {
			elapsed := now.Sub(lastTime).Seconds()
			if elapsed > 0 && total > lastBytes {
				bwMbps = float64(total-lastBytes) * 8 / elapsed / 1e6
			}
		}
		lastBytes = total
		lastTime = now

		ok := exitDataPlane.isOK()
		cpuPct, memPct, diskPct := collectSysMetrics()
		hbPayload := map[string]interface{}{
			"id":            nodeID,
			"token":         token,
			"rtt_ms":        exitDataPlane.rtt(),
			"bytes_total":   total,
			"bw_mbps":       bwMbps,
			"fingerprint":   fingerprint,
			"data_plane_ok": ok,
			"cpu_pct":       cpuPct,
			"mem_pct":       memPct,
			"disk_pct":      diskPct,
		}
		if probe != nil {
			hbPayload["capabilities"] = probe.Capabilities()
		}
		payload, _ := json.Marshal(hbPayload)
		start := time.Now()
		resp, err := c.Post(url, "application/json", strings.NewReader(string(payload)))
		if err != nil {
			logWarnf("arbiter heartbeat: POST failed: %v", err)
			return
		}
		resp.Body.Close()
		dur := time.Since(start).Round(time.Millisecond)
		if resp.StatusCode != http.StatusOK {
			logWarnf("arbiter heartbeat: status=%d dur=%s", resp.StatusCode, dur)
			return
		}
		logDebugf("arbiter heartbeat: ok token=%.8s… bw=%.1fMbps dur=%s", nodeID, bwMbps, dur)
	}

	send() // immediate on startup
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			send()
		}
	}()
}
