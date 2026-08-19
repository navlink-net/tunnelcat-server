// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

const (
	healthProbeInterval = 10 * time.Second
	healthProbeTimeout  = 5 * time.Second // enough for TLS handshake + HTTP round-trip
	deadAfterFails      = 2               // consecutive failures before marking dead
	aliveAfterSuccesses = 2               // consecutive successes before restoring to rotation
)

const (
	trafficRTTAlpha      = 0.15 // EMA smoothing factor for traffic dial RTT
	trafficRTTMinSamples = 5    // samples before traffic RTT is published
)

// exitHealth tracks the health state of a single exit node.
type exitHealth struct {
	alive          bool
	consecutive    int     // >0 = consecutive ok, <0 = consecutive failures
	rttMs          float64 // last HTTP probe RTT (ms)
	trafficRttMs   float64 // EMA of TCP dial RTT from real proxied connections (ms)
	trafficSamples int     // number of traffic RTT samples recorded
}

// StartHealthChecker launches a background goroutine that probes every exit
// via HTTP ping every healthProbeInterval and updates exit health state.
// sites may be nil, in which case data-plane probing is skipped.
// Call once after the ExitRegistry is created and started.
func (r *ExitRegistry) StartHealthChecker(sites *ProbeSiteRegistry) {
	r.probeSites = sites
	r.healthMu.Lock()
	r.health = make(map[string]*exitHealth)
	r.healthMu.Unlock()
	go r.healthLoop()
}

const allDeadRestartAfter = 10 * time.Minute

func (r *ExitRegistry) healthLoop() {
	ticker := time.NewTicker(healthProbeInterval)
	defer ticker.Stop()
	var allDeadSince time.Time
	for range ticker.C {
		r.probeAll()
		exits := r.Exits()
		if len(exits) == 0 || r.anyAlive() {
			allDeadSince = time.Time{}
			continue
		}
		if allDeadSince.IsZero() {
			allDeadSince = time.Now()
			logWarnf("exit-health: all %d exits dead — will restart in %s if not recovered", len(exits), allDeadRestartAfter)
		} else if d := time.Since(allDeadSince); d >= allDeadRestartAfter {
			logWarnf("exit-health: all exits dead for %s — restarting service", d.Round(time.Second))
			os.Exit(1)
		}
	}
}

// anyAlive reports whether at least one exit is considered alive.
// Returns true if the health map is empty (not yet probed — benefit of the doubt).
func (r *ExitRegistry) anyAlive() bool {
	r.healthMu.RLock()
	defer r.healthMu.RUnlock()
	if len(r.health) == 0 {
		return true
	}
	for _, h := range r.health {
		if h.alive {
			return true
		}
	}
	return false
}

func (r *ExitRegistry) probeAll() {
	exits := r.Exits()
	var wg sync.WaitGroup
	for _, e := range exits {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			r.probeOne(addr)
		}(e.Addr)
	}
	wg.Wait()
}

// healthProbeClient is reused across probes to keep connection overhead low.
// InsecureSkipVerify is intentional — exits use LE certs bound to their IP,
// not a hostname we know at probe time.
var healthProbeClient = &http.Client{
	Timeout: healthProbeTimeout,
	Transport: &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		DisableKeepAlives:   true,                                  // each probe opens a fresh connection
		MaxIdleConnsPerHost: 0,
	},
}

// regionOf returns the region code for the given exit address from the last refresh.
func (r *ExitRegistry) regionOf(addr string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.exitRegions[addr]
}

// probeDataPlane asks the exit to HEAD-request each probe URL for its region.
// Returns nil if ≥20% of URLs succeed, an error otherwise.
// Runs without healthMu held to avoid blocking other probe goroutines during I/O.
func (r *ExitRegistry) probeDataPlane(exitAddr, region string) error {
	urls := r.probeSites.ForRegion(region)
	if len(urls) == 0 {
		return nil // no sites configured yet — skip
	}
	base := "https://" + exitDialAddr(exitAddr) + "/p/v1/probe?url="
	successes := 0
	for _, u := range urls {
		resp, err := healthProbeClient.Get(base + url.QueryEscape(u))
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				successes++
			}
		}
	}
	// 20% threshold: successes*5 >= len(urls) avoids floating-point.
	if successes*5 >= len(urls) {
		return nil
	}
	return fmt.Errorf("data-plane: %d/%d sites reachable (need ≥20%%)", successes, len(urls))
}

func (r *ExitRegistry) probeOne(addr string) {
	// HTTP ping exercises the full data path (TCP + TLS + HTTP server response).
	// A raw TCP dial would pass even when the exit is unable to process traffic
	// (e.g. goroutines blocked on log I/O).
	pingURL := fmt.Sprintf("https://%s/p/v1/ping", exitDialAddr(addr))
	start := time.Now()
	resp, err := healthProbeClient.Get(pingURL)
	rtt := time.Since(start).Seconds() * 1000
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("ping returned HTTP %d", resp.StatusCode)
		}
	}

	// Data-plane probe: if ping passed and probe sites are available, verify the
	// exit can actually reach the open internet through its outbound interface.
	// Also measure control→exit→internet RTT using the first probe URL; this
	// replaces the ping-only RTT which only covers the control→exit leg.
	if err == nil && r.probeSites != nil {
		region := r.regionOf(addr)
		if urls := r.probeSites.ForRegion(region); len(urls) > 0 {
			outboundURL := "https://" + exitDialAddr(addr) + "/p/v1/probe?url=" + url.QueryEscape(urls[0])
			outboundStart := time.Now()
			outboundResp, outboundErr := healthProbeClient.Get(outboundURL)
			if outboundErr == nil {
				outboundResp.Body.Close()
				if outboundResp.StatusCode == http.StatusOK {
					rtt = time.Since(outboundStart).Seconds() * 1000
				}
			}
		}
		err = r.probeDataPlane(addr, region)
	}

	r.healthMu.Lock()

	h, ok := r.health[addr]
	if !ok {
		h = &exitHealth{alive: true}
		r.health[addr] = h
	}

	justDied := false
	if err != nil {
		if h.consecutive > 0 {
			h.consecutive = -1
		} else {
			h.consecutive--
		}
		if h.alive && -h.consecutive >= deadAfterFails {
			h.alive = false
			justDied = true
			logWarnf("exit-health: %s marked DEAD after %d consecutive failures", addr, -h.consecutive)
		}
	} else {
		if h.consecutive < 0 {
			h.consecutive = 1
		} else {
			h.consecutive++
		}
		h.rttMs = rtt
		if !h.alive && h.consecutive >= aliveAfterSuccesses {
			h.alive = true
			logInfof("exit-health: %s restored to rotation after %d consecutive ok (rtt=%.0fms)", addr, h.consecutive, rtt)
		}
	}

	r.healthMu.Unlock()

	// Notify outside the lock so the callback can safely acquire other locks.
	if justDied && r.onDead != nil {
		r.onDead(addr)
	}
}

// isAlive reports whether addr is considered healthy.
// Returns true for exits not yet probed (benefit of the doubt).
func (r *ExitRegistry) isAlive(addr string) bool {
	r.healthMu.RLock()
	h, ok := r.health[addr]
	r.healthMu.RUnlock()
	if !ok {
		return true // not yet probed — assume alive
	}
	return h.alive
}

// RecordDialRTT records a TCP dial round-trip sample for addr (from a real
// proxied client connection).  Updates a per-exit EMA; the blended RTT from
// rttOf() will reflect this after trafficRTTMinSamples samples.
func (r *ExitRegistry) RecordDialRTT(addr string, d time.Duration) {
	ms := float64(d.Milliseconds())
	r.healthMu.Lock()
	h, ok := r.health[addr]
	if !ok {
		h = &exitHealth{alive: true}
		r.health[addr] = h
	}
	if h.trafficSamples == 0 {
		h.trafficRttMs = ms
	} else {
		h.trafficRttMs = trafficRTTAlpha*ms + (1-trafficRTTAlpha)*h.trafficRttMs
	}
	h.trafficSamples++
	r.healthMu.Unlock()
}

// rttOf returns the effective RTT for addr in milliseconds.
// Blends probe RTT (30%) with traffic dial RTT (70%) when both are available;
// falls back to whichever is non-zero.
func (r *ExitRegistry) rttOf(addr string) float64 {
	r.healthMu.RLock()
	h, ok := r.health[addr]
	r.healthMu.RUnlock()
	if !ok {
		return 0
	}
	probe := h.rttMs
	traffic := h.trafficRttMs
	if h.trafficSamples < trafficRTTMinSamples {
		traffic = 0 // suppress noisy early samples
	}
	if probe > 0 && traffic > 0 {
		return 0.3*probe + 0.7*traffic
	}
	if traffic > 0 {
		return traffic
	}
	return probe
}

// MinProbeRTT returns the lowest pure HTTP-probe RTT (control->exit->real
// internet target, see probeOne) across all alive exits, ignoring the
// traffic-dial blend that MinEffectiveRTT uses for routing. This is the
// historical "Average RTT" health signal the heartbeat has always reported
// under the "rtt_ms" field -- it must keep meaning exactly this, forever,
// so a "Average RTT" chart never silently changes what it's measuring again.
// The routing-facing value lives in its own field (see MinEffectiveRTT).
func (r *ExitRegistry) MinProbeRTT() float64 {
	r.mu.Lock()
	exits := make([]ExitNode, len(r.exits))
	copy(exits, r.exits)
	r.mu.Unlock()

	r.healthMu.RLock()
	defer r.healthMu.RUnlock()

	// Dead exits keep a frozen h.rttMs from their last successful probe
	// (probeOne only updates it on success) and can linger in r.exits for
	// up to staleExitAfter after being decommissioned — without this
	// filter, a single long-dead exit's stale (often tiny) RTT would win
	// the min() forever. Fall back to the full list if all are dead so the
	// signal doesn't disappear entirely (mirrors PickFor's fallback).
	best := minProbeRTTOver(exits, r.health, true)
	if best == 0 {
		best = minProbeRTTOver(exits, r.health, false)
	}
	return best
}

func minProbeRTTOver(exits []ExitNode, health map[string]*exitHealth, aliveOnly bool) float64 {
	var best float64
	for _, e := range exits {
		if aliveOnly {
			if h, ok := health[e.Addr]; ok && !h.alive {
				continue
			}
		}
		rtt := e.RTTms
		if h, ok := health[e.Addr]; ok && h.rttMs > 0 {
			rtt = h.rttMs
		}
		if rtt > 0 && (best == 0 || rtt < best) {
			best = rtt
		}
	}
	return best
}

// MinEffectiveRTT returns the lowest effective RTT across all alive exits,
// using the same blending logic as rttOf() and preferring e.RTTms (exit
// self-report) when available — identical to Pick()'s effectiveRTT function.
// Reported in the heartbeat as a SEPARATE field ("routing_rtt_ms") from the
// probe-only "rtt_ms" (see MinProbeRTT) -- this is the value actually used
// to pick an exit, so the dashboard can show it, but it must never overwrite
// the historical "Average RTT" metric again (see routing_rtt_ms column
// comment in snc-arbiter/db.go for the 2026-08-10 incident this fixes).
func (r *ExitRegistry) MinEffectiveRTT() float64 {
	r.mu.Lock()
	exits := make([]ExitNode, len(r.exits))
	copy(exits, r.exits)
	r.mu.Unlock()

	// Same dead-exit filtering as MinProbeRTT — see its comment. Falls back
	// to the full list if every exit is dead, so the signal never vanishes.
	best := minEffectiveRTTOver(r, exits, true)
	if best == 0 {
		best = minEffectiveRTTOver(r, exits, false)
	}
	return best
}

func minEffectiveRTTOver(r *ExitRegistry, exits []ExitNode, aliveOnly bool) float64 {
	var best float64
	for _, e := range exits {
		if aliveOnly && !r.isAlive(e.Addr) {
			continue
		}
		var rtt float64
		if own := r.rttOf(e.Addr); own > 0 {
			rtt = own
		} else {
			rtt = e.RTTms
		}
		if rtt > 0 && (best == 0 || rtt < best) {
			best = rtt
		}
	}
	return best
}
