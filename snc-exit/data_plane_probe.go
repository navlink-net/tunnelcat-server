// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"net"
	"sync"
	"time"
)

const (
	probeInterval = 30 * time.Second
	probeTimeout  = 5 * time.Second
)

// probeTargets are tried in parallel; OK if any one succeeds.
// Includes both global and Russian addresses so exits in restricted
// networks (e.g. Yandex Cloud) pass even when Cloudflare is blocked.
var probeTargets = []string{
	"1.1.1.1:80",        // Cloudflare
	"8.8.8.8:80",        // Google
	"77.88.8.8:80",      // Yandex DNS
	"208.67.222.222:80", // OpenDNS
}

// dataPlaneProber periodically TCP-dials external hosts to verify this exit
// can actually forward traffic to the internet.
type dataPlaneProber struct {
	mu    sync.RWMutex
	ok    bool
	rttMs float64
}

var exitDataPlane = &dataPlaneProber{ok: true} // assume OK until first probe

func (p *dataPlaneProber) probe() {
	type result struct {
		rtt float64
		via string
	}
	ch := make(chan result, len(probeTargets))
	for _, target := range probeTargets {
		go func(t string) {
			start := time.Now()
			conn, err := net.DialTimeout("tcp", t, probeTimeout)
			if err != nil {
				ch <- result{}
				return
			}
			conn.Close()
			ch <- result{rtt: time.Since(start).Seconds() * 1000, via: t}
		}(target)
	}

	var first result
	failed := 0
	for range probeTargets {
		r := <-ch
		if r.via != "" && first.via == "" {
			first = r
		}
		if r.via == "" {
			failed++
		}
	}

	p.mu.Lock()
	if first.via != "" {
		p.ok = true
		p.rttMs = first.rtt
		logDebugf("data-plane: probe ok via=%s rtt=%.1fms (%d/%d failed)", first.via, first.rtt, failed, len(probeTargets))
	} else {
		p.ok = false
		logWarnf("data-plane: all %d probe targets unreachable", len(probeTargets))
	}
	p.mu.Unlock()
}

func (p *dataPlaneProber) isOK() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.ok
}

func (p *dataPlaneProber) rtt() float64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.rttMs
}

// startDataPlaneProber runs an immediate probe then repeats every probeInterval.
func startDataPlaneProber() {
	exitDataPlane.probe()
	go func() {
		t := time.NewTicker(probeInterval)
		defer t.Stop()
		for range t.C {
			exitDataPlane.probe()
		}
	}()
}
