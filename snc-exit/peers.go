// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// PeerEntry holds the address, region, and whitelist capabilities of a peer exit node.
type PeerEntry struct {
	Addr         string          // host:port
	Region       string          // ISO-3166-1 alpha-2 (e.g. "EU", "RU")
	Capabilities map[string]bool // domain → reachable; nil = unknown (assume capable)
}

// PeerRegistry fetches and caches the list of peer exit nodes from the arbiter.
// It supports geo-routing (pick a peer in a target region) and fallback (any peer).
type PeerRegistry struct {
	auth     *authClient
	myRegion string // resolved from arbiter geoip on startup

	mu      sync.RWMutex
	peers   []PeerEntry
	alive   map[string]bool // addr → reachable (nil = not yet probed)
	fetched time.Time
}

func newPeerRegistry(auth *authClient) *PeerRegistry {
	return &PeerRegistry{auth: auth}
}

// outboundIP returns the local IP the OS would use to reach the internet.
// Uses a UDP "connect" to 8.8.8.8 — no packet is actually sent.
func outboundIP() string {
	conn, err := net.DialTimeout("udp", "8.8.8.8:80", 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return addr.IP.String()
	}
	return ""
}

// Start launches background goroutines: one resolves own region (retrying every
// 10s until the arbiter returns a non-empty answer), the other refreshes the
// peer list every 5 minutes, and a third probes peer health every 30 seconds.
func (pr *PeerRegistry) Start() {
	pr.refresh()
	go pr.resolveRegionLoop()
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for range t.C {
			pr.refresh()
		}
	}()
	go pr.healthLoop()
}

// healthLoop probes all known peers every 30 s and updates the alive map.
func (pr *PeerRegistry) healthLoop() {
	pr.probeAll()
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for range t.C {
		pr.probeAll()
	}
}

// probeAll attempts a TLS dial to each peer, marks it alive or dead, and
// fetches whitelist capabilities from each alive peer.
func (pr *PeerRegistry) probeAll() {
	pr.mu.RLock()
	peers := make([]PeerEntry, len(pr.peers))
	copy(peers, pr.peers)
	pr.mu.RUnlock()

	results := make(map[string]bool, len(peers))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, p := range peers {
		wg.Add(1)
		go func(p PeerEntry) {
			defer wg.Done()
			alive := probePeer(p.Addr)
			mu.Lock()
			results[p.Addr] = alive
			mu.Unlock()
			if !alive {
				logWarnf("peers: health: %s DEAD", p.Addr)
			}
		}(p)
	}
	wg.Wait()

	pr.mu.Lock()
	pr.alive = results
	pr.mu.Unlock()

	// Fetch whitelist capabilities from alive peers in parallel.
	allCaps := make(map[string]map[string]bool)
	var capsMu sync.Mutex
	var capsWg sync.WaitGroup
	for _, p := range peers {
		if !results[p.Addr] {
			continue
		}
		capsWg.Add(1)
		go func(p PeerEntry) {
			defer capsWg.Done()
			c := fetchPeerCapabilities(p.Addr, pr.auth.nodeToken)
			if c != nil {
				capsMu.Lock()
				allCaps[p.Addr] = c
				capsMu.Unlock()
			}
		}(p)
	}
	capsWg.Wait()

	if len(allCaps) > 0 {
		pr.mu.Lock()
		for i := range pr.peers {
			if c, ok := allCaps[pr.peers[i].Addr]; ok {
				pr.peers[i].Capabilities = c
			}
		}
		pr.mu.Unlock()
	}
}

// probePeer returns true if a TLS connection to addr succeeds within 3 seconds.
func probePeer(addr string) bool {
	if !strings.Contains(addr, ":") {
		addr = addr + ":443"
	}
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 3 * time.Second},
		"tcp", addr,
		&tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// regionOther is the sentinel used when the arbiter returns no region match,
// meaning this exit's IP falls outside all known CIDR buckets ("rest of world").
const regionOther = "OTHER"

// resolveRegionLoop determines this exit's own region.
// Priority: (1) the arbiter's signed self_region -- resolved server-side from
// this exit's own X-Node-Token, so it's authoritative and RegionOverride-aware
// regardless of what this exit's own outbound-IP self-detection would find.
// That self-detection breaks behind cloud-provider NAT (e.g. Yandex Cloud):
// outboundIP() returns the internal NAT address, never the public one, so
// this exit could never match itself in the exit list by IP (incident
// 2026-08-12: 51.250.110.41 stuck reporting myRegion="OTHER" despite an
// admin-set RegionOverride=RU, because its "own IP" was 10.129.0.31).
// (2) CIDR-based geoip lookup on the outbound IP, (3) regionOther.
// Retries every 10 s on geoip errors until a definitive answer is obtained.
func (pr *PeerRegistry) resolveRegionLoop() {
	for {
		if _, selfRegion, err := pr.auth.fetchExitList(); err == nil && selfRegion != "" {
			pr.myRegion = selfRegion
			logInfof("peers: own region=%q (signed self_region from arbiter)", selfRegion)
			return
		}

		// Fall back to CIDR-based lookup on our own outbound IP.
		ip := outboundIP()
		if ip == "" {
			logWarnf("peers: could not determine outbound IP — geo-routing disabled")
			return
		}
		region, err := pr.auth.fetchRegion(ip)
		if err != nil {
			logWarnf("peers: region lookup failed for ip=%s: %v — retry in 10s", ip, err)
			time.Sleep(10 * time.Second)
			continue
		}
		if region == "" {
			region = regionOther
		}
		pr.myRegion = region
		logInfof("peers: own IP=%s region=%q (from geoip)", ip, region)
		return
	}
}

func (pr *PeerRegistry) refresh() {
	peers, _, err := pr.auth.fetchExitList()
	if err != nil {
		pr.mu.RLock()
		have := len(pr.peers)
		pr.mu.RUnlock()
		logWarnf("peers: refresh failed (%v); keeping %d cached entries", err, have)
		return
	}
	pr.mu.Lock()
	pr.peers = peers
	pr.fetched = time.Now()
	pr.mu.Unlock()
	logInfof("peers: refreshed count=%d myRegion=%q", len(peers), pr.myRegion)
}

// MyRegion returns this exit's own region code (empty if unknown).
func (pr *PeerRegistry) MyRegion() string {
	return pr.myRegion
}

// PeerInRegion returns a random peer whose region matches cc.
// Returns nil if no peer matches.
func (pr *PeerRegistry) PeerInRegion(cc string) *PeerEntry {
	if cc == "" {
		return nil
	}
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	var candidates []PeerEntry
	for _, p := range pr.peers {
		if p.Region == cc {
			candidates = append(candidates, p)
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	c := candidates[rand.Intn(len(candidates))]
	return &c
}

// AnyPeer returns a random peer from any region, or nil if none are known.
func (pr *PeerRegistry) AnyPeer() *PeerEntry {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	if len(pr.peers) == 0 {
		return nil
	}
	c := pr.peers[rand.Intn(len(pr.peers))]
	return &c
}

// PeersCapableOf returns alive peers that can reach domain (or have no caps info).
// Peers with caps data explicitly marking domain false are excluded.
func (pr *PeerRegistry) PeersCapableOf(domain string) []PeerEntry {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	var out []PeerEntry
	for _, p := range pr.peers {
		if len(pr.alive) > 0 && !pr.alive[p.Addr] {
			continue
		}
		if p.Capabilities != nil {
			if v, ok := p.Capabilities[domain]; ok && !v {
				continue
			}
		}
		out = append(out, p)
	}
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// fetchPeerCapabilities retrieves the whitelist capability map and torrent
// policy from a peer exit. Returns (nil, false) on any error (caller treats
// nil capabilities as "assume all capable"; a failed torrent-policy fetch
// defaults to false -- an unreachable/unknown peer is never treated as a
// valid torrent-egress target).
func fetchPeerCapabilities(addr, nodeToken string) map[string]bool {
	if !strings.Contains(addr, ":") {
		addr = addr + ":443"
	}
	host, _, _ := net.SplitHostPort(addr)
	url := "https://" + addr + "/api/peer/capabilities"
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         host,
				InsecureSkipVerify: true, //nolint:gosec
			},
		},
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("X-Peer-Token", nodeToken)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var result struct {
		Capabilities map[string]bool `json:"capabilities"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&result); err != nil {
		return nil
	}
	return result.Capabilities
}

// ShufflePeers returns alive peers in random order.
// If the health map is not yet populated (first probe pending), all peers are
// returned so routing is not blocked on startup.
func (pr *PeerRegistry) ShufflePeers() []PeerEntry {
	pr.mu.RLock()
	defer pr.mu.RUnlock()
	if len(pr.peers) == 0 {
		return nil
	}
	src := pr.peers
	if len(pr.alive) > 0 {
		var live []PeerEntry
		for _, p := range pr.peers {
			if pr.alive[p.Addr] {
				live = append(live, p)
			}
		}
		if len(live) > 0 {
			src = live
		}
	}
	out := make([]PeerEntry, len(src))
	copy(out, src)
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}
