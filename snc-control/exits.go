// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// minValidExits is the smallest signed exit list refresh() will accept.
	// A response with fewer nodes is treated as invalid (arbiter hiccup,
	// transient empty/partial response) and discarded rather than applied.
	minValidExits = 3

	// staleExitAfter is how long an exit is kept in rotation after it last
	// appeared in a valid signed response before refresh() drops it.
	staleExitAfter = 24 * time.Hour
)

// ExitNode is a live exit as returned by the arbiter.
type ExitNode struct {
	Addr        string  `json:"addr"`
	Fingerprint string  `json:"fingerprint,omitempty"`
	RTTms       float64 `json:"rtt_ms,omitempty"`
	Load        float64 `json:"load,omitempty"`
	DataPlaneOK *bool   `json:"data_plane_ok,omitempty"`
}

// effectiveLoadFactor returns f, or the neutral 1.0 when unset (<=0).
// Mirrors snc/core/router.go's function of the same name and purpose --
// "no data yet" (fresh exit, or load-factor balancing disabled on the
// arbiter) must fall back to pure RTT-based scoring, never a zero weight
// that would erase the exit from consideration entirely.
func effectiveLoadFactor(f float64) float64 {
	if f <= 0 {
		return 1.0
	}
	return f
}

// ExitRegistry holds a periodically-refreshed list of live exits.
// It is the only component that knows exit addresses — clients never see them.
// It deliberately does NOT hold the arbiter's address: every arbiter call
// goes through exitProxyURL(exit.Addr, ...), which only needs the exit's own
// address plus a fixed path prefix (see exitProxyURL below).
type ExitRegistry struct {
	nodeToken string
	pubkey     ed25519.PublicKey // arbiter's signing pubkey; nil = skip verification
	cacheFile  string            // path for on-disk cache; empty = no cache
	myRegion   string            // ISO-3166 region code of this control node; "" = no filter

	// relayEnabled mirrors the arbiter's relay_enabled advisory flag.
	// When false, the relay API rejects registrations and serves empty lists.
	relayEnabled atomic.Bool

	mu          sync.Mutex
	exits       []ExitNode
	exitRegions map[string]string    // addr → ISO region code (advisory, from arbiter)
	lastSeen    map[string]time.Time // addr → last time seen in a valid signed refresh

	healthMu   sync.RWMutex
	health     map[string]*exitHealth // per-exit health state; nil until StartHealthChecker
	probeSites *ProbeSiteRegistry     // nil = skip data-plane probing

	// onDead is called (outside any lock) when an exit transitions to DEAD.
	// Set once at startup before goroutines start; no synchronisation needed.
	onDead func(addr string)

	client *http.Client
}

func newExitRegistry(nodeToken string, pubkey ed25519.PublicKey, cacheFile string) *ExitRegistry {
	r := &ExitRegistry{
		nodeToken: nodeToken,
		pubkey:    pubkey,
		cacheFile: cacheFile,
		client:    &http.Client{Timeout: 15 * time.Second},
	}
	r.relayEnabled.Store(true) // default until first arbiter refresh
	return r
}

// RelayEnabled reports whether client-relay registration is allowed.
// Mirrors the arbiter's relay_enabled advisory flag; defaults to true until
// the first exits refresh.
func (r *ExitRegistry) RelayEnabled() bool {
	return r.relayEnabled.Load()
}

// MyRegion returns the region code set via SetMyRegion, or "" if not yet known.
func (r *ExitRegistry) MyRegion() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.myRegion
}

// SetMyRegion sets the ISO-3166 region code for this control node (e.g. "RU").
// Pick() will prefer exits that are NOT in this region so that traffic crosses
// the border at the control→exit link.  Pass "" to disable region filtering.
func (r *ExitRegistry) SetMyRegion(cc string) {
	r.mu.Lock()
	r.myRegion = cc
	r.mu.Unlock()
	if cc != "" {
		logInfof("exits: my region set to %q — will prefer out-of-region exits", cc)
	}
}

// LoadBootstrap pre-populates the exit list from a static comma-separated
// address list (e.g. from SNC_EXITS env var written at deploy time).
// Called before Start() so the node can route on first tick without waiting
// for a successful refresh.
func (r *ExitRegistry) LoadBootstrap(addrs []string) {
	var nodes []ExitNode
	for _, a := range addrs {
		a = strings.TrimSpace(a)
		if a != "" {
			nodes = append(nodes, ExitNode{Addr: a})
		}
	}
	if len(nodes) == 0 {
		return
	}
	now := time.Now()
	r.mu.Lock()
	r.exits = nodes
	if r.lastSeen == nil {
		r.lastSeen = make(map[string]time.Time)
	}
	for _, n := range nodes {
		r.lastSeen[n.Addr] = now
	}
	r.mu.Unlock()
	logInfof("exits: loaded %d bootstrap exits from static list", len(nodes))
}

// LoadCached merges the on-disk cache into the current exit list — it never
// replaces a good in-memory list (e.g. from LoadBootstrap) with a stale or
// empty one, for the same reason refresh() merges rather than replaces: a
// single bad snapshot must never be able to wipe out a known-good list.
// Non-fatal: logs a warning and returns if the file is missing or invalid.
func (r *ExitRegistry) LoadCached() {
	if r.cacheFile == "" {
		return
	}
	data, err := os.ReadFile(r.cacheFile)
	if err != nil {
		logDebugf("exits: no disk cache: %v", err)
		return
	}
	data = bytes.TrimSpace(data)
	var nodes []ExitNode
	cachedSeen := make(map[string]time.Time)
	if len(data) > 0 && data[0] == '{' {
		var wrapper struct {
			Nodes    []ExitNode       `json:"nodes"`
			LastSeen map[string]int64 `json:"last_seen"`
		}
		if err := json.Unmarshal(data, &wrapper); err != nil {
			logWarnf("exits: disk cache corrupt, ignoring: %v", err)
			return
		}
		nodes = wrapper.Nodes
		for addr, ts := range wrapper.LastSeen {
			cachedSeen[addr] = time.Unix(ts, 0)
		}
	} else if err := json.Unmarshal(data, &nodes); err != nil {
		// Legacy cache format: a plain []ExitNode array with no lastSeen data.
		logWarnf("exits: disk cache corrupt, ignoring: %v", err)
		return
	}

	now := time.Now()
	r.mu.Lock()
	if r.lastSeen == nil {
		r.lastSeen = make(map[string]time.Time)
	}
	byAddr := make(map[string]ExitNode, len(r.exits)+len(nodes))
	for _, e := range r.exits {
		byAddr[e.Addr] = e
	}
	for _, e := range nodes {
		byAddr[e.Addr] = e
		if t, ok := cachedSeen[e.Addr]; ok {
			r.lastSeen[e.Addr] = t
		} else if _, ok := r.lastSeen[e.Addr]; !ok {
			r.lastSeen[e.Addr] = now
		}
	}
	merged := make([]ExitNode, 0, len(byAddr))
	for _, e := range byAddr {
		merged = append(merged, e)
	}
	r.exits = merged
	r.mu.Unlock()
	logInfof("exits: loaded %d exits from disk cache (merged total=%d)", len(nodes), len(merged))
}

// persist writes the current exit list and per-exit last-seen timestamps to
// the on-disk cache.
func (r *ExitRegistry) persist(nodes []ExitNode, lastSeen map[string]time.Time) {
	if r.cacheFile == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(r.cacheFile), 0700); err != nil {
		logWarnf("exits: cache dir: %v", err)
		return
	}
	ls := make(map[string]int64, len(nodes))
	for _, n := range nodes {
		if t, ok := lastSeen[n.Addr]; ok {
			ls[n.Addr] = t.Unix()
		}
	}
	data, _ := json.Marshal(struct {
		Nodes    []ExitNode       `json:"nodes"`
		LastSeen map[string]int64 `json:"last_seen"`
	}{Nodes: nodes, LastSeen: ls})
	if err := os.WriteFile(r.cacheFile, data, 0600); err != nil {
		logWarnf("exits: cache write: %v", err)
	}
}

// Start fetches the exit list immediately, then refreshes every interval.
func (r *ExitRegistry) Start(interval time.Duration) {
	if err := r.refresh(); err != nil {
		logWarnf("exits: initial fetch failed: %v", err)
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			if err := r.refresh(); err != nil {
				logWarnf("exits: refresh failed: %v", err)
			}
		}
	}()
}

// Pick returns the best healthy exit for an unknown client (no country filter
// beyond the control's own region).  Calls PickFor("").
func (r *ExitRegistry) Pick() (ExitNode, error) {
	return r.PickFor("")
}

// PickFor returns the best healthy exit, preferring exits that are outside
// both this control's own region AND the client's country (clientCC).  When
// no such exits exist, falls back to all alive exits so connectivity is
// preserved.  clientCC="" disables the client-country filter.
func (r *ExitRegistry) PickFor(clientCC string) (ExitNode, error) {
	r.mu.Lock()
	exits := make([]ExitNode, len(r.exits))
	copy(exits, r.exits)
	regions := r.exitRegions
	myRegion := r.myRegion
	r.mu.Unlock()

	if len(exits) == 0 {
		return ExitNode{}, fmt.Errorf("no live exits available")
	}

	// Filter: TCP-reachable (HTTP probe) AND data plane OK (self-reported).
	// DataPlaneOK==nil means the exit hasn't reported yet — treat as OK.
	// Fall back to full list if all exits are filtered out.
	var live []ExitNode
	for _, e := range exits {
		if r.isAlive(e.Addr) && (e.DataPlaneOK == nil || *e.DataPlaneOK) {
			live = append(live, e)
		}
	}
	if len(live) == 0 {
		logWarnf("exits: all exits dead — falling back to full list")
		live = exits
	}

	// Regional preference: exclude exits in the control's own region and in
	// the client's country so traffic always crosses a national border at the
	// control→exit link.  Unknown-country exits (cc=="") are kept in pool.
	// Falls back to all alive exits when no foreign exits remain.
	excluded := func(cc string) bool {
		if cc == "" {
			return false // unknown country — benefit of doubt
		}
		if myRegion != "" && cc == myRegion {
			return true
		}
		if clientCC != "" && cc == clientCC {
			return true
		}
		return false
	}
	if myRegion == "" && clientCC == "" {
		logDebugf("exits: geo-filter skipped: myRegion and clientCC both unknown")
	} else if len(regions) == 0 {
		logWarnf("exits: geo-filter skipped: arbiter returned no region data (myRegion=%s clientCC=%s)", myRegion, clientCC)
	}
	if (myRegion != "" || clientCC != "") && len(regions) > 0 {
		var abroad []ExitNode
		for _, e := range live {
			if !excluded(regions[e.Addr]) {
				abroad = append(abroad, e)
			}
		}
		if len(abroad) > 0 {
			logInfof("exits: geo-filter: %d/%d exits kept (myRegion=%s clientCC=%s excluded=%v)",
				len(abroad), len(live), myRegion, clientCC, func() []string {
					var ex []string
					for _, e := range live {
						if excluded(regions[e.Addr]) {
							ex = append(ex, e.Addr+"("+regions[e.Addr]+")")
						}
					}
					return ex
				}())
			live = abroad
		} else {
			logWarnf("exits: no exits outside control+client regions (myRegion=%s clientCC=%s) — using all alive", myRegion, clientCC)
		}
	}

	// Pick: find lowest RTT, then collect all exits within 30% of it and pick
	// one at random.  RTT source priority: self-reported data-plane RTT from
	// the arbiter node list (e.RTTms), falling back to the HTTP-probe RTT
	// (rttOf) only when the exit hasn't reported yet.
	// Exits with RTT=0 from both sources are treated as equal to the best.
	// Load factor (e.Load, from the arbiter's signed exit list -- see
	// snc-arbiter/load_factor.go) is a bonus/malus multiplier on top: an
	// above-average-loaded exit is deprioritised, below-average preferred,
	// same convention as Router.nodeScore on the client side.
	effectiveRTT := func(e ExitNode) float64 {
		var rtt float64
		if own := r.rttOf(e.Addr); own > 0 {
			rtt = own
		} else {
			rtt = e.RTTms
		}
		return rtt * effectiveLoadFactor(e.Load)
	}
	bestRTT := 0.0
	for _, e := range live {
		if rtt := effectiveRTT(e); rtt > 0 && (bestRTT == 0 || rtt < bestRTT) {
			bestRTT = rtt
		}
	}
	// Skip RTT filter on small deployments so all healthy exits stay in rotation.
	var pool []ExitNode
	if len(exits) < 5 {
		pool = live
	} else {
		for _, e := range live {
			rtt := effectiveRTT(e)
			if rtt == 0 || bestRTT == 0 || rtt <= bestRTT*1.3 {
				pool = append(pool, e)
			}
		}
	}
	best := pool[rand.Intn(len(pool))]

	logDebugf("exits: pick addr=%s rtt=%.1fms load=%.2f (pool=%d live=%d/%d)",
		best.Addr, effectiveRTT(best), best.Load, len(pool), len(live), len(exits))
	return best, nil
}

// PickForClient selects an exit for clientIP/clientCC, honouring the same
// geo rule as PickFor (never route through an exit in the control's own
// region or the client's own country) and then, among the geo-eligible
// candidates, choosing with probability inversely proportional to RTT --
// faster exits get picked more often, but slower ones are never fully
// excluded. Selection is deterministic on clientIP (weighted by a hash, not
// rand), so a given client always lands on the same exit as long as the
// candidate set and their RTTs are stable -- this keeps app-level sessions
// that need a consistent source IP (e.g. CDN uploads) working correctly.
func (r *ExitRegistry) PickForClient(clientIP, clientCC string) (ExitNode, error) {
	r.mu.Lock()
	exits := make([]ExitNode, len(r.exits))
	copy(exits, r.exits)
	regions := r.exitRegions
	myRegion := r.myRegion
	r.mu.Unlock()

	if len(exits) == 0 {
		return ExitNode{}, fmt.Errorf("no live exits available")
	}

	// Diagnostic: 2026-08-11 call-quality investigation found the final
	// candidate pool sometimes much smaller than the raw exit count would
	// predict (e.g. 3 candidates out of ~9 known exits), with no matching
	// isAlive/DataPlaneOK/region explanation found by static code reading
	// alone. Log the per-exit reason for every drop at each stage so the
	// actual live cause is visible instead of having to re-derive it from
	// the merged-exits/health logs after the fact.
	var droppedAlive []string
	var live []ExitNode
	for _, e := range exits {
		if r.isAlive(e.Addr) && (e.DataPlaneOK == nil || *e.DataPlaneOK) {
			live = append(live, e)
		} else {
			dpOK := "nil"
			if e.DataPlaneOK != nil {
				dpOK = fmt.Sprintf("%v", *e.DataPlaneOK)
			}
			droppedAlive = append(droppedAlive, fmt.Sprintf("%s(alive=%v,dataPlaneOK=%s)", e.Addr, r.isAlive(e.Addr), dpOK))
		}
	}
	if len(live) == 0 {
		logDebugf("exits: pick-for-client all %d exit(s) failed alive/dataplane filter — falling back to unfiltered list: %v", len(exits), droppedAlive)
		live = exits
	} else if len(droppedAlive) > 0 {
		logDebugf("exits: pick-for-client alive/dataplane filter dropped %d/%d: %v", len(droppedAlive), len(exits), droppedAlive)
	}

	excluded := func(cc string) bool {
		if cc == "" {
			return false
		}
		return (myRegion != "" && cc == myRegion) || (clientCC != "" && cc == clientCC)
	}
	if (myRegion != "" || clientCC != "") && len(regions) > 0 {
		var abroad []ExitNode
		var droppedRegion []string
		for _, e := range live {
			if !excluded(regions[e.Addr]) {
				abroad = append(abroad, e)
			} else {
				droppedRegion = append(droppedRegion, fmt.Sprintf("%s(region=%q)", e.Addr, regions[e.Addr]))
			}
		}
		if len(droppedRegion) > 0 {
			logDebugf("exits: pick-for-client region filter (myRegion=%q clientCC=%q) dropped %d/%d: %v",
				myRegion, clientCC, len(droppedRegion), len(live), droppedRegion)
		}
		if len(abroad) > 0 {
			live = abroad
		} else {
			logDebugf("exits: pick-for-client region filter would drop all %d remaining — keeping pre-filter set instead", len(live))
		}
	}
	if len(live) == 1 {
		return live[0], nil
	}

	// RTT source priority mirrors PickFor: self-reported data-plane RTT from
	// the arbiter node list, falling back to the HTTP-probe RTT when the exit
	// hasn't reported yet. Exits with no RTT data at all get a neutral 1ms
	// weight so they're tried instead of starved outright. Load factor
	// (e.Load) multiplies in the same way as PickFor's effectiveRTT above.
	effectiveRTT := func(e ExitNode) float64 {
		rtt := r.rttOf(e.Addr)
		if rtt <= 0 {
			rtt = e.RTTms
		}
		if rtt <= 0 {
			rtt = 1
		}
		return rtt * effectiveLoadFactor(e.Load)
	}
	weights := make([]float64, len(live))
	var total float64
	for i, e := range live {
		w := 1.0 / effectiveRTT(e)
		weights[i] = w
		total += w
	}

	// Deterministic weighted pick: hash clientIP into a fraction of [0,1) and
	// walk the cumulative weight table. Same clientIP -> same fraction ->
	// same exit every time (unlike rand-based weighting), which is what
	// gives us session stickiness.
	h := sha256.Sum256([]byte(clientIP))
	hv := binary.BigEndian.Uint64(h[:8])
	frac := float64(hv) / float64(math.MaxUint64)
	target := frac * total
	best := live[len(live)-1]
	for i, w := range weights {
		target -= w
		if target <= 0 {
			best = live[i]
			break
		}
	}
	logDebugf("exits: weighted sticky pick client=%s exit=%s rtt=%.1fms (candidates=%d)",
		clientIP, best.Addr, effectiveRTT(best), len(live))
	return best, nil
}

// ForceRefresh triggers an immediate exit-list reload outside the normal ticker.
func (r *ExitRegistry) ForceRefresh() error {
	return r.refresh()
}

// Exits returns a snapshot of the current exit list.
func (r *ExitRegistry) Exits() []ExitNode {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]ExitNode, len(r.exits))
	copy(out, r.exits)
	return out
}

// PickRandom returns a random live exit, ignoring RTT scores.
// Used for management traffic (heartbeat, refresh) where any exit is fine.
func (r *ExitRegistry) PickRandom() (ExitNode, error) {
	r.mu.Lock()
	exits := make([]ExitNode, len(r.exits))
	copy(exits, r.exits)
	r.mu.Unlock()

	if len(exits) == 0 {
		// In-memory list is empty — try reviving from the on-disk cache so the
		// control can recover without a restart.
		r.LoadCached()
		r.mu.Lock()
		exits = make([]ExitNode, len(r.exits))
		copy(exits, r.exits)
		r.mu.Unlock()
		if len(exits) > 0 {
			logWarnf("exits: in-memory list was empty — revived %d entries from disk cache", len(exits))
		}
	}

	if len(exits) == 0 {
		return ExitNode{}, fmt.Errorf("no exits available")
	}

	// Prefer healthy exits; fall back to all if none healthy.
	var live []ExitNode
	for _, e := range exits {
		if r.isAlive(e.Addr) {
			live = append(live, e)
		}
	}
	if len(live) == 0 {
		live = exits
	}

	return live[rand.Intn(len(live))], nil
}

// nodeProxyClient returns an HTTP client that skips TLS verification.
// Used for calls through exit nodes (which may have self-signed or LE certs).
func nodeProxyClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
}

// exitProxyURL builds the URL for a proxied arbiter call through an exit.
// e.g. exitProxyURL("1.2.3.4:443", "/api/exits") → "https://1.2.3.4:443/p/node/v1/arbiter/api/exits"
func exitProxyURL(exitAddr, arbiterPath string) string {
	addr := strings.TrimPrefix(exitAddr, "https://")
	addr = strings.TrimPrefix(addr, "http://")
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = addr + ":443"
	}
	return "https://" + addr + "/p/node/v1/arbiter" + arbiterPath
}

// refresh fetches and verifies the signed exit list via a random exit.
// Returns an error if no exits are known yet; caller should retry later.
// Never contacts the arbiter directly — all traffic goes through exits.
func (r *ExitRegistry) refresh() error {
	const apiPath = "/api/exits"

	exit, err := r.PickRandom()
	if err != nil {
		return fmt.Errorf("exits: no exits available for refresh: %w", err)
	}
	fetchURL := exitProxyURL(exit.Addr, apiPath)
	logDebugf("exits: refresh via exit %s", exit.Addr)

	req, err := http.NewRequest("GET", fetchURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Node-Token", r.nodeToken)
	resp, err := nodeProxyClient().Do(req)
	if err != nil {
		return fmt.Errorf("fetch exits via %s: %w", exit.Addr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("arbiter returned %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read exits: %w", err)
	}

	var signed struct {
		Type         string            `json:"type"`
		TS           int64             `json:"ts"`
		Nodes        []ExitNode        `json:"nodes"`
		Sig          string            `json:"sig"`
		Regions      map[string]string `json:"regions,omitempty"`       // advisory; not covered by Sig
		RelayEnabled *bool             `json:"relay_enabled,omitempty"` // advisory; nil → default true
	}
	if err := json.Unmarshal(raw, &signed); err != nil {
		return fmt.Errorf("parse exits: %w", err)
	}

	// Verify Ed25519 signature if we have the arbiter pubkey.
	if r.pubkey != nil {
		payload := struct {
			Type  string     `json:"type"`
			TS    int64      `json:"ts"`
			Nodes []ExitNode `json:"nodes"`
		}{Type: signed.Type, TS: signed.TS, Nodes: signed.Nodes}
		canonical, _ := json.Marshal(payload)
		sigBytes, err := base64.RawURLEncoding.DecodeString(signed.Sig)
		if err != nil || !ed25519.Verify(r.pubkey, canonical, sigBytes) {
			return fmt.Errorf("exits: signature verification failed")
		}
	}

	// Replay protection: reject lists older than 10 minutes.
	age := time.Since(time.Unix(signed.TS, 0))
	if age > 10*time.Minute {
		return fmt.Errorf("exits: signed list too old (%s)", age.Round(time.Second))
	}

	// Verify TLS fingerprints for exits that have one.
	// Exits without a registered fingerprint are accepted as-is (backward compat).
	var verified []ExitNode
	for _, node := range signed.Nodes {
		if node.Fingerprint == "" {
			verified = append(verified, node)
			continue
		}
		if err := verifyExitFingerprint(node.Addr, node.Fingerprint); err != nil {
			logWarnf("exits: fingerprint mismatch addr=%s: %v — skipping", node.Addr, err)
			continue
		}
		logDebugf("exits: fingerprint OK addr=%s", node.Addr)
		verified = append(verified, node)
	}

	// A signed list with fewer than minValidExits nodes is suspect (arbiter
	// hiccup, transient partial/empty response, mass fingerprint mismatch,
	// etc.) but is still merged in below rather than discarded outright —
	// any node it does name gets its lastSeen refreshed, and the merge never
	// removes a previously known-good node just because this particular
	// response is short.  Only the merge's own staleExitAfter grace period
	// can ever drop an exit, never the size of a single response.
	if len(verified) < minValidExits {
		logWarnf("exits: signed list has only %d valid node(s) (< %d) — merging cautiously, not treating as a full list", len(verified), minValidExits)
	}

	// Merge rather than replace: an exit missing from this particular signed
	// response (arbiter blip, exit temporarily unreachable from the arbiter's
	// vantage point, etc.) is kept in rotation until it has been absent from
	// every fresh response for staleExitAfter. Only then is it dropped.
	now := time.Now()
	r.mu.Lock()
	if r.lastSeen == nil {
		r.lastSeen = make(map[string]time.Time)
	}
	byAddr := make(map[string]ExitNode, len(r.exits)+len(verified))
	for _, e := range r.exits {
		byAddr[e.Addr] = e
	}
	for _, e := range verified {
		byAddr[e.Addr] = e
		r.lastSeen[e.Addr] = now
	}
	merged := make([]ExitNode, 0, len(byAddr))
	for addr, e := range byAddr {
		seen, ok := r.lastSeen[addr]
		if !ok {
			// No record (e.g. loaded via LoadBootstrap/LoadCached without a
			// timestamp) — start its grace period now rather than purging it
			// on sight.
			r.lastSeen[addr] = now
			seen = now
		}
		if now.Sub(seen) > staleExitAfter {
			logInfof("exits: dropping %s — absent from arbiter list for %s", addr, now.Sub(seen).Round(time.Minute))
			delete(r.lastSeen, addr)
			continue
		}
		merged = append(merged, e)
	}
	r.exits = merged
	r.exitRegions = signed.Regions
	lastSeenSnapshot := make(map[string]time.Time, len(r.lastSeen))
	for addr, t := range r.lastSeen {
		lastSeenSnapshot[addr] = t
	}
	r.mu.Unlock()

	// Apply advisory relay_enabled flag (nil = not set by arbiter → keep true default).
	relayEnabled := signed.RelayEnabled == nil || *signed.RelayEnabled
	if prev := r.relayEnabled.Swap(relayEnabled); prev != relayEnabled {
		if relayEnabled {
			logInfof("exits: relay registration enabled (arbiter signal)")
		} else {
			logInfof("exits: relay registration disabled (arbiter signal)")
		}
	}

	r.persist(merged, lastSeenSnapshot)

	addrs := make([]string, len(merged))
	for i, n := range merged {
		addrs[i] = fmt.Sprintf("%s(rtt=%.0fms,load=%.2f)", n.Addr, n.RTTms, n.Load)
	}
	logInfof("exits: refreshed signed_count=%d merged_count=%d ts=%d age=%s nodes=[%s]",
		len(signed.Nodes), len(merged), signed.TS,
		time.Since(time.Unix(signed.TS, 0)).Round(time.Second),
		strings.Join(addrs, ", "))
	return nil
}

// verifyExitFingerprint dials the exit via TLS and checks that the server
// certificate's SHA-256 fingerprint matches expectedFP (colon-separated hex).
// The TLS connection is closed immediately after the handshake.
func verifyExitFingerprint(addr, expectedFP string) error {
	dialAddr := exitDialAddr(addr)
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp", dialAddr,
		&tls.Config{InsecureSkipVerify: true}, //nolint:gosec // fingerprint verified manually
	)
	if err != nil {
		return fmt.Errorf("TLS probe: %w", err)
	}
	conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return fmt.Errorf("no certificates in TLS handshake")
	}
	sum := sha256.Sum256(certs[0].Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	got := strings.Join(parts, ":")
	if got != strings.ToUpper(expectedFP) {
		return fmt.Errorf("got %s want %s", got, strings.ToUpper(expectedFP))
	}
	return nil
}

// ── arbiter heartbeat ────────────────────────────────────────────────────────

// startHeartbeat sends a periodic heartbeat to the arbiter via a random exit.
// If no exits are available the tick is skipped silently — the node stays
// offline until at least one exit is reachable.  Never contacts the arbiter
// directly.
func startHeartbeat(exits *ExitRegistry, nodeToken string) {
	const apiPath = "/api/heartbeat"

	var lastBytes int64
	var lastTime time.Time

	send := func() {
		// Touch before any log call so the watchdog can detect log-writer stalls.
		lastHeartbeatAt.Store(time.Now().Unix())

		exit, err := exits.PickRandom()
		if err != nil {
			logWarnf("heartbeat: no exits available, skipping")
			return
		}
		targetURL := exitProxyURL(exit.Addr, apiPath)

		now := time.Now()
		total := controlBytesTotal.Load()

		var bwMbps float64
		if !lastTime.IsZero() {
			elapsed := now.Sub(lastTime).Seconds()
			if elapsed > 0 && total > lastBytes {
				bwMbps = float64(total-lastBytes) * 8 / elapsed / 1e6
			}
		}
		lastBytes = total
		lastTime = now

		cpuPct, memPct, diskPct := collectSysMetrics()
		payload, _ := json.Marshal(map[string]interface{}{
			"id":             nodeToken[:min(8, len(nodeToken))],
			"token":          nodeToken,
			"rtt_ms":         exits.MinProbeRTT(),
			"routing_rtt_ms": exits.MinEffectiveRTT(),
			"bytes_total":    total,
			"bw_mbps":        bwMbps,
			"data_plane_ok":  true,
			"cpu_pct":        cpuPct,
			"mem_pct":        memPct,
			"disk_pct":       diskPct,
		})

		start := time.Now()
		resp, err := nodeProxyClient().Post(targetURL, "application/json", strings.NewReader(string(payload)))
		if err != nil {
			logWarnf("heartbeat: via exit %s failed: %v", exit.Addr, err)
			return
		}
		resp.Body.Close()
		dur := time.Since(start).Round(time.Millisecond)
		if resp.StatusCode != http.StatusOK {
			logWarnf("heartbeat: arbiter returned %d via %s dur=%s", resp.StatusCode, exit.Addr, dur)
			return
		}
		logDebugf("heartbeat: ok token=%.8s… bw=%.1fMbps via %s dur=%s", nodeToken, bwMbps, exit.Addr, dur)
	}

	send()
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			send()
		}
	}()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
