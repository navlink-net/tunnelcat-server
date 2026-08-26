// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"tunnel_cat/binlog"
	"tunnel_cat/logevent"
)

// Router selects the best path through available relay nodes to the control.
//
// Route structures (in priority order):
//
//	A:        Client → Relay → Control → Exit
//	B:        Client → Relay → Relay → Control → Exit          (future: route vector)
//	C:        Client → Relay → Relay → Relay → Control → Exit  (future: route vector)
//	Fallback: Client → Control → Exit
//
// Multiple control nodes are supported. BuildPaths generates candidate paths
// across all alive controls; scoring naturally prefers lower-latency controls.
// Advance() cycles through paths, which may switch to a different control.
//
// Control selection policy (see memory/project_control_routing_policy.md):
//   - In-country hard filter: if any in-country control is alive, out-of-country
//     controls are excluded entirely (not just de-prioritised).
//   - RTT threshold: only controls with score ≤ best×1.5 qualify.
//   - Top-5 cap.
//   - RTT is measured via a real HTTP data-plane probe, not a TCP SYN/ACK,
//     so DPI body-stripping is detected at probe time.
//
// When myCountry is set, same-region relays are preferred.  If none are alive
// the router falls back to all alive relays (connectivity beats policy).
type Router struct {
	mu        sync.Mutex
	relays    []*routerNode
	controls  []*routerNode // all known control nodes (replaces single control field)
	paths     []RouterPath
	pathIdx   int
	myCountry string // ISO country code of the client (e.g. "RU"); "" = no filter

	// dataDead maps control addr → expiry time.  A control is excluded from
	// BuildPaths even if TCP-reachable, to handle DPI body-stripping attacks.
	dataDead map[string]time.Time

	// udpDataFailed maps control addr → expiry time.  During the TTL ProbeDataPlane
	// skips the UDP fallback probe so a broken UDP channel is not re-created.
	// After the TTL the probe runs again: if UDP is fixed it re-enables; if still
	// broken it extends the TTL.
	udpDataFailed map[string]time.Time

	selfNodeID string // own DHT node ID; entries with this ID are skipped in MergeDHTRelays

	udpMu    sync.RWMutex
	udpPeers map[string]*UDPRelayConn // nodeID or addr → live UDP relay conn

	// flapMu protects flaps. Separate from mu so RecordControlFlap can be
	// called from data-path goroutines without blocking BuildPaths readers.
	flapMu sync.Mutex
	flaps  map[string][]time.Time // control addr → timestamps of recent stream evictions

	// flapEventCount is a separate lifetime-ish counter, independent of
	// flaps/flapMu, drained by DrainFlapCount for stats reporting. Never
	// read by flapPenaltyOf/scoring -- see DrainFlapCount's doc comment.
	flapEventCount int32
}

// Flap penalty: each stream eviction within flapWindow adds flapPenaltyPerEviction
// to the control's effective RTT, capped at flapPenaltyCap. This deprioritises
// controls that are under active DPI interference without permanently excluding them.
const (
	flapWindow             = 5 * time.Minute
	flapPenaltyPerEviction = 200 * time.Millisecond
	flapPenaltyCap         = 2 * time.Second
)

// Pool size bounds for the set of controls BuildPaths considers "qualifying".
// MinPoolControls: floor for redundancy (matches the client-side top-up floor
// applied again after e2e probing in each main_*.go).
// MaxPoolControls: ceiling so path generation (O(controls × relays^3)) can't
// blow up and so traffic doesn't spread so thin per control that RTT/fail-ratio
// stats never accumulate meaningful sample counts.
//
// Exported (and vars, not consts) so a platform can scale them to device
// capability -- see Android's CoreProcess.kt, which derives both from device
// RAM the same way it already derives GOMEMLIMIT/ChanDepth, and passes them
// via SNC_MIN_POOL_CONTROLS/SNC_MAX_POOL_CONTROLS. No other platform's
// main_*.go sets those env vars, so this default (5/12) is unchanged for them.
var (
	MinPoolControls = 5
	MaxPoolControls = 12
)

// controlTransport records which protocol the router detected for a control node.
type controlTransport uint8

const (
	transportTCP controlTransport = 0 // default; TCP data-plane probe succeeded
	// transportUDP: TCP failed, QUIC handshake succeeded. Named for the old
	// SNCU-over-UDP fallback this replaced; kept as "udp" throughout the
	// public API (ControlTransportName, hook names) since every platform's
	// main_*.go already keys off that string — only the transport underneath
	// changed, not the label.
	transportUDP controlTransport = 1
)

// routerNode is an internal node representation with measurement state.
type routerNode struct {
	ID          string
	Addr        string        // host or host:port
	OperatorID  string        // used to avoid selecting two nodes from the same operator
	CountryCode string        // ISO country code reported by the relay (may be "")
	RTT         time.Duration // 0 = unmeasured; updated by ProbeDataPlane
	TrafficRTT  time.Duration // 0 = unmeasured; updated by passive POST round-trip observation
	Loss        float64       // 0.0–1.0 (reserved for future probing)
	// LoadFactor is the arbiter-computed bonus/malus coefficient from the
	// signed manifest (manifestNode.Load), relative to this node's last-hour
	// traffic share among its type+region peers. <=0 means "no data yet" and
	// must be treated as the neutral 1.0, never as a zero multiplier -- see
	// effectiveLoadFactor. Only ever set for controls (via SetLoadFactors);
	// relays have no such signal and stay at their zero-value default, which
	// is exactly the neutral case.
	LoadFactor float64
	LastSeen   time.Time
	IsAlive    bool
	transport  controlTransport // TCP or UDP; only meaningful for control nodes
}

// RouterPath is a scored candidate path returned by BuildPaths.
type RouterPath struct {
	// Relays is the ordered list of relay hops (0–3 nodes).
	// Currently only len 0 (direct) and len 1 (single relay) are executed;
	// multi-hop entries are generated for scoring but require route-vector
	// support before they can be used.
	Relays      []*RouterPathNode
	ControlAddr string
	Score       float64       // lower is better (ms-equivalent)
	UDPRelay    *UDPRelayConn // non-nil if first relay hop has a live UDP conn (M4.5)
}

// RouterPathNode is a relay node reference returned in RouterPath.
type RouterPathNode struct {
	ID   string
	Addr string
}

func (p *RouterPath) IsDirect() bool { return len(p.Relays) == 0 }

// NewRouter creates an idle router.  Call SetControl + UpdateRelays +
// MeasureRTTs + BuildPaths before using Primary.
func NewRouter() *Router {
	return &Router{
		udpPeers:      make(map[string]*UDPRelayConn),
		dataDead:      make(map[string]time.Time),
		udpDataFailed: make(map[string]time.Time),
	}
}

// SetSelfNodeID tells the router its own DHT node ID so it can exclude itself
// from relay selection in MergeDHTRelays.
func (r *Router) SetSelfNodeID(id string) {
	r.mu.Lock()
	r.selfNodeID = id
	r.mu.Unlock()
}

// MarkControlDataDead temporarily excludes a control from path building even if
// it is TCP-reachable.  Use when the data plane is blocked (e.g. DPI body
// stripping) so BuildPaths routes around it until the deadline.
func (r *Router) MarkControlDataDead(addr string, until time.Time) {
	r.mu.Lock()
	r.dataDead[addr] = until
	r.mu.Unlock()
	logevent.Emit(binlog.TagTunnel, logevent.EventRouterControlMarkedDead,
		logevent.Str(logevent.AttrAddr, addr),
		logevent.Str(logevent.AttrUntil, until.Format(time.RFC3339)))
}

// MarkControlAlive refreshes the liveness timestamp for the control at addr.
// Direct TCP probing (ProbeDataPlane) is skipped entirely in WildCat mode —
// WildCat relay auth success is the real liveness signal there — so without this,
// LastSeen is stamped once at bootstrap and goes stale after 30s, making
// alive() (and therefore BuildPaths/QualifyingControlAddrs) falsely report
// every control as unreachable on the very next rebuild.
func (r *Router) MarkControlAlive(addr string) {
	norm := normaliseAddr(addr)
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range r.controls {
		if n.Addr == norm {
			n.IsAlive = true
			n.LastSeen = time.Now()
			return
		}
	}
}

// SetLoadFactors updates the load-balancing bonus/malus coefficient for each
// known control, keyed by address (post-normalisation). Advisory data from
// the manifest (see Discoverer.LoadFactors), refreshed independently of and
// on a different cadence than SetControlsWithRegions -- call this any time
// after the control list itself has been set. Addresses not present in
// factors, or with a non-positive value, are left untouched (effectiveLoadFactor
// treats a routerNode's zero-value default as neutral already).
func (r *Router) SetLoadFactors(factors map[string]float64) {
	if len(factors) == 0 {
		return
	}
	// factors is keyed by the raw manifest addr string (see
	// Discoverer.LoadFactors), which may not byte-match n.Addr --
	// SetControlsWithRegions stores routerNode.Addr post-normaliseAddr, so
	// normalise the lookup keys the same way before matching.
	norm := make(map[string]float64, len(factors))
	for addr, f := range factors {
		norm[normaliseAddr(addr)] = f
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range r.controls {
		if f, ok := norm[n.Addr]; ok && f > 0 {
			n.LoadFactor = f
		}
	}
}

// LoadFactorFor returns the current load-balancing bonus/malus coefficient
// for the control at addr, or 0 if unknown/unset. Used to refresh a pool
// TunnelDialer's own cached value (see TunnelDialer.SetLoadFactor) after
// SetLoadFactors updates the router's copy.
func (r *Router) LoadFactorFor(addr string) float64 {
	norm := normaliseAddr(addr)
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range r.controls {
		if n.Addr == norm {
			return n.LoadFactor
		}
	}
	return 0
}

// MarkUDPDataFailed forces addr to TCP-only for 5 minutes, e.g. after a live
// QUIC send failure even though the last RTT probe looked fine.  ProbeDataPlane
// skips the QUIC probe for addr during this window so a broken QUIC path is not
// immediately re-selected.  After the TTL, probing resumes and QUIC competes
// on RTT again like any other transport; if still broken, the TTL is extended.
func (r *Router) MarkUDPDataFailed(addr string) {
	r.mu.Lock()
	// Downgrade transport immediately so NewControlDialer returns a TCP dialer.
	for _, c := range r.controls {
		if c.Addr == addr && c.transport == transportUDP {
			c.transport = transportTCP
			break
		}
	}
	r.udpDataFailed[addr] = time.Now().Add(5 * time.Minute)
	r.mu.Unlock()
	logevent.Emit(binlog.TagTunnel, logevent.EventRouterUdpDowngraded,
		logevent.Str(logevent.AttrAddr, addr))
}

// RegisterUDPPeer registers a live UDP relay connection to a peer identified
// by nodeID (or addr when nodeID is unknown).  The router gives this peer a
// score bonus so it is preferred when building paths.
func (r *Router) RegisterUDPPeer(key string, conn *UDPRelayConn) {
	r.udpMu.Lock()
	if old, ok := r.udpPeers[key]; ok {
		old.Close()
	}
	r.udpPeers[key] = conn
	r.udpMu.Unlock()
	Log.Printf("router: udp peer registered key=%s", key)
}

// RemoveUDPPeer removes and closes the UDP relay connection for key.
func (r *Router) RemoveUDPPeer(key string) {
	r.udpMu.Lock()
	if c, ok := r.udpPeers[key]; ok {
		c.Close()
		delete(r.udpPeers, key)
		Log.Printf("router: udp peer removed key=%s", key)
	}
	r.udpMu.Unlock()
}

// CloseAllUDPPeers closes and removes all registered UDP relay connections.
func (r *Router) CloseAllUDPPeers() {
	r.udpMu.Lock()
	for k, c := range r.udpPeers {
		c.Close()
		delete(r.udpPeers, k)
	}
	r.udpMu.Unlock()
}

// udpPeer returns the UDP conn for a relay node (matched by ID or Addr).
func (r *Router) udpPeer(id, addr string) *UDPRelayConn {
	r.udpMu.RLock()
	defer r.udpMu.RUnlock()
	if c, ok := r.udpPeers[id]; ok {
		return c
	}
	if c, ok := r.udpPeers[addr]; ok {
		return c
	}
	return nil
}

// SetMyCountry sets the client's ISO country code (e.g. "RU").
// BuildPaths will only consider relays with a matching CountryCode.
// Pass "" to disable regional filtering (consider all relays).
func (r *Router) SetMyCountry(cc string) {
	r.mu.Lock()
	r.myCountry = cc
	r.mu.Unlock()
	Log.Printf("router: my country set to %q", cc)
}

// SetControls replaces the control node list. The first address is the preferred
// control; additional addresses are fallbacks. Call MeasureRTTs + BuildPaths after.
func (r *Router) SetControls(addrs []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.controls = make([]*routerNode, len(addrs))
	for i, addr := range addrs {
		r.controls[i] = &routerNode{
			ID:         addr,
			Addr:       normaliseAddr(addr),
			OperatorID: addr,
			LastSeen:   time.Now(),
			IsAlive:    true,
		}
	}
}

// SetControl sets a single control node. Compatibility shim; prefer SetControls.
func (r *Router) SetControl(addr string) { r.SetControls([]string{addr}) }

// AddControl appends a single control node to the existing list, unlike
// SetControls/SetControlsWithRegions which replace it wholesale. Used by
// TopupClient (manifest_topup.go) to fold in one already-probed node at a
// time without disturbing the rest of the router's state. No-op if addr is
// already known. Call BuildPaths after, same as SetControls.
func (r *Router) AddControl(addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	norm := normaliseAddr(addr)
	for _, c := range r.controls {
		if c.Addr == norm {
			return
		}
	}
	r.controls = append(r.controls, &routerNode{
		ID:         addr,
		Addr:       norm,
		OperatorID: addr,
		LastSeen:   time.Now(),
		IsAlive:    true,
	})
}

// SetControlsWithRegions sets the control list and annotates each address with
// its ISO country code from the regions map (addr → cc).  Use this instead of
// SetControls whenever region data is available (e.g. from the discoverer manifest
// on Windows or from bypass CIDR classification on Android).
func (r *Router) SetControlsWithRegions(addrs []string, regions map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.controls = make([]*routerNode, len(addrs))
	for i, addr := range addrs {
		cc := ""
		if regions != nil {
			cc = regions[addr]
		}
		r.controls[i] = &routerNode{
			ID:          addr,
			Addr:        normaliseAddr(addr),
			OperatorID:  addr,
			CountryCode: cc,
			LastSeen:    time.Now(),
			IsAlive:     true,
		}
	}
}

// UpdateRelays replaces the relay list.  Existing RTT measurements are
// discarded; call MeasureRTTs afterwards.
func (r *Router) UpdateRelays(relays []RelayEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.relays = make([]*routerNode, len(relays))
	for i, re := range relays {
		host := re.Addr
		if h, _, err := net.SplitHostPort(re.Addr); err == nil {
			host = h // use only host for operator ID
		}
		r.relays[i] = &routerNode{
			ID:          re.NodeID,
			Addr:        normaliseAddr(re.Addr),
			OperatorID:  host,
			CountryCode: re.CountryCode,
			LastSeen:    time.Now(),
			IsAlive:     true,
		}
	}
}

// MergeDHTRelays adds relay entries discovered via the DHT that are not already
// known from the control API.  Existing relay RTT measurements are preserved.
// New entries are inserted with IsAlive=true; they will be probed on the next
// MeasureRTTs call.
func (r *Router) MergeDHTRelays(entries []DHTRelayEntry) {
	if len(entries) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	// Build a set of already-known node IDs.
	known := make(map[string]struct{}, len(r.relays))
	for _, n := range r.relays {
		known[n.ID] = struct{}{}
	}

	added := 0
	for _, e := range entries {
		if _, exists := known[e.NodeID]; exists {
			continue
		}
		if r.selfNodeID != "" && e.NodeID == r.selfNodeID {
			continue // never route through ourselves
		}
		host := e.Addr
		if h, _, err := net.SplitHostPort(e.Addr); err == nil {
			host = h
		}
		r.relays = append(r.relays, &routerNode{
			ID:          e.NodeID,
			Addr:        normaliseAddr(e.Addr),
			OperatorID:  host,
			CountryCode: e.CountryCode,
			LastSeen:    time.Now(),
			IsAlive:     true,
		})
		known[e.NodeID] = struct{}{}
		added++
	}
	if added > 0 {
		Log.Printf("router: merged %d DHT relay(s) (total=%d)", added, len(r.relays))
	}
}

// MarkRelayAlive marks the relay identified by id (NodeID or Addr) as alive
// with the current timestamp.  Call this when a UDP hole-punch connection to
// the relay is successfully established.
func (r *Router) MarkRelayAlive(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range r.relays {
		if n.ID == id || n.Addr == id {
			n.IsAlive = true
			n.LastSeen = time.Now()
			Log.Printf("router: relay %s marked alive (UDP hole-punch)", n.Addr)
			return
		}
	}
}

// ProbeDataPlane probes the data plane health of control nodes:
//   - Controls: HTTP GET /p/v1/ping via the uTLS ChRelayAPI channel (H1) over
//     TCP, and the same ping over a real QUIC handshake, run concurrently.
//     A non-empty response body confirms the data plane is intact — a
//     TCP-only probe would pass even when DPI strips HTTP bodies.
//     Whichever transport answers with the lower RTT is recorded as the
//     node's transport for routing purposes — QUIC is a real alternative
//     dialer chosen on RTT merit, not a fallback only tried when TCP fails.
//   - Relays are NOT probed via TCP (they are NAT-behind client nodes, not servers).
//     Relay liveness is determined by RegisterUDPPeer / MarkRelayAlive only.
//
// Nodes that fail both probes are marked !IsAlive; a node alive on only one
// transport is recorded with that transport's RTT.
// Call this instead of MeasureRTTs whenever reliable data-plane detection matters.
func (r *Router) ProbeDataPlane(timeout time.Duration) {
	r.mu.Lock()
	controls := make([]*routerNode, len(r.controls))
	copy(controls, r.controls)
	r.mu.Unlock()

	var wg sync.WaitGroup

	for _, n := range controls {
		wg.Add(1)
		go func(n *routerNode) {
			defer wg.Done()

			r.mu.Lock()
			quicSuppressed := time.Now().Before(r.udpDataFailed[n.Addr])
			r.mu.Unlock()

			var tcpWG sync.WaitGroup
			var tcpRTT, quicRTT time.Duration
			var tcpOK, quicOK bool

			tcpWG.Add(1)
			go func() {
				defer tcpWG.Done()
				tcpRTT, tcpOK = probeControlPing(n.Addr, timeout)
			}()
			if !quicSuppressed {
				tcpWG.Add(1)
				go func() {
					defer tcpWG.Done()
					quicRTT, quicOK = ProbeControlQUIC(n.Addr, timeout)
				}()
			}
			tcpWG.Wait()

			r.mu.Lock()
			defer r.mu.Unlock()
			switch {
			case tcpOK && (!quicOK || tcpRTT <= quicRTT):
				n.RTT = tcpRTT
				n.IsAlive = true
				n.LastSeen = time.Now()
				n.transport = transportTCP
			case quicOK:
				n.RTT = quicRTT
				n.IsAlive = true
				n.LastSeen = time.Now()
				n.transport = transportUDP
				Log.Printf("router: control %s QUIC faster/only-alive rtt=%s (tcp ok=%v)", n.Addr, quicRTT, tcpOK)
			default:
				n.IsAlive = false
				n.transport = transportTCP // reset to default
				if quicSuppressed {
					Log.Printf("router: control %s TCP failed, QUIC suppressed (data-failed TTL active)", n.Addr)
				} else {
					Log.Printf("router: control %s TCP+QUIC both failed", n.Addr)
				}
			}
		}(n)
	}

	wg.Wait()
}

// QuickHealthCheck reports whether addr (a control's host:port) responds to
// a bounded-duration ping. Exported for callers outside snc/core that need a
// cheap "is the tunnel likely still usable" signal without going through the
// full Router/DialerPool machinery -- e.g. a platform's power-resume handler
// deciding whether a wake event actually needs a full reconnect, or whether
// the existing session probably survived the sleep.
func QuickHealthCheck(addr string, timeout time.Duration) bool {
	_, ok := probeControlPing(addr, timeout)
	return ok
}

// probeControlPing performs GET https://<addr>/p/v1/ping and returns the
// round-trip time.  ok=false when the control is unreachable or reports no
// alive exits (body.OK=false).  Mirrors ProbeControlE2E so that ProbeDataPlane
// and buildViableAddrs use the same liveness definition.
func probeControlPing(addr string, timeout time.Duration) (rtt time.Duration, ok bool) {
	client := newUTLSH1Client(true)
	client.Timeout = timeout
	url := fmt.Sprintf("https://%s/p/v1/ping", addr)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, false
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	var body struct {
		OK    bool    `json:"ok"`
		RTTMs float64 `json:"rtt_ms"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || !body.OK {
		return 0, false
	}
	elapsed := time.Since(start)
	if body.RTTMs > 0 {
		return elapsed + time.Duration(body.RTTMs*float64(time.Millisecond)), true
	}
	return elapsed, true
}

// ProbeControlE2E performs GET https://<addr>/p/v1/ping and returns the
// end-to-end RTT: the control's best measured exit latency reported in the
// response body.  Returns ok=false when the control is unreachable or reports
// no alive exits (empty body).  Uses the same uTLS transport as the tunnel so
// the probe is subject to the same DPI and dialControl constraints.
func ProbeControlE2E(addr string, timeout time.Duration) (rtt time.Duration, ok bool) {
	client := newUTLSH1Client(true)
	client.Timeout = timeout
	url := fmt.Sprintf("https://%s/p/v1/ping", addr)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, false
	}
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, false
	}
	defer resp.Body.Close()
	var body struct {
		OK    bool    `json:"ok"`
		RTTMs float64 `json:"rtt_ms"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || !body.OK {
		return 0, false
	}
	elapsed := time.Since(start)
	if body.RTTMs > 0 {
		return elapsed + time.Duration(body.RTTMs*float64(time.Millisecond)), true
	}
	// Control alive but no exit RTT measured yet (fresh start). Return elapsed
	// so the caller treats this as a live path with a real measured latency.
	return elapsed, true
}

// UpdateControlRTT overwrites the stored RTT for addr with the given value.
// Used by buildPoolDialers to feed real e2e latency into path scoring after
// a ProbeControlE2E call, replacing the TCP-only RTT from ProbeDataPlane.
func (r *Router) UpdateControlRTT(addr string, rtt time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, n := range r.controls {
		if n.Addr == addr {
			n.RTT = rtt
			return
		}
	}
}

// ControlRTT returns the effective RTT for addr including any flap penalty,
// or 0 if the address is unknown. Used to sort pool dialers by effective
// latency so dialers[0] is always the best available control. QUIC-transported
// controls (transportUDP) are not penalized relative to TCP ones — since
// ProbeDataPlane already picks whichever transport measured the lower RTT for
// each node, n.RTT is directly comparable across transports as-is.
func (r *Router) ControlRTT(addr string) time.Duration {
	r.mu.Lock()
	var rtt time.Duration
	for _, n := range r.controls {
		if n.Addr == addr {
			rtt = n.RTT
			break
		}
	}
	r.mu.Unlock()
	penalty := time.Duration(r.flapPenaltyOf(addr) * float64(time.Millisecond))
	return rtt + penalty
}

// RecordControlFlap records one stream eviction for addr. Called from the
// dialer's first-fail hook so the router deprioritises controls that are
// under active DPI interference within the rolling flapWindow.
func (r *Router) RecordControlFlap(addr string) {
	r.flapMu.Lock()
	defer r.flapMu.Unlock()
	now := time.Now()
	if r.flaps == nil {
		r.flaps = make(map[string][]time.Time)
	}
	cutoff := now.Add(-flapWindow)
	prev := r.flaps[addr]
	kept := prev[:0]
	for _, t := range prev {
		if !t.Before(cutoff) {
			kept = append(kept, t)
		}
	}
	r.flaps[addr] = append(kept, now)
	atomic.AddInt32(&r.flapEventCount, 1)
}

// DrainFlapCount returns and resets flapEventCount -- mirrors
// DialerPool.DrainEvictions' read-and-reset shape, for connection-stats
// reporting (ConnStatsCollector). Deliberately a SEPARATE counter from
// r.flaps (never touches it): r.flaps is live routing state that
// flapPenaltyOf sums over a rolling window on every scoring pass -- clearing
// it here to serve a stats snapshot would silently zero out the penalty
// every controls actually still deserve until new flaps re-accumulate,
// a real regression to existing routing behaviour, not just an unused
// side effect.
func (r *Router) DrainFlapCount() int {
	return int(atomic.SwapInt32(&r.flapEventCount, 0))
}

// flapPenaltyOf returns the penalty in milliseconds for addr based on recent
// stream evictions within flapWindow. Safe to call while r.mu is held.
func (r *Router) flapPenaltyOf(addr string) float64 {
	r.flapMu.Lock()
	defer r.flapMu.Unlock()
	if r.flaps == nil {
		return 0
	}
	cutoff := time.Now().Add(-flapWindow)
	count := 0
	for _, t := range r.flaps[addr] {
		if !t.Before(cutoff) {
			count++
		}
	}
	penalty := float64(count) * float64(flapPenaltyPerEviction.Milliseconds())
	cap := float64(flapPenaltyCap.Milliseconds())
	if penalty > cap {
		return cap
	}
	return penalty
}

// MeasureRTTs probes all relays and all control nodes concurrently via TCP dial.
// Nodes that fail to connect within timeout are marked !IsAlive.
// Deprecated: use ProbeDataPlane for production use; MeasureRTTs does not detect
// DPI body-stripping because it only checks TCP reachability.
func (r *Router) MeasureRTTs(timeout time.Duration) {
	r.mu.Lock()
	nodes := make([]*routerNode, len(r.relays))
	copy(nodes, r.relays)
	nodes = append(nodes, r.controls...)
	r.mu.Unlock()

	var wg sync.WaitGroup
	for _, n := range nodes {
		wg.Add(1)
		go func(n *routerNode) {
			defer wg.Done()
			start := time.Now()
			conn, err := net.DialTimeout("tcp", n.Addr, timeout)
			r.mu.Lock()
			if err != nil {
				n.IsAlive = false
			} else {
				conn.Close()
				n.RTT = time.Since(start)
				n.IsAlive = true
				n.LastSeen = time.Now()
			}
			r.mu.Unlock()
		}(n)
	}
	wg.Wait()
}

// BuildPaths generates, scores, and stores the top-5 candidate paths across all
// alive control nodes.  Call after MeasureRTTs.  The result is accessible via
// Primary / Advance.
func (r *Router) BuildPaths() {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Collect alive control nodes split by country so we can supplement later.
	var aliveControls, outOfCountry []*routerNode
	for _, c := range r.controls {
		if r.alive(c) {
			aliveControls = append(aliveControls, c)
		}
	}
	if r.myCountry != "" {
		var inCountry []*routerNode
		for _, c := range aliveControls {
			if c.CountryCode == r.myCountry {
				inCountry = append(inCountry, c)
			} else {
				outOfCountry = append(outOfCountry, c)
			}
		}
		if len(inCountry) > 0 {
			Log.Printf("router: %d in-country control(s) available (cc=%s) — excluding %d out-of-country",
				len(inCountry), r.myCountry, len(outOfCountry))
			aliveControls = inCountry
		} else {
			Log.Printf("router: no in-country controls (cc=%s) — using all %d alive controls",
				r.myCountry, len(aliveControls))
			outOfCountry = nil // already all included
		}
	}
	// QUIC (transportUDP) is a real alternative transport now, chosen by
	// ProbeDataPlane on RTT merit against TCP for each control individually —
	// no hard TCP-preference filter here. A control's transport only affects
	// which TunnelDialer NewControlDialer builds for it; pool ordering is by
	// ControlRTT (which is directly comparable across transports) alone.

	if len(aliveControls) == 0 {
		r.paths = nil
		Log.Printf("router: all controls unreachable")
		return
	}

	// Pool size bounds: at least MinPoolControls for redundancy (losing one
	// control shouldn't ever leave a client down to a single point of
	// failure), at most MaxPoolControls so path-generation below (which is
	// O(controls × relays^3)) can't blow up and so traffic isn't spread so
	// thin across controls that per-control RTT stats never accumulate
	// meaningful sample counts. Mirrors the client-side 5..12 bound applied
	// again after e2e probing in each main_*.go.
	if len(aliveControls) < MinPoolControls && len(outOfCountry) > 0 {
		sort.Slice(outOfCountry, func(i, j int) bool {
			return r.nodeScore(outOfCountry[i]) < r.nodeScore(outOfCountry[j])
		})
		need := MinPoolControls - len(aliveControls)
		if need > len(outOfCountry) {
			need = len(outOfCountry)
		}
		Log.Printf("router: pool < %d after filtering — supplementing with %d out-of-country control(s)", MinPoolControls, need)
		aliveControls = append(aliveControls, outOfCountry[:need]...)
	}
	if len(aliveControls) > MaxPoolControls {
		sort.Slice(aliveControls, func(i, j int) bool {
			return r.nodeScore(aliveControls[i]) < r.nodeScore(aliveControls[j])
		})
		Log.Printf("router: %d controls after filtering — capping to best %d", len(aliveControls), MaxPoolControls)
		aliveControls = aliveControls[:MaxPoolControls]
	}

	// R_best: alive relays within 30 s, sorted by effective RTT+loss, top 20.
	// When myCountry is set, restrict to same-region relays only.
	var live []*routerNode
	for _, n := range r.relays {
		if r.alive(n) {
			if r.myCountry == "" || n.CountryCode == r.myCountry {
				live = append(live, n)
			}
		}
	}
	if r.myCountry != "" && len(live) == 0 {
		Log.Printf("router: no same-region relays (country=%s) — falling back to all alive relays", r.myCountry)
		for _, n := range r.relays {
			if r.alive(n) {
				live = append(live, n)
			}
		}
	}
	sort.Slice(live, func(i, j int) bool {
		return r.nodeScore(live[i]) < r.nodeScore(live[j])
	})
	if len(live) > 20 {
		live = live[:20]
	}

	var paths []RouterPath

	// Generate candidate paths for every alive control node.
	for _, ctrl := range aliveControls {
		// Direct path via this control.
		paths = append(paths, RouterPath{ControlAddr: ctrl.Addr})

		// 1-relay paths.
		for _, r1 := range live {
			paths = append(paths, RouterPath{
				Relays:      []*RouterPathNode{{ID: r1.ID, Addr: r1.Addr}},
				ControlAddr: ctrl.Addr,
			})

			// 2-relay paths (generated for future use; not yet executed).
			for _, r2 := range live {
				if r2.ID == r1.ID || r2.OperatorID == r1.OperatorID {
					continue
				}
				paths = append(paths, RouterPath{
					Relays: []*RouterPathNode{
						{ID: r1.ID, Addr: r1.Addr},
						{ID: r2.ID, Addr: r2.Addr},
					},
					ControlAddr: ctrl.Addr,
				})

				// 3-relay paths (generated for future use; not yet executed).
				for _, r3 := range live {
					if r3.ID == r1.ID || r3.ID == r2.ID {
						continue
					}
					if r3.OperatorID == r1.OperatorID || r3.OperatorID == r2.OperatorID {
						continue
					}
					paths = append(paths, RouterPath{
						Relays: []*RouterPathNode{
							{ID: r1.ID, Addr: r1.Addr},
							{ID: r2.ID, Addr: r2.Addr},
							{ID: r3.ID, Addr: r3.Addr},
						},
						ControlAddr: ctrl.Addr,
					})
				}
			}
		}
	}

	// Score all paths (scorePath looks up the control node by ControlAddr).
	for i := range paths {
		paths[i].Score = r.scorePath(&paths[i], aliveControls, live)
	}

	candidates := paths

	// Sort: relay paths first (obscure signature), then by score.
	sort.SliceStable(candidates, func(i, j int) bool {
		iRelay := len(candidates[i].Relays) > 0
		jRelay := len(candidates[j].Relays) > 0
		if iRelay != jRelay {
			return iRelay // relay paths go first
		}
		return candidates[i].Score < candidates[j].Score
	})

	// Cap the final candidate list, but guarantee every alive control keeps
	// at least its own single best-scoring path before applying the cut.
	// Without this, one control paired with several relays can occupy every
	// slot on its own -- all of its relay-paths sort ahead of every other
	// control's paths (relay paths sort first, above), regardless of how
	// good those other controls' own scores are -- silently excluding
	// otherwise-healthy controls from QualifyingControlAddrs (and therefore
	// from DialerPool) entirely, not just under-weighting them. One slot per
	// control covers DialerPool's needs; the small headroom on top keeps
	// some relay-path variety for Router.Primary/Advance.
	capN := len(aliveControls) + 5
	if capN > len(candidates) {
		capN = len(candidates)
	}
	if len(candidates) > capN {
		seen := make(map[string]bool, len(aliveControls))
		var guaranteed, rest []RouterPath
		for _, p := range candidates {
			if !seen[p.ControlAddr] {
				seen[p.ControlAddr] = true
				guaranteed = append(guaranteed, p)
			} else {
				rest = append(rest, p)
			}
		}
		// Both guaranteed and rest are subsequences of the sort above, so
		// each stays in relay-first/score order; append rest to top up.
		out := guaranteed
		for _, p := range rest {
			if len(out) >= capN {
				break
			}
			out = append(out, p)
		}
		candidates = out
	}

	// Shuffle all candidates so every reconnect picks a random path from the
	// full pool of alive controls. Score-based sorting above ensures the pool
	// is ordered, but weighted randomisation across all entries avoids
	// permanently pinning to the same control under partial interference.
	rand.Shuffle(len(candidates), func(i, j int) {
		candidates[i], candidates[j] = candidates[j], candidates[i]
	})

	r.paths = candidates
	r.pathIdx = 0

	var best float64
	for _, p := range r.paths {
		if best == 0 || p.Score < best {
			best = p.Score
		}
	}
	logevent.Emit(binlog.TagTunnel, logevent.EventRouterPathsBuilt,
		logevent.Int(logevent.AttrCount, int64(len(r.paths))),
		logevent.Int(logevent.AttrBestMs, int64(best)))
	for i, p := range r.paths {
		tag := "direct"
		if len(p.Relays) > 0 {
			tag = p.Relays[0].Addr
		}
		logevent.Emit(binlog.TagTunnel, logevent.EventRouterPathEntry,
			logevent.Int(logevent.AttrIndex, int64(i)),
			logevent.Int(logevent.AttrScore, int64(p.Score)),
			logevent.Int(logevent.AttrHops, int64(len(p.Relays))),
			logevent.Str(logevent.AttrVia, tag))
	}
}

// Primary returns the current top-ranked path, or nil if none.
func (r *Router) Primary() *RouterPath {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.paths) == 0 {
		return nil
	}
	p := r.paths[r.pathIdx]
	return &p
}

// Advance marks the current path as failed and moves to the next candidate.
// Returns true if a new path is available, false if all paths are exhausted
// (index wraps back to 0 so the next call to Primary returns the top path).
func (r *Router) Advance() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pathIdx+1 < len(r.paths) {
		r.pathIdx++
		Log.Printf("router: advanced to path[%d]", r.pathIdx)
		return true
	}
	r.pathIdx = 0
	Log.Printf("router: all paths exhausted, wrapping to path[0]")
	return false
}

// Reset returns the path index to 0 (top-ranked path).
func (r *Router) Reset() {
	r.mu.Lock()
	r.pathIdx = 0
	r.mu.Unlock()
}

// PickRandom returns a random path from the current top-N candidates.
// Unlike Primary, it does not advance pathIdx — each call picks independently.
// Use this to distribute concurrent SOCKS5 connections across the qualifying pool.
func (r *Router) PickRandom() *RouterPath {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.paths) == 0 {
		return nil
	}
	p := r.paths[rand.Intn(len(r.paths))]
	return &p
}

// PrimaryIsBetter reports whether switching to the primary path's control is
// warranted.  It returns (true, primary) when:
//   - the primary control differs from currentAddr, AND
//   - the primary's score is at least `factor` times lower than the best score
//     of the current control among the candidate paths (e.g. factor=1.5 means
//     the current control must be ≥50% slower to trigger a switch).
//
// If the current control is absent from all paths (dead), any alive primary is
// preferable and the function returns (true, primary) immediately.
// Returns (false, nil) when staying on the current control is correct.
func (r *Router) PrimaryIsBetter(currentAddr string, factor float64) (bool, *RouterPath) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.paths) == 0 {
		return false, nil
	}
	p := r.paths[r.pathIdx]
	norm := normaliseAddr(currentAddr)
	if p.ControlAddr == norm {
		return false, nil // already on the primary control
	}
	// Find the best score for the current control among candidate paths.
	currentBest := 0.0
	found := false
	for _, path := range r.paths {
		if path.ControlAddr == norm && (!found || path.Score < currentBest) {
			currentBest = path.Score
			found = true
		}
	}
	if !found {
		// Current control has dropped out of all paths — switch immediately.
		return true, &p
	}
	// Switch only when the primary is strictly better by the required margin.
	return p.Score*factor <= currentBest, &p
}

// Paths returns a snapshot of the current candidate paths (post-BuildPaths).
// Used by DialerPool to determine which control addresses qualify.
func (r *Router) Paths() []RouterPath {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RouterPath, len(r.paths))
	copy(out, r.paths)
	return out
}

// QualifyingControlAddrs returns the unique control addresses present in the
// current candidate paths (post-BuildPaths).  The DialerPool authenticates to
// each of these and distributes connections randomly across them.
func (r *Router) QualifyingControlAddrs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := make(map[string]struct{}, len(r.paths))
	var out []string
	for _, p := range r.paths {
		if _, ok := seen[p.ControlAddr]; !ok {
			seen[p.ControlAddr] = struct{}{}
			out = append(out, p.ControlAddr)
		}
	}
	return out
}

// BalanceByTransport caps addrs (assumed already sorted best-first, e.g. by
// e2e RTT) at max entries while guaranteeing real transport diversity in the
// pool: TCP and QUIC are co-equal transports, not a primary/fallback pair --
// letting a pure RTT sort fill the whole pool with whichever one happens to
// win more probe races risks losing ALL redundancy on that transport the
// moment it degrades on the client's actual network (confirmed live
// 2026-08-25: a mobile client whose QUIC path was silently blackholed had
// its entire pool won by QUIC, so nothing fell back to TCP until the
// last-resort watchdog eventually fired a full restart -- if even one TCP
// dialer had been in the pool, none of that would have been needed).
// Reserves up to half of max for each transport, backfilling from whichever
// group has more entries if the other can't fill its half, then re-sorts
// the combined result by ControlRTT so the best working connections still
// come first overall -- diversity is added on top of quality, not instead
// of it.
func (r *Router) BalanceByTransport(addrs []string, max int) []string {
	if max <= 0 || len(addrs) <= max {
		return addrs
	}
	var tcp, quic []string
	for _, a := range addrs {
		if r.ControlTransport(a) == transportUDP {
			quic = append(quic, a)
		} else {
			tcp = append(tcp, a)
		}
	}
	tcpN, quicN := max/2, max-max/2
	if len(tcp) < tcpN {
		quicN += tcpN - len(tcp)
		tcpN = len(tcp)
	}
	if len(quic) < quicN {
		tcpN += quicN - len(quic)
		quicN = len(quic)
	}
	if tcpN > len(tcp) {
		tcpN = len(tcp)
	}
	out := append(append([]string(nil), tcp[:tcpN]...), quic[:quicN]...)
	sort.Slice(out, func(i, j int) bool {
		ri, rj := r.ControlRTT(out[i]), r.ControlRTT(out[j])
		if ri == 0 {
			return false
		}
		if rj == 0 {
			return true
		}
		return ri < rj
	})
	return out
}

// AllControlAddrs returns every known control address regardless of liveness.
// TCP-based liveness (alive/LastSeen) is meaningless in WildCat mode — direct
// TCP to controls is blocked, so ProbeDataPlane never runs and LastSeen goes
// stale after 30s. Filtering through QualifyingControlAddrs (which only
// returns addrs present in r.paths, itself built from r.alive()) creates a
// one-way death spiral: a control that drops out from staleness is never
// retried, so it never gets marked alive again, so it never returns. WildCat
// pool building must use this instead — relay auth success is the only
// liveness signal that matters there.
func (r *Router) AllControlAddrs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.controls))
	for i, c := range r.controls {
		out[i] = c.Addr
	}
	return out
}

// UnreachableControls returns control addresses that are known but currently
// not alive — i.e. candidates for relay-assisted access.
func (r *Router) UnreachableControls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, c := range r.controls {
		if !r.alive(c) {
			out = append(out, c.Addr)
		}
	}
	return out
}

// HasUDPPeer reports whether a live UDP relay connection exists for the given node ID.
func (r *Router) HasUDPPeer(nodeID string) bool {
	r.udpMu.Lock()
	defer r.udpMu.Unlock()
	c, ok := r.udpPeers[nodeID]
	return ok && !c.Failed()
}

// ControlTransport returns the transport protocol detected for addr by the last
// ProbeDataPlane call.  Returns transportTCP for unknown addresses.
func (r *Router) ControlTransport(addr string) controlTransport {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.controls {
		if c.Addr == addr {
			return c.transport
		}
	}
	return transportTCP
}

// ControlTransportName returns a human-readable transport name for addr ("tcp" or "udp").
func (r *Router) ControlTransportName(addr string) string {
	if r.ControlTransport(addr) == transportUDP {
		return "udp"
	}
	return "tcp"
}

// NewControlDialer creates the appropriate TunnelDialer for a qualifying control
// address.  When ProbeDataPlane detected that addr is only reachable via QUIC,
// the returned dialer sends all tunnel traffic over a QUIC connection to the
// control.  Otherwise a standard TCP-backed TunnelDialer is returned.
func (r *Router) NewControlDialer(addr string, auth *Authenticator) (*TunnelDialer, error) {
	if r.ControlTransport(addr) == transportUDP {
		return NewQUICRelayDialer(addr, auth), nil
	}
	return NewTunnelDialer(auth), nil
}

// ── internal helpers ──────────────────────────────────────────────────────────

func (r *Router) alive(n *routerNode) bool {
	if !n.IsAlive || time.Since(n.LastSeen) >= 30*time.Second {
		return false
	}
	if exp, bad := r.dataDead[n.Addr]; bad && time.Now().Before(exp) {
		return false
	}
	return true
}

// UpdateTrafficRTT records a passive round-trip observation for the node at addr.
// addr is matched after normalisation (scheme + path stripped, :443 appended if
// no port is present).  Silently ignored if addr does not match any known node.
func (r *Router) UpdateTrafficRTT(addr string, rtt time.Duration) {
	norm := normaliseAddr(addr)
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.controls {
		if c.Addr == norm {
			c.TrafficRTT = rtt
			return
		}
	}
	for _, rel := range r.relays {
		if rel.Addr == norm {
			rel.TrafficRTT = rtt
			return
		}
	}
}

// effectiveLoadFactor returns n.LoadFactor, or the neutral 1.0 when unset
// (<=0). "Unset" covers: relays (never given a load factor at all), and
// controls before the arbiter has computed one yet or with load-factor
// balancing administratively disabled (recomputeLoadFactors resets to 0 in
// that case, see snc-arbiter/load_factor.go) -- all of which must fall back
// to pure RTT-based scoring, not a zero-weight multiplier that would erase
// the node from consideration entirely.
func effectiveLoadFactor(f float64) float64 {
	if f <= 0 {
		return 1.0
	}
	return f
}

func (r *Router) nodeScore(n *routerNode) float64 {
	// Blend probe RTT with traffic RTT when both are available.
	// Traffic RTT (passive POST observation) reflects real node load;
	// probe RTT (synthetic ping) captures baseline latency.
	rtt := n.RTT
	if n.TrafficRTT > 0 && n.RTT > 0 {
		rtt = time.Duration(0.3*float64(n.RTT) + 0.7*float64(n.TrafficRTT))
	} else if n.TrafficRTT > 0 {
		rtt = n.TrafficRTT
	}
	// Load factor multiplies the latency term only -- it's a bonus/malus on
	// top of RTT-based routing (per explicit design decision, 2026-08-11),
	// not a replacement for it and not something that should scale the flap
	// penalty (which already has its own independent reasoning).
	return float64(rtt.Milliseconds())*effectiveLoadFactor(n.LoadFactor) + n.Loss*100 + r.flapPenaltyOf(n.Addr)
}

func instabilityPenalty(n *routerNode) float64 {
	since := time.Since(n.LastSeen)
	switch {
	case since > 15*time.Second:
		return 100
	case since > 5*time.Second:
		return 20
	default:
		return 0
	}
}

func (r *Router) scorePath(p *RouterPath, controls []*routerNode, live []*routerNode) float64 {
	// Control contribution: find the control node matching this path's ControlAddr.
	var ctrl *routerNode
	for _, c := range controls {
		if c.Addr == p.ControlAddr {
			ctrl = c
			break
		}
	}
	var s float64
	if ctrl != nil {
		s = float64(ctrl.RTT.Milliseconds())*effectiveLoadFactor(ctrl.LoadFactor) + ctrl.Loss*100 + instabilityPenalty(ctrl)
	}

	// Relay contributions.
	for i, rn := range p.Relays {
		var node *routerNode
		for _, n := range live {
			if n.ID == rn.ID {
				node = n
				break
			}
		}
		if node != nil {
			s += float64(node.RTT.Milliseconds()) + node.Loss*100 + instabilityPenalty(node)
		}
		s += 10 // 10 ms relay overhead per hop

		// UDP bonus: direct P2P path has lower effective latency.
		if i == 0 {
			if uc := r.udpPeer(rn.ID, rn.Addr); uc != nil {
				p.UDPRelay = uc
				s -= 30 // 30 ms bonus for live UDP hole punch
			}
		}
	}
	return s
}

// normaliseAddr ensures addr is in "host:port" form.
func normaliseAddr(addr string) string {
	for _, prefix := range []string{"https://", "http://"} {
		addr = trimPrefix(addr, prefix)
	}
	if i := indexByte(addr, '/'); i >= 0 {
		addr = addr[:i]
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return addr + ":443"
	}
	return addr
}

func trimPrefix(s, prefix string) string {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
