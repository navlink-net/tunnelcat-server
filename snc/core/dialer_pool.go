// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

// dialerState is the lifecycle state of a slot in DialerPool.
type dialerState int8

const (
	// dialerStandby is a warm, authenticated dialer eligible for Pick().
	dialerStandby dialerState = iota
	// dialerDraining accepts no new connections; transitions back to dialerStandby
	// once OpenConns() drops to zero.
	dialerDraining
)

type dialerSlot struct {
	dialer *TunnelDialer
	state  dialerState
}

// DialerPool manages a set of TunnelDialers with RTT-weighted selection.
//
// Pick() selects from all non-draining dialers with probability proportional
// to 1/RTT, so faster controls receive more connections automatically.
// Dialers without sufficient RTT data yet receive a default weight equivalent
// to defaultPickRTT so new dialers participate until real measurements arrive.
// Draining dialers finish in-flight connections then return to standby.
type DialerPool struct {
	mu           sync.Mutex
	slots        []*dialerSlot
	evictCount   int32 // incremented by Evict; read+reset by DrainEvictions
	activityHook func()
	affinity     map[string]hostAffinityEntry // destination host -> sticky dialer, see PickForHost
	appAffinity  map[int]*TunnelDialer        // app UID -> sticky dialer, see PickForUID
}

// hostAffinityEntry is one destination host's sticky dialer choice.
type hostAffinityEntry struct {
	dialer *TunnelDialer
	at     time.Time
}

// defaultPickRTT is the assumed RTT for dialers with no measured data yet.
const defaultPickRTT = time.Second

// hostAffinityTTL bounds how long a destination host stays pinned to the
// same dialer before PickForHost is willing to re-roll it. Long enough to
// cover one browsing session's worth of parallel/repeat connections to the
// same site (the actual goal -- see PickForHost), short enough that the
// affinity map doesn't grow unbounded over a multi-hour/multi-day VPN
// session visiting thousands of distinct hosts.
const hostAffinityTTL = 10 * time.Minute

// softMinQuality floors the reliability multiplier applied in pickWeight so a
// struggling-but-not-yet-evicted dialer keeps some chance of being picked
// (useful when it's briefly the only in-country control available) rather
// than dropping to near-zero weight before the hard-eviction thresholds in
// recordDialOutcome (50%/80%) even get a chance to fire.
const softMinQuality = 0.1

// NewDialerPool creates a pool from the given dialers (all start as standby).
func NewDialerPool(dialers []*TunnelDialer) *DialerPool {
	p := &DialerPool{}
	for _, d := range dialers {
		p.slots = append(p.slots, &dialerSlot{dialer: d, state: dialerStandby})
	}
	return p
}

// SetActivityHook registers fn to be called on every tunnel POST by any dialer.
func (p *DialerPool) SetActivityHook(fn func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.activityHook = fn
	for _, s := range p.slots {
		s.dialer.SetActivityHook(fn)
	}
}

// Pick selects a dialer with probability proportional to 1/RTT.
// Returns nil only when every slot is draining or the pool is empty.
func (p *DialerPool) Pick() *TunnelDialer {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pickLocked(nil)
}

// PickExcluding selects a dialer the same way as Pick, but never returns
// exclude. Used to retry a dial that just failed against a different pool
// member instead of hammering the same one again (a brief blip on one
// control node shouldn't cost the caller the full retry budget against that
// same node — see the 2026-08-12 incident this was added for). Returns nil
// if exclude is the only non-draining dialer available, same as Pick()
// returning nil for an empty pool: the caller has nothing else to try.
func (p *DialerPool) PickExcluding(exclude *TunnelDialer) *TunnelDialer {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pickLocked(exclude)
}

// pickLocked does the RTT-weighted random draw behind Pick/PickExcluding/
// PickForHost/PickForUID, optionally excluding one dialer. Callers must hold
// p.mu -- factored out so callers that need to check-then-pick-then-pin
// under one continuous lock hold (PickForHost, PickForUID) can do so without
// a nested self-deadlock on the non-reentrant p.mu.
func (p *DialerPool) pickLocked(exclude *TunnelDialer) *TunnelDialer {
	var total float64
	for _, s := range p.slots {
		if s.state == dialerDraining || s.dialer == exclude {
			continue
		}
		total += pickWeight(s.dialer)
	}
	if total == 0 {
		return nil
	}

	r := rand.Float64() * total
	for _, s := range p.slots {
		if s.state == dialerDraining || s.dialer == exclude {
			continue
		}
		r -= pickWeight(s.dialer)
		if r <= 0 {
			return s.dialer
		}
	}
	// Floating-point residual: return last eligible dialer.
	for i := len(p.slots) - 1; i >= 0; i-- {
		if p.slots[i].state != dialerDraining && p.slots[i].dialer != exclude {
			return p.slots[i].dialer
		}
	}
	return nil
}

// PickForHost returns a dialer for connections to host, keeping the same
// dialer for repeat/parallel connections to the same host within
// hostAffinityTTL instead of Pick's per-connection random draw. Browsers
// routinely open several parallel TCP connections per page load; without
// this, those connections could land on different controls (and therefore
// different exit IPs) purely by chance, which some sites' abuse detection
// reads as session hijacking / a shared proxy pool (confirmed live,
// 2026-08-17: a single browsing session tripped Google's "unusual traffic"
// block after two of its parallel connections came from two different
// legitimate exit IPs). host should be the bare hostname (no port) -- see
// remoteHost.
//
// Falls through to a fresh Pick() -- and re-pins the affinity to whatever
// that returns -- whenever there's nothing cached yet, the cached entry has
// aged past hostAffinityTTL, or the previously-picked dialer is no longer
// in the pool at all (its control died and was evicted, or the pool was
// wholesale Swap()'d) -- so a dead control is never stuck as a host's
// sticky choice.
func (p *DialerPool) PickForHost(host string) *TunnelDialer {
	if host == "" {
		return p.Pick()
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.affinity[host]; ok && time.Since(e.at) < hostAffinityTTL && p.containsUnlocked(e.dialer) {
		return e.dialer
	}
	// Held across the whole check-then-pick-then-pin sequence (not released
	// between the cache check and pickLocked) so a burst of concurrent first
	// connections to a brand-new host all converge on one dialer instead of
	// racing each other into picking (and pinning) different ones.
	d := p.pickLocked(nil)
	if d != nil {
		p.setHostAffinityLocked(host, d)
	}
	return d
}

// SetHostAffinity pins host to d explicitly, refreshing the TTL. Exported so
// callers that fall back to a different dialer after the sticky one fails a
// dial (see socks5.go's PickExcluding retry) can update the pin immediately
// instead of waiting for the next PickForHost call to notice the old dialer
// is gone and re-roll -- otherwise every subsequent connection to that host
// would retry the dead dialer once before falling back, every time, until
// hostAffinityTTL or an eviction catches up.
func (p *DialerPool) SetHostAffinity(host string, d *TunnelDialer) {
	if host == "" || d == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.setHostAffinityLocked(host, d)
}

// setHostAffinityLocked is SetHostAffinity's body, for callers (PickForHost)
// that already hold p.mu. Callers must hold p.mu.
func (p *DialerPool) setHostAffinityLocked(host string, d *TunnelDialer) {
	if p.affinity == nil {
		p.affinity = make(map[string]hostAffinityEntry)
	}
	p.affinity[host] = hostAffinityEntry{dialer: d, at: time.Now()}
}

// containsUnlocked reports whether d is still a non-draining member of the
// pool. Callers must hold p.mu.
func (p *DialerPool) containsUnlocked(d *TunnelDialer) bool {
	for _, s := range p.slots {
		if s.dialer == d {
			return s.state != dialerDraining
		}
	}
	return false
}

// sweepAffinityLocked drops expired affinity entries so the map doesn't grow
// unbounded over a long session visiting many distinct hosts. Callers must
// hold p.mu. Piggybacks on manage()'s existing periodic tick rather than a
// separate timer.
func (p *DialerPool) sweepAffinityLocked() {
	if len(p.affinity) == 0 {
		return
	}
	now := time.Now()
	for host, e := range p.affinity {
		if now.Sub(e.at) >= hostAffinityTTL {
			delete(p.affinity, host)
		}
	}
}

// pickWeight returns 1/RTT for a dialer (or 1/defaultPickRTT if no data yet),
// scaled down by its current failure ratio so a control that's reliably fast
// but increasingly unreliable gets deprioritized smoothly — rather than
// keeping full weight right up until it either recovers or crosses the hard
// eviction threshold. Recomputed fresh on every call from the live window
// (TunnelDialer.FailRatio), so it self-heals as soon as reliability improves,
// no separate recovery state needed.
func pickWeight(td *TunnelDialer) float64 {
	rtt := td.TrafficRTT()
	if rtt <= 0 {
		rtt = defaultPickRTT
	}
	// Load factor is a bonus/malus multiplier on the effective RTT, same
	// convention as Router.nodeScore/scorePath (see router.go's
	// effectiveLoadFactor): >1.0 = above-average loaded control, deprioritise;
	// <1.0 = below-average, prefer. 0/unset = neutral 1.0, i.e. pure
	// RTT-based weighting exactly as before this existed (2026-08-11).
	lf := td.LoadFactor()
	if lf <= 0 {
		lf = 1.0
	}
	base := 1.0 / (float64(rtt) * lf)
	quality := 1.0 - td.FailRatio()
	if quality < softMinQuality {
		quality = softMinQuality
	}
	return base * quality
}

// PickForUID returns a dialer for connections made by the app with the given
// Linux UID, keeping the same dialer for every connection that app makes
// (all its tabs/requests, indefinitely, not just a time window) instead of
// Pick's per-connection random draw -- so one app's traffic always exits
// through the same control (and therefore, thanks to that control's own
// per-client exit selection, the same exit IP), while a different app (a
// different UID) picks independently and isn't forced onto the same one.
//
// This used to just call Pick() unconditionally (comment: "exit stickiness
// handled by control") -- true for a single control's own clients, but not
// across controls: two parallel connections from the same app landing on
// two different controls each get their own, independently "sticky" exit,
// which is still two different exit IPs for the same app (confirmed live,
// 2026-08-17: this is what tripped Google's "unusual traffic" block). A
// per-destination-host version of this was tried first and wasn't enough
// either -- a single site can resolve to several different IPs, especially
// in proxy-only mode where the client never sees the hostname at all, only
// the already-resolved IP. Grouping by the traffic's actual originator (the
// app) rather than its destination is what the caller (android-core's
// appStickyDialer) asked for -- it resolves the real UID via Kotlin's
// ConnectivityManager.getConnectionOwnerUid over IPC (see UidClient in
// android-core/uid_linux.go). No TTL, unlike PickForHost: distinct UIDs on
// one device are a handful, not thousands, so there's no unbounded-growth
// concern to bound with one.
//
// A negative uid (unresolved -- the lookup failed or timed out for this one
// connection) is never pinned or matched against another negative uid: it
// falls straight through to a plain, unpinned pick every time. Pinning
// unresolved lookups together was a real, shipped incident (2026-08-17): an
// earlier UID source (/proc/net/tcp) turned out to always fail on modern
// Android, so every single connection resolved to the same sentinel value
// and PickForUID happily "stuck" every app in the pool to one shared
// control -- silently reintroducing the exact whole-VPN-on-one-control
// behavior this feature exists to avoid. An unresolved UID must degrade to
// no-stickiness-for-this-connection, never to accidental one-bucket-for-
// everyone stickiness.
//
// Falls through to a fresh pick -- and re-pins to whatever that returns --
// whenever nothing is pinned for this UID yet, or the pinned dialer is no
// longer in the pool at all (its control died and was evicted, or the pool
// was wholesale Swap()'d), so a dead control is never stuck as an app's
// sticky choice.
func (p *DialerPool) PickForUID(uid int) *TunnelDialer {
	if uid < 0 {
		return p.Pick()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if d, ok := p.appAffinity[uid]; ok && p.containsUnlocked(d) {
		return d
	}
	// Held across the whole check-then-pick-then-pin sequence so a burst of
	// concurrent first connections from the same app (a browser opening many
	// parallel connections at once) all converge on one dialer instead of
	// racing each other into picking (and pinning) different ones.
	d := p.pickLocked(nil)
	if d != nil {
		p.setUIDAffinityLocked(uid, d)
	}
	return d
}

// SetUIDAffinity pins uid to d explicitly. Exported so a caller that falls
// back to a different dialer after the sticky one fails a dial can update
// the pin immediately instead of waiting for the next PickForUID call to
// notice the old dialer is gone and re-roll -- otherwise every subsequent
// connection from that app would retry the dead dialer once before falling
// back, every time, until an eviction catches up.
func (p *DialerPool) SetUIDAffinity(uid int, d *TunnelDialer) {
	if d == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.setUIDAffinityLocked(uid, d)
}

// setUIDAffinityLocked is SetUIDAffinity's body, for callers (PickForUID)
// that already hold p.mu. Callers must hold p.mu.
func (p *DialerPool) setUIDAffinityLocked(uid int, d *TunnelDialer) {
	if p.appAffinity == nil {
		p.appAffinity = make(map[int]*TunnelDialer)
	}
	p.appAffinity[uid] = d
}

// Size returns the number of non-draining dialers.
func (p *DialerPool) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sizeUnlocked()
}

// LastDataTime returns the most recent successful POST time across all dialers.
func (p *DialerPool) LastDataTime() time.Time {
	p.mu.Lock()
	slots := make([]*dialerSlot, len(p.slots))
	copy(slots, p.slots)
	p.mu.Unlock()
	var latest time.Time
	for _, s := range slots {
		if t := s.dialer.LastDataTime(); t.After(latest) {
			latest = t
		}
	}
	return latest
}

// Dialers returns a snapshot of every non-draining dialer currently in the
// pool -- for callers that need to inspect the whole pool (e.g.
// ConnStatsCollector.Snapshot's pool-composition breakdown), not pick one.
func (p *DialerPool) Dialers() []*TunnelDialer {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*TunnelDialer, 0, len(p.slots))
	for _, s := range p.slots {
		if s.state != dialerDraining {
			out = append(out, s.dialer)
		}
	}
	return out
}

// URLs returns the distinct control URLs of every dialer currently in the
// pool (non-draining), regardless of transport (TCP, UDP relay, ...). Used
// to widen manifest-fetch candidates beyond whatever the last-cached
// manifest happened to contain -- see Discoverer.SetExtraURLsProvider.
func (p *DialerPool) URLs() []string {
	dialers := p.Dialers()
	seen := make(map[string]bool, len(dialers))
	out := make([]string, 0, len(dialers))
	for _, td := range dialers {
		auth := td.Auth()
		if auth == nil {
			continue
		}
		u := auth.ServerURL()
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	return out
}

// Add appends td as a standby dialer eligible for Pick().
func (p *DialerPool) Add(td *TunnelDialer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.activityHook != nil {
		td.SetActivityHook(p.activityHook)
	}
	p.slots = append(p.slots, &dialerSlot{dialer: td, state: dialerStandby})
	Log.Printf("dialer-pool: added dialer addr=%s pool=%d", td.ServerURL(), len(p.slots))
}

// Evict removes td from the pool.
func (p *DialerPool) Evict(td *TunnelDialer) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	found := false
	next := p.slots[:0]
	for _, s := range p.slots {
		if s.dialer == td {
			found = true
		} else {
			next = append(next, s)
		}
	}
	if !found {
		return p.sizeUnlocked()
	}
	p.slots = next
	atomic.AddInt32(&p.evictCount, 1)
	n := p.sizeUnlocked()
	Log.Printf("dialer-pool: evicted addr=%s %d remaining", td.ServerURL(), n)
	return n
}

// Swap replaces all dialers wholesale.
func (p *DialerPool) Swap(dialers []*TunnelDialer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.activityHook != nil {
		for _, d := range dialers {
			d.SetActivityHook(p.activityHook)
		}
	}
	p.slots = p.slots[:0]
	for _, d := range dialers {
		p.slots = append(p.slots, &dialerSlot{dialer: d, state: dialerStandby})
	}
	Log.Printf("dialer-pool: swapped to %d dialer(s)", len(dialers))
}

// NeedsRefill reports whether the pool has fewer than target non-draining dialers.
func (p *DialerPool) NeedsRefill(target int) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sizeUnlocked() < target
}

// Has reports whether the pool already contains a non-draining dialer for ctrlURL.
func (p *DialerPool) Has(ctrlURL string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.slots {
		if s.state != dialerDraining && s.dialer.ServerURL() == ctrlURL {
			return true
		}
	}
	return false
}

// Get returns the non-draining dialer for ctrlURL, or nil if not present.
func (p *DialerPool) Get(ctrlURL string) *TunnelDialer {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.slots {
		if s.state != dialerDraining && s.dialer.ServerURL() == ctrlURL {
			return s.dialer
		}
	}
	return nil
}

// DrainEvictions returns and resets the eviction counter.
func (p *DialerPool) DrainEvictions() int {
	return int(atomic.SwapInt32(&p.evictCount, 0))
}

// StartManagement launches the drain-completion background loop.
func (p *DialerPool) StartManagement(interval time.Duration, stopCh <-chan struct{}) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-t.C:
				p.manage()
			}
		}
	}()
}

// manage runs one tick: drain completion.
func (p *DialerPool) manage() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.slots {
		if s.state == dialerDraining && s.dialer.OpenConns() == 0 {
			s.state = dialerStandby
			Log.Printf("dialer-pool: drained → standby addr=%s", s.dialer.ServerURL())
		}
	}
	p.sweepAffinityLocked()
}

func (p *DialerPool) sizeUnlocked() int {
	n := 0
	for _, s := range p.slots {
		if s.state != dialerDraining {
			n++
		}
	}
	return n
}

func dialerStateName(s dialerState) string {
	switch s {
	case dialerDraining:
		return "draining"
	default:
		return "standby"
	}
}
