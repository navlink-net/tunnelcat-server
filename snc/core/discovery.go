// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// manifestNode is a control node entry in the signed manifest.
// Fields must stay in sync with NodeEntry in snc-arbiter/signing.go — the
// canonical JSON reconstructed here must be byte-identical to what the
// arbiter signed.
type manifestNode struct {
	Addr        string  `json:"addr"`
	Fingerprint string  `json:"fingerprint,omitempty"`
	RTTms       float64 `json:"rtt_ms,omitempty"`
	Load        float64 `json:"load,omitempty"`
	DataPlaneOK *bool   `json:"data_plane_ok,omitempty"`
}

// Notification is an admin broadcast message delivered in the manifest.
// Advisory only — not covered by the arbiter's Ed25519 signature.
type Notification struct {
	ID        string `json:"id"`
	Message   string `json:"message"`
	CreatedAt int64  `json:"created_at"`
}

// signedManifest is the wire format returned by the exit's /api/manifest endpoint.
// The arbiter signs it; the exit relays it verbatim.
type signedManifest struct {
	Type           string              `json:"type"` // must be "manifest"
	TS             int64               `json:"ts"`
	Nodes          []manifestNode      `json:"nodes"`
	Sig            string              `json:"sig"`                        // base64url Ed25519 over {type,ts,nodes}
	Regions        map[string]string   `json:"regions,omitempty"`          // addr → ISO region code; advisory, not signed
	Notifications  []Notification      `json:"notifications,omitempty"`    // advisory; not signed
	NodeSNIs       map[string][]string `json:"node_snis,omitempty"`        // advisory; addr → SNI rotation list
	Excluded       []string            `json:"excluded,omitempty"`         // advisory; addrs clients must skip (decommissioned nodes)
	IPv6Enabled    *bool               `json:"ipv6_enabled,omitempty"`     // advisory; nil = arbiter said nothing, keep local default. Admin kill switch -- see snc-arbiter/admin_ipv6.go
}

// Discoverer fetches the signed control-node manifest from the control's relay
// API (channel 0x01, /p/v1/manifest), verifies the arbiter's Ed25519 signature,
// and maintains a refreshed list of controls.
// It persists the manifest to disk so the updated list survives restarts.
type Discoverer struct {
	pubkey    ed25519.PublicKey // arbiter pubkey; nil = skip sig verification (dev)
	client    *http.Client      // retained for API compatibility; no longer used by fetch()
	cacheFile string            // path to persist the manifest on disk; "" = no persistence

	// httpClientFactory, if non-nil, overrides the HTTP client used by fetch().
	// Default (nil) uses NewRelayAPIH1Client (channel 0x01 uTLS). Override in tests.
	httpClientFactory func() *http.Client

	mu             sync.RWMutex
	serverURLs     []string            // https:// URLs of all known controls; updated after each successful fetch
	controls       []string            // current list of control addresses
	regions        map[string]string   // addr → ISO region code (advisory, from arbiter)
	nodeSNIs       map[string][]string // addr → SNI rotation list (advisory, from arbiter)
	loadFactors    map[string]float64  // addr → bonus/malus coefficient (advisory, from the *signed* nodes list --
	// see manifestNode.Load; not itself covered by a separate signature, but
	// signed as part of the same node entry as rtt_ms/fingerprint)
	fingerprints map[string]string // addr → SHA-256 cert fingerprint (colon-hex), from the *signed* part of
	// the manifest -- unlike the advisory maps above, this one is covered by
	// the arbiter's Ed25519 signature (see manifestNode/verify), which is what
	// makes pinning against it meaningful. See FingerprintFor/tls.go's
	// verifyPeerCertFingerprint for where this is actually enforced.
	notifications   []Notification       // pending broadcast notifications (advisory, from arbiter)
	onChange        func([]string)       // called when controls change; may be nil
	onFetch         func([]byte, int64)  // called after each successful fetch (raw, ts)
	onNotifications func([]Notification) // called when new notifications arrive; may be nil

	// extraURLs, if set, is consulted on every fetch() for additional candidate
	// control URLs beyond serverURLs -- e.g. the client's active DialerPool,
	// which can hold a control that dropped out of the last-cached (≤12-node)
	// manifest, or vice versa. See SetExtraURLsProvider.
	extraURLs func() []string

	// navlink fallback config -- see SetNavlinkFallback. navlinkSet
	// distinguishes "never configured" from "configured". physIPFn is a
	// closure, not a snapshotted string, because the physical-NIC address
	// isn't stable across connect/disconnect/reconnect the way controlFn
	// (Android's VpnService.protect callback, set once at startup) is.
	navlinkSet       bool
	navlinkPhysIPFn  func() string
	navlinkControlFn func(string, string, syscall.RawConn) error
	navlinkBearerKey string

	// ipv6Enabled mirrors the manifest's advisory ipv6_enabled kill switch.
	// nil = arbiter said nothing (no manifest fetched yet, or an old arbiter
	// that predates this field) -- callers should keep whatever local default
	// they had. Non-nil is the arbiter's authoritative say on whether any
	// exit in the current fleet can route IPv6 at all; see admin_ipv6.go.
	ipv6Enabled *bool

	// manifestSource tracks how the current manifest was obtained:
	// 0 = not loaded, 1 = loaded from on-disk cache, 2 = fetched live this session.
	manifestSource int32 // accessed atomically

	done chan struct{} // closed by Stop() to terminate the background polling goroutine
}

// NewDiscoveryClient returns an http.Client suitable for talking to exit nodes
// that present self-signed TLS certificates.  Use this when creating a
// Discoverer outside of an existing Authenticator context.
//
// Security note (2026-08-07 review): unlike the control-node connections in
// tls.go, this has no fingerprint pinning -- and must not get one the way
// control nodes did. Clients must NEVER learn exit addresses (see
// snc-control/exits.go, "ExitRegistry ... clients never see addresses" --
// this is a hard anonymity property, not an oversight to eventually fix), so
// there can be no client-side signed source of "which exit am I talking to,
// what cert should it have" to pin against without violating that property.
// In current usage this client is passed to NewDiscoverer as its `client`
// field, which per that struct's own comment is "retained for API
// compatibility; no longer used by fetch()" -- so this InsecureSkipVerify is
// not believed to be reachable by live network traffic today. If that ever
// changes, the fix is not "expose exit fingerprints to the client" -- it's
// whatever preserves both properties at once (e.g. the *control* node
// verifying the exit on the client's behalf, as exits.go already does).
func NewDiscoveryClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // see doc comment above
		},
	}
}

// NewDiscoverer creates a Discoverer for the given exit server URL.
//
// pubkeyHex is the arbiter's Ed25519 public key in hex (from KeyData.ArbiterPubkey).
// Pass "" to skip signature verification (development only).
//
// client should be the same http.Client used for tunnel requests (InsecureSkipVerify
// is already set there for self-signed exit certs).
//
// cacheFile is the full path where the raw manifest JSON is persisted; pass ""
// to disable on-disk caching.
//
// onChange is called whenever the control list changes; may be nil.
func NewDiscoverer(serverURL, pubkeyHex string, client *http.Client, cacheFile string, onChange func([]string)) (*Discoverer, error) {
	d := &Discoverer{
		serverURLs: []string{strings.TrimRight(serverURL, "/")},
		client:     client,
		cacheFile:  cacheFile,
		onChange:   onChange,
		done:       make(chan struct{}),
	}
	if pubkeyHex != "" {
		b, err := hex.DecodeString(pubkeyHex)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("discovery: invalid arbiter pubkey hex (need %d bytes)", ed25519.PublicKeySize)
		}
		d.pubkey = ed25519.PublicKey(b)
	}
	return d, nil
}

// ReadManifestCacheControls reads and verifies a cached manifest file and returns
// the list of control addresses it contains.  Useful for augmenting bootstrap
// candidates before a Discoverer instance is available.
//
// pubkeyHex is the arbiter's Ed25519 public key in hex; pass "" to skip
// signature verification (development only).  Returns nil on any error
// (missing file, bad signature, etc.) — the caller should treat absence as
// non-fatal.
func ReadManifestCacheControls(cacheFile, pubkeyHex string) []string {
	addrs, _ := ReadManifestCacheControlsAndRegions(cacheFile, pubkeyHex)
	return addrs
}

// ReadManifestCacheControlsAndRegions is like ReadManifestCacheControls but
// also returns the addr→country-code map from the cached manifest.
// The map is nil when regions are unavailable (first run, bad cache, etc.).
func ReadManifestCacheControlsAndRegions(cacheFile, pubkeyHex string) ([]string, map[string]string) {
	enc, err := os.ReadFile(cacheFile)
	if err != nil {
		return nil, nil
	}
	plain, err := nodeIDDecrypt(enc)
	if err != nil {
		plain = enc // legacy plaintext
	}
	d := &Discoverer{}
	if pubkeyHex != "" {
		if b, err := hex.DecodeString(pubkeyHex); err == nil && len(b) == ed25519.PublicKeySize {
			d.pubkey = ed25519.PublicKey(b)
		}
	}
	addrs, regions, _, _, _, _, _, err := d.verify(plain)
	if err != nil {
		return nil, nil
	}
	return addrs, regions
}

// BootstrapControlList returns the address list a client should race auth
// against. A key's embedded ControlNodes/Servers (KeyData.Nodes) is a
// snapshot frozen at key-download time and must be used ONLY until the first
// manifest has ever been obtained — after that, the manifest is authoritative
// and the key's node list must not be consulted again, merged or otherwise,
// even if some of its addresses happen to still be alive. This is what makes
// node retirement (a control removed from the live manifest) actually take
// effect for existing installs instead of that control being raced forever.
// cachedControls is whatever ReadManifestCacheControls / Discoverer.Controls
// returned; pass whichever is freshest. Returns kd.Nodes() only when
// cachedControls is empty (no manifest has ever been cached — true cold
// start with a brand new key).
func BootstrapControlList(cachedControls, keyNodes []string) []string {
	if len(cachedControls) > 0 {
		return cachedControls
	}
	return keyNodes
}

// LoadCached reads a previously-persisted manifest from disk and populates the
// in-memory control list.  Returns a non-nil error if the cache is missing or
// the manifest fails to parse/verify — the caller should treat this as a
// non-fatal condition (the live fetch will fill the list shortly).
func (d *Discoverer) LoadCached() error {
	if d.cacheFile == "" {
		return fmt.Errorf("discovery: no cache file configured")
	}
	enc, err := os.ReadFile(d.cacheFile)
	if err != nil {
		return err
	}
	plain, err := nodeIDDecrypt(enc)
	if err != nil {
		// Legacy plaintext file — accept once, will be re-saved encrypted.
		Log.Printf("discovery: cache decrypt failed (%v) — trying legacy plaintext", err)
		plain = enc
	}
	addrs, regions, notifs, snis, fingerprints, loadFactors, ipv6Enabled, err := d.verify(plain)
	if err != nil {
		return fmt.Errorf("discovery: cached manifest invalid: %w", err)
	}
	d.setControls(addrs, regions, notifs, snis, fingerprints, loadFactors, ipv6Enabled)
	atomic.StoreInt32(&d.manifestSource, 1)
	Log.Printf("discovery: loaded %d controls from cache", len(addrs))
	return nil
}

// Start performs an immediate manifest fetch and then refreshes on interval.
// Errors are logged but do not stop the loop.
func (d *Discoverer) Start(interval time.Duration) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				Log.Printf("discovery: PANIC in background fetch: %v\n%s", r, debug.Stack())
			}
		}()
		d.fetchAndApply()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-d.done:
				return
			case <-t.C:
				d.fetchAndApply()
			}
		}
	}()
}

// Stop signals the background polling goroutine started by Start to exit.
// Safe to call multiple times; no-op if Start was never called.
func (d *Discoverer) Stop() {
	select {
	case <-d.done:
	default:
		close(d.done)
	}
}

// Controls returns a snapshot of the current control node addresses.
func (d *Discoverer) Controls() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]string, len(d.controls))
	copy(out, d.controls)
	return out
}

// Regions returns a snapshot of the current addr → ISO region map.
// The map is advisory (not covered by the arbiter's signature).
func (d *Discoverer) Regions() map[string]string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.regions == nil {
		return nil
	}
	out := make(map[string]string, len(d.regions))
	for k, v := range d.regions {
		out[k] = v
	}
	return out
}

// IPv6Enabled returns the arbiter's current advisory kill switch: nil = no
// opinion (keep local default), non-nil = the fleet's actual IPv6 capability
// as last reported in the manifest. See the ipv6Enabled field doc comment.
func (d *Discoverer) IPv6Enabled() *bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.ipv6Enabled
}

// ipv6TunnelDisabled mirrors the arbiter's ipv6_enabled kill switch as a
// process-global flag, updated by every Discoverer's setControls regardless
// of which one is asking. Global (rather than requiring every platform's
// route-setup code to thread a *Discoverer reference through) because
// route-setup on Windows/Mac/Linux/iOS runs far from wherever the app
// constructed its Discoverer, and every platform needs the same answer.
// Android doesn't use this -- its snc-core runs as a separate process from
// the Kotlin UI, so it goes through the file-based snc.ipv6 handoff instead
// (see shortnerdcat/snc/android/cmd/snc-core/main_linux.go writeIPv6State).
// Defaults to false (route IPv6 normally) until a manifest says otherwise.
var ipv6TunnelDisabled atomic.Bool

// IPv6TunnelDisabled reports whether the arbiter's last-known manifest says
// no exit in the fleet can route IPv6 right now (see admin_ipv6.go on the
// arbiter). Platform code must actually BLOCK IPv6 egress when this is true
// -- not just skip adding an IPv6 route into the tunnel. Omitting the route
// is not the same as blocking: with no IPv6 route on the VPN interface, the
// OS simply routes IPv6-destined packets via the real underlying network
// interface instead, completely bypassing the VPN (confirmed as a real,
// live traffic leak 2026-08-15 on Windows and 2026-08-16 on Android/macOS/
// Linux/iOS). See routes.go (Windows Firewall rule), routes_darwin.go (pf
// anchor), routes_linux.go (ip6tables chain), and SNCVpnService.kt /
// android-core/tun_dialer_linux.go (always capture into TUN, drop per-dial)
// for the actual enforcement on each platform.
func IPv6TunnelDisabled() bool {
	return ipv6TunnelDisabled.Load()
}

// LoadFactors returns a snapshot of the current addr → load-factor map.
// Advisory (signed as part of each node entry, but not independently
// authenticated) -- see Router.SetLoadFactors, which treats a missing or
// non-positive entry as neutral (1.0), never as a zero weight.
func (d *Discoverer) LoadFactors() map[string]float64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.loadFactors == nil {
		return nil
	}
	out := make(map[string]float64, len(d.loadFactors))
	for k, v := range d.loadFactors {
		out[k] = v
	}
	return out
}

// SNIFor returns a randomly chosen SNI hostname for the given control addr
// (host:port). Returns "" if no SNI list is configured for that addr.
func (d *Discoverer) SNIFor(addr string) string {
	d.mu.RLock()
	snis := d.nodeSNIs[addr]
	d.mu.RUnlock()
	if len(snis) == 0 {
		return ""
	}
	return snis[rand.Intn(len(snis))]
}

// UseAsSNIProvider registers this discoverer as the process-wide SNI source
// for uTLS connections to control nodes. Call once after creating the discoverer.
func (d *Discoverer) UseAsSNIProvider() {
	ControlSNILookup = d.SNIFor
}

// FingerprintFor returns the expected SHA-256 certificate fingerprint (colon-hex,
// uppercase) for the given control addr, as reported in the signed manifest.
// Returns "" if the manifest has no fingerprint for that addr yet (a node that
// hasn't reported one, or no manifest fetched at all) -- callers must treat that
// as "pinning not available for this addr", not "pinning failed", matching the
// backward-compat behaviour already used for exit nodes in snc-control/exits.go.
func (d *Discoverer) FingerprintFor(addr string) string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.fingerprints[addr]
}

// UseAsFingerprintProvider registers this discoverer as the process-wide cert-
// pinning source for uTLS connections to control nodes. Call once after creating
// the discoverer -- see ControlFingerprintLookup in tls.go for where this is read.
func (d *Discoverer) UseAsFingerprintProvider() {
	ControlFingerprintLookup = d.FingerprintFor
}

// SetExtraURLsProvider registers a function fetch() calls on every attempt to
// get additional candidate control URLs beyond the last-cached manifest's
// serverURLs -- typically the client's active DialerPool via (*DialerPool).URLs.
// The manifest only ever hands a client ≤12 randomly-chosen controls
// (anti-topology-disclosure — see snc-arbiter's maxManifestNodes); a control
// the client is actively tunneling through via the pool may or may not be
// among them. Pass nil to disable (default).
func (d *Discoverer) SetExtraURLsProvider(fn func() []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.extraURLs = fn
}

// SetNavlinkFallback configures fetchAndApply to fall back to
// FetchFromNavlink whenever a normal fetch() attempt fails against every
// known control (extraURLs included) -- i.e. exactly the situation the
// navlink.net endpoint exists for. physIPFn is called fresh on every fallback
// attempt (pass a closure like func() string { return routes.LocalAddr() },
// not a snapshot -- the physical-NIC address isn't stable across connect/
// disconnect/reconnect); pass nil on platforms that need no TUN bypass at
// all (iOS). controlFn is passed straight through to FetchFromNavlink.
// bearerKey is the shared clientTelemetryKey. Call once at startup.
func (d *Discoverer) SetNavlinkFallback(physIPFn func() string, controlFn func(string, string, syscall.RawConn) error, bearerKey string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.navlinkSet = true
	d.navlinkPhysIPFn = physIPFn
	d.navlinkControlFn = controlFn
	d.navlinkBearerKey = bearerKey
}

// SetFetchCallback registers a function called after each successful manifest
// fetch.  The callback receives the raw signed manifest JSON and the manifest
// ts — use this to feed the manifest into the DHT gossip layer.
func (d *Discoverer) SetFetchCallback(fn func(raw []byte, ts int64)) {
	d.mu.Lock()
	d.onFetch = fn
	d.mu.Unlock()
}

// SetNotificationCallback registers a function called whenever the manifest
// delivers one or more new broadcast notifications.  The callback receives
// only the advisory slice as-is; deduplication/TTL are the caller's job.
func (d *Discoverer) SetNotificationCallback(fn func([]Notification)) {
	d.mu.Lock()
	d.onNotifications = fn
	d.mu.Unlock()
}

// Notifications returns a snapshot of the most-recently-received notifications.
func (d *Discoverer) Notifications() []Notification {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.notifications) == 0 {
		return nil
	}
	out := make([]Notification, len(d.notifications))
	copy(out, d.notifications)
	return out
}

// InjectRaw accepts a raw signed manifest from an external source (e.g. DHT
// gossip).  It verifies the signature, applies the control list, and persists
// it — identical to a local fetch but without the HTTP round-trip.
// Returns an error if verification fails; the caller should not apply or
// re-gossip invalid data.
func (d *Discoverer) InjectRaw(data []byte) error {
	addrs, regions, notifs, snis, fingerprints, loadFactors, ipv6Enabled, err := d.verify(data)
	if err != nil {
		return fmt.Errorf("discovery: inject verify: %w", err)
	}
	d.setControls(addrs, regions, notifs, snis, fingerprints, loadFactors, ipv6Enabled)
	if d.cacheFile != "" {
		d.persist(data)
	}
	Log.Printf("discovery: manifest injected (%d controls)", len(addrs))
	return nil
}

// navlinkManifestURL is the client-facing manifest endpoint reachable via the
// public nginx proxy in front of the arbiter -- see snc-arbiter's
// apiManifestClientFetch (manifest_client_api.go).
const navlinkManifestURL = "https://navlink.net/api/manifest/client"

// FetchFromNavlink fetches a fresh manifest directly from navlink.net,
// bypassing TUN exactly like decoy traffic does (physIP LocalAddr binding on
// Windows/macOS/Linux, controlFn/VpnService.protect on Android; pass ""/nil
// on iOS where no bypass is needed -- see NewDecoyTransport's callers for
// the per-platform convention already established for decoy.go).
//
// Independent of every other manifest path (control-relayed fetch, DHT
// gossip): those all depend on some control or exit already being reachable,
// which is exactly what's in question when a client's cached manifest is
// entirely stale. This one depends only on navlink.net itself. Not the
// primary path -- callers should try the normal fetch()-based Start() loop
// first and fall back to this only when that's been failing.
//
// bearerKey is the shared clientTelemetryKey every build embeds (see
// tunnel_cat/snc/core/client_telemetry_key.go) -- required by the arbiter
// endpoint to keep it off generic scanner reach; not a content-security
// boundary, the manifest's own Ed25519 signature is (verified here exactly
// as fetch() results are, via InjectRaw).
func (d *Discoverer) FetchFromNavlink(physIP string, controlFn func(string, string, syscall.RawConn) error, bearerKey string) error {
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: NewDecoyTransport(physIP, controlFn),
	}
	req, err := http.NewRequest(http.MethodGet, navlinkManifestURL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if bearerKey != "" {
		req.Header.Set("Authorization", "Bearer "+bearerKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", navlinkManifestURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", navlinkManifestURL, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	if len(data) == 0 {
		return fmt.Errorf("empty response")
	}
	return d.InjectRaw(data)
}

// ManifestStatus returns the current manifest load state: "none", "cached", or "fresh".
func (d *Discoverer) ManifestStatus() string {
	switch atomic.LoadInt32(&d.manifestSource) {
	case 1:
		return "cached"
	case 2:
		return "fresh"
	default:
		return "none"
	}
}

// fetchAndApply fetches the manifest, verifies it, and updates the control list.
func (d *Discoverer) fetchAndApply() {
	data, err := d.fetch()
	if err != nil {
		Log.Printf("discovery: fetch failed: %v", err)
		d.mu.RLock()
		navlinkSet, physIPFn, controlFn, bearerKey := d.navlinkSet, d.navlinkPhysIPFn, d.navlinkControlFn, d.navlinkBearerKey
		d.mu.RUnlock()
		if navlinkSet {
			physIP := ""
			if physIPFn != nil {
				physIP = physIPFn()
			}
			Log.Printf("discovery: falling back to navlink.net directly")
			if nerr := d.FetchFromNavlink(physIP, controlFn, bearerKey); nerr != nil {
				Log.Printf("discovery: navlink.net fallback failed: %v", nerr)
			} else {
				atomic.StoreInt32(&d.manifestSource, 2)
			}
		}
		return
	}
	addrs, regions, notifs, snis, fingerprints, loadFactors, ipv6Enabled, err := d.verify(data)
	if err != nil {
		Log.Printf("discovery: verify failed: %v", err)
		return
	}
	d.setControls(addrs, regions, notifs, snis, fingerprints, loadFactors, ipv6Enabled)
	atomic.StoreInt32(&d.manifestSource, 2)
	if d.cacheFile != "" {
		d.persist(data)
	}
	// Notify DHT layer so it can gossip this fresh manifest to peers.
	d.mu.RLock()
	cb := d.onFetch
	d.mu.RUnlock()
	if cb != nil {
		ts := manifestTS(data)
		cb(data, ts)
	}
}

// fetch fetches the manifest from the control's relay API (channel 0x01,
// /p/v1/manifest). Tries all known control URLs in random order so that a
// dead bootstrap control does not permanently block manifest refresh.
//
// Uses NewRelayAPIH1ClientUnpinned, not the pinned default: the manifest is
// its own independently-verified artifact (Ed25519 signature checked in
// verify() below, against the arbiter's pubkey baked into the client), so
// pinning the *transport* cert on top of that is redundant defense that, in
// practice, actively broke delivery -- a control that rotates its IP also
// reissues its TLS cert, and an existing client's cached manifest still
// carries the old fingerprint, so every fetch attempt against that control
// failed with "certificate fingerprint mismatch" until a fresh manifest
// arrived by some other path (DHT gossip, a different control). See
// NewRelayAPIH1ClientUnpinned's doc comment.
func (d *Discoverer) fetch() ([]byte, error) {
	factory := d.httpClientFactory
	if factory == nil {
		factory = NewRelayAPIH1ClientUnpinned
	}

	d.mu.RLock()
	urls := make([]string, len(d.serverURLs))
	copy(urls, d.serverURLs)
	extraFn := d.extraURLs
	d.mu.RUnlock()

	// Merge in whatever the extra-URLs provider (typically the active
	// DialerPool) offers, deduped against serverURLs -- see
	// SetExtraURLsProvider's doc comment for why the manifest's own ≤12-node
	// list isn't always sufficient on its own.
	if extraFn != nil {
		seen := make(map[string]bool, len(urls))
		for _, u := range urls {
			seen[u] = true
		}
		for _, u := range extraFn() {
			if u != "" && !seen[u] {
				seen[u] = true
				urls = append(urls, u)
			}
		}
	}

	// Shuffle so all controls share fetch load and a dead first-in-list
	// does not always block the round.
	rand.Shuffle(len(urls), func(i, j int) { urls[i], urls[j] = urls[j], urls[i] })

	var lastErr error
	for _, srvURL := range urls {
		data, err := func() ([]byte, error) {
			client := factory()
			req, err := http.NewRequest(http.MethodGet, srvURL+"/p/v1/manifest", nil)
			if err != nil {
				return nil, err
			}
			resp, err := client.Do(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
			}
			data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			if err != nil {
				return nil, err
			}
			if len(data) == 0 {
				return nil, fmt.Errorf("empty response")
			}
			return data, nil
		}()
		if err != nil {
			Log.Printf("discovery: fetch %s: %v", srvURL, err)
			lastErr = err
			continue
		}
		return data, nil
	}
	if lastErr != nil {
		return nil, fmt.Errorf("GET /p/v1/manifest: %w", lastErr)
	}
	return nil, fmt.Errorf("discovery: no controls to fetch from")
}

// ProbeManifest fetches /p/v1/manifest once and returns (nodeCount, error).
// Intended for snc-probe -manifest; not used in normal client operation.
func (d *Discoverer) ProbeManifest(timeout time.Duration) (nodes int, err error) {
	old := d.httpClientFactory
	d.httpClientFactory = func() *http.Client {
		c := NewRelayAPIH1Client()
		c.Timeout = timeout
		return c
	}
	defer func() { d.httpClientFactory = old }()

	data, err := d.fetch()
	if err != nil {
		return 0, err
	}
	addrs, _, _, _, _, _, _, err := d.verify(data)
	if err != nil {
		return 0, fmt.Errorf("verify: %w (raw size=%d)", err, len(data))
	}
	return len(addrs), nil
}

// verify parses and optionally verifies the Ed25519 signature on a raw manifest.
// Returns control addresses, advisory regions, advisory notifications, advisory
// node SNI lists, per-addr cert fingerprints (signed, not advisory), advisory
// load factors, and the advisory ipv6Enabled kill switch on success.
func (d *Discoverer) verify(data []byte) ([]string, map[string]string, []Notification, map[string][]string, map[string]string, map[string]float64, *bool, error) {
	var m signedManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("parse: %w", err)
	}
	if m.Type != "manifest" {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("unexpected manifest type %q", m.Type)
	}

	if d.pubkey != nil {
		// Reconstruct the canonical payload the arbiter signed (advisory fields excluded).
		payload := struct {
			Type  string         `json:"type"`
			TS    int64          `json:"ts"`
			Nodes []manifestNode `json:"nodes"`
		}{Type: m.Type, TS: m.TS, Nodes: m.Nodes}
		canonical, _ := json.Marshal(payload)

		sigBytes, err := base64.RawURLEncoding.DecodeString(m.Sig)
		if err != nil || !ed25519.Verify(d.pubkey, canonical, sigBytes) {
			return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("signature verification failed")
		}
	} else {
		Log.Printf("discovery: WARNING — arbiter pubkey not set, skipping signature verification")
	}

	excluded := make(map[string]bool, len(m.Excluded))
	for _, addr := range m.Excluded {
		excluded[addr] = true
	}
	if len(excluded) > 0 {
		Log.Printf("discovery: manifest excludes %d node(s): %v", len(excluded), m.Excluded)
	}

	addrs := make([]string, 0, len(m.Nodes))
	fingerprints := make(map[string]string, len(m.Nodes))
	loadFactors := make(map[string]float64, len(m.Nodes))
	for _, n := range m.Nodes {
		if n.Addr != "" && !excluded[n.Addr] {
			addrs = append(addrs, n.Addr)
			if n.Fingerprint != "" {
				fingerprints[n.Addr] = n.Fingerprint
			}
			if n.Load > 0 {
				loadFactors[n.Addr] = n.Load
			}
		}
	}
	if len(addrs) == 0 {
		return nil, nil, nil, nil, nil, nil, nil, fmt.Errorf("manifest contains no control nodes")
	}
	return addrs, m.Regions, m.Notifications, m.NodeSNIs, fingerprints, loadFactors, m.IPv6Enabled, nil
}

// setControls atomically replaces the control list, regions, notifications,
// node SNI lists, cert fingerprints, load factors, and the ipv6Enabled kill
// switch, then fires callbacks.
func (d *Discoverer) setControls(addrs []string, regions map[string]string, notifs []Notification, snis map[string][]string, fingerprints map[string]string, loadFactors map[string]float64, ipv6Enabled *bool) {
	d.mu.Lock()
	changed := !stringSliceEqual(d.controls, addrs)
	d.controls = addrs
	d.regions = regions
	d.notifications = notifs
	d.nodeSNIs = snis
	d.fingerprints = fingerprints
	d.loadFactors = loadFactors
	d.ipv6Enabled = ipv6Enabled
	if ipv6Enabled != nil {
		ipv6TunnelDisabled.Store(!*ipv6Enabled)
	}
	cbNotif := d.onNotifications
	// Keep serverURLs in sync with the full control list so future fetch()
	// calls try every known control, not just the initial bootstrap URL.
	urls := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if strings.HasPrefix(a, "http") {
			urls = append(urls, a)
		} else {
			urls = append(urls, "https://"+a)
		}
	}
	if len(urls) > 0 {
		d.serverURLs = urls
	}
	d.mu.Unlock()

	Log.Printf("discovery: %d control nodes (changed=%v), %d notification(s)", len(addrs), changed, len(notifs))
	if changed && d.onChange != nil {
		d.onChange(addrs)
	}
	if len(notifs) > 0 && cbNotif != nil {
		cbNotif(notifs)
	}
}

// persist writes the DPAPI-encrypted manifest to cacheFile.
func (d *Discoverer) persist(data []byte) {
	if err := os.MkdirAll(filepath.Dir(d.cacheFile), 0700); err != nil {
		Log.Printf("discovery: mkdir %s: %v", filepath.Dir(d.cacheFile), err)
		return
	}
	enc, err := nodeIDEncrypt(data)
	if err != nil {
		Log.Printf("discovery: cache encrypt: %v", err)
		return
	}
	if err := os.WriteFile(d.cacheFile, enc, 0600); err != nil {
		Log.Printf("discovery: write cache %s: %v", d.cacheFile, err)
	}
}

// manifestTS extracts the ts field from a raw manifest JSON without full parsing.
// Returns 0 if the field is missing or malformed.
func manifestTS(data []byte) int64 {
	var m struct {
		TS int64 `json:"ts"`
	}
	json.Unmarshal(data, &m) //nolint:errcheck
	return m.TS
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
