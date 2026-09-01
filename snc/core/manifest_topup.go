// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"syscall"
	"time"
)

// manifest_topup.go — client side of the on-demand, one-node-at-a-time
// control-list supplement (see snc-arbiter/manifest_topup_api.go for the
// server side and full design rationale). Added 2026-08-19 alongside the
// manifest system, not a replacement for it: the manifest is the normal,
// bulk way a client learns about controls; TopupClient exists for the case
// where that isn't enough right now (some of what the manifest gave it
// turned out dead) and the client wants exactly one more, checked, live one
// without waiting for the next full manifest refresh.
//
// Runs regardless of tunnel state -- reachable at https://navlink.net
// directly, not through the active tunnel dialer the way LogUploader/
// ConnStatsUploader are, since the whole point is to help a client that may
// have zero live controls right now.

const (
	// topupTarget is how many live controls a client wants before it stops
	// asking for more.
	topupTarget = 12

	// topupTriedWindow is how long a node stays in the "already tried, don't
	// hand it back" exclude set after this client asked for and received it.
	// After this, a later round may receive the same node again -- conditions
	// (rotation, the node coming back up) can change in that time. This is
	// also the periodic re-check interval: both the exclude-window and the
	// "is it worth checking again" cadence are the same 5 minutes by design.
	topupTriedWindow = 5 * time.Minute

	topupPath = "/api/manifest/topup"
)

// topupTriedEntry is one node this client received from the topup endpoint,
// with when it was received -- pruned out of the exclude set once older
// than topupTriedWindow.
type topupTriedEntry struct {
	addr string
	at   time.Time
}

// TopupClient drives the topup loop for one client process. One instance is
// shared for the process lifetime (create once at startup alongside the
// Router/Authenticator it works with), same convention as
// ConnStatsCollector.
type TopupClient struct {
	navlinkURL string
	keyAuth    keyAuthInfo
	physIPFn   func() string
	controlFn  func(string, string, syscall.RawConn) error

	mu    sync.Mutex
	tried []topupTriedEntry
}

// NewTopupClient creates a TopupClient. navlinkURL is the direct (non-
// tunneled) base URL, e.g. "https://navlink.net". physIPFn/controlFn are the
// same TUN-bypass pair Discoverer.SetNavlinkFallback takes (see that
// function's doc comment) -- physIPFn resolved fresh on every request
// (LocalAddr binding on Windows/macOS/Linux, "" when no route manager is up
// yet e.g. disconnected), controlFn (VpnService.protect) on Android, both
// nil/no-op on iOS. Deliberately re-resolved per request rather than baked
// into the transport once, the way NewDecoyTransport's caller normally would
// -- this client must behave identically whether the tunnel is connected or
// not, and physIPFn's answer changes across that boundary while the process
// (and this TopupClient, along with its 5-minute tried-history) keeps running.
func NewTopupClient(navlinkURL string, keyAuth keyAuthInfo, physIPFn func() string, controlFn func(string, string, syscall.RawConn) error) *TopupClient {
	if physIPFn == nil {
		physIPFn = func() string { return "" }
	}
	return &TopupClient{
		navlinkURL: navlinkURL,
		keyAuth:    keyAuth,
		physIPFn:   physIPFn,
		controlFn:  controlFn,
	}
}

// NewTopupClientFromKey is NewTopupClient for callers outside this package,
// which can't build a keyAuthInfo directly (unexported fields) but already
// hold the *KeyData they used for Authenticator.SetKeyAuth -- the same
// fields, just re-shaped here the way SetKeyAuth does internally.
func NewTopupClientFromKey(navlinkURL string, kd *KeyData, physIPFn func() string, controlFn func(string, string, syscall.RawConn) error) *TopupClient {
	return NewTopupClient(navlinkURL, keyAuthInfo{
		username:      kd.Username,
		servers:       kd.Servers,
		controlNodes:  kd.ControlNodes,
		arbiterPubkey: kd.ArbiterPubkey,
		nodeID:        kd.NodeID,
		apiKey:        kd.APIKey,
		clientID:      kd.ClientID,
		keyID:         kd.KeyID,
		authSig:       kd.AuthSig,
	}, physIPFn, controlFn)
}

// pruneLocked drops tried entries older than topupTriedWindow. Caller holds t.mu.
func (t *TopupClient) pruneLocked(now time.Time) {
	kept := t.tried[:0]
	for _, e := range t.tried {
		if now.Sub(e.at) < topupTriedWindow {
			kept = append(kept, e)
		}
	}
	t.tried = kept
}

// excludeSetLocked returns the current exclude list: this client's own
// trailing-5-minute topup history, plus its currently-known controls (no
// point asking for something it already has right now, independent of when
// it was obtained). Caller holds t.mu.
func (t *TopupClient) excludeSetLocked(known []string) []string {
	seen := make(map[string]bool, len(t.tried)+len(known))
	out := make([]string, 0, len(t.tried)+len(known))
	for _, e := range t.tried {
		if !seen[e.addr] {
			seen[e.addr] = true
			out = append(out, e.addr)
		}
	}
	for _, a := range known {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

// requestOne asks the server for exactly one control not in exclude.
// Returns (entry, exhausted, error) -- exhausted=true means the server has
// nothing left to offer this client (excluding club-restricted nodes it
// isn't a member of), not an error condition.
func (t *TopupClient) requestOne(ctx context.Context, exclude []string) (manifestNode, bool, error) {
	body, err := json.Marshal(struct {
		Username      string   `json:"username"`
		Servers       []string `json:"servers"`
		ControlNodes  []string `json:"control_nodes"`
		ArbiterPubkey string   `json:"arbiter_pubkey"`
		NodeID        string   `json:"node_id"`
		APIKey        string   `json:"api_key"`
		ClientID      string   `json:"client_id"`
		KeyID         string   `json:"key_id"`
		AuthSig       string   `json:"auth_sig"`
		Exclude       []string `json:"exclude"`
	}{
		Username:      t.keyAuth.username,
		Servers:       t.keyAuth.servers,
		ControlNodes:  t.keyAuth.controlNodes,
		ArbiterPubkey: t.keyAuth.arbiterPubkey,
		NodeID:        t.keyAuth.nodeID,
		APIKey:        t.keyAuth.apiKey,
		ClientID:      t.keyAuth.clientID,
		KeyID:         t.keyAuth.keyID,
		AuthSig:       t.keyAuth.authSig,
		Exclude:       exclude,
	})
	if err != nil {
		return manifestNode{}, false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.navlinkURL+topupPath, bytes.NewReader(body))
	if err != nil {
		return manifestNode{}, false, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: NewDecoyTransport(t.physIPFn(), t.controlFn),
	}
	resp, err := client.Do(req)
	if err != nil {
		return manifestNode{}, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return manifestNode{}, false, fmt.Errorf("topup: rate limited")
	}
	if resp.StatusCode != http.StatusOK {
		return manifestNode{}, false, fmt.Errorf("topup: status %d", resp.StatusCode)
	}

	var out struct {
		manifestNode
		Exhausted bool `json:"exhausted"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return manifestNode{}, false, err
	}
	return out.manifestNode, out.Exhausted, nil
}

// Run performs one topup round: while liveCount() < topupTarget, ask for one
// more control, probe it (probeFn), and if it's actually reachable hand it
// to addFn so the caller can fold it into the router/discoverer's known
// controls. Stops on reaching the target, the server reporting exhausted,
// or ctx cancellation. Safe to call from a periodic ticker and from a fresh
// connect attempt -- concurrent calls serialize on t.mu's use inside
// pruneLocked/excludeSetLocked (the network calls themselves are not
// mutex-held, so a slow probe in one round doesn't block another caller
// from starting; worst case both rounds ask for and probe an extra node or
// two, which is harmless).
//
// knownFn returns the caller's full currently-known control address list
// (e.g. Router.AllControlAddrs()); liveCount returns how many of those are
// currently qualifying/e2e-alive (e.g. len(Router.QualifyingControlAddrs())).
// probeFn does the same e2e TCP check the router already does elsewhere for
// a single candidate address, returning true if it's reachable. addFn takes
// just the address (e.g. Router.AddControl) -- deliberately not the full
// manifestNode entry, which is unexported and can't cross the package
// boundary into a caller-supplied func literal.
func (t *TopupClient) Run(ctx context.Context, knownFn func() []string, liveCount func() int, probeFn func(addr string) bool, addFn func(addr string)) {
	now := time.Now()
	t.mu.Lock()
	t.pruneLocked(now)
	t.mu.Unlock()

	for {
		if ctx.Err() != nil {
			return
		}
		if liveCount() >= topupTarget {
			return
		}

		t.mu.Lock()
		exclude := t.excludeSetLocked(knownFn())
		t.mu.Unlock()

		entry, exhausted, err := t.requestOne(ctx, exclude)
		if err != nil {
			Log.Printf("manifest-topup: request failed: %v", err)
			return
		}
		if exhausted {
			Log.Printf("manifest-topup: server reports pool exhausted (have %d/%d live, excluded %d)",
				liveCount(), topupTarget, len(exclude))
			return
		}

		t.mu.Lock()
		t.tried = append(t.tried, topupTriedEntry{addr: entry.Addr, at: time.Now()})
		t.mu.Unlock()

		ok := probeFn(entry.Addr)
		Log.Printf("manifest-topup: received %s fingerprint=%.8s... probe_ok=%v (live %d/%d before this)",
			entry.Addr, entry.Fingerprint, ok, liveCount(), topupTarget)
		if ok {
			addFn(entry.Addr)
		}
	}
}
