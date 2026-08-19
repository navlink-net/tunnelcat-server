// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// club_discovery.go — client-side half of the parallel, per-club encrypted
// manifest channel. Independent of Discoverer (discovery.go) by design: the
// general manifest pipeline is never touched by this feature. A
// ClubDiscoverer's resulting extra control addresses are meant to be
// *added* to whatever the app already uses from Discoverer, never to
// replace it. See tunnel_cat/docs/club-membership.md.

// signedClubManifest mirrors SignedClubManifest in snc-arbiter/signing.go —
// the wire format must stay byte-identical for the Ed25519 verification
// (over {type,club_id,ts,nonce,cipher}) to succeed.
type signedClubManifest struct {
	Type   string `json:"type"`
	ClubID int64  `json:"club_id"`
	TS     int64  `json:"ts"`
	Nonce  string `json:"nonce"`
	Cipher string `json:"cipher"`
	Sig    string `json:"sig"`
}

// ClubDiscoverer fetches, verifies, and decrypts one club's parallel
// manifest via a control's relay API (/p/v1/club-key and
// /p/v1/club-manifest). The club key is fetched once (gated by the
// server-side membership check on every fetch, not by anything cached
// client-side) and reused for every subsequent manifest decrypt — it does
// not rotate under normal operation, see the design doc.
type ClubDiscoverer struct {
	slug        string            // "cat_club" | "elite_cat_club"
	pubkey      ed25519.PublicKey // arbiter pubkey; nil = skip sig verification (dev)
	sessionTok  func() string     // returns the current session token; called fresh each fetch
	httpFactory func() *http.Client

	mu               sync.RWMutex
	serverURL        string // https:// URL of a control to fetch through; set via SetServerURL
	key              []byte // raw club symmetric key, once fetched; nil = not a member (or not fetched yet)
	nodes            []manifestNode
	membershipNumber int64  // set alongside key; the granting club's permanent member number
	membershipClub   string // which club actually granted access -- may differ from d.slug via subsumption (e.g. Elite reading Cat Club's key)

	onChange     func([]string) // called when the extra control list changes; may be nil
	onMembership func(bool)     // called once, when the membership key is first successfully obtained; may be nil
}

// NewClubDiscoverer creates a discoverer for one club. pubkeyHex is the
// arbiter's Ed25519 public key in hex, same as NewDiscoverer; sessionTok
// must return the caller's current session token (the same one used for
// X-Session elsewhere) on each call, since it may be refreshed over time.
func NewClubDiscoverer(slug, pubkeyHex string, sessionTok func() string, onChange func([]string)) (*ClubDiscoverer, error) {
	d := &ClubDiscoverer{slug: slug, sessionTok: sessionTok, onChange: onChange}
	if pubkeyHex != "" {
		b, err := hex.DecodeString(pubkeyHex)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("club-discovery: invalid arbiter pubkey hex (need %d bytes)", ed25519.PublicKeySize)
		}
		d.pubkey = ed25519.PublicKey(b)
	}
	return d, nil
}

// SetServerURL updates which control to fetch through. Safe to call
// concurrently; takes effect on the next poll.
func (d *ClubDiscoverer) SetServerURL(url string) {
	d.mu.Lock()
	d.serverURL = url
	d.mu.Unlock()
}

// Start performs an immediate fetch and then refreshes on interval. Errors
// (including "not a member") are logged but never stop the loop — a user
// who joins the club later should start seeing extra controls without an
// app restart.
func (d *ClubDiscoverer) Start(interval time.Duration) (stop func()) {
	done := make(chan struct{})
	go func() {
		d.pollOnce()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				d.pollOnce()
			}
		}
	}()
	return func() { close(done) }
}

// Controls returns the current extra control addresses from this club's
// manifest, or nil if not currently a member (or nothing fetched yet).
func (d *ClubDiscoverer) Controls() []string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]string, 0, len(d.nodes))
	for _, n := range d.nodes {
		out = append(out, n.Addr)
	}
	return out
}

// MembershipInfo returns the granting club's slug and this user's
// permanent membership number in it, for display (e.g. a "Cat Club Member
// #N" badge). club may differ from the slug this discoverer was created
// for when access came via subsumption (an Elite Cat Club member reading
// Cat Club's manifest has no direct Cat Club grant of their own -- the
// badge should say Elite). ok=false before the first successful key fetch.
func (d *ClubDiscoverer) MembershipInfo() (club string, number int64, ok bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.key == nil {
		return "", 0, false
	}
	return d.membershipClub, d.membershipNumber, true
}

// IsMember reports whether the club key has been obtained -- i.e. the
// arbiter's membership check has passed at least once. Does not itself
// re-check membership; reflects the outcome of the last poll.
func (d *ClubDiscoverer) IsMember() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.key != nil
}

// SetMembershipCallback registers a function called exactly once, the
// first time this discoverer confirms membership (the key fetch
// succeeds) -- independent of whether the club's control list happens to
// be non-empty, unlike onChange. Call before Start(); not safe to change
// concurrently with polling.
func (d *ClubDiscoverer) SetMembershipCallback(fn func(bool)) {
	d.onMembership = fn
}

func (d *ClubDiscoverer) pollOnce() {
	d.mu.RLock()
	srv := d.serverURL
	key := d.key
	d.mu.RUnlock()
	if srv == "" {
		return
	}

	client := d.client()

	// Retried every poll even after a "not a member" response — the key
	// fetch is one cheap request on a multi-minute interval, and a user who
	// joins the club after this discoverer started must start picking up
	// extra controls without an app restart. No permanent latch here.
	if key == nil {
		res, err := d.fetchKey(client, srv)
		if err != nil {
			if err == errNotMember {
				Log.Printf("club-discovery %s: not a member (will retry next poll)", d.slug)
			} else {
				Log.Printf("club-discovery %s: key fetch failed: %v", d.slug, err)
			}
			return
		}
		d.mu.Lock()
		d.key = res.key
		d.membershipNumber = res.membershipNumber
		d.membershipClub = res.membershipClub
		cb := d.onMembership
		d.mu.Unlock()
		key = res.key
		if cb != nil {
			cb(true)
		}
	}

	nodes, err := d.fetchAndDecrypt(client, srv, key)
	if err != nil {
		Log.Printf("club-discovery %s: manifest fetch/decrypt failed: %v", d.slug, err)
		return
	}

	d.mu.Lock()
	changed := len(nodes) != len(d.nodes)
	d.nodes = nodes
	cb := d.onChange
	d.mu.Unlock()

	if changed && cb != nil {
		addrs := make([]string, len(nodes))
		for i, n := range nodes {
			addrs[i] = n.Addr
		}
		cb(addrs)
	}
}

var errNotMember = fmt.Errorf("club-discovery: not a member")

func (d *ClubDiscoverer) client() *http.Client {
	if d.httpFactory != nil {
		return d.httpFactory()
	}
	return NewRelayAPIH1Client()
}

// fetchKeyResult bundles the club key with the membership badge info that
// rides along in the same response (see apiClubKey in snc-arbiter).
type fetchKeyResult struct {
	key              []byte
	membershipNumber int64
	membershipClub   string
}

func (d *ClubDiscoverer) fetchKey(client *http.Client, srv string) (fetchKeyResult, error) {
	req, err := http.NewRequest(http.MethodGet, srv+"/p/v1/club-key?club="+d.slug, nil)
	if err != nil {
		return fetchKeyResult{}, err
	}
	req.Header.Set("X-Session", d.sessionTok())
	resp, err := client.Do(req)
	if err != nil {
		return fetchKeyResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		return fetchKeyResult{}, errNotMember
	}
	if resp.StatusCode != http.StatusOK {
		return fetchKeyResult{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var out struct {
		Club             string `json:"club"`
		Key              string `json:"key"`
		MembershipNumber int64  `json:"membership_number"`
		MembershipClub   string `json:"membership_club"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&out); err != nil {
		return fetchKeyResult{}, fmt.Errorf("parse: %w", err)
	}
	key, err := base64.RawURLEncoding.DecodeString(out.Key)
	if err != nil {
		return fetchKeyResult{}, fmt.Errorf("decode key: %w", err)
	}
	membershipClub := out.MembershipClub
	if membershipClub == "" {
		membershipClub = out.Club
	}
	return fetchKeyResult{key: key, membershipNumber: out.MembershipNumber, membershipClub: membershipClub}, nil
}

func (d *ClubDiscoverer) fetchAndDecrypt(client *http.Client, srv string, key []byte) ([]manifestNode, error) {
	req, err := http.NewRequest(http.MethodGet, srv+"/p/v1/club-manifest?club="+d.slug, nil)
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

	var m signedClubManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if m.Type != "club_manifest" {
		return nil, fmt.Errorf("unexpected type %q", m.Type)
	}

	if d.pubkey != nil {
		payload := struct {
			Type   string `json:"type"`
			ClubID int64  `json:"club_id"`
			TS     int64  `json:"ts"`
			Nonce  string `json:"nonce"`
			Cipher string `json:"cipher"`
		}{Type: m.Type, ClubID: m.ClubID, TS: m.TS, Nonce: m.Nonce, Cipher: m.Cipher}
		canonical, _ := json.Marshal(payload)
		sigBytes, err := base64.RawURLEncoding.DecodeString(m.Sig)
		if err != nil || !ed25519.Verify(d.pubkey, canonical, sigBytes) {
			return nil, fmt.Errorf("signature verification failed")
		}
	}

	nonce, err := base64.RawURLEncoding.DecodeString(m.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	ct, err := base64.RawURLEncoding.DecodeString(m.Cipher)
	if err != nil {
		return nil, fmt.Errorf("decode cipher: %w", err)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("aead init: %w", err)
	}
	plain, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	var nodes []manifestNode
	if err := json.Unmarshal(plain, &nodes); err != nil {
		return nil, fmt.Errorf("parse decrypted nodes: %w", err)
	}
	return nodes, nil
}

// RecommendCatClubMember submits a Cat Club recommendation for
// targetUsername via a control's relay API (/p/v1/club-recommend) — the
// client-app equivalent of the /my/club/recommend web form. serverURL is
// any known control's https:// base URL (same one a ClubDiscoverer would
// use); sessionTok returns the caller's current session token. Recommends
// for Cat Club specifically — that's the only club with a recommendation
// path (see db_clubs.go's RecThresholdCat/RecThresholdElite on the
// arbiter), so there is no club parameter here.
func RecommendCatClubMember(serverURL string, sessionTok func() string, targetUsername string) error {
	body, err := json.Marshal(struct {
		TargetUsername string `json:"target_username"`
	}{TargetUsername: targetUsername})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, serverURL+"/p/v1/club-recommend", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Session", sessionTok())
	req.Header.Set("Content-Type", "application/json")
	resp, err := NewRelayAPIH1Client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("club-recommend: HTTP %d: %s", resp.StatusCode, string(msg))
	}
	return nil
}

// whoAmIURL is the client-facing account-status endpoint, reachable via the
// public nginx proxy in front of the arbiter -- same navlink.net domain as
// NavlinkAuth's login/free-key calls, see snc-arbiter's apiWhoAmI.
const whoAmIURL = "https://navlink.net/api/whoami"

// AdminStatusPoller periodically re-checks whether the logged-in account is
// currently an admin, via a *direct* call to navlink.net -- deliberately NOT
// routed through a control node. Control's client-facing relay API exists
// for exactly one purpose (manifest distribution); layering an account-status
// check onto it would mean every future "check something live against the
// arbiter" need requires editing control source and redeploying the entire
// fleet. See project_control_is_manifest_only_not_generic_relay memory.
//
// This deliberately does NOT bypass the TUN the way FetchFromNavlink does.
// When a tunnel is active, an unprotected socket is captured by the TUN and
// routed out through it automatically -- exactly like any other traffic the
// app or device sends while connected, so this naturally goes "through the
// tunnel when there is one, direct when there isn't" with zero platform-
// specific dial-control plumbing required.
//
// Also NOT the same thing as KeyData.IsAdmin, which is baked into the key
// string at issuance time and never updates again -- a role change (promoted
// to or demoted from admin) would otherwise never reach an already-running
// client. Confirmed gap, 2026-08-14: an admin whose key predated this
// feature saw no admin-only UI at all with no way to tell why short of
// re-keying blind.
type AdminStatusPoller struct {
	sessionTok func() string

	mu      sync.RWMutex
	isAdmin bool

	onChange func(bool) // called whenever the value changes (including the first poll); may be nil
}

// NewAdminStatusPoller creates a poller seeded with the initial value from
// the key string (KeyData.IsAdmin) so the UI has a reasonable answer before
// the first live poll completes, rather than defaulting to false and
// flickering an admin's menu items in and out at startup.
func NewAdminStatusPoller(sessionTok func() string, seedIsAdmin bool, onChange func(bool)) *AdminStatusPoller {
	return &AdminStatusPoller{sessionTok: sessionTok, isAdmin: seedIsAdmin, onChange: onChange}
}

// IsAdmin returns the most recently polled value (or the seed value, before
// the first poll completes).
func (p *AdminStatusPoller) IsAdmin() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.isAdmin
}

// Start performs an immediate poll and then refreshes on interval. A failed
// poll (network error, navlink.net unreachable) is logged and leaves the
// last known value in place -- never reverts to the key-string seed value,
// since a transient failure is not evidence the role changed back.
func (p *AdminStatusPoller) Start(interval time.Duration) (stop func()) {
	done := make(chan struct{})
	go func() {
		p.pollOnce()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				p.pollOnce()
			}
		}
	}()
	return func() { close(done) }
}

func (p *AdminStatusPoller) pollOnce() {
	req, err := http.NewRequest(http.MethodGet, whoAmIURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("X-Session", p.sessionTok())
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		Log.Printf("admin-status: poll: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		Log.Printf("admin-status: poll: HTTP %d", resp.StatusCode)
		return
	}
	var out struct {
		IsAdmin bool `json:"is_admin"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1024)).Decode(&out); err != nil {
		Log.Printf("admin-status: poll: parse: %v", err)
		return
	}
	p.mu.Lock()
	changed := out.IsAdmin != p.isAdmin
	p.isAdmin = out.IsAdmin
	cb := p.onChange
	p.mu.Unlock()
	if changed && cb != nil {
		cb(out.IsAdmin)
	}
}
