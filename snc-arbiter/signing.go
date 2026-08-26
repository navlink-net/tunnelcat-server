// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

type signingKey struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// loadOrGenSigningKey loads an Ed25519 private key from path, generating and
// saving a new one if the file does not exist.
func loadOrGenSigningKey(path string) (*signingKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "ED25519 PRIVATE KEY" {
			return nil, fmt.Errorf("sign-key: invalid PEM in %s", path)
		}
		if len(block.Bytes) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("sign-key: bad key length in %s", path)
		}
		priv := ed25519.PrivateKey(block.Bytes)
		return &signingKey{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
	}

	// Generate new key.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sign-key: generate: %w", err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, fmt.Errorf("sign-key: write %s: %w", path, err)
	}
	if err := pem.Encode(f, &pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: []byte(priv),
	}); err != nil {
		f.Close()
		return nil, fmt.Errorf("sign-key: encode PEM: %w", err)
	}
	f.Close()
	logInfof("signing: generated new Ed25519 key → %s", path)

	return &signingKey{priv: priv, pub: pub}, nil
}

// pubkeyHex returns the public key as a hex string for embedding at build time.
func (s *signingKey) pubkeyHex() string {
	return fmt.Sprintf("%x", s.pub)
}

// pubkeyB64 returns the public key base64url-encoded.
func (s *signingKey) pubkeyB64() string {
	return base64.RawURLEncoding.EncodeToString(s.pub)
}

// ── signed node list ──────────────────────────────────────────────────────────

type NodeEntry struct {
	Addr        string  `json:"addr"`
	Fingerprint string  `json:"fingerprint,omitempty"`
	RTTms       float64 `json:"rtt_ms,omitempty"`
	Load        float64 `json:"load,omitempty"`
	DataPlaneOK *bool   `json:"data_plane_ok,omitempty"`
}

type SignedList struct {
	Type           string              `json:"type"` // "exits" | "controls"
	TS             int64               `json:"ts"`
	Nodes          []NodeEntry         `json:"nodes"`
	Sig            string              `json:"sig"`                        // base64url Ed25519 signature over canonical JSON of {type,ts,nodes}
	Regions        map[string]string   `json:"regions,omitempty"`          // addr → ISO-3166 region code; advisory only, not signed
	RelayEnabled   *bool               `json:"relay_enabled,omitempty"`    // advisory; nil → clients keep current default (true)
	Notifications  []NotificationEntry `json:"notifications,omitempty"`    // advisory; admin broadcast messages, 24 h TTL
	NodeSNIs       map[string][]string `json:"node_snis,omitempty"`        // advisory; addr → SNI rotation list for that control
	Excluded       []string            `json:"excluded,omitempty"`         // advisory; control addrs clients must skip (decommissioned nodes)
	NodeWLWTPPorts map[string][]int    `json:"node_wlwtp_ports,omitempty"` // advisory; addr → dynamic WLWTP UDP ports (reported by each control)
	SelfRegion     string              `json:"self_region,omitempty"`      // advisory; the *calling* node's own effective region (RegionOverride-aware), resolved server-side by X-Node-Token so the node never has to self-detect its own IP/region (see incident 2026-08-12: outboundIP() returns the NAT-internal IP behind cloud-provider NAT, e.g. Yandex Cloud, so a node can never match itself in Regions by IP)
	IPv6Enabled    *bool               `json:"ipv6_enabled,omitempty"`     // advisory; nil → client keeps its own local default. Admin-controlled global kill switch (see admin_ipv6.go) -- when false, clients force their "disable IPv6" behavior on and hide the manual toggle, since it's arbiter-controlled at that point. Added 2026-08-12: every exit lacks IPv6 and none of the hosting providers in use can enable it, which was silently breaking Facebook/WhatsApp.
	NavlinkMirrors []string            `json:"navlink_mirrors,omitempty"`  // advisory; addrs ("host:port", same format as every other node addr in this struct) of live navlink.net-mirror forwarder nodes a client can fall back to (prefixing "https://") if navlink.net itself is unreachable, e.g. blocked in-country
	TorrentEnabled *bool               `json:"torrent_enabled,omitempty"`  // advisory; nil = arbiter said nothing, keep local default (false). Fleet-wide kill switch for the client-side BitTorrent engine -- see admin_torrent_enabled.go and snc/core/torrent.go's TorrentGate. Unlike IPv6Enabled, false is the safe default here, so this is always bolted on (never left nil) by apiManifest/apiManifestClientFetch, same treatment as IPv6Enabled.
	TorrentMagnets       map[string]string `json:"torrent_magnets,omitempty"`        // advisory; product/platform slug -> magnet URI for client software the torrent-seed fleet already seeds -- see torrent_magnets.go
	TorrentManifestMagnet string           `json:"torrent_manifest_magnet,omitempty"` // advisory; magnet for this arbiter's own last-published signed manifest torrent -- see torrent_magnets.go
}

// ── signed whitelist ──────────────────────────────────────────────────────────

// WhitelistEntryJSON is the wire representation of one whitelist entry.
type WhitelistEntryJSON struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// SignedWhitelist is the signed traffic whitelist delivered to exits (drives
// exit-to-exit peer-routing fallback — see snc-exit/handler.go).
type SignedWhitelist struct {
	TS      int64                `json:"ts"`
	Entries []WhitelistEntryJSON `json:"entries"`
	Sig     string               `json:"sig"` // base64url Ed25519 over {ts, entries}
}

// signWhitelist builds a signed whitelist manifest from DB entries.
func (s *signingKey) signWhitelist(entries []WhitelistEntry) ([]byte, error) {
	wire := make([]WhitelistEntryJSON, len(entries))
	for i, e := range entries {
		wire[i] = WhitelistEntryJSON{Type: e.Type, Value: e.Value}
	}
	ts := time.Now().Unix()
	payload := struct {
		TS      int64                `json:"ts"`
		Entries []WhitelistEntryJSON `json:"entries"`
	}{TS: ts, Entries: wire}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal whitelist: %w", err)
	}
	sig := ed25519.Sign(s.priv, canonical)
	out := SignedWhitelist{TS: ts, Entries: wire, Sig: base64.RawURLEncoding.EncodeToString(sig)}
	return json.Marshal(out)
}

// ── signed service region blocks ────────────────────────────────────────────

// ServiceRegionBlockJSON is the wire representation of one service-region-block rule.
type ServiceRegionBlockJSON struct {
	Type           string   `json:"type"`
	Value          string   `json:"value"`
	BlockedRegions []string `json:"blocked_regions"`
}

// SignedServiceRegionBlocks is the signed manifest delivered to exit nodes,
// telling each one which destinations it must not dial directly given its
// own region (see snc-exit/service_blocks.go).
type SignedServiceRegionBlocks struct {
	TS      int64                    `json:"ts"`
	Entries []ServiceRegionBlockJSON `json:"entries"`
	Sig     string                   `json:"sig"` // base64url Ed25519 over {ts, entries}
}

// signServiceRegionBlocks builds a signed manifest from DB entries.
func (s *signingKey) signServiceRegionBlocks(entries []ServiceRegionBlock) ([]byte, error) {
	wire := make([]ServiceRegionBlockJSON, len(entries))
	for i, e := range entries {
		wire[i] = ServiceRegionBlockJSON{Type: e.Type, Value: e.Value, BlockedRegions: e.BlockedRegions}
	}
	ts := time.Now().Unix()
	payload := struct {
		TS      int64                    `json:"ts"`
		Entries []ServiceRegionBlockJSON `json:"entries"`
	}{TS: ts, Entries: wire}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal service region blocks: %w", err)
	}
	sig := ed25519.Sign(s.priv, canonical)
	out := SignedServiceRegionBlocks{TS: ts, Entries: wire, Sig: base64.RawURLEncoding.EncodeToString(sig)}
	return json.Marshal(out)
}

// ── signed anonymous bootstrap manifest ─────────────────────────────────────

// AnonAllowlistEntryJSON is the wire representation of one anon-allowlist rule.
type AnonAllowlistEntryJSON struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// SignedAnonBootstrap is the signed manifest delivered to exit/control nodes:
// the current shared bootstrap token plus the destinations it's allowed to
// reach. Bundled together (rather than two separate fetches) so an exit
// always has a matching token+allowlist pair, never a token refreshed
// without its allowlist or vice versa.
type SignedAnonBootstrap struct {
	TS      int64                    `json:"ts"`
	Token   string                   `json:"token"`
	Entries []AnonAllowlistEntryJSON `json:"entries"`
	Sig     string                   `json:"sig"` // base64url Ed25519 over {ts, token, entries}
}

// signAnonBootstrap builds a signed manifest from the current DB state.
func (s *signingKey) signAnonBootstrap(token string, entries []AnonAllowlistEntry) ([]byte, error) {
	wire := make([]AnonAllowlistEntryJSON, len(entries))
	for i, e := range entries {
		wire[i] = AnonAllowlistEntryJSON{Type: e.Type, Value: e.Value}
	}
	ts := time.Now().Unix()
	payload := struct {
		TS      int64                    `json:"ts"`
		Token   string                   `json:"token"`
		Entries []AnonAllowlistEntryJSON `json:"entries"`
	}{TS: ts, Token: token, Entries: wire}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal anon bootstrap: %w", err)
	}
	sig := ed25519.Sign(s.priv, canonical)
	out := SignedAnonBootstrap{TS: ts, Token: token, Entries: wire, Sig: base64.RawURLEncoding.EncodeToString(sig)}
	return json.Marshal(out)
}

// ── signed blacklist ──────────────────────────────────────────────────────────

// SignedBlacklist is the signed exit-address blacklist delivered to exit nodes.
type SignedBlacklist struct {
	TS    int64    `json:"ts"`
	Addrs []string `json:"addrs"`
	Sig   string   `json:"sig"` // base64url Ed25519 over {ts, addrs}
}

// signBlacklist builds a signed blacklist manifest from DB entries.
// SignedTorrentBlocked is the signed torrent-blocked-exits manifest (blacklist
// model: presence in Addrs means torrent egress is blocked there; absence, by
// default including newly onboarded exits, means allowed). SelfAllowed is
// computed per-request for the calling node (not part of the signed
// canonical payload -- Addrs alone is enough for a peer to verify it, and a
// fresh signature is generated per request anyway, so there's no staleness
// concern with including a caller-specific field outside the signature).
type SignedTorrentBlocked struct {
	TS          int64    `json:"ts"`
	Addrs       []string `json:"addrs"` // blocked exit addrs
	SelfAllowed bool     `json:"self_allowed"`
	Sig         string   `json:"sig"` // base64url Ed25519 over {ts, addrs}
}

// signTorrentBlocked builds a signed torrent-blocked-exits manifest from DB
// entries. selfAllowed reports whether callerAddr is ABSENT from entries
// (blacklist model — default allowed).
func (s *signingKey) signTorrentBlocked(entries []TorrentBlockedEntry, callerAddr string) ([]byte, error) {
	addrs := make([]string, len(entries))
	selfBlocked := false
	for i, e := range entries {
		addrs[i] = e.Addr
		if e.Addr == callerAddr {
			selfBlocked = true
		}
	}
	ts := time.Now().Unix()
	payload := struct {
		TS    int64    `json:"ts"`
		Addrs []string `json:"addrs"`
	}{TS: ts, Addrs: addrs}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal torrent-blocked: %w", err)
	}
	sig := ed25519.Sign(s.priv, canonical)
	out := SignedTorrentBlocked{TS: ts, Addrs: addrs, SelfAllowed: !selfBlocked, Sig: base64.RawURLEncoding.EncodeToString(sig)}
	return json.Marshal(out)
}

func (s *signingKey) signBlacklist(entries []BlacklistEntry) ([]byte, error) {
	addrs := make([]string, len(entries))
	for i, e := range entries {
		addrs[i] = e.Addr
	}
	ts := time.Now().Unix()
	payload := struct {
		TS    int64    `json:"ts"`
		Addrs []string `json:"addrs"`
	}{TS: ts, Addrs: addrs}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal blacklist: %w", err)
	}
	sig := ed25519.Sign(s.priv, canonical)
	out := SignedBlacklist{TS: ts, Addrs: addrs, Sig: base64.RawURLEncoding.EncodeToString(sig)}
	return json.Marshal(out)
}

// ── signed content manifest (torrent-like mirroring) ──────────────────────────

// ContentFileEntry describes one file in the content-manifest: its size and
// the SHA-256 hash of each fixed-size chunk, in order. Chunk i covers bytes
// [i*ChunkSize, min((i+1)*ChunkSize, Size)) of the file.
type ContentFileEntry struct {
	Path        string   `json:"path"`
	Size        int64    `json:"size"`
	ChunkSize   int      `json:"chunk_size"`
	ChunkHashes []string `json:"chunk_hashes"` // hex SHA-256, one per chunk
}

// SignedContentManifest is the signed, arbitrary-file mirroring manifest
// gossiped to clients via the DHT content-manifest channel.
type SignedContentManifest struct {
	Type  string             `json:"type"` // "content"
	TS    int64              `json:"ts"`
	Files []ContentFileEntry `json:"files"`
	Sig   string             `json:"sig"` // base64url Ed25519 over canonical {type,ts,files}
}

// signContentManifest builds and signs a content manifest from a file list.
func (s *signingKey) signContentManifest(files []ContentFileEntry) ([]byte, error) {
	ts := time.Now().Unix()
	payload := struct {
		Type  string             `json:"type"`
		TS    int64              `json:"ts"`
		Files []ContentFileEntry `json:"files"`
	}{Type: "content", TS: ts, Files: files}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal content manifest: %w", err)
	}
	sig := ed25519.Sign(s.priv, canonical)
	out := SignedContentManifest{Type: "content", TS: ts, Files: files, Sig: base64.RawURLEncoding.EncodeToString(sig)}
	return json.Marshal(out)
}

// signList builds a SignedList from nodes and signs it.
// The signature covers only the canonical JSON of {type, ts, nodes} — the Regions
// field is advisory/unsigned and safe to add without breaking existing verifiers.
//
// regionFn, if non-nil, maps a node address to its ISO-3166 region code ("RU",
// "US", …).  Pass nil to omit the Regions map.
func (s *signingKey) signList(listType string, nodes []Node, regionFn func(string) string) ([]byte, error) {
	entries := make([]NodeEntry, 0, len(nodes))
	for _, n := range nodes {
		entries = append(entries, NodeEntry{
			Addr:        n.Addr,
			Fingerprint: n.Fingerprint,
			RTTms:       n.RTTms,
			Load:        n.Load,
			DataPlaneOK: n.DataPlaneOK,
		})
	}

	ts := time.Now().Unix()

	// Build canonical payload (without sig, without regions) for signing.
	payload := struct {
		Type  string      `json:"type"`
		TS    int64       `json:"ts"`
		Nodes []NodeEntry `json:"nodes"`
	}{Type: listType, TS: ts, Nodes: entries}

	canonical, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	sig := ed25519.Sign(s.priv, canonical)

	// Populate optional advisory region map.
	var regions map[string]string
	if regionFn != nil {
		for _, e := range entries {
			if cc := regionFn(e.Addr); cc != "" {
				if regions == nil {
					regions = make(map[string]string)
				}
				regions[e.Addr] = cc
			}
		}
	}

	out := SignedList{
		Type:    listType,
		TS:      ts,
		Nodes:   entries,
		Sig:     base64.RawURLEncoding.EncodeToString(sig),
		Regions: regions,
	}
	return json.Marshal(out)
}

// signListWithConfig appends the advisory relay_enabled field after the
// signature without changing the signed canonical payload.
// Old clients that don't know this field ignore it.
func (s *signingKey) signListWithConfig(listType string, nodes []Node, regionFn func(string) string, relayEnabled bool, selfRegion string) ([]byte, error) {
	data, err := s.signList(listType, nodes, regionFn)
	if err != nil {
		return nil, err
	}
	var out SignedList
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	out.RelayEnabled = &relayEnabled
	out.SelfRegion = selfRegion
	return json.Marshal(out)
}

// ── signed club manifest (encrypted, per-club symmetric key) ───────────────
//
// Parallel channel to the regular controls manifest above — same signing
// key, same NodeEntry shape, but the node list itself is encrypted under a
// per-club symmetric key (XChaCha20-Poly1305, same primitive and nonce size
// as keyenc.go's key-string encryption) so only a holder of that club's key
// can read it. The Ed25519 signature covers the encrypted envelope, giving
// authenticity independently of confidentiality: anyone with the arbiter's
// public key can confirm the arbiter produced this ciphertext without being
// able to decrypt it themselves.

const clubManifestNonceSize = 24 // XChaCha20-Poly1305 nonce size, matches keyenc.go's keyEncNonce

// SignedClubManifest is the wire format for one club's parallel manifest.
type SignedClubManifest struct {
	Type   string `json:"type"`    // "club_manifest"
	ClubID int64  `json:"club_id"` // which club this belongs to; not secret, only the node list is
	TS     int64  `json:"ts"`
	Nonce  string `json:"nonce"`  // base64url, clubManifestNonceSize bytes
	Cipher string `json:"cipher"` // base64url XChaCha20-Poly1305(JSON([]NodeEntry))
	Sig    string `json:"sig"`    // base64url Ed25519 over canonical {type,club_id,ts,nonce,cipher}
}

// signClubManifest encrypts nodes under clubKey (raw bytes, already
// base64-decoded by the caller — see DB.ClubManifestKey) and signs the
// resulting envelope with the arbiter's own Ed25519 key.
func (s *signingKey) signClubManifest(clubID int64, clubKey []byte, nodes []Node) ([]byte, error) {
	entries := make([]NodeEntry, 0, len(nodes))
	for _, n := range nodes {
		entries = append(entries, NodeEntry{
			Addr:        n.Addr,
			Fingerprint: n.Fingerprint,
			RTTms:       n.RTTms,
			Load:        n.Load,
			DataPlaneOK: n.DataPlaneOK,
		})
	}
	plain, err := json.Marshal(entries)
	if err != nil {
		return nil, fmt.Errorf("marshal club nodes: %w", err)
	}

	aead, err := chacha20poly1305.NewX(clubKey)
	if err != nil {
		return nil, fmt.Errorf("club manifest aead: %w", err)
	}
	nonce := make([]byte, clubManifestNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("club manifest nonce: %w", err)
	}
	ct := aead.Seal(nil, nonce, plain, nil)

	ts := time.Now().Unix()
	payload := struct {
		Type   string `json:"type"`
		ClubID int64  `json:"club_id"`
		TS     int64  `json:"ts"`
		Nonce  string `json:"nonce"`
		Cipher string `json:"cipher"`
	}{
		Type:   "club_manifest",
		ClubID: clubID,
		TS:     ts,
		Nonce:  base64.RawURLEncoding.EncodeToString(nonce),
		Cipher: base64.RawURLEncoding.EncodeToString(ct),
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal club manifest payload: %w", err)
	}
	sig := ed25519.Sign(s.priv, canonical)

	out := SignedClubManifest{
		Type:   payload.Type,
		ClubID: payload.ClubID,
		TS:     payload.TS,
		Nonce:  payload.Nonce,
		Cipher: payload.Cipher,
		Sig:    base64.RawURLEncoding.EncodeToString(sig),
	}
	return json.Marshal(out)
}
