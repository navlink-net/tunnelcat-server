// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

// Package core — ShortNerdCat client internals.
package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

// appSecret is the 32-byte application secret baked into the binary.
// In production this would be replaced at build time via -ldflags.
var appSecret = [32]byte{
	0x53, 0x4e, 0x43, 0x61, 0x74, 0x2d, 0x73, 0x65,
	0x63, 0x72, 0x65, 0x74, 0x2d, 0x6b, 0x65, 0x79,
	0x2d, 0x70, 0x68, 0x61, 0x73, 0x65, 0x31, 0x2d,
	0x64, 0x65, 0x76, 0x6f, 0x6e, 0x6c, 0x79, 0x00,
}

const (
	keyMagicV1 = uint32(0x534E4301) // 'SNC\x01' — unsigned (legacy)
	keyMagicV2 = uint32(0x534E4302) // 'SNC\x02' — arbiter-signed
	nonceSize  = 24                 // XChaCha20-Poly1305
	macSize    = 16
)

// KeyData holds the parsed content of a key-string.
//
// M1 (legacy) keys have a "servers" field pointing directly at snc-exit addresses.
// M2+ keys have "control_nodes" pointing at snc-control addresses, and optionally
// "arbiter_pubkey" (hex-encoded Ed25519 public key) for signature verification.
// M3+ keys additionally carry "client_id" (immutable billing identifier) and
// "sig" (base64url Ed25519 signature by the arbiter over the rest of the payload).
//
// ParseKeyString accepts all formats.  Use Nodes() to get whichever is present.
type KeyData struct {
	Username      string   `json:"username"`
	Password      string   `json:"password"`
	Servers       []string `json:"servers,omitempty"`        // M1 legacy: direct exits
	ControlNodes  []string `json:"control_nodes,omitempty"`  // M2+: control node addresses
	ArbiterPubkey string   `json:"arbiter_pubkey,omitempty"` // M2+: arbiter Ed25519 pubkey hex
	NodeID        string   `json:"node_id"`
	APIKey        string   `json:"api_key,omitempty"`
	ClientID      string   `json:"client_id,omitempty"`      // M3+: arbiter-assigned billing ID
	KeyID         string   `json:"key_id,omitempty"`         // M4+: key binding identifier
	AuthSig string `json:"auth_sig,omitempty"` // M5+: Ed25519 sig over payload sans password
	Sig     string `json:"sig,omitempty"`      // M3+: arbiter Ed25519 sig over payload sans sig

	// IsAdmin is advisory, like Regions/RelayEnabled elsewhere in this
	// codebase -- deliberately outside AuthSig/Sig coverage (see
	// keyPayloadCanonical/keyPayloadAuthCanonical in snc-arbiter/keyenc.go,
	// which this field is NOT added to). Only gates cosmetic client UI (the
	// club-theme preview switcher), never a real permission, so tamper-
	// resistance isn't needed here the way it is for the rest of the key.
	IsAdmin bool `json:"is_admin,omitempty"`
}

// Nodes returns the list of addresses the client should connect to.
// For M2+ keys this is ControlNodes; for M1 legacy keys it is Servers.
func (kd *KeyData) Nodes() []string {
	if len(kd.ControlNodes) > 0 {
		return kd.ControlNodes
	}
	return kd.Servers
}

// IsLegacy reports whether this is an M1-style key (direct exit, no control nodes).
func (kd *KeyData) IsLegacy() bool {
	return len(kd.ControlNodes) == 0
}

// deriveKey returns BLAKE2b-256(appSecret || salt).
func deriveKey(salt byte) ([]byte, error) {
	h, err := blake2b.New256(nil)
	if err != nil {
		return nil, err
	}
	h.Write(appSecret[:])
	h.Write([]byte{salt})
	return h.Sum(nil), nil
}

// ParseKeyString decodes and decrypts a key-string produced by the server.
//
// Wire format (binary, then base64url-encoded):
//
//	[4 magic][24 nonce][ciphertext...][16 poly1305 tag]
//
// The ciphertext decrypts to JSON-encoded KeyData.
//
// For V2 keys (magic SNC\x02) the payload contains a "sig" field: an Ed25519
// signature by the arbiter over the canonical JSON of the payload with "sig"
// omitted.  If ArbiterPubkey is set, the signature is verified; a missing or
// invalid signature is a hard error.  If ArbiterPubkey is absent the signature
// field is accepted without verification (dev / legacy mode).
func ParseKeyString(ks string) (*KeyData, error) {
	raw, err := base64.RawURLEncoding.DecodeString(ks)
	if err != nil {
		return nil, fmt.Errorf("key: base64 decode: %w", err)
	}

	minLen := 4 + nonceSize + macSize + 1
	if len(raw) < minLen {
		return nil, errors.New("key: too short")
	}

	magic := binary.BigEndian.Uint32(raw[:4])
	if magic != keyMagicV1 && magic != keyMagicV2 {
		return nil, fmt.Errorf("key: bad magic %08x", magic)
	}

	nonce := raw[4 : 4+nonceSize]
	ciphertext := raw[4+nonceSize:]

	dk, err := deriveKey(0x01)
	if err != nil {
		return nil, fmt.Errorf("key: derive: %w", err)
	}

	aead, err := chacha20poly1305.NewX(dk)
	if err != nil {
		return nil, fmt.Errorf("key: aead init: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("key: decrypt: %w", err)
	}

	var kd KeyData
	if err := json.Unmarshal(plaintext, &kd); err != nil {
		return nil, fmt.Errorf("key: json: %w", err)
	}
	if kd.Username == "" {
		return nil, errors.New("key: missing username")
	}

	// V2 key: verify arbiter signature.
	if magic == keyMagicV2 {
		if err := verifyKeySignature(&kd); err != nil {
			return nil, fmt.Errorf("key: signature: %w", err)
		}
	}

	return &kd, nil
}

// verifyKeySignature checks the arbiter's Ed25519 signature embedded in kd.Sig.
// The signed payload is the canonical JSON of kd with the Sig field cleared.
//
// Every V2 key issued by an arbiter (see snc-arbiter/admin_keygen.go,
// get_key.go, my_handler.go, signup.go — all of them funnel through
// issueKey/buildSignedKey) always sets ArbiterPubkey and signs the payload.
// A V2-magic key with no ArbiterPubkey/Sig is therefore never something a
// real arbiter produced — it can only be hand-crafted by someone who knows
// the (published, non-secret) wire-format encryption key. Accepting it
// unverified would let that person hand a victim a "key" pointing at
// arbitrary control nodes of their choosing, so this is a hard error, not a
// fallback mode.
func verifyKeySignature(kd *KeyData) error {
	if kd.ArbiterPubkey == "" {
		return errors.New("V2 key missing arbiter pubkey")
	}
	if kd.Sig == "" {
		return errors.New("missing signature")
	}
	pubBytes, err := hex.DecodeString(kd.ArbiterPubkey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return errors.New("invalid arbiter pubkey")
	}
	sig, err := base64.RawURLEncoding.DecodeString(kd.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("invalid signature encoding")
	}
	// Build canonical payload: same as kd but Sig cleared.
	canonical, err := keyCanonical(kd)
	if err != nil {
		return fmt.Errorf("canonical: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pubBytes), canonical, sig) {
		return errors.New("signature verification failed")
	}
	return nil
}

// keyCanonical returns the JSON of kd with the Sig field omitted, used as the
// signed payload.  Field order is stable because json.Marshal sorts map keys
// alphabetically, but we use a struct to guarantee stability.
func keyCanonical(kd *KeyData) ([]byte, error) {
	// keyCanonicalPayload is the signed subset of KeyData (Sig field excluded).
	// KeyID is included so device binding is covered by the arbiter's signature.
	type keyCanonicalPayload struct {
		Username      string   `json:"username"`
		Password      string   `json:"password"`
		Servers       []string `json:"servers,omitempty"`
		ControlNodes  []string `json:"control_nodes,omitempty"`
		ArbiterPubkey string   `json:"arbiter_pubkey,omitempty"`
		NodeID        string   `json:"node_id"`
		APIKey        string   `json:"api_key,omitempty"`
		ClientID      string   `json:"client_id,omitempty"`
		KeyID         string   `json:"key_id,omitempty"`
	}
	return json.Marshal(keyCanonicalPayload{
		Username:      kd.Username,
		Password:      kd.Password,
		Servers:       kd.Servers,
		ControlNodes:  kd.ControlNodes,
		ArbiterPubkey: kd.ArbiterPubkey,
		NodeID:        kd.NodeID,
		APIKey:        kd.APIKey,
		ClientID:      kd.ClientID,
		KeyID:         kd.KeyID,
	})
}

// EncodeKeyString encrypts kd and returns a base64url key-string (V1, unsigned).
// Used in tests and for legacy key generation without a signing key.
func EncodeKeyString(kd *KeyData) (string, error) {
	return encodeKey(kd, keyMagicV1)
}

// EncodeSignedKeyString signs kd with priv (arbiter Ed25519 key), then encrypts
// and encodes it as a V2 key-string.  The signature covers all fields except Sig.
func EncodeSignedKeyString(kd *KeyData, priv ed25519.PrivateKey) (string, error) {
	canonical, err := keyCanonical(kd)
	if err != nil {
		return "", fmt.Errorf("canonical: %w", err)
	}
	sig := ed25519.Sign(priv, canonical)
	signed := *kd
	signed.Sig = base64.RawURLEncoding.EncodeToString(sig)
	return encodeKey(&signed, keyMagicV2)
}

// encodeKey is the shared encrypt-and-encode step for both V1 and V2.
func encodeKey(kd *KeyData, magic uint32) (string, error) {
	plaintext, err := json.Marshal(kd)
	if err != nil {
		return "", err
	}

	dk, err := deriveKey(0x01)
	if err != nil {
		return "", err
	}

	aead, err := chacha20poly1305.NewX(dk)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	buf := make([]byte, 4+nonceSize+len(ciphertext))
	binary.BigEndian.PutUint32(buf[:4], magic)
	copy(buf[4:], nonce)
	copy(buf[4+nonceSize:], ciphertext)

	return base64.RawURLEncoding.EncodeToString(buf), nil
}
