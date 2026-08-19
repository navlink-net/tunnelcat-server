// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

// keyenc implements key-string encoding for the arbiter.
// The wire format mirrors win-client/core/key.go — both sides must stay in sync.
//
// Wire: base64url( [4B magic_be][24B nonce][XChaCha20-Poly1305(JSON(KeyData))] )
//
//	Magic SNC\x01 (0x534E4301) — unsigned (V1, legacy)
//	Magic SNC\x02 (0x534E4302) — arbiter-signed (V2)
//
// For V2 the JSON payload contains "sig": base64url(Ed25519(canonical_json))
// where canonical_json is the same struct with "sig" omitted.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	keyEncMagicV2 = uint32(0x534E4302) // 'SNC\x02'
	keyEncNonce   = 24                 // XChaCha20-Poly1305 nonce size
)

// keyEncSecret must be kept in sync with win-client/core/key.go appSecret.
// In production both are replaced at build time via -ldflags.
var keyEncSecret = [32]byte{
	0x53, 0x4e, 0x43, 0x61, 0x74, 0x2d, 0x73, 0x65,
	0x63, 0x72, 0x65, 0x74, 0x2d, 0x6b, 0x65, 0x79,
	0x2d, 0x70, 0x68, 0x61, 0x73, 0x65, 0x31, 0x2d,
	0x64, 0x65, 0x76, 0x6f, 0x6e, 0x6c, 0x79, 0x00,
}

// keyPayload mirrors KeyData in win-client/core/key.go.
type keyPayload struct {
	Username      string   `json:"username"`
	Password      string   `json:"password"`
	Servers       []string `json:"servers,omitempty"`
	ControlNodes  []string `json:"control_nodes,omitempty"`
	ArbiterPubkey string   `json:"arbiter_pubkey,omitempty"`
	NodeID        string   `json:"node_id"`
	APIKey        string   `json:"api_key,omitempty"`
	ClientID      string   `json:"client_id,omitempty"`
	KeyID         string   `json:"key_id,omitempty"`   // M4+: key binding identifier
	AuthSig       string   `json:"auth_sig,omitempty"` // M5+: Ed25519 sig over payload sans password
	Sig           string   `json:"sig,omitempty"`

	// IsAdmin is advisory -- deliberately absent from keyPayloadCanonical
	// and keyPayloadAuthCanonical below, so it's outside both signatures.
	// Only gates a cosmetic client UI switcher (club-theme preview), never
	// a real permission, so it doesn't need tamper-resistance the way the
	// rest of this payload does.
	IsAdmin bool `json:"is_admin,omitempty"`
}

// keyPayloadCanonical is keyPayload without Sig and AuthSig, used as the signed message for Sig.
// Includes Password so that the main signature covers all key content.
type keyPayloadCanonical struct {
	Username      string   `json:"username"`
	Password      string   `json:"password"`
	Servers       []string `json:"servers,omitempty"`
	ControlNodes  []string `json:"control_nodes,omitempty"`
	ArbiterPubkey string   `json:"arbiter_pubkey,omitempty"`
	NodeID        string   `json:"node_id"`
	APIKey        string   `json:"api_key,omitempty"`
	ClientID      string   `json:"client_id,omitempty"`
	KeyID         string   `json:"key_id,omitempty"` // M4+: included in signature
}

// keyPayloadAuthCanonical is keyPayload without Password, Sig, and AuthSig.
// Used as the signed message for AuthSig so the key remains valid after a password change.
type keyPayloadAuthCanonical struct {
	Username      string   `json:"username"`
	Servers       []string `json:"servers,omitempty"`
	ControlNodes  []string `json:"control_nodes,omitempty"`
	ArbiterPubkey string   `json:"arbiter_pubkey,omitempty"`
	NodeID        string   `json:"node_id"`
	APIKey        string   `json:"api_key,omitempty"`
	ClientID      string   `json:"client_id,omitempty"`
	KeyID         string   `json:"key_id,omitempty"`
}

// buildSignedKey creates a V2 signed key-string for the given payload.
func buildSignedKey(p *keyPayload, priv ed25519.PrivateKey) (string, error) {
	// Compute AuthSig: sign canonical payload without password.
	// This allows key authentication even after a password change.
	authCanon, err := json.Marshal(keyPayloadAuthCanonical{
		Username:      p.Username,
		Servers:       p.Servers,
		ControlNodes:  p.ControlNodes,
		ArbiterPubkey: p.ArbiterPubkey,
		NodeID:        p.NodeID,
		APIKey:        p.APIKey,
		ClientID:      p.ClientID,
		KeyID:         p.KeyID,
	})
	if err != nil {
		return "", fmt.Errorf("auth canonical marshal: %w", err)
	}
	p.AuthSig = base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, authCanon))

	// Compute Sig: sign canonical payload including password (excludes AuthSig and Sig).
	canon, err := json.Marshal(keyPayloadCanonical{
		Username:      p.Username,
		Password:      p.Password,
		Servers:       p.Servers,
		ControlNodes:  p.ControlNodes,
		ArbiterPubkey: p.ArbiterPubkey,
		NodeID:        p.NodeID,
		APIKey:        p.APIKey,
		ClientID:      p.ClientID,
		KeyID:         p.KeyID,
	})
	if err != nil {
		return "", fmt.Errorf("canonical marshal: %w", err)
	}
	sig := ed25519.Sign(priv, canon)
	p.Sig = base64.RawURLEncoding.EncodeToString(sig)

	// Encrypt full payload.
	plain, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}

	dk := keyDeriveEncKey()
	aead, err := chacha20poly1305.NewX(dk)
	if err != nil {
		return "", fmt.Errorf("aead: %w", err)
	}
	nonce := make([]byte, keyEncNonce)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	ct := aead.Seal(nil, nonce, plain, nil)

	buf := make([]byte, 4+keyEncNonce+len(ct))
	binary.BigEndian.PutUint32(buf[:4], keyEncMagicV2)
	copy(buf[4:], nonce)
	copy(buf[4+keyEncNonce:], ct)
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// keyDeriveEncKey derives the 32-byte encryption key from keyEncSecret.
// Must mirror deriveKey(0x01) in win-client/core/key.go.
func keyDeriveEncKey() []byte {
	h, _ := blake2b.New256(nil)
	h.Write(keyEncSecret[:])
	h.Write([]byte{0x01})
	return h.Sum(nil)
}
