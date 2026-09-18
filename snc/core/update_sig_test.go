// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// withThrowawayKey swaps UpdateSigningPubKeyHex for a fresh keypair's pubkey
// for the duration of one test, so tests don't depend on (or need to know)
// the real production value.
func withThrowawayKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	orig := UpdateSigningPubKeyHex
	UpdateSigningPubKeyHex = hex.EncodeToString(pub)
	t.Cleanup(func() { UpdateSigningPubKeyHex = orig })
	return priv
}

func TestSignAndVerifyUpdate_RoundTrip(t *testing.T) {
	priv := withThrowawayKey(t)

	sig := SignUpdate(priv, "windows", "202609180001", "deadbeef")
	if !VerifyUpdateSig("windows", "202609180001", "deadbeef", sig) {
		t.Fatal("valid signature was rejected")
	}
}

func TestVerifyUpdateSig_RejectsTamperedFields(t *testing.T) {
	priv := withThrowawayKey(t)
	sig := SignUpdate(priv, "windows", "202609180001", "deadbeef")

	cases := []struct {
		name, slug, version, hash string
	}{
		{"wrong slug", "macos", "202609180001", "deadbeef"},
		{"wrong version", "windows", "202609180002", "deadbeef"},
		{"wrong hash", "windows", "202609180001", "cafebabe"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if VerifyUpdateSig(c.slug, c.version, c.hash, sig) {
				t.Fatal("signature for a different (slug,version,hash) triple was accepted")
			}
		})
	}
}

func TestVerifyUpdateSig_RejectsMalformedInput(t *testing.T) {
	withThrowawayKey(t)

	if VerifyUpdateSig("windows", "202609180001", "deadbeef", "") {
		t.Fatal("empty signature accepted")
	}
	if VerifyUpdateSig("windows", "202609180001", "deadbeef", "not-valid-base64!!!") {
		t.Fatal("garbage signature accepted")
	}
}

func TestParseUpdateSigningKeyHex(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseUpdateSigningKeyHex(hex.EncodeToString(priv))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !parsed.Equal(priv) {
		t.Fatal("round-tripped key does not match original")
	}

	if _, err := ParseUpdateSigningKeyHex("not-hex"); err == nil {
		t.Fatal("expected error for non-hex input")
	}
	if _, err := ParseUpdateSigningKeyHex("aabbcc"); err == nil {
		t.Fatal("expected error for wrong-length key")
	}
}
