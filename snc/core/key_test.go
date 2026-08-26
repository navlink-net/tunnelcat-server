// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func encodeB64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func TestEncodeParseRoundtrip(t *testing.T) {
	kd := &KeyData{
		Username: "alice",
		Password: "secret",
		Servers:  []string{"ru1.example.com:443", "ru2.example.com:443"},
		NodeID:   "node-abc",
		APIKey:   "testApiKey123",
	}
	ks, err := EncodeKeyString(kd)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	got, err := ParseKeyString(ks)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if got.Username != kd.Username {
		t.Errorf("username: got %q want %q", got.Username, kd.Username)
	}
	if got.Password != kd.Password {
		t.Errorf("password: got %q want %q", got.Password, kd.Password)
	}
	if len(got.Servers) != len(kd.Servers) {
		t.Errorf("servers len: got %d want %d", len(got.Servers), len(kd.Servers))
	}
	if got.NodeID != kd.NodeID {
		t.Errorf("node_id: got %q want %q", got.NodeID, kd.NodeID)
	}
	if got.APIKey != kd.APIKey {
		t.Errorf("api_key: got %q want %q", got.APIKey, kd.APIKey)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	cases := []string{"", "notbase64!!!", "AAAA"}
	for _, c := range cases {
		if _, err := ParseKeyString(c); err == nil {
			t.Errorf("expected error for %q", c)
		}
	}
}

func TestParseRejectsBadMagic(t *testing.T) {
	// valid base64url but wrong magic
	raw := make([]byte, 50)
	raw[0] = 0xFF
	import64 := encodeB64(raw)
	_, err := ParseKeyString(import64)
	if err == nil {
		t.Fatal("expected error for bad magic")
	}
}

func TestSignedKeyRoundtrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubHex := encodeHex(pub)

	kd := &KeyData{
		Username:      "alice",
		Password:      "s3cr3t",
		ControlNodes:  []string{"ctrl1.example.com:443"},
		ArbiterPubkey: pubHex,
		ClientID:      "clt_deadbeef",
	}

	ks, err := EncodeSignedKeyString(kd, priv)
	if err != nil {
		t.Fatalf("EncodeSignedKeyString: %v", err)
	}

	got, err := ParseKeyString(ks)
	if err != nil {
		t.Fatalf("ParseKeyString: %v", err)
	}
	if got.ClientID != "clt_deadbeef" {
		t.Errorf("ClientID: got %q want %q", got.ClientID, "clt_deadbeef")
	}
	if got.Sig == "" {
		t.Error("Sig should be non-empty in V2 key")
	}
}

func TestSignedKeyRejectsTampering(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pubHex := encodeHex(pub)

	kd := &KeyData{
		Username:      "alice",
		Password:      "s3cr3t",
		ControlNodes:  []string{"ctrl1.example.com:443"},
		ArbiterPubkey: pubHex,
		ClientID:      "clt_aaa",
	}
	ks, _ := EncodeSignedKeyString(kd, priv)

	// Tamper: decode, flip a byte in the ciphertext, re-encode.
	raw, _ := base64.RawURLEncoding.DecodeString(ks)
	raw[len(raw)-1] ^= 0xFF // corrupt last byte of poly1305 tag
	tampered := base64.RawURLEncoding.EncodeToString(raw)

	if _, err := ParseKeyString(tampered); err == nil {
		t.Error("expected error for tampered key")
	}
}

func TestSignedKeyRejectsWrongPubkey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, wrongPub, _ := ed25519.GenerateKey(rand.Reader)

	kd := &KeyData{
		Username:      "alice",
		Password:      "s3cr3t",
		ControlNodes:  []string{"ctrl1.example.com:443"},
		ArbiterPubkey: encodeHex(wrongPub), // wrong pubkey embedded
		ClientID:      "clt_bbb",
	}
	ks, _ := EncodeSignedKeyString(kd, priv)

	if _, err := ParseKeyString(ks); err == nil {
		t.Error("expected signature verification failure with wrong pubkey")
	}
}

func encodeHex(b []byte) string {
	const hextable = "0123456789abcdef"
	dst := make([]byte, len(b)*2)
	for i, v := range b {
		dst[i*2] = hextable[v>>4]
		dst[i*2+1] = hextable[v&0x0f]
	}
	return string(dst)
}

func TestEncodeIsDeterministicallyRandom(t *testing.T) {
	kd := &KeyData{Username: "bob", Password: "pw", Servers: nil, NodeID: "n"}
	ks1, _ := EncodeKeyString(kd)
	ks2, _ := EncodeKeyString(kd)
	if ks1 == ks2 {
		t.Error("two encodes should differ (random nonce)")
	}
}

func TestParseRejectsMissingUsername(t *testing.T) {
	kd := &KeyData{Username: "", Password: "pw"}
	ks, _ := EncodeKeyString(kd)
	_, err := ParseKeyString(ks)
	if err == nil {
		t.Fatal("expected error for empty username")
	}
}
