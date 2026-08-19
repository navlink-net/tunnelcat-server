// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// selfSignedDER returns the raw DER of a throwaway self-signed cert, matching
// the shape verifyPeerCertFingerprint actually receives from a live handshake.
func selfSignedDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return der
}

func TestVerifyPeerCertFingerprint_EmptyExpectedAccepts(t *testing.T) {
	der := selfSignedDER(t)
	verify := verifyPeerCertFingerprint("")
	if err := verify([][]byte{der}, nil); err != nil {
		t.Fatalf("empty expected fingerprint should accept unconditionally, got: %v", err)
	}
}

func TestVerifyPeerCertFingerprint_MatchingAccepts(t *testing.T) {
	der := selfSignedDER(t)
	expected := certFingerprint(der)
	verify := verifyPeerCertFingerprint(expected)
	if err := verify([][]byte{der}, nil); err != nil {
		t.Fatalf("matching fingerprint should accept, got: %v", err)
	}
	// Case-insensitivity: manifest data could plausibly arrive lowercase.
	verifyLower := verifyPeerCertFingerprint(toLowerFP(expected))
	if err := verifyLower([][]byte{der}, nil); err != nil {
		t.Fatalf("lowercase-but-matching fingerprint should accept, got: %v", err)
	}
}

func TestVerifyPeerCertFingerprint_MismatchRejects(t *testing.T) {
	der := selfSignedDER(t)
	other := selfSignedDER(t)
	expected := certFingerprint(other) // deliberately the wrong cert's fingerprint
	verify := verifyPeerCertFingerprint(expected)
	if err := verify([][]byte{der}, nil); err == nil {
		t.Fatal("mismatched fingerprint should reject, got nil error")
	}
}

func TestVerifyPeerCertFingerprint_NoCertsRejects(t *testing.T) {
	verify := verifyPeerCertFingerprint("AA:BB")
	if err := verify(nil, nil); err == nil {
		t.Fatal("no certificates presented should reject, got nil error")
	}
}

func toLowerFP(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'F' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
