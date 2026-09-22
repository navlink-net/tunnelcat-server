// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// UpdateSigningPubKeyHex is the Ed25519 public key (hex, 32 bytes) that
// signs every OTA client update artifact. The matching private key lives
// only on the release/arbiter side (see snc-arbiter's --update-signing-key
// flag, admin_downloads.go's adminDownloadsUpload) and is never committed
// anywhere. This constant is not a secret -- shipping the verify key inside
// every client binary is the entire point, exactly like the arbiter's own
// node-list signing pubkey the client already pins via the SNC key string.
//
// Self-hosters running their own arbiter/control fleet from this repo must
// generate their own keypair and replace this value with their own public
// key before building clients -- see docs/UPDATE_SIGNING.md. Clients built
// against the value below only trust updates signed by the official
// navlink.net fleet's key.
//
// Added 2026-09-18: closes the gap where OTA updates were fetched over a
// deliberately-unverified TLS connection (controls are addressed by IP with
// self-signed certs -- see updater.go) with no integrity check beyond a
// SHA-256 fetched over that same unauthenticated channel, i.e. no actual
// protection against a malicious or on-path-compromised control node
// serving an arbitrary binary. See the 2026-09 security review.
//
// Not a const: TestSignAndVerifyUpdate_RoundTrip and friends (update_sig_test.go)
// swap in a throwaway keypair rather than depending on this real value.
var UpdateSigningPubKeyHex = "a4ce8cbc4c4020b71814b529b6a94498f95edb1104c32b029f27100ac543414f"

// updateSigMessage builds the exact byte string signed at upload time and
// re-derived at verify time: slug|version|sha256hex. Binding all three
// prevents splicing a validly-signed sidecar from one slug/version onto a
// different binary -- a bare "sign the hash" scheme wouldn't catch that.
func updateSigMessage(slug, version, sha256Hex string) []byte {
	return []byte(slug + "|" + version + "|" + sha256Hex)
}

// VerifyUpdateSig reports whether sigB64 (RawURLEncoding base64, as produced
// by SignUpdate) is a valid Ed25519 signature over (slug, version, sha256Hex)
// under UpdateSigningPubKeyHex. Never panics -- any malformed input (bad hex,
// bad base64, wrong length) simply fails closed. A client MUST treat a false
// return exactly like a SHA-256 mismatch: refuse to apply the update.
func VerifyUpdateSig(slug, version, sha256Hex, sigB64 string) bool {
	pub, err := hex.DecodeString(UpdateSigningPubKeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, updateSigMessage(slug, version, sha256Hex), sig)
}

// SignUpdate signs (slug, version, sha256Hex) with priv and returns the
// RawURLEncoding base64 signature VerifyUpdateSig expects. Used only by the
// arbiter's upload handler, which holds the matching private key -- exported
// here so the signing and verification message format can never drift apart
// into two independently hand-written copies.
func SignUpdate(priv ed25519.PrivateKey, slug, version, sha256Hex string) string {
	sig := ed25519.Sign(priv, updateSigMessage(slug, version, sha256Hex))
	return base64.RawURLEncoding.EncodeToString(sig)
}

// ParseUpdateSigningKeyHex decodes a hex-encoded Ed25519 private key (64
// bytes: 32-byte seed + 32-byte public key, Go's standard ed25519.PrivateKey
// encoding) as loaded from the --update-signing-key flag/file. Kept here
// alongside Verify/Sign so every caller parses the exact same way.
func ParseUpdateSigningKeyHex(hexKey string) (ed25519.PrivateKey, error) {
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, errUpdateKeySize
	}
	return ed25519.PrivateKey(b), nil
}

// VerifyTorrentFileHash hashes the file at path and compares it against
// expectedSHA256Hex (case-insensitive hex). Used by every platform's
// ApplyTorrentDownloaded* to check a torrent-delivered update artifact
// against the manifest-signed hash (Discoverer.TorrentHash) before it is
// extracted/installed -- a BitTorrent infohash alone only proves the bytes
// match the magnet the client happened to be given, not that the magnet
// came from the arbiter; this closes that gap. Fails closed: an empty
// expectedSHA256Hex (no signed hash known for this slug -- e.g. an old
// arbiter, or the manifest hasn't been fetched yet) is treated as a mismatch,
// never as "no check requested."
func VerifyTorrentFileHash(path, expectedSHA256Hex string) error {
	if expectedSHA256Hex == "" {
		return fmt.Errorf("torrent update: no signed hash known for this artifact, refusing to install")
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("torrent update: open %s: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("torrent update: hash %s: %w", path, err)
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(actual, expectedSHA256Hex) {
		return fmt.Errorf("torrent update: SHA-256 mismatch for %s: manifest says %s, got %s -- refusing to install", path, expectedSHA256Hex, actual)
	}
	return nil
}

var errUpdateKeySize = updateKeySizeError{}

type updateKeySizeError struct{}

func (updateKeySizeError) Error() string {
	return "update signing key: expected 64-byte (128 hex char) Ed25519 private key"
}
