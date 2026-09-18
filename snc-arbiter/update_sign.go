// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// signUpdate and parseUpdateSigningKeyHex mirror snc/core/update_sig.go's
// SignUpdate/ParseUpdateSigningKeyHex exactly (same message format:
// slug|version|sha256hex, same RawURLEncoding base64 signature encoding),
// duplicated here rather than importing tunnel_cat/snc/core -- see
// tls_pin.go's doc comment for why snc-arbiter avoids that import. Clients
// verify with core.VerifyUpdateSig against the SAME two functions' output;
// keep this in sync with update_sig.go if either format ever changes.
func signUpdate(priv ed25519.PrivateKey, slug, version, sha256Hex string) string {
	msg := []byte(slug + "|" + version + "|" + sha256Hex)
	sig := ed25519.Sign(priv, msg)
	return base64.RawURLEncoding.EncodeToString(sig)
}

// parseUpdateSigningKeyHex decodes a hex-encoded Ed25519 private key (64
// bytes: 32-byte seed + 32-byte public key) as loaded from the
// --update-signing-key flag/file.
func parseUpdateSigningKeyHex(hexKey string) (ed25519.PrivateKey, error) {
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("update signing key: %w", err)
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("update signing key: expected 64-byte (128 hex char) Ed25519 private key, got %d bytes", len(b))
	}
	return ed25519.PrivateKey(b), nil
}
