// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
)

// certFingerprint and pinnedTLSConfig mirror snc/core/tls.go's
// certFingerprint/PinnedTLSConfig exactly (same SHA-256-over-DER,
// colon-hex, uppercase format), duplicated here on purpose rather than
// importing tunnel_cat/snc/core: that package's log.go init() hard-exits any
// binary that imports it unless built with -ldflags -X
// tunnel_cat/snc/core.Version=<real timestamp> -- snc-arbiter has never
// needed that build step and pulling in this one small primitive isn't
// worth taking it on. If a second real need for snc/core shows up in
// snc-arbiter, revisit this duplication then.
func certFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// pinnedTLSConfig returns a *tls.Config that verifies a peer by certificate
// fingerprint instead of the normal PKI chain -- used for arbiter-to-arbiter
// replication, where each cluster node's cert is issued for its own bare IP
// (see replicateOneUpload's doc comment) so standard verification always
// fails. An empty expectedFP accepts unconditionally ("not pinned yet", not
// a verification failure) so an operator who hasn't configured
// --peer-arbiter-fingerprints yet gets the old behavior, not a hard failure.
func pinnedTLSConfig(expectedFP string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // fingerprint verified manually below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if expectedFP == "" {
				return nil
			}
			if len(rawCerts) == 0 {
				return fmt.Errorf("tls: no certificate presented")
			}
			got := certFingerprint(rawCerts[0])
			if got != strings.ToUpper(expectedFP) {
				return fmt.Errorf("tls: certificate fingerprint mismatch: got %s want %s", got, strings.ToUpper(expectedFP))
			}
			return nil
		},
	}
}
