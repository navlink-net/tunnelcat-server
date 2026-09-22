// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// selfSignedTLSConfig returns a *tls.Config using a self-signed ECDSA cert.
// The cert is generated on first call and cached in certDir.
// Valid for 10 years; includes the server's non-loopback IPs as SANs so that
// clients can pin it by fingerprint.
func selfSignedTLSConfig(certDir string) (*tls.Config, error) {
	certPath := filepath.Join(certDir, "self-signed.crt")
	keyPath := filepath.Join(certDir, "self-signed.key")

	if err := os.MkdirAll(certDir, 0700); err != nil {
		return nil, err
	}

	// Reuse existing pair if both files are present and not expired.
	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			if time.Until(leaf.NotAfter) > 30*24*time.Hour {
				fp := certFingerprint(leaf.Raw)
				logInfof("tls: loaded self-signed cert %s (expires %s) fingerprint=%s",
					certPath, leaf.NotAfter.Format("2006-01-02"), fp)
				return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
			}
			logInfof("tls: self-signed cert expires soon, regenerating")
		}
	}

	// Generate new ECDSA P-256 key.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Collect local IPs for SANs.
	var ipSANs []net.IP
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && !ip.IsLoopback() {
				ipSANs = append(ipSANs, ip)
			}
		}
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "snc-exit"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  ipSANs,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	// Write cert.
	cf, err := os.OpenFile(certPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, err
	}
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cf.Close()

	// Write key.
	kf, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	kf.Close()

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	fp := certFingerprint(leaf.Raw)
	logInfof("tls: generated self-signed cert → %s (expires %s, SANs: %v) fingerprint=%s",
		certPath, leaf.NotAfter.Format("2006-01-02"), ipSANs, fp)

	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

func certFingerprint(der []byte) string {
	h := sha256.Sum256(der)
	parts := make([]string, len(h))
	for i, b := range h {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// pinnedTLSConfig returns a *tls.Config for dialing another exit whose
// identity is verified by certificate fingerprint rather than the normal PKI
// chain -- the same mechanism control-node connections already use (see
// tunnel_cat/snc/core/tls.go's PinnedTLSConfig; duplicated here in package
// main rather than imported so this file's own certFingerprint stays the
// single source of truth for the fingerprint format both sides compare).
//
// Added 2026-09 security review #2: dialPeer/probePeer/fetchPeerCapabilities
// previously used a bare InsecureSkipVerify with no verification at all,
// letting an on-path attacker between two exit-node datacenters MITM
// relayed user traffic and this exit's own bearer node token. expectedFP
// comes from PeerEntry.Fingerprint, itself sourced from the arbiter's
// Ed25519-signed "exits" list -- empty only when the arbiter hasn't
// recorded a fingerprint for that peer yet (e.g. autocert not fetched),
// in which case this intentionally behaves like an unpinned bootstrap
// connection rather than refusing to dial at all, exactly like
// verifyPeerCertFingerprint's own doc comment describes for the client side.
func pinnedTLSConfig(expectedFP string) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify:    true, //nolint:gosec // fingerprint verified manually below
		VerifyPeerCertificate: verifyPeerCertFingerprint(expectedFP),
	}
}

func verifyPeerCertFingerprint(expectedFP string) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if expectedFP == "" {
			return nil
		}
		if len(rawCerts) == 0 {
			return fmt.Errorf("tls: no certificate presented")
		}
		got := certFingerprint(rawCerts[0])
		if got != strings.ToUpper(expectedFP) {
			return fmt.Errorf("tls: peer certificate fingerprint mismatch: got %s want %s", got, strings.ToUpper(expectedFP))
		}
		return nil
	}
}
