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

// selfSignedTLSConfig returns a *tls.Config backed by a self-signed ECDSA cert.
// The cert is generated once and cached in certDir.
func selfSignedTLSConfig(certDir string) (*tls.Config, error) {
	certPath := filepath.Join(certDir, "control.crt")
	keyPath := filepath.Join(certDir, "control.key")

	if err := os.MkdirAll(certDir, 0700); err != nil {
		return nil, err
	}

	// Reuse if present and not expiring soon.
	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			if time.Until(leaf.NotAfter) > 30*24*time.Hour {
				fp := tlsCertFingerprint(leaf.Raw)
				logInfof("tls: loaded cert %s (expires %s) fingerprint=%s",
					certPath, leaf.NotAfter.Format("2006-01-02"), fp)
				return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
			}
			logInfof("tls: cert expires soon, regenerating")
		}
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

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
		Subject:      pkix.Name{CommonName: "snc-control"},
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

	cf, err := os.OpenFile(certPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, err
	}
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der}) //nolint:errcheck
	cf.Close()

	kf, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}) //nolint:errcheck
	kf.Close()

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	fp := tlsCertFingerprint(leaf.Raw)
	logInfof("tls: generated cert → %s (expires %s, SANs: %v) fingerprint=%s",
		certPath, leaf.NotAfter.Format("2006-01-02"), ipSANs, fp)

	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

func tlsCertFingerprint(der []byte) string {
	h := sha256.Sum256(der)
	parts := make([]string, len(h))
	for i, b := range h {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}
