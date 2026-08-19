// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

func newAutocertManager(domain, cacheDir string) *autocert.Manager {
	return &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),
		Cache:      autocert.DirCache(cacheDir),
	}
}

// dualCertTLSConfig serves two certificates from the one listener, picked by
// SNI -- lets an IP-literal-addressed fleet and a domain-addressed fleet be
// migrated gradually with zero breakage window, instead of a hard cutover.
// certPath/keyPath is the fallback served whenever the ClientHello carries no
// SNI (Go's TLS client never sends SNI for a bare IP literal per RFC 6066,
// which is exactly today's exit fleet) or an SNI that matches neither cert;
// cert2Path/key2Path is served only when the SNI hostname verifies against
// its leaf (e.g. the new domain cert, once exits start dialing by name).
func dualCertTLSConfig(certPath, keyPath, cert2Path, key2Path string) (*tls.Config, error) {
	cert1, err := loadCertWithLeaf(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	cert2, err := loadCertWithLeaf(cert2Path, key2Path)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName != "" && cert2.Leaf.VerifyHostname(hello.ServerName) == nil {
				return &cert2, nil
			}
			return &cert1, nil
		},
	}, nil
}

func loadCertWithLeaf(certPath, keyPath string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, err
	}
	cert.Leaf = leaf
	return cert, nil
}

func selfSignedTLSConfig(certDir string) (*tls.Config, error) {
	certPath := filepath.Join(certDir, "self-signed.crt")
	keyPath := filepath.Join(certDir, "self-signed.key")

	if err := os.MkdirAll(certDir, 0700); err != nil {
		return nil, err
	}

	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			if time.Until(leaf.NotAfter) > 30*24*time.Hour {
				logInfof("tls: loaded existing self-signed cert %s (expires %s)",
					certPath, leaf.NotAfter.Format("2006-01-02"))
				return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
			}
			logInfof("tls: self-signed cert expires soon, regenerating")
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
		Subject:      pkix.Name{CommonName: "snc-arbiter"},
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
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cf.Close()

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
	logInfof("tls: generated self-signed cert → %s (expires %s, SANs: %v)",
		certPath, leaf.NotAfter.Format("2006-01-02"), ipSANs)

	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}
