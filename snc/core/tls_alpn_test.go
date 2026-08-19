// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// selfSignedCert returns a tls.Certificate for a throwaway self-signed cert,
// usable directly in a tls.Config for a real listener (unlike selfSignedDER,
// which only returns the raw DER for fingerprint tests).
func selfSignedCert(t *testing.T) tls.Certificate {
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
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestNewUTLSTransportRaw_RejectsNonH2Peer is the direct regression test for
// the 2026-08-16 "frame too large" root cause: http2.Transport trusts a
// custom DialTLSContext's connection to speak h2 without ever checking
// ConnectionState().NegotiatedProtocol itself. A peer whose tls.Config
// doesn't list "h2" in NextProtos (the actual state of snc-control's
// serveRelayAPI for any endpoint other than what its own local mux answers,
// and reproduced live via an isolated sandbox control+exit pair) silently
// gets garbage h2 preface bytes and answers with a genuine small HTTP/1.1
// response -- which surfaced as an opaque, misleading "frame too large"
// parse error instead of a clean dial failure.
func TestNewUTLSTransportRaw_RejectsNonH2Peer(t *testing.T) {
	cert := selfSignedCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		// NextProtos deliberately left empty -- this is the exact peer
		// state that broke: no ALPN participation at all.
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Plain HTTP/1.1 server: read the (garbled h2 preface) request
			// line and answer with a real, small HTTP/1.1 response, exactly
			// like the live snc-control reproduction did.
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				c.Read(buf) //nolint:errcheck
				io.WriteString(c, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n") //nolint:errcheck
			}(conn)
		}
	}()

	client := NewUTLSClientWithPreset(AllUTLSPresets()[0])
	client.Timeout = 5 * time.Second
	req, _ := http.NewRequest(http.MethodGet, "https://"+ln.Addr().String()+"/", nil)
	_, err = client.Do(req)

	if err == nil {
		t.Fatal("expected a dial error against a peer that never negotiates h2, got nil")
	}
	if !strings.Contains(err.Error(), "peer did not negotiate h2") {
		t.Errorf("expected a clean 'peer did not negotiate h2' error, got: %v", err)
	}
	if strings.Contains(err.Error(), "frame too large") {
		t.Errorf("got the old opaque 'frame too large' corruption error instead of a clean dial failure: %v", err)
	}
}

// TestNewUTLSTransportRaw_AcceptsRealH2Peer is the positive-case counterpart:
// a peer that actually negotiates and serves h2 must keep working exactly as
// before -- the fix must not turn genuinely-h2-capable connections into
// failures.
func TestNewUTLSTransportRaw_AcceptsRealH2Peer(t *testing.T) {
	cert := selfSignedCert(t)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		}),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	if err := http2.ConfigureServer(srv, nil); err != nil {
		t.Fatalf("ConfigureServer: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srv.TLSConfig)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go srv.Serve(ln) //nolint:errcheck

	client := NewUTLSClientWithPreset(AllUTLSPresets()[0])
	client.Timeout = 5 * time.Second
	req, _ := http.NewRequest(http.MethodGet, "https://"+ln.Addr().String()+"/", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("expected a clean h2 round trip against a real h2 peer, got: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTeapot {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusTeapot)
	}
}
