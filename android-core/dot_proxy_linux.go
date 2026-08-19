// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

//go:build linux

package androidcore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"

	snc "tunnel_cat/snc/core"
)

// dotProxy is a local DNS-over-TLS terminator.  It listens on an ephemeral
// loopback port, accepts TLS connections (self-signed cert; Android
// opportunistic DoT â€” RFC 7858 Â§4 â€” does not verify the server cert),
// and forwards each DNS query as DNS-over-TCP to Russian-capable upstream
// resolvers using protected sockets that bypass the VPN TUN.
//
// The TUN dialer intercepts TCP connections to port 853 and redirects them
// here, so Android Private DNS in "Automatic" mode continues to work even
// when 8.8.8.8 is blocked by the carrier.
type dotProxy struct {
	ln      net.Listener
	addr    string // e.g. "127.0.0.1:34567"
	dialFn  func(addr string) (net.Conn, error)
	servers []string
}

// NewDotProxy starts the TLS listener on an ephemeral loopback port.
// dialFn must create sockets that bypass the VPN TUN (use Protect.DialControl).
func NewDotProxy(dialFn func(addr string) (net.Conn, error)) (*dotProxy, error) {
	cert, err := dotSelfSignedCert()
	if err != nil {
		return nil, fmt.Errorf("dot-proxy: cert: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("dot-proxy: listen: %w", err)
	}
	p := &dotProxy{
		ln:     ln,
		addr:   ln.Addr().String(),
		dialFn: dialFn,
		// Russian-capable resolvers first so 8.8.8.8 being blocked does not
		// cause a timeout before a working server is tried.
		servers: []string{
			"77.88.8.8:53",
			"77.88.8.1:53",
			"8.8.8.8:53",
			"8.8.4.4:53",
			"1.1.1.1:53",
		},
	}
	snc.Log.Printf("dot-proxy: listening on %s", p.addr)
	return p, nil
}

// Addr returns the local address the proxy is listening on (e.g. "127.0.0.1:34567").
func (p *dotProxy) Addr() string { return p.addr }

// Serve accepts connections until Close is called.  Meant to run in a goroutine.
func (p *dotProxy) Serve() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handleConn(conn)
	}
}

// Close shuts down the listener.
func (p *dotProxy) Close() { p.ln.Close() }

func (p *dotProxy) handleConn(conn net.Conn) {
	defer conn.Close()
	for {
		// RFC 7858 Â§3.3: each DNS message is preceded by a 2-octet length field.
		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		msgLen := binary.BigEndian.Uint16(lenBuf[:])
		if msgLen == 0 {
			return
		}
		query := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}

		snc.Log.Printf("dot-proxy: query q=%q", snc.DescribeQuestion(query))
		resp, err := p.forward(query)
		if err != nil {
			snc.Log.Printf("dot-proxy: forward: %v", err)
			return
		}
		// Learn IPâ†’FQDN mappings so ShouldBypass's TLD override can apply to
		// queries resolved over DoT (Android Private DNS), not just the
		// UDP:53 path through udp_assoc.go.
		snc.GlobalDNSCache.ParseAndLearn(resp)

		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out, uint16(len(resp)))
		copy(out[2:], resp)
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

// forward sends query to each upstream resolver until one responds.
func (p *dotProxy) forward(query []byte) ([]byte, error) {
	var lastErr error
	for _, srv := range p.servers {
		conn, err := p.dialFn(srv)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := dotExchangeTCP(conn, query)
		conn.Close()
		if err != nil {
			lastErr = err
			continue
		}
		return resp, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("all resolvers failed")
}

// dotExchangeTCP sends query and reads the response on a DNS-over-TCP connection
// (RFC 1035 Â§4.2.2: 2-byte big-endian length prefix before each message).
func dotExchangeTCP(conn net.Conn, query []byte) ([]byte, error) {
	conn.SetDeadline(time.Now().Add(4 * time.Second)) //nolint:errcheck

	buf := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(buf, uint16(len(query)))
	copy(buf[2:], query)
	if _, err := conn.Write(buf); err != nil {
		return nil, err
	}

	var rlenBuf [2]byte
	if _, err := io.ReadFull(conn, rlenBuf[:]); err != nil {
		return nil, err
	}
	rlen := binary.BigEndian.Uint16(rlenBuf[:])
	resp := make([]byte, rlen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// dotSelfSignedCert generates a throw-away ECDSA P-256 certificate.
// Android Private DNS "Automatic" (opportunistic TLS) does not verify the
// server certificate, so any cert is accepted.
func dotSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "snc-dot"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}, nil
}
