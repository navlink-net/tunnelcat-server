// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// waitQUICFailed polls rc.Failed() until it reports true or the deadline
// passes. quic-go marks a connection's context Done asynchronously relative
// to CloseWithError returning, so callers that just closed a connection to
// simulate a failure need this instead of asserting Failed() immediately.
func waitQUICFailed(t *testing.T, rc *quicControlConn) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if rc.Failed() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("quicControlConn never reported Failed() after CloseWithError")
}

// newTestQUICControlConn starts a local QUIC listener, dials it, and returns
// a quicControlConn wrapping the live client-side connection plus a cleanup
// func. Used by udp_assoc_test.go's realtime-dialer tests, which need a real
// *quic.Conn whose liveness (Failed()) they can control by closing it.
func newTestQUICControlConn(t *testing.T) (rc *quicControlConn, cleanup func()) {
	t.Helper()

	cert := selfSignedCert(t)
	srvTLS := &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{quicClientALPN}}

	ln, err := quic.ListenAddr("127.0.0.1:0", srvTLS, nil)
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				for {
					if _, err := conn.AcceptStream(context.Background()); err != nil {
						return
					}
				}
			}()
		}
	}()

	conn, err := quic.DialAddr(context.Background(), ln.Addr().String(), quicClientTLSConfig(), quicConnConfig())
	if err != nil {
		ln.Close() //nolint:errcheck
		t.Fatalf("quic dial: %v", err)
	}

	rc = &quicControlConn{addr: ln.Addr().String(), conn: conn}
	cleanup = func() {
		conn.CloseWithError(0, "") //nolint:errcheck
		ln.Close()                 //nolint:errcheck
	}
	return rc, cleanup
}
