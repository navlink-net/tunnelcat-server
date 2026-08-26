// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

// QUIC-based client<->control tunnel transport. Replaces the old SNCU UDP
// fallback (see the now-removed udp_tunnel.go): rather than a bespoke
// request/response protocol with its own retry/backoff logic, each tunneled
// connection gets one QUIC stream, wrapped as a plain net.Conn and handed to
// the *same* tcpProxy.handle used for the normal TCP path — so relaying,
// auth, and exit selection are entirely unchanged and only the transport
// underneath is new.
//
// Scope: client<->control only. The control<->exit hop still uses its own
// existing mechanism and is untouched by this file.

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// quicALPN must also be set as the client's tls.Config.NextProtos.
const quicALPN = "snc-tun-v1"

// startQUICTunnel brings up a QUIC listener sharing demux (already wired
// into UDPReflector, using the same tracker, so QUIC-classified packets
// reach it) and serves every accepted stream through proxy.handle.
func startQUICTunnel(demux *quicPacketConn, tracker *quicCIDTracker, tlsCfg *tls.Config, proxy *tcpProxy) {
	qTLS := tlsCfg.Clone()
	qTLS.NextProtos = []string{quicALPN}

	cidGen := &quicConnIDGenerator{tracker: tracker}

	transport := &quic.Transport{
		Conn:                  demux,
		ConnectionIDGenerator: cidGen,
	}

	ln, err := transport.Listen(qTLS, &quic.Config{
		MaxIdleTimeout: 60 * time.Second,
		// Matches the client's own dial timeout (snc/core/quic_relay.go's
		// quicConnConfig) -- a real client gives up on its side after ~1s
		// anyway, so the server holding handshake state any longer than
		// that for a stalled/malicious attempt buys nothing and just wastes
		// resources under load.
		HandshakeIdleTimeout: 1 * time.Second,
		KeepAlivePeriod:      20 * time.Second,
	})
	if err != nil {
		logErrorf("quic: listen: %v", err)
		return
	}
	logInfof("quic: tunnel listening (ALPN=%s)", quicALPN)

	for {
		conn, err := ln.Accept(context.Background())
		if err != nil {
			logWarnf("quic: accept: %v", err)
			continue
		}
		go serveQUICConn(conn, proxy)
	}
}

func serveQUICConn(conn *quic.Conn, proxy *tcpProxy) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return // connection closed/idle-timed-out
		}
		go proxy.handle(&quicStreamConn{stream: stream, conn: conn})
	}
}

// quicStreamConn adapts a *quic.Stream (which has Read/Write/Close/deadlines
// but no address methods, since a stream isn't itself addressed) into a
// net.Conn by borrowing the parent connection's addresses.
type quicStreamConn struct {
	stream *quic.Stream
	conn   *quic.Conn
}

func (c *quicStreamConn) Read(p []byte) (int, error)         { return c.stream.Read(p) }
func (c *quicStreamConn) Write(p []byte) (int, error)        { return c.stream.Write(p) }
func (c *quicStreamConn) Close() error                       { return c.stream.Close() }
func (c *quicStreamConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *quicStreamConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *quicStreamConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *quicStreamConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *quicStreamConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }
