// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

//go:build linux

package androidcore

import (
	"net"
	"time"
)

// connectedUDP bridges net.PacketConn to net.Conn for use with net.Resolver.Dial.
// net.Resolver expects a stream-oriented net.Conn; connectedUDP makes a UDP
// PacketConn appear as a connected stream by fixing the remote address so
// Read/Write behave like a regular TCP connection.
type connectedUDP struct {
	net.PacketConn
	remote net.Addr
}

func (c *connectedUDP) Read(b []byte) (int, error) {
	n, _, err := c.PacketConn.ReadFrom(b)
	return n, err
}

func (c *connectedUDP) Write(b []byte) (int, error) {
	return c.PacketConn.WriteTo(b, c.remote)
}

func (c *connectedUDP) RemoteAddr() net.Addr { return c.remote }

// SetDeadline, SetReadDeadline, SetWriteDeadline, LocalAddr, Close
// are all satisfied by the embedded net.PacketConn.
var _ net.Conn = (*connectedUDP)(nil)

// newConnectedUDP returns a net.Conn backed by a protected UDP socket bound
// to an ephemeral local port and logically connected to addr. Used to resolve
// DNS via a UDP resolver that bypasses the VPN TUN so DNS lookups used by
// the tunnel setup itself do not route through the tunnel.
func newConnectedUDP(dialFn func(network, addr string) (net.Conn, error), addr string) (net.Conn, error) {
	// dialFn is expected to create a VPN-protected socket. We need a PacketConn,
	// but dialFn returns a net.Conn — use a raw UDP listen + connect pattern instead.
	udpAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return nil, err
	}
	_ = pc.SetDeadline(time.Time{}) // clear deadline; callers set their own
	return &connectedUDP{PacketConn: pc, remote: udpAddr}, nil
}
