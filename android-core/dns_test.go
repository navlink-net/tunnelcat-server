// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

//go:build linux

package androidcore

import (
	"context"
	"net"
	"testing"
)

// TestConnectedUDP verifies that connectedUDP correctly bridges net.PacketConn
// to the net.Conn interface expected by net.Resolver.Dial.
// Runs on any Linux machine with internet access — no Android, no protect socket needed.
func TestConnectedUDP(t *testing.T) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			lc := net.ListenConfig{}
			pc, err := lc.ListenPacket(ctx, "udp4", ":0")
			if err != nil {
				return nil, err
			}
			return &connectedUDP{PacketConn: pc, remote: &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}}, nil
		},
	}

	addrs, err := resolver.LookupHost(context.Background(), "google.com")
	if err != nil {
		t.Fatalf("LookupHost: %v", err)
	}
	if len(addrs) == 0 {
		t.Fatal("no addresses returned")
	}
	t.Logf("google.com → %v", addrs)
}
