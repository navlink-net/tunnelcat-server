// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

//go:build linux

package androidcore

import (
	"fmt"
	"net"
	"time"

	snc "tunnel_cat/snc/core"
)

// LogNetworkInterfaces logs all active network interfaces and their addresses.
// Called once at startup before bootstrap to establish a baseline for diagnostics.
func LogNetworkInterfaces() {
	ifaces, err := net.Interfaces()
	if err != nil {
		snc.Log.Printf("diag: interfaces: %v", err)
		return
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		var addrStrs []string
		for _, a := range addrs {
			addrStrs = append(addrStrs, a.String())
		}
		snc.Log.Printf("diag: iface %s flags=%v addrs=%v", iface.Name, iface.Flags, addrStrs)
	}
}

// ProbeTCP attempts a raw TCP connection to addr and logs the result with timing.
// Uses Protect.DialControl so the socket bypasses the VPN TUN on Android.
// Returns the error (nil = reachable).
func ProbeTCP(addr string) error {
	t0 := time.Now()
	d := net.Dialer{
		Timeout: 5 * time.Second,
		Control: Protect.DialControl,
	}
	conn, err := d.Dial("tcp", addr)
	elapsed := time.Since(t0).Round(time.Millisecond)
	if err != nil {
		snc.Log.Printf("diag: TCP probe %s FAILED elapsed=%s err=%v", addr, elapsed, err)
		return err
	}
	conn.Close()
	snc.Log.Printf("diag: TCP probe %s OK elapsed=%s", addr, elapsed)
	return nil
}

// ProbeAddr returns addr with :443 appended if no port is present.
func ProbeAddr(node string) string {
	if _, _, err := net.SplitHostPort(node); err != nil {
		return fmt.Sprintf("%s:443", node)
	}
	return node
}
