// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

// startUDPMTUEcho listens on port 19309 and echoes every received UDP datagram
// back to its sender. Used by snc-probe --mtu-probe to measure the maximum UDP
// datagram size that the VK TURN relay can deliver end-to-end without loss.
// Port 19308 is reserved for the WLWTP listener.
//
// No authentication: the port is only reachable via the VK TURN relay (not
// directly from the internet, since the relay address is ephemeral and private).

import (
	"fmt"
	"net"
	"os"
)

const mtuEchoPort = "19309"

func startUDPMTUEcho() {
	port := os.Getenv("VK_TURN_MTU_ECHO_PORT")
	if port == "" {
		port = mtuEchoPort
	}
	conn, err := net.ListenPacket("udp", "0.0.0.0:"+port)
	if err != nil {
		logWarnf("mtu-echo: listen udp :%s: %v", port, err)
		return
	}
	logInfof("mtu-echo: listening on %s", conn.LocalAddr())
	go serveUDPMTUEcho(conn)
}

func serveUDPMTUEcho(conn net.PacketConn) {
	defer conn.Close()
	buf := make([]byte, 65535)
	for {
		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		go func() {
			if _, err := conn.WriteTo(pkt, src); err != nil {
				logDebugf("mtu-echo: write to %s: %v", src, err)
			} else {
				logDebugf("mtu-echo: echoed %d bytes to %s", len(pkt), src)
			}
		}()
		fmt.Printf("") // keep compiler happy
	}
}
