// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

// dns_forward.go — exit-local DNS forwarding for udp_tunnel.go's port-53
// interception (see handleUDPRelay). Plain forward-with-fallback, no
// recursive resolution: this exit's own egress asks a fixed list of public
// resolvers, same as any other client on this network segment would.

import (
	"fmt"
	"net"
	"time"
)

// dnsUpstreams are tried in order, first success wins. Deliberately more
// than one and deliberately NOT all the same operator -- the whole point of
// resolving exit-side is to stop every client fleet-wide depending on one
// shared external resolver (previously: every client's OS hardcoded to
// 1.1.1.1 specifically). If Cloudflare's resolver has a bad day, or gets
// filtered on some path this exit's egress happens to sit behind, the next
// entry takes over -- per-exit, independent of every other exit's fate.
var dnsUpstreams = []string{
	"1.1.1.1:53", // Cloudflare
	"8.8.8.8:53", // Google
	"9.9.9.9:53", // Quad9
}

const dnsUpstreamTimeout = 1500 * time.Millisecond

// forwardDNS tries each of dnsUpstreams in turn against a single raw DNS
// query (as received verbatim from the client's UDP relay frame), returning
// the first successful raw response. query/response are opaque wire-format
// DNS messages -- this never parses or rewrites them, just relays.
func forwardDNS(query []byte) ([]byte, error) {
	var lastErr error
	for _, upstream := range dnsUpstreams {
		resp, err := forwardDNSOne(upstream, query)
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("all dns upstreams failed, last error: %w", lastErr)
}

func forwardDNSOne(upstream string, query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", upstream, dnsUpstreamTimeout)
	if err != nil {
		return nil, fmt.Errorf("%s: dial: %w", upstream, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(dnsUpstreamTimeout)); err != nil {
		return nil, fmt.Errorf("%s: set deadline: %w", upstream, err)
	}
	if _, err := conn.Write(query); err != nil {
		return nil, fmt.Errorf("%s: write: %w", upstream, err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("%s: read: %w", upstream, err)
	}
	return buf[:n], nil
}
