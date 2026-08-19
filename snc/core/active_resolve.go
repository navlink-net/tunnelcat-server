// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// activeResolveServers mirrors the resolver preference order already used by
// android-core's dotProxy (Russian-capable resolvers first so 8.8.8.8 being
// blocked doesn't cause a timeout before a working server is tried).
var activeResolveServers = []string{
	"77.88.8.8:53",
	"77.88.8.1:53",
	"8.8.8.8:53",
	"8.8.4.4:53",
	"1.1.1.1:53",
}

const activeResolveTimeout = 3 * time.Second

// ActiveResolveIPv4 finds an IPv4 address for a blocked IPv6 destination by
// actively querying through the tunnel — PTR on the IPv6 address to learn
// its hostname, then A on that hostname — instead of passively waiting for
// GlobalDNSCache to have learned it from traffic that happened to pass
// through our own DNS relay.
//
// Why this exists: confirmed live, 2026-08-18, that Chrome can obtain an
// AAAA answer for a host (e.g. ya.ru) entirely from Android's own system DNS
// cache, with zero bytes of that resolution ever transiting our relay or DoT
// proxy -- GlobalDNSCache had nothing to learn from because there was
// nothing to observe. Android exposes no API for a non-root app to flush or
// bypass that system cache, so the only way to stop depending on it is to
// not depend on it: resolve ourselves, through the tunnel, on demand.
//
// dial must route through the tunnel (e.g. TunnelDialer.Dial) so this query
// is not exposed to leaking outside the VPN -- same privacy goal as the
// existing DNS-over-tunnel path in udp_assoc.go's forwardOutbound.
func ActiveResolveIPv4(dial func(target string) (net.Conn, error), blockedIPv6 netip.Addr) (ipv4 string, fqdn string, err error) {
	fqdn, err = activeReverseResolve(dial, blockedIPv6)
	if err != nil {
		return "", "", fmt.Errorf("active-resolve: PTR %s: %w", blockedIPv6, err)
	}
	ipv4, err = activeForwardResolveA(dial, fqdn)
	if err != nil {
		return "", "", fmt.Errorf("active-resolve: A %s: %w", fqdn, err)
	}
	return ipv4, fqdn, nil
}

// ActiveResolveIPv4ForHost resolves fqdn's IPv4 address through the tunnel
// directly (A query only, no PTR step) and caches the result. Used when the
// caller already knows the real hostname -- e.g. sniffed from a TLS
// ClientHello's SNI extension -- which is strictly more reliable than the
// PTR-then-A path ActiveResolveIPv4 falls back to when no hostname is known:
// PTR records are frequently missing even for major, high-traffic hosts
// (confirmed live, 2026-08-18: sso.passport.yandex.ru, which ya.ru redirects
// to on every normal login, has none), while SNI is the exact real hostname
// the client is trying to reach, with no reverse-lookup ambiguity at all.
func ActiveResolveIPv4ForHost(dial func(target string) (net.Conn, error), fqdn string) (string, error) {
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}
	return activeForwardResolveA(dial, fqdn)
}

func activeReverseResolve(dial func(target string) (net.Conn, error), ip netip.Addr) (string, error) {
	name, err := ptrName(ip)
	if err != nil {
		return "", err
	}
	resp, err := activeExchange(dial, name, dnsmessage.TypePTR)
	if err != nil {
		return "", err
	}
	var p dnsmessage.Parser
	if _, err := p.Start(resp); err != nil {
		return "", err
	}
	if err := p.SkipAllQuestions(); err != nil {
		return "", err
	}
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			return "", fmt.Errorf("no PTR answer")
		}
		if h.Type == dnsmessage.TypePTR {
			r, err := p.PTRResource()
			if err != nil {
				return "", err
			}
			return r.PTR.String(), nil
		}
		if err := p.SkipAnswer(); err != nil {
			return "", fmt.Errorf("no PTR answer")
		}
	}
}

func activeForwardResolveA(dial func(target string) (net.Conn, error), fqdn string) (string, error) {
	resp, err := activeExchange(dial, fqdn, dnsmessage.TypeA)
	if err != nil {
		return "", err
	}
	var p dnsmessage.Parser
	if _, err := p.Start(resp); err != nil {
		return "", err
	}
	if err := p.SkipAllQuestions(); err != nil {
		return "", err
	}
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			return "", fmt.Errorf("no A answer")
		}
		if h.Type == dnsmessage.TypeA {
			r, err := p.AResource()
			if err != nil {
				return "", err
			}
			ip := net.IP(r.A[:]).String()
			ttl := time.Duration(h.TTL) * time.Second
			GlobalDNSCache.Set(ip, fqdn, ttl)
			GlobalDNSCache.setHost(fqdn, ip, ttl)
			return ip, nil
		}
		if err := p.SkipAnswer(); err != nil {
			return "", fmt.Errorf("no A answer")
		}
	}
}

// activeExchange tries each server in activeResolveServers in turn, over a
// tunneled DNS-over-TCP connection, until one answers.
func activeExchange(dial func(target string) (net.Conn, error), name string, qtype dnsmessage.Type) ([]byte, error) {
	query, err := buildQuery(name, qtype)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, srv := range activeResolveServers {
		conn, err := dial(srv)
		if err != nil {
			lastErr = err
			continue
		}
		resp, err := dnsExchangeTCP(conn, query)
		conn.Close()
		if err != nil {
			lastErr = err
			continue
		}
		return resp, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no resolvers reachable")
	}
	return nil, lastErr
}

// dnsExchangeTCP sends query and reads the response on a DNS-over-TCP
// connection (RFC 1035 §4.2.2: 2-byte big-endian length prefix per message).
func dnsExchangeTCP(conn net.Conn, query []byte) ([]byte, error) {
	conn.SetDeadline(time.Now().Add(activeResolveTimeout)) //nolint:errcheck

	buf := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(buf, uint16(len(query)))
	copy(buf[2:], query)
	if _, err := conn.Write(buf); err != nil {
		return nil, err
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	rlen := binary.BigEndian.Uint16(lenBuf[:])
	resp := make([]byte, rlen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func buildQuery(name string, qtype dnsmessage.Type) ([]byte, error) {
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}
	id := uint16(rand.Intn(1 << 16)) //nolint:gosec
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: n, Type: qtype, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	return b.Finish()
}

// ptrName builds the reverse-lookup name for ip (RFC 3596 §2.5 for IPv6:
// nibble-reversed hex under ip6.arpa; RFC 1035 §3.5 style for IPv4 under
// in-addr.arpa).
func ptrName(ip netip.Addr) (string, error) {
	if ip.Is4() || ip.Is4In6() {
		b := ip.As4()
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", b[3], b[2], b[1], b[0]), nil
	}
	if !ip.Is6() {
		return "", fmt.Errorf("ptrName: unsupported address %s", ip)
	}
	b := ip.As16()
	var sb strings.Builder
	for i := len(b) - 1; i >= 0; i-- {
		sb.WriteString(fmt.Sprintf("%x.%x.", b[i]&0xf, b[i]>>4))
	}
	sb.WriteString("ip6.arpa.")
	return sb.String(), nil
}
