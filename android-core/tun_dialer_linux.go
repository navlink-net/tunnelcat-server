// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

//go:build linux

package androidcore

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
	snc "tunnel_cat/snc/core"
)

// appStickyDialer is a tun2socks proxy.Dialer that pins each Android app (by
// Linux UID) to a specific TunnelDialer so all TCP connections from the same
// app traverse the same control node and thus reach the same exit node.
//
// Why per-app sticky instead of per-connection random:
// A single app (e.g., a browser) opens many parallel TCP connections for the
// same page load. If each connection uses a different control â†’ different exit,
// the remote server sees requests arriving from different IP addresses â€” which
// looks like a botnet to CloudFlare, triggers CAPTCHAs, and breaks session
// cookies that are IP-pinned. Sticky-per-app keeps all connections from one app
// on the same exit IP, making the traffic indistinguishable from normal browsing.
//
// Why UID comes from Kotlin (ConnectivityManager.getConnectionOwnerUid) and
// not /proc/net/tcp or SO_PEERCRED:
// SO_PEERCRED gives the UID of the process on the other end of a Unix socket,
// not a TCP socket, so it doesn't apply here. /proc/net/tcp was tried first
// (scanning it by local port) but is silently non-functional on Android 11+,
// which restricts unprivileged processes to seeing only their own socket
// entries there -- confirmed live, 2026-08-17: every single lookup returned
// -1 on a real device across two full sessions, which (before PickForUID
// was fixed to treat a negative UID as "don't pin") meant every app's
// traffic matched every other app's on the same sentinel value and got
// pinned to one shared control -- silently reintroducing the exact
// whole-VPN-on-one-control behavior this feature exists to avoid.
// ConnectivityManager.getConnectionOwnerUid is the API Android actually
// grants for this, to the app holding the active VpnService role (the same
// privilege level that already lets addDisallowedApplication work for the
// per-app bypass feature) -- see UidClient in uid_linux.go and
// SNCVpnService.kt's uidLoop for the Kotlin side.
//
// UDP ASSOCIATE is delegated to the local SOCKS5 server because UDP relay
// requires a long-lived per-session state (the udpAssocSession struct) that
// survives across multiple UDP datagrams and must be torn down only when the
// control TCP connection closes. The SOCKS5 server already manages this
// lifetime correctly; duplicating it in the TUN dialer would create two
// independent relay paths with conflicting state.
//
// dotAddr, when non-empty, redirects TCP connections to port 853 (DoT) to the
// local DoT proxy instead of forwarding them through the tunnel.  This allows
// Android Private DNS to work even when 8.8.8.8:853 is blocked by the carrier.
type appStickyDialer struct {
	pool        *snc.DialerPool
	bypass      *snc.BypassManager
	socksAddr   string // local SOCKS5 server address for UDP ASSOCIATE
	dotAddr     string // local DoT proxy address; empty = no interception
	blockQUIC   bool   // when true, reject UDP:443 so apps fall back to TLS/TCP (QUIC-over-TCP-tunnel performs poorly)
	disableIPv6 bool   // user's manual "disable IPv6" preference, snapshotted at connect time (see main_linux.go SNC_DISABLE_IPV6)
}

// ipv6Blocked reports whether metadata's destination is a real IPv6 address
// (not an IPv4-mapped one) and IPv6 is currently supposed to be off, either
// by the user's own preference or the arbiter's live kill switch (see
// snc.IPv6TunnelDisabled's doc comment / admin_ipv6.go).
//
// This is the actual enforcement point. Kotlin's addSplitTunnelRoutes always
// captures ::/0 into the TUN now specifically so this check can run instead
// of letting the OS route IPv6 around the VPN entirely -- omitting the
// tunnel route is not the same as blocking IPv6 (confirmed real leak,
// 2026-08-16: with the route omitted, IPv6-capable apps just used the
// physical interface's own IPv6 directly, bypassing the tunnel completely).
// Checked live per-dial (not snapshotted) so a kill-switch flip from the
// arbiter takes effect immediately, mid-session, with no reconnect needed.
func (d *appStickyDialer) ipv6Blocked(addr netip.Addr) bool {
	if !addr.Is6() || addr.Is4In6() {
		return false
	}
	return d.disableIPv6 || snc.IPv6TunnelDisabled()
}

func (d *appStickyDialer) DialContext(ctx context.Context, metadata *M.Metadata) (net.Conn, error) {
	target := metadata.DestinationAddress()

	if d.ipv6Blocked(metadata.DstIP) {
		// Don't just refuse and hope the caller retries on IPv4: it won't.
		// gVisor's TCP forwarder (core/tcp.go in tun2socks) completes the
		// three-way handshake with the local app -- Chrome included --
		// *before* this dialer is ever invoked (r.CreateEndpoint() runs
		// first, DialContext second). By the time we get here, Chrome's
		// Happy Eyeballs has already seen its IPv6 attempt "succeed" (the
		// local handshake, not a real round trip) and, per RFC 8305 §6,
		// cancelled its parallel IPv4 attempt -- it never even sends an
		// IPv4 SYN. Confirmed live, 2026-08-17: ya.ru's IPv6 dial refused
		// here dozens of times over several minutes with zero IPv4 dial
		// attempts ever appearing in the same log. tun2socks has no public
		// hook to reject a SYN before CreateEndpoint, so there's no way to
		// give Chrome a real, fast failure early enough for its own
		// fallback to kick in.
		//
		// Instead we do the fallback ourselves: GlobalDNSCache already
		// learns both AAAA and A answers from every DNS response that
		// passes through our own relay (see dns_cache.go, fed from
		// udp_assoc.go's relayLoop and dot_proxy_linux.go). If the blocked
		// IPv6 address's hostname also resolved to an IPv4 address
		// recently -- which it did for ya.ru, Chrome/Android query both
		// families in parallel -- dial that instead, transparently. Chrome
		// never learns the difference: its "connection" is with the local
		// gVisor endpoint, not with whichever real IP we actually dial.
		if fqdn := snc.GlobalDNSCache.Get(metadata.DstIP.String()); fqdn != "" {
			if ipv4 := snc.GlobalDNSCache.GetIPv4ForHost(fqdn); ipv4 != "" {
				v4Target := net.JoinHostPort(ipv4, fmt.Sprintf("%d", metadata.DstPort))
				snc.TunLog.Printf("TCP uid=?      ipv6    %s (%s) has no route -- substituting IPv4 %s (cached)", target, fqdn, v4Target)
				target = v4Target
				goto dial
			}
		}
		// SNI hint takes priority over PTR: sniffed straight from the TLS
		// ClientHello (see sni_sniff.go), so it's the exact real hostname --
		// no reverse-lookup ambiguity, and it works even for hosts with no
		// PTR record at all (confirmed 2026-08-18: sso.passport.yandex.ru,
		// which ya.ru redirects to on every normal login, has none).
		if sni := sniHintFrom(ctx); sni != "" {
			if resolveDialer := d.pool.Pick(); resolveDialer != nil {
				if ipv4, err := snc.ActiveResolveIPv4ForHost(resolveDialer.Dial, sni); err == nil {
					v4Target := net.JoinHostPort(ipv4, fmt.Sprintf("%d", metadata.DstPort))
					snc.TunLog.Printf("TCP uid=?      ipv6    %s (sni=%s) has no route -- substituting IPv4 %s (sni-resolved)", target, sni, v4Target)
					target = v4Target
					goto dial
				}
			}
		}
		// No SNI (non-TLS connection, or the ClientHello didn't arrive within
		// the peek window) and nothing cached: fall back to PTR-then-A --
		// worse odds (PTR isn't always configured) but better than nothing
		// for non-TLS traffic, which has no SNI to sniff in the first place.
		// See ActiveResolveIPv4's doc comment in snc/core/active_resolve.go.
		if resolveDialer := d.pool.Pick(); resolveDialer != nil {
			if ipv4, fqdn, err := snc.ActiveResolveIPv4(resolveDialer.Dial, metadata.DstIP); err == nil {
				v4Target := net.JoinHostPort(ipv4, fmt.Sprintf("%d", metadata.DstPort))
				snc.TunLog.Printf("TCP uid=?      ipv6    %s (%s) has no route -- substituting IPv4 %s (active-resolved)", target, fqdn, v4Target)
				target = v4Target
				goto dial
			} else {
				snc.TunLog.Printf("TCP uid=?      ipv6    blocked %s (active-resolve failed: %v)", target, err)
				return nil, fmt.Errorf("ipv6 disabled, refusing %s", target)
			}
		}
		snc.TunLog.Printf("TCP uid=?      ipv6    blocked %s (no known IPv4 for this host)", target)
		return nil, fmt.Errorf("ipv6 disabled, refusing %s", target)
	}
dial:

	// Intercept DoT (port 853): redirect to the local DoT proxy so Android
	// Private DNS resolves correctly even when 8.8.8.8:853 is blocked.
	if d.dotAddr != "" && metadata.DstPort == 853 {
		conn, err := net.Dial("tcp", d.dotAddr)
		if err == nil {
			snc.TunLog.Printf("TCP uid=?      dot     %s", target)
		}
		return conn, err
	}

	// Bypass: LAN addresses and in-country IPs connect directly via the NIC
	// (protected by VpnService.protect) rather than through the tunnel.
	if d.bypass != nil && (snc.IsLANAddress(target) || d.bypass.ShouldBypass(target)) {
		conn, err := d.bypass.BypassDialer().DialContext(ctx, "tcp", target)
		if err == nil {
			snc.TunLog.Printf("TCP uid=?      bypass  %s", target)
			return conn, nil
		}
		snc.Log.Printf("tun-dialer: bypass %s failed: %v", target, err)
		if snc.IsLANAddress(target) {
			return nil, fmt.Errorf("lan dial %s: %w", target, err)
		}
		// In-country bypass failed: remember the failure and fall through to tunnel.
		d.bypass.RecordBypassFailure(target)
		snc.Log.Printf("tun-dialer: retrying %s via tunnel", target)
	}

	// UID resolution is a real IPC round-trip now (see UidClient), not a
	// free local lookup -- only pay for it on the path that actually uses
	// it (PickForUID), not the ipv6/dot/bypass paths above that never route
	// by app.
	uid := UID.Lookup("tcp", metadata.SrcIP, metadata.SrcPort, metadata.DstIP, metadata.DstPort)
	dialer := d.pool.PickForUID(uid)
	if dialer == nil {
		snc.TunLog.Printf("TCP uid=%-6d tunnel  %s â€” no dialer", uid, target)
		return nil, fmt.Errorf("no tunnel dialer available")
	}
	snc.TunLog.Printf("TCP uid=%-6d tunnel  %s", uid, target)
	conn, err := dialer.Dial(target)
	if err != nil {
		// One retry against a different pool member instead of giving up
		// outright, same pattern as snc/core/socks5.go's handleConnect --
		// a brief blip on the app's pinned control shouldn't cost this
		// connection entirely.
		if d2 := d.pool.PickExcluding(dialer); d2 != nil {
			snc.TunLog.Printf("TCP uid=%-6d tunnel  %s via %s failed (%v) â€” retrying via a different control", uid, target, dialer.ServerURL(), err)
			conn, err = d2.Dial(target)
			if err == nil {
				// The app's pinned dialer just failed -- re-pin the app to
				// the one that actually worked, so its next connection
				// doesn't retry the dead one from scratch. See
				// SetUIDAffinity's doc comment.
				d.pool.SetUIDAffinity(uid, d2)
			}
		}
	}
	return conn, err
}

func (d *appStickyDialer) DialUDP(metadata *M.Metadata) (net.PacketConn, error) {
	if metadata != nil && d.ipv6Blocked(metadata.DstIP) {
		snc.TunLog.Printf("UDP             ipv6    blocked %s", metadata.DestinationAddress())
		return nil, fmt.Errorf("ipv6 disabled, refusing %s", metadata.DestinationAddress())
	}
	if d.blockQUIC && metadata != nil && metadata.DstPort == 443 {
		// QUIC (UDP:443) over a TCP-based SNC tunnel performs poorly: UDP-in-TCP introduces
		// head-of-line blocking and breaks QUIC's loss-recovery model. Rejecting UDP:443
		// forces apps (browsers, Facebook, etc.) to fall back to TLS/TCP:443.
		// Enabled automatically for RU/CN regions where QUIC through the tunnel is always lossy.
		snc.TunLog.Printf("UDP             blocked %s (quicâ†’tcp)", metadata.DestinationAddress())
		return nil, fmt.Errorf("udp:443 rejected, use tcp")
	}
	// Delegate to the local SOCKS5 server: it handles bypass CIDRs and creates
	// a udpAssocSession pinned to one dialer for the life of the UDP session.
	if metadata != nil {
		snc.TunLog.Printf("UDP             tunnel  %s", metadata.DestinationAddress())
	}
	s5, err := proxy.NewSocks5(d.socksAddr, "", "")
	if err != nil {
		return nil, err
	}
	return s5.DialUDP(nil)
}
