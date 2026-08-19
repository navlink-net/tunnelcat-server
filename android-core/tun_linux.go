// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

//go:build linux

package androidcore

import (
	"fmt"
	"strconv"

	t2score "github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/device/fdbased"
	"github.com/xjasonlyu/tun2socks/v2/core/option"
	"github.com/xjasonlyu/tun2socks/v2/tunnel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	snc "tunnel_cat/snc/core"
)

// activeTUNStack holds the running gVisor stack so Stop() can tear it down.
var activeTUNStack *stack.Stack

// StartTUN wires the TUN file descriptor into gVisor netstack and forwards
// traffic through appStickyDialer, which pins each app (Linux UID) to one
// TunnelDialer for TCP and delegates UDP ASSOCIATE to the local SOCKS5 server.
// dotAddr, when non-empty, redirects port-853 (DoT) connections to the local
// DoT proxy so Android Private DNS works when 8.8.8.8 is blocked.
//
// Why gVisor netstack instead of a simple SOCKS5 redirect at the iptables level:
// Android VPN apps receive a raw TUN fd from VpnService.establish(). We don't own
// the iptables rules (those require root) and we can't intercept traffic with
// tproxy either (same reason). The only portable option is a userspace TCP/IP
// stack that reads raw IP packets from the TUN fd and synthesises TCP connections
// that we can then route â€” exactly what tun2socks/gVisor does.
//
// Why fdbased: Kotlin's VpnService.establish() returns an int fd pointing at the
// TUN interface it created; we attach to that existing fd rather than creating a
// new /dev/tun device (which would require root).
func StartTUN(tunFD int, socksAddr string, pool *snc.DialerPool, bypass *snc.BypassManager, dotAddr string, blockQUIC, disableIPv6 bool) error {
	dev, err := fdbased.Open(strconv.Itoa(tunFD), 1500, 0)
	if err != nil {
		return fmt.Errorf("tun: open fd %d: %w", tunFD, err)
	}

	dialer := &appStickyDialer{pool: pool, bypass: bypass, socksAddr: socksAddr, dotAddr: dotAddr, blockQUIC: blockQUIC, disableIPv6: disableIPv6}
	// UDP still goes through tun2socks's own Tunnel (tunnel.T()) -- its
	// UDP ASSOCIATE session handling is unrelated to the TCP SNI-sniffing
	// problem below and already works correctly. Only TCP needs our own
	// TransportHandler, so we can peek each connection's TLS ClientHello
	// before dialing -- see tcp_handler_linux.go's doc comment.
	tunnel.T().SetDialer(dialer)
	handler := &sniffingTransportHandler{dialer: dialer, udpHandler: tunnel.T()}

	s, err := t2score.CreateStack(&t2score.Config{
		LinkEndpoint:     dev,
		TransportHandler: handler,
		Options: []option.Option{
			// Auto-tune per-connection receive buffers downward for idle connections,
			// reducing memory pressure and CPU copy overhead under heavy concurrent load.
			option.WithTCPModerateReceiveBuffer(true),
			// Cubic handles mobile packet loss better than reno: faster recovery
			// reduces retransmission CPU and keeps throughput stable on lossy links.
			option.WithTCPCongestionControl("cubic"),
		},
	})
	if err != nil {
		dev.Close()
		return fmt.Errorf("tun: create stack: %w", err)
	}

	activeTUNStack = s
	return nil
}

// TUNRunning reports whether a TUN stack is currently active.
func TUNRunning() bool { return activeTUNStack != nil }

// StopTUN tears down the gVisor netstack.
func StopTUN() {
	if activeTUNStack != nil {
		activeTUNStack.Close()
		activeTUNStack.Wait()
		activeTUNStack = nil
	}
}
