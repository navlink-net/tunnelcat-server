// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

//go:build linux

package androidcore

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
	"gvisor.dev/gvisor/pkg/tcpip"

	snc "tunnel_cat/snc/core"
)

// parseTCPIPAddress mirrors tun2socks's own unexported tunnel.parseTCPIPAddress
// (tunnel/addr.go) -- not reusable directly since we're not using their
// Tunnel type for TCP anymore (that's the whole point: it never gives us a
// hook to peek bytes before dialing).
func parseTCPIPAddress(addr tcpip.Address) netip.Addr {
	ip, _ := netip.AddrFromSlice(addr.AsSlice())
	return ip
}

const (
	tcpConnectTimeout = 5 * time.Second
	sniPeekTimeout    = 300 * time.Millisecond
	sniPeekMaxBytes   = 8192
)

// sniffingTransportHandler is our own adapter.TransportHandler, replacing
// tun2socks's built-in tunnel.Tunnel for TCP so we can peek each
// connection's TLS ClientHello (if any) for its SNI hostname before
// deciding where to dial -- see sni_sniff.go's doc comment for why this
// replaced the earlier PTR-based approach. UDP is unaffected by any of
// this and is delegated to udpHandler unchanged (tunnel.Tunnel's own,
// already-correct UDP ASSOCIATE handling).
type sniffingTransportHandler struct {
	dialer     proxy.Dialer
	udpHandler adapter.TransportHandler
}

var _ adapter.TransportHandler = (*sniffingTransportHandler)(nil)

func (h *sniffingTransportHandler) HandleUDP(conn adapter.UDPConn) {
	h.udpHandler.HandleUDP(conn)
}

func (h *sniffingTransportHandler) HandleTCP(conn adapter.TCPConn) {
	go h.handleTCP(conn)
}

func (h *sniffingTransportHandler) handleTCP(conn adapter.TCPConn) {
	defer conn.Close()

	id := conn.ID()
	metadata := &M.Metadata{
		Network: M.TCP,
		SrcIP:   parseTCPIPAddress(id.RemoteAddress),
		SrcPort: id.RemotePort,
		DstIP:   parseTCPIPAddress(id.LocalAddress),
		DstPort: id.LocalPort,
	}

	peeked := peekClientHello(conn)
	sni := extractSNI(peeked)

	ctx, cancel := context.WithTimeout(withSNIHint(context.Background(), sni), tcpConnectTimeout)
	defer cancel()

	remoteConn, err := h.dialer.DialContext(ctx, metadata)
	if err != nil {
		snc.Log.Printf("tcp-handler: dial %s (sni=%q): %v", metadata.DestinationAddress(), sni, err)
		return
	}
	defer remoteConn.Close()

	if len(peeked) > 0 {
		if _, err := remoteConn.Write(peeked); err != nil {
			return
		}
	}
	pipeTCP(conn, remoteConn)
}

// peekClientHello reads whatever bytes the app sends within sniPeekTimeout
// (typically just the TLS ClientHello, sent immediately on connect), up to
// sniPeekMaxBytes. Always returns whatever it got, even on timeout or a
// non-TLS connection -- the caller replays these bytes to the real
// destination regardless of whether SNI extraction succeeds, so a timeout
// or a non-TLS protocol never loses data, it just means no SNI hint.
func peekClientHello(conn net.Conn) []byte {
	conn.SetReadDeadline(time.Now().Add(sniPeekTimeout)) //nolint:errcheck
	buf := make([]byte, sniPeekMaxBytes)
	n, _ := conn.Read(buf)
	conn.SetReadDeadline(time.Time{}) //nolint:errcheck
	return buf[:n]
}

// pipeTCP mirrors tun2socks's own tunnel/tcp.go pipe()/unidirectionalStream()
// (unexported there, so not reusable directly) -- same half-close behavior,
// just without its statistics-tracker wiring, which we don't use here.
func pipeTCP(origin, remote net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go copyHalf(remote, origin, &wg)
	go copyHalf(origin, remote, &wg)
	wg.Wait()
}

func copyHalf(dst, src net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	io.Copy(dst, src) //nolint:errcheck
	if cr, ok := src.(interface{ CloseRead() error }); ok {
		cr.CloseRead()
	}
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}
