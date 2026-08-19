// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// connLimiter enforces a maximum number of concurrent tunneled connections per
// source IP.  Connections beyond the limit are queued (the goroutine blocks on
// the semaphore) rather than rejected, so the client sees a slow connection
// instead of an error.  Bypass connections are not counted.
type connLimiter struct {
	sems  sync.Map // string (IP) → chan struct{}
	perIP int
}

func newConnLimiter(perIP int) *connLimiter {
	return &connLimiter{perIP: perIP}
}

// acquire blocks until a slot is available for ip.
func (l *connLimiter) acquire(ip string) {
	v, _ := l.sems.LoadOrStore(ip, make(chan struct{}, l.perIP))
	v.(chan struct{}) <- struct{}{}
}

// release frees the slot previously acquired for ip.
func (l *connLimiter) release(ip string) {
	if v, ok := l.sems.Load(ip); ok {
		<-v.(chan struct{})
	}
}

// remoteHost strips the port from a "host:port" or "[::1]:port" address string.
func remoteHost(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return h
}

// SOCKS5 constants
const (
	socks5Version = 0x05
	authNone      = 0x00
	authNoAccept  = 0xFF
	cmdConnect    = 0x01
	cmdUDPAssoc   = 0x03
	atypIPv4      = 0x01
	atypDomain    = 0x03
	atypIPv6      = 0x04
	repSuccess    = 0x00
	repCmdNotSupp = 0x07
	repGenFail    = 0x01
)

// socks5PerIPLimit is the maximum number of simultaneous tunneled connections
// from a single source IP.  All browser connections come from 127.0.0.1, so
// this is effectively a global cap.  Set high enough that a web app (Facebook,
// WhatsApp) with many parallel asset fetches, or a BitTorrent client with a
// large peer swarm, never hits the queue -- the client-side port block that
// used to make BitTorrent's connection count moot was removed; exit-side
// policy is what decides whether torrent traffic is allowed now.
const socks5PerIPLimit = 500

// SOCKS5Server listens on a local port and proxies CONNECT requests through
// a DialerPool.  Each new connection picks a random dialer from the pool so
// concurrent connections are distributed across all qualifying controls.
// If bypass is non-nil, in-country addresses are routed directly via the NIC.
// If dialFn is non-nil it overrides the pool for all CONNECT requests.
type SOCKS5Server struct {
	addr       string
	pool       *DialerPool
	bypass     *BypassManager // nil = no bypass
	limiter    *connLimiter
	ln         net.Listener
	DisableUDP bool // if true, UDP ASSOCIATE returns command-not-supported

	// BlockQUIC: when true, datagrams to UDP:443 are silently dropped so that
	// QUIC/HTTP3 apps fall back to TLS/TCP. Enabled automatically for RU/CN regions
	// where QUIC-over-TCP-tunnel causes head-of-line blocking and poor media quality.
	BlockQUIC bool
	// RealtimeUDPDialer: experimental (2026-08-13 trial, Android only for now).
	// When set, non-DNS UDP ASSOCIATE traffic (voice/video call media, games,
	// any general UDP) pins to this dedicated dialer instead of picking from
	// the shared pool -- it must be a dialer whose TunnelDialer.udpRelay is a
	// direct (non-relay-peer) native UDP connection to the control node
	// (core.NewUDPControlConn + NewUDPRelayDialer), so doPost's existing
	// UDP-relay path carries this traffic instead of one HTTP POST per
	// datagram. Two problems this targets at once: (1) HTTP/2-over-TCP's
	// head-of-line blocking is gone for this traffic since native UDP has no
	// such ordering guarantee to enforce, and (2) it no longer shares an
	// HTTP/2 connection (and TCP congestion window) with unrelated DNS/bulk
	// traffic on the same control. Falls back to the normal pool automatically
	// if this dialer's udpRelay reports Failed() (already-existing keepalive/
	// failure detection, see udp_relay.go) -- nil (the default) leaves every
	// platform's behavior completely unchanged.
	RealtimeUDPDialer *TunnelDialer
}

// NewSOCKS5Server creates a server bound to addr using a single dialer.
// Wraps the dialer in a 1-element DialerPool for API compatibility.
func NewSOCKS5Server(addr string, dialer *TunnelDialer) *SOCKS5Server {
	return &SOCKS5Server{addr: addr, pool: NewDialerPool([]*TunnelDialer{dialer}), limiter: newConnLimiter(socks5PerIPLimit)}
}

// NewSOCKS5ServerWithBypass creates a server with a single dialer and bypass.
func NewSOCKS5ServerWithBypass(addr string, dialer *TunnelDialer, bypass *BypassManager) *SOCKS5Server {
	return &SOCKS5Server{addr: addr, pool: NewDialerPool([]*TunnelDialer{dialer}), bypass: bypass, limiter: newConnLimiter(socks5PerIPLimit)}
}

// NewSOCKS5ServerWithPool creates a server that distributes connections across
// the pool.  Use this to enable the multi-control parallel serving policy.
func NewSOCKS5ServerWithPool(addr string, pool *DialerPool, bypass *BypassManager) *SOCKS5Server {
	return &SOCKS5Server{addr: addr, pool: pool, bypass: bypass, limiter: newConnLimiter(socks5PerIPLimit)}
}

// ListenAndServe binds to s.addr and starts accepting SOCKS5 connections.
// Blocks until the listener is closed.
func (s *SOCKS5Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// Serve accepts connections on the given listener. Blocks until closed.
func (s *SOCKS5Server) Serve(ln net.Listener) error {
	s.ln = ln
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

// Close shuts down the listener.
func (s *SOCKS5Server) Close() error {
	if s.ln != nil {
		return s.ln.Close()
	}
	return nil
}

func (s *SOCKS5Server) handle(c net.Conn) {
	defer c.Close()

	Log.Printf("socks5: new connection from %s", c.RemoteAddr())

	// ── 1. Handshake ─────────────────────────────────────────────────────────
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		Log.Printf("socks5: handshake read error from %s: %v", c.RemoteAddr(), err)
		return
	}
	if hdr[0] != socks5Version {
		return
	}
	nmethods := int(hdr[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	// Accept "no authentication" only.
	supported := false
	for _, m := range methods {
		if m == authNone {
			supported = true
			break
		}
	}
	if !supported {
		c.Write([]byte{socks5Version, authNoAccept})
		return
	}
	c.Write([]byte{socks5Version, authNone})

	// ── 2. Request ───────────────────────────────────────────────────────────
	reqHdr := make([]byte, 4)
	if _, err := io.ReadFull(c, reqHdr); err != nil {
		return
	}
	if reqHdr[0] != socks5Version {
		return
	}
	cmd := reqHdr[1]
	// reqHdr[2] is reserved

	var target string
	switch reqHdr[3] { // atyp
	case atypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(c, addr); err != nil {
			return
		}
		target = net.IP(addr).String()
	case atypIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(c, addr); err != nil {
			return
		}
		target = "[" + net.IP(addr).String() + "]"
	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(c, lenBuf); err != nil {
			return
		}
		domain := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(c, domain); err != nil {
			return
		}
		target = string(domain)
	default:
		sendSOCKS5Reply(c, repGenFail)
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(c, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)
	target = fmt.Sprintf("%s:%d", target, port)

	// ── 3. Dispatch ──────────────────────────────────────────────────────────
	switch cmd {
	case cmdConnect:
		s.handleConnect(c, target)
	case cmdUDPAssoc:
		s.handleUDPAssoc(c, target)
	default:
		sendSOCKS5Reply(c, repCmdNotSupp)
	}
}

func (s *SOCKS5Server) handleConnect(c net.Conn, target string) {
	Log.Printf("socks5: CONNECT %s", target)

	// Bypass: in-country traffic and LAN (RFC1918 / link-local) go directly
	// via the original NIC so that printers, routers, and other local devices
	// remain reachable while the tunnel is active.
	//
	// For LAN addresses the tunnel is never an option — fail hard.
	// For in-country addresses the bypass is attempted first (8 s timeout so a
	// silently-dropped ISP connection doesn't stall the user indefinitely); if it
	// fails we fall through and retry via the tunnel.
	// ShouldBypass returns false for IPs previously recorded as bypass-failures,
	// so those go straight to the tunnel without attempting bypass at all.
	bypassFailed := false
	generalBypass := s.bypass != nil && s.bypass.ShouldBypass(target)
	Log.Printf("socks5: routing decision target=%s generalBypass=%v lan=%v",
		target, generalBypass, isLANAddress(target))
	if s.bypass != nil && (generalBypass || isLANAddress(target)) {
		lan := isLANAddress(target)
		Log.Printf("socks5: bypass %s", target)
		// LAN addresses get a short timeout: silently-dropped LAN connections
		// (e.g. Windows Update peer 192.168.x.x:7680) should fail fast rather
		// than blocking the user for 8 seconds before returning a hard error.
		bypassTimeout := 8 * time.Second
		if lan {
			bypassTimeout = 1 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), bypassTimeout)
		conn, err := s.bypass.BypassDialer().DialContext(ctx, "tcp", target)
		cancel()
		if err != nil {
			Log.Printf("socks5: bypass dial %s failed: %v", target, err)
			if lan {
				sendSOCKS5Reply(c, repGenFail)
				return
			}
			Log.Printf("socks5: retrying %s via tunnel", target)
			bypassFailed = true
			// fall through to tunnel below
		} else {
			sendSOCKS5Reply(c, repSuccess)
			relayConns(c, conn, target, "bypass")
			return
		}
	}

	// Acquire per-IP slot before dialing through the tunnel.
	// If the source IP already has socks5PerIPLimit active tunneled connections,
	// this blocks until one finishes — the client sees a slow CONNECT, not an error.
	if s.limiter != nil {
		ip := remoteHost(c.RemoteAddr().String())
		s.limiter.acquire(ip)
		defer s.limiter.release(ip)
	}

	var tun net.Conn
	var err error
	{
		// s.pool can legitimately be nil -- e.g. a caller that nulls its
		// dialerPool on disconnect without cancelling in-flight requests
		// (see main_windows.go) can race a fresh CONNECT in against the nil
		// window. The UDP ASSOCIATE path below already guards this; TCP
		// didn't, so s.pool.Pick() panicked on the nil receiver instead of
		// failing this one connection (confirmed crash, 2026-08-11).
		if s.pool == nil {
			Log.Printf("socks5: no dialer pool for %s", target)
			sendSOCKS5Reply(c, repGenFail)
			return
		}
		// PickForHost (not Pick) keeps repeat/parallel connections to the same
		// destination host on the same control -- see its doc comment for why
		// (fixes a real anti-abuse false-positive from a single browsing
		// session's parallel connections landing on different exit IPs).
		host := remoteHost(target)
		d := s.pool.PickForHost(host)
		if d == nil {
			Log.Printf("socks5: no available dialer for %s", target)
			sendSOCKS5Reply(c, repGenFail)
			return
		}
		tun, err = d.Dial(target)
		if err != nil {
			// One retry against a different pool member instead of giving up
			// outright: Dial's own internal retries all hit the same control
			// node, so a node that's merely having a brief blip (not actually
			// down) otherwise costs the caller the connection entirely rather
			// than just some latency. onFirstFail has already fired inside
			// Dial on the failed node by this point, so this pick is already
			// naturally biased away from it even before PickExcluding's hard
			// exclusion. See the 2026-08-12 stalled-video incident.
			if d2 := s.pool.PickExcluding(d); d2 != nil {
				Log.Printf("socks5: dial %s via %s failed (%v) — retrying via a different control", target, d.ServerURL(), err)
				tun, err = d2.Dial(target)
				if err == nil {
					// The sticky dialer just failed -- re-pin this host to the
					// one that actually worked, so the next connection to it
					// doesn't retry the dead one from scratch. See
					// SetHostAffinity's doc comment.
					s.pool.SetHostAffinity(host, d2)
				}
			}
		}
	}
	// Bypass failed: always record it so future connections skip the bypass
	// attempt and go straight to the tunnel — even if the tunnel also fails here.
	// Without this, repeated bypass timeouts (e.g. relay peers behind the same
	// CGNAT) each waste tunnelCBCooldown seconds on the bypass path.
	if bypassFailed && s.bypass != nil {
		s.bypass.RecordBypassFailure(target)
	}
	if err != nil {
		Log.Printf("socks5: dial %s failed: %v", target, err)
		sendSOCKS5Reply(c, repGenFail)
		return
	}
	Log.Printf("socks5: dial %s OK, starting relay", target)
	sendSOCKS5Reply(c, repSuccess)
	relayConns(c, tun, target, "")
}

// IsLANAddress reports whether target (host:port or bare host) is a private
// LAN address that should bypass the tunnel: RFC1918, link-local, or loopback.
func IsLANAddress(target string) bool { return isLANAddress(target) }

func isLANAddress(target string) bool {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate()
}

// firstByteReader wraps an io.Reader and records the time elapsed before the
// first byte is successfully returned.  Used to measure time-to-first-byte
// from the remote side so we can distinguish a slow server from a dead one.
type firstByteReader struct {
	r     io.Reader
	start time.Time
	ttb   time.Duration // set on first non-zero Read; 0 means not yet seen
	done  bool
}

func (f *firstByteReader) Read(b []byte) (int, error) {
	n, err := f.r.Read(b)
	if n > 0 && !f.done {
		f.done = true
		f.ttb = time.Since(f.start)
	}
	return n, err
}

// relayConns copies data between c (browser/client) and remote (tunnel/target)
// in both directions until either side closes.  label ("mitm", "bypass", "")
// prefixes the log lines so log output can be filtered by connection type.
func relayConns(c, remote net.Conn, target, label string) {
	prefix := "socks5"
	if label != "" {
		prefix = "socks5 " + label
	}
	start := time.Now()
	done := make(chan struct{}, 2)
	var sent, recv int64
	// sendErr/recvErr feed into the single "done" line below instead of only
	// being logged where they occur -- a bypassed session's actual close
	// reason (reset vs clean EOF vs timeout) used to only appear in these two
	// earlier, separate log lines, and a real incident (2026-08-17, a user's
	// bypassed .ru-TLD connections closing with no diagnosable reason)
	// couldn't be root-caused because the shared 256KB ring buffer had
	// already evicted them by the time of upload, leaving only bytes/duration
	// with no explanation. The "done" line is the last one written for a
	// given connection, so it's the one most likely to survive -- folding
	// the reason into it means a single surviving line is now self-contained.
	var sendErr, recvErr error
	fbr := &firstByteReader{r: remote, start: start}
	go func() {
		n, err := io.Copy(remote, c)
		sent = n
		if err != nil && err != io.EOF {
			sendErr = err
			Log.Printf("%s: relay client→remote %s: %d B err=%v", prefix, target, n, err)
		}
		remote.Close()
		done <- struct{}{}
	}()
	go func() {
		n, err := io.Copy(c, fbr)
		recv = n
		if err != nil && err != io.EOF {
			recvErr = err
			Log.Printf("%s: relay remote→client %s: %d B err=%v", prefix, target, n, err)
		}
		c.Close()
		done <- struct{}{}
	}()
	<-done
	<-done
	ttbStr := "-"
	if fbr.done {
		ttbStr = fbr.ttb.Round(time.Millisecond).String()
	}
	closeReason := "eof"
	switch {
	case sendErr != nil && recvErr != nil:
		closeReason = fmt.Sprintf("send=%v recv=%v", sendErr, recvErr)
	case sendErr != nil:
		closeReason = fmt.Sprintf("send=%v", sendErr)
	case recvErr != nil:
		closeReason = fmt.Sprintf("recv=%v", recvErr)
	}
	Log.Printf("%s: done %s ttb=%s dur=%s sent=%dB recv=%dB close=%s",
		prefix, target, ttbStr, time.Since(start).Round(time.Millisecond), sent, recv, closeReason)
}

// sendSOCKS5Reply writes a minimal SOCKS5 reply with bound address 0.0.0.0:0.
func sendSOCKS5Reply(c net.Conn, rep byte) {
	c.Write([]byte{ //nolint:errcheck
		socks5Version, rep, 0x00, // ver, rep, rsv
		atypIPv4, 0, 0, 0, 0, 0, 0, // atyp, 0.0.0.0, port 0
	})
}

func sendSOCKS5UDPReply(c net.Conn, ip net.IP, port uint16) {
	ip4 := ip.To4()
	if ip4 != nil {
		buf := []byte{socks5Version, repSuccess, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}
		copy(buf[4:8], ip4)
		binary.BigEndian.PutUint16(buf[8:], port)
		c.Write(buf) //nolint:errcheck
	} else {
		buf := make([]byte, 4+16+2)
		buf[0] = socks5Version
		buf[1] = repSuccess
		buf[3] = atypIPv6
		copy(buf[4:20], ip.To16())
		binary.BigEndian.PutUint16(buf[20:], port)
		c.Write(buf) //nolint:errcheck
	}
}

func (s *SOCKS5Server) handleUDPAssoc(c net.Conn, _ string) {
	if s.DisableUDP || s.pool == nil {
		// No dialer pool configured; UDP ASSOCIATE is not supported.
		sendSOCKS5Reply(c, repCmdNotSupp)
		return
	}

	// UDP ASSOCIATE sessions always go to bypass (SNC tunnel is TCP-only).
	// They do not consume tunnel capacity, so they are not subject to the
	// per-IP tunnel connection limit.  A new UDP ASSOCIATE request proves
	// the TUN bridge is alive, so we touch the tunnel monitor here.
	TunnelMonitor.Reset()

	if s.pool.Pick() == nil {
		Log.Printf("socks5: no available dialer for UDP ASSOCIATE")
		sendSOCKS5Reply(c, repGenFail)
		return
	}
	// Pass pool.Pick as the dialer picker so each UDP send uses the current
	// best dialer. This lets the session survive control evictions — when the
	// original control dies, subsequent sends automatically route to the next
	// standby rather than hanging for 30 s on a dead reference.
	sess, err := newUDPAssocSession(c, s.bypass, s.pool.Pick, s.BlockQUIC, s.RealtimeUDPDialer)
	if err != nil {
		Log.Printf("socks5: UDP ASSOCIATE setup failed: %v", err)
		sendSOCKS5Reply(c, repGenFail)
		return
	}
	localAddr := sess.bypassConn.LocalAddr().(*net.UDPAddr)
	replyIP := localAddr.IP
	if replyIP == nil || replyIP.IsUnspecified() {
		// On Android the bypass socket is bound to 0.0.0.0 (protected all-interface bind).
		// tun2socks connects via loopback — report 127.0.0.1 so it knows where to send datagrams.
		// The relay socket accepts on all interfaces, so 127.0.0.1:PORT will reach it.
		replyIP = net.IPv4(127, 0, 0, 1)
	}
	Log.Printf("socks5: UDP ASSOCIATE relay=%s:%d", replyIP, localAddr.Port)
	sendSOCKS5UDPReply(c, replyIP, uint16(localAddr.Port))
	go sess.watchCtrl()
	sess.relayLoop()
}
