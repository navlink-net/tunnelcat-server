// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// controlBytesTotal is a monotonically increasing counter of all bytes relayed
// by this control node (up + down combined). Read by the heartbeat to compute bw_mbps.
var controlBytesTotal atomic.Int64

// SNI pool for port-443 demultiplexing.
// The relay-API connection type picks a random SNI from this pool at dial
// time. The server recognises any SNI from the pool; all other SNIs are
// proxied to exit. Using a pool of plausible CDN-like hostnames instead of
// a fixed value prevents DPI fingerprinting by a single known string.
var relayAPISNIPool = []string{
	"ctrl.cdn-assets.net",
	"api.cdn-relay.net",
	"mgmt.edge-static.net",
	"admin.cdn-cache.net",
	"svc.static-assets.net",
}

// sniType maps every recognised SNI value to its connection category.
// Populated once at init from the pool above.
var sniType map[string]string

func init() {
	sniType = make(map[string]string, len(relayAPISNIPool))
	for _, s := range relayAPISNIPool {
		sniType[s] = "relay"
	}
}

// countWriter wraps an io.Writer and counts the bytes written through it.
type countWriter struct {
	dst io.Writer
	n   int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.dst.Write(p)
	c.n += int64(n)
	return n, err
}

// prependConn replays buffered bytes before delegating to the underlying conn.
// Used to put back bytes that were peeked for SNI detection.
type prependConn struct {
	net.Conn
	buf []byte
	pos int
}

func (c *prependConn) Read(p []byte) (int, error) {
	if c.pos < len(c.buf) {
		n := copy(p, c.buf[c.pos:])
		c.pos += n
		return n, nil
	}
	return c.Conn.Read(p)
}

// CloseWrite forwards to the underlying TCP connection, if available.
func (c *prependConn) CloseWrite() error {
	if tc, ok := c.Conn.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	return nil
}

// CloseRead forwards to the underlying TCP connection, if available.
func (c *prependConn) CloseRead() error {
	if tc, ok := c.Conn.(*net.TCPConn); ok {
		return tc.CloseRead()
	}
	return nil
}

// oneConnListener wraps a single net.Conn as a net.Listener.
// The first Accept returns the conn; all subsequent calls return net.ErrClosed.
type oneConnListener struct {
	mu   sync.Mutex
	conn net.Conn
	addr net.Addr
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conn == nil {
		return nil, net.ErrClosed
	}
	c := l.conn
	l.conn = nil
	return c, nil
}

func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return l.addr }

// halfCloser is the subset of *net.TCPConn used for graceful half-close.
type halfCloser interface {
	CloseRead() error
	CloseWrite() error
}

// chMagic is the Session ID marker byte written by SNC clients at sid[0].
// sid[1] carries the channel type. Standard TLS 1.3 clients send random bytes,
// so accidental collisions are negligible. Non-SNC connections (gossip, old
// clients) fall back to SNI-based routing for backward compatibility.
const chMagic byte = 0xA7

// extractChannel reads the SNC channel type from a TLS ClientHello Session ID.
// Returns (channelType, true) when sid[0]==chMagic; otherwise (0, false).
func extractChannel(data []byte) (byte, bool) {
	if len(data) < 5 || data[0] != 0x16 {
		return 0, false
	}
	hs := data[5:]
	if len(hs) < 4 || hs[0] != 0x01 {
		return 0, false
	}
	ch := hs[4:]
	// skip version(2) + random(32)
	pos := 34
	if pos >= len(ch) {
		return 0, false
	}
	sidLen := int(ch[pos])
	pos++
	if sidLen < 2 || pos+sidLen > len(ch) {
		return 0, false
	}
	if ch[pos] != chMagic {
		return 0, false
	}
	return ch[pos+1], true
}

// tcpProxy accepts client TCP connections, peeks the TLS ClientHello, and routes:
//   - SNC channel byte 0x01 → relay tracker API (TLS-terminated HTTP)
//   - SNI fallback (old clients): relayAPISNI → relay handler
//   - anything else → raw TCP proxy to exit node
type tcpProxy struct {
	exits     *ExitRegistry
	relayAPI  *relayAPIHandler
	relayCfg  *tls.Config
	cidrC     *cidrCache // client country lookup for exit selection; nil = skip
	nodeToken string     // sent as X-Node-Token when calling exit relay endpoints

	// activeMu guards active: a registry of open exitConns keyed by exit addr.
	// When an exit goes dead, closeExitConns closes all its connections so clients
	// reconnect immediately rather than waiting for TCP timeout.
	activeMu sync.Mutex
	active   map[string]map[int]net.Conn
	nextID   int
}

func newTCPProxy(exits *ExitRegistry, relayAPI *relayAPIHandler, relayCfg *tls.Config, cidrC *cidrCache, nodeToken string) *tcpProxy {
	p := &tcpProxy{
		exits: exits, relayAPI: relayAPI, relayCfg: relayCfg, cidrC: cidrC,
		nodeToken: nodeToken,
		active:    make(map[string]map[int]net.Conn),
	}
	return p
}

func (p *tcpProxy) registerExitConn(addr string, conn net.Conn) int {
	p.activeMu.Lock()
	defer p.activeMu.Unlock()
	p.nextID++
	id := p.nextID
	if p.active[addr] == nil {
		p.active[addr] = make(map[int]net.Conn)
	}
	p.active[addr][id] = conn
	return id
}

func (p *tcpProxy) unregisterExitConn(addr string, id int) {
	p.activeMu.Lock()
	delete(p.active[addr], id)
	p.activeMu.Unlock()
}

// closeExitConns closes all connections currently piped through addr.
// Called by ExitRegistry.onDead when the exit is marked dead.
func (p *tcpProxy) closeExitConns(addr string) {
	p.activeMu.Lock()
	conns := p.active[addr]
	delete(p.active, addr)
	p.activeMu.Unlock()

	if len(conns) == 0 {
		return
	}
	for _, c := range conns {
		c.Close()
	}
	logWarnf("exit-health: closed %d active connection(s) through dead exit %s", len(conns), addr)
}

func (p *tcpProxy) handle(client net.Conn) {
	// Peek up to 512 bytes — enough for any TLS ClientHello SNI extension.
	buf := make([]byte, 512)
	client.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	n, err := client.Read(buf)
	client.SetReadDeadline(time.Time{}) //nolint:errcheck
	if err != nil && n == 0 {
		logDebugf("handle: read peek from %s failed n=0 err=%v — closing", client.RemoteAddr(), err)
		client.Close()
		return
	}
	peeked := buf[:n]
	wrapped := &prependConn{Conn: client, buf: peeked}

	// Prefer channel byte (new SNC clients); fall back to SNI (gossip, old clients).
	connType := ""
	if ch, ok := extractChannel(peeked); ok {
		if ch == 0x01 {
			connType = "relay"
		}
		logDebugf("handle: conn from %s channel=0x%02x type=%q", client.RemoteAddr(), ch, connType)
	} else {
		sni := extractSNI(peeked)
		connType = sniType[sni]
		logDebugf("handle: conn from %s sni=%q type=%q (fallback)", client.RemoteAddr(), sni, connType)
	}

	switch connType {
	case "relay":
		if p.relayAPI != nil && p.relayCfg != nil {
			p.serveRelayAPI(wrapped)
			return
		}
		logWarnf("handle: %s → relay API but handler/cfg nil — proxying to exit", client.RemoteAddr())
	}
	p.proxyToExit(wrapped)
}

func (p *tcpProxy) serveRelayAPI(conn net.Conn) {
	logDebugf("serveRelayAPI: starting TLS handshake for %s", conn.RemoteAddr())
	tlsConn := tls.Server(conn, p.relayCfg)
	if err := tlsConn.Handshake(); err != nil {
		logWarnf("serveRelayAPI: TLS handshake failed for %s: %v", conn.RemoteAddr(), err)
		tlsConn.Close()
		return
	}
	logDebugf("serveRelayAPI: TLS handshake OK for %s, serving HTTP", conn.RemoteAddr())
	ln := &oneConnListener{conn: tlsConn, addr: conn.LocalAddr()}
	srv := &http.Server{Handler: p.relayAPI}
	srv.Serve(ln) //nolint:errcheck
	logDebugf("serveRelayAPI: done for %s", conn.RemoteAddr())
}

func (p *tcpProxy) proxyToExit(client net.Conn) {
	start := time.Now()
	defer client.Close()

	// Determine the client's country so we can avoid routing their traffic
	// to an exit in their own country (which would defeat the bypass).
	clientCC := ""
	clientIP := ""
	if host, _, err := net.SplitHostPort(client.RemoteAddr().String()); err == nil {
		clientIP = host
		if p.cidrC != nil {
			if ip := net.ParseIP(host); ip != nil {
				clientCC = p.cidrC.lookupCC(ip)
			}
		}
	}

	logDebugf("proxy: client=%s clientCC=%q picking exit", client.RemoteAddr(), clientCC)
	exit, err := p.exits.PickForClient(clientIP, clientCC)
	if err != nil {
		logWarnf("proxy: no exit available client=%s: %v", client.RemoteAddr(), err)
		return
	}

	exitAddr := exitDialAddr(exit.Addr)
	dialStart := time.Now()
	exitConn, err := net.DialTimeout("tcp", exitAddr, 10*time.Second)
	if err != nil {
		logWarnf("proxy: dial exit=%s client=%s: %v", exitAddr, client.RemoteAddr(), err)
		return
	}
	dialRTT := time.Since(dialStart)
	id := p.registerExitConn(exit.Addr, exitConn)
	defer p.unregisterExitConn(exit.Addr, id)
	defer exitConn.Close()
	p.exits.RecordDialRTT(exit.Addr, dialRTT)
	logInfof("proxy: open client=%s exit=%s dial=%s",
		client.RemoteAddr(), exitAddr, dialRTT.Round(time.Millisecond))

	upCounter := &countWriter{dst: exitConn}
	downCounter := &countWriter{dst: client}

	done := make(chan string, 2)
	go func() {
		io.Copy(upCounter, client) //nolint:errcheck
		if hc, ok := exitConn.(halfCloser); ok {
			hc.CloseWrite() //nolint:errcheck
		}
		done <- "client"
	}()
	go func() {
		io.Copy(downCounter, exitConn) //nolint:errcheck
		if hc, ok := client.(halfCloser); ok {
			hc.CloseWrite() //nolint:errcheck
		}
		done <- "exit"
	}()

	first := <-done
	if hc, ok := client.(halfCloser); ok {
		hc.CloseRead() //nolint:errcheck
	}
	if hc, ok := exitConn.(halfCloser); ok {
		hc.CloseRead() //nolint:errcheck
	}
	<-done

	controlBytesTotal.Add(upCounter.n + downCounter.n)
	logInfof("proxy: close client=%s exit=%s closed-by=%s dur=%s up=%d down=%d bytes",
		client.RemoteAddr(), exitAddr, first,
		time.Since(start).Round(time.Millisecond),
		upCounter.n, downCounter.n)
}

// extractSNI parses a TLS ClientHello record and returns the SNI value.
// Returns "" if the data is not a valid ClientHello or contains no SNI.
func extractSNI(data []byte) string {
	// TLS record header: content-type(1) + version(2) + length(2)
	if len(data) < 5 || data[0] != 0x16 {
		return ""
	}
	// SNI is always early in the ClientHello — do not require the full record
	// in the peek buffer (TLS 1.3 ClientHellos with key_share can exceed 512 B).
	// Handshake header: type(1) + length(3)
	hs := data[5:]
	if len(hs) < 4 || hs[0] != 0x01 { // 0x01 = ClientHello
		return ""
	}
	ch := hs[4:]
	// ClientHello body: version(2) + random(32) = skip 34 bytes
	pos := 34
	if pos >= len(ch) {
		return ""
	}
	// Session ID
	sidLen := int(ch[pos])
	pos += 1 + sidLen
	if pos+2 > len(ch) {
		return ""
	}
	// Cipher suites
	csLen := int(binary.BigEndian.Uint16(ch[pos : pos+2]))
	pos += 2 + csLen
	if pos >= len(ch) {
		return ""
	}
	// Compression methods
	cmLen := int(ch[pos])
	pos += 1 + cmLen
	if pos+2 > len(ch) {
		return ""
	}
	// Extensions list
	extLen := int(binary.BigEndian.Uint16(ch[pos : pos+2]))
	pos += 2
	end := pos + extLen
	for pos+4 <= end && pos+4 <= len(ch) {
		extType := binary.BigEndian.Uint16(ch[pos : pos+2])
		extDataLen := int(binary.BigEndian.Uint16(ch[pos+2 : pos+4]))
		pos += 4
		if extType == 0x0000 { // SNI extension
			// SNI data: list-length(2) + name-type(1) + name-length(2) + name
			if extDataLen < 5 || pos+extDataLen > len(ch) {
				return ""
			}
			nameLen := int(binary.BigEndian.Uint16(ch[pos+3 : pos+5]))
			if pos+5+nameLen > len(ch) {
				return ""
			}
			return string(ch[pos+5 : pos+5+nameLen])
		}
		pos += extDataLen
	}
	return ""
}

// exitDialAddr strips any scheme prefix and ensures host:port format.
// The exit always listens on :443 when no port is specified.
func exitDialAddr(addr string) string {
	addr = strings.TrimPrefix(addr, "https://")
	addr = strings.TrimPrefix(addr, "http://")
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return addr + ":443"
	}
	return addr
}
