// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

// QUIC demux: lets a QUIC listener share the same UDP:443 socket that
// UDPReflector already owns (SNCU tunnel — being removed — DHT gossip, and
// the STUN-style IP reflector). UDPReflector.Serve() remains the sole reader
// of the socket; packets it classifies as QUIC are handed to quicPacketConn,
// which quic-go's Transport treats as an ordinary net.PacketConn.
//
// Two classification paths:
//
//  1. Long-header Initial packets (new connection attempts): recognised by
//     QUIC's wire format itself — top two bits of the first byte plus a
//     4-byte version field matching a version we actually speak. Reflector
//     ciphertext is uniformly random, so matching both the 2 header bits and
//     a specific 4-byte version by chance is ~1-in-2^34 — not a realistic
//     collision risk.
//
//  2. Short-header packets on an already-established connection: matched by
//     destination connection ID against quicCIDTracker's active set.
//     Connection IDs are generated uniformly at random (never a fixed
//     prefix — see quicConnIDGenerator) specifically so QUIC traffic isn't
//     more fingerprintable than plain QUIC/HTTP3 traffic would be; the
//     tracker is how we still recognise "this is ours" without a marker on
//     the wire.
//
// Neither check consumes anything from the SNCU/DHT/reflector paths' own
// namespace, so ordering relative to them in Serve() doesn't matter much;
// it's checked first purely because it's the cheapest test.

import (
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	quicCIDLen    = 8
	quicCIDTTL    = 10 * time.Minute
	quicPktChSize = 2048
)

var quicVersions = map[uint32]bool{
	1:          true, // QUIC v1 (RFC 9000)
	0x6b3343cf: true, // QUIC v2 (RFC 9369)
}

// looksLikeQUICInitial reports whether pkt's first bytes structurally match
// a QUIC long-header packet with a version we speak (Initial, Handshake,
// 0-RTT, or Retry all share this header shape; we don't need to distinguish
// them here, quic-go does that once it owns the packet).
func looksLikeQUICInitial(pkt []byte) bool {
	if len(pkt) < 5 {
		return false
	}
	// bit7 = long header form, bit6 = fixed bit (both must be 1).
	if pkt[0]&0xC0 != 0xC0 {
		return false
	}
	version := uint32(pkt[1])<<24 | uint32(pkt[2])<<16 | uint32(pkt[3])<<8 | uint32(pkt[4])
	return quicVersions[version]
}

// quicCIDTracker is the active-set of connection IDs our own QUIC
// connections are currently using. Entries expire on a TTL rather than
// being explicitly removed on connection close (a connection can rotate
// through several CIDs over its life via NAT-rebinding/privacy migration;
// tying removal to "the" connection isn't well-defined). A stale entry
// briefly outliving its connection just means one more packet gets routed
// to quic-go instead of the reflector, which quic-go drops harmlessly.
type quicCIDTracker struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newQUICCIDTracker() *quicCIDTracker {
	t := &quicCIDTracker{seen: make(map[string]time.Time)}
	go t.cleanup()
	return t
}

func (t *quicCIDTracker) cleanup() {
	tk := time.NewTicker(time.Minute)
	defer tk.Stop()
	for range tk.C {
		cutoff := time.Now().Add(-quicCIDTTL)
		t.mu.Lock()
		for cid, seenAt := range t.seen {
			if seenAt.Before(cutoff) {
				delete(t.seen, cid)
			}
		}
		t.mu.Unlock()
	}
}

func (t *quicCIDTracker) add(cid []byte) {
	t.mu.Lock()
	t.seen[string(cid)] = time.Now()
	t.mu.Unlock()
}

func (t *quicCIDTracker) has(cid []byte) bool {
	t.mu.Lock()
	_, ok := t.seen[string(cid)]
	t.mu.Unlock()
	return ok
}

// quicConnIDGenerator hands out cryptographically random, unlinkable
// connection IDs (per quic-go's own doc comment: "observers should not be
// able to correlate two Connection IDs") and registers each one with the
// tracker so the demux can later recognise packets addressed to it.
type quicConnIDGenerator struct {
	tracker *quicCIDTracker
}

func (g *quicConnIDGenerator) GenerateConnectionID() (quic.ConnectionID, error) {
	b := make([]byte, quicCIDLen)
	if _, err := rand.Read(b); err != nil {
		return quic.ConnectionID{}, err
	}
	g.tracker.add(b)
	return quic.ConnectionIDFromBytes(b), nil
}

func (g *quicConnIDGenerator) ConnectionIDLen() int {
	return quicCIDLen
}

// classifyQUIC decides whether pkt should be routed to the QUIC transport:
// either a fresh long-header connection attempt, or a short-header packet
// whose destination CID belongs to one of our active connections.
func (t *quicCIDTracker) classify(pkt []byte) bool {
	if looksLikeQUICInitial(pkt) {
		return true
	}
	// Short header: byte0 top bit clear, followed by the (fixed-length)
	// destination connection ID.
	if len(pkt) < 1+quicCIDLen {
		return false
	}
	if pkt[0]&0x80 != 0 {
		return false
	}
	return t.has(pkt[1 : 1+quicCIDLen])
}

type quicPkt struct {
	data []byte
	addr *net.UDPAddr
}

// quicPacketConn is a net.PacketConn view over the shared UDP:443 socket,
// fed by UDPReflector.Serve() (the socket's sole reader) instead of reading
// the socket itself. Writes go straight through to the real socket.
type quicPacketConn struct {
	conn   *net.UDPConn
	pktCh  chan quicPkt
	closed chan struct{}
	once   sync.Once
}

func newQUICPacketConn(conn *net.UDPConn) *quicPacketConn {
	return &quicPacketConn{
		conn:   conn,
		pktCh:  make(chan quicPkt, quicPktChSize),
		closed: make(chan struct{}),
	}
}

// deliver is called from UDPReflector.Serve() for packets classified as
// QUIC. Non-blocking: a full channel means we're badly overloaded, in which
// case dropping is preferable to stalling the reflector's single read loop
// for every other protocol sharing the socket.
func (c *quicPacketConn) deliver(data []byte, addr *net.UDPAddr) {
	select {
	case c.pktCh <- quicPkt{data: data, addr: addr}:
	default:
		logWarnf("quic-demux: packet queue full, dropping from %s", addr)
	}
}

func (c *quicPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pkt := <-c.pktCh:
		n := copy(p, pkt.data)
		return n, pkt.addr, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *quicPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, errors.New("quic-demux: WriteTo requires *net.UDPAddr")
	}
	return c.conn.WriteToUDP(p, udpAddr)
}

// Close only tears down the demux's own view; the real socket is owned and
// closed elsewhere (it's shared with SNCU/DHT/reflector).
func (c *quicPacketConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *quicPacketConn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

func (c *quicPacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *quicPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *quicPacketConn) SetWriteDeadline(t time.Time) error { return nil }
