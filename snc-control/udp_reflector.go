// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

// UDPReflector listens on a UDP port and responds to reflection requests with
// the observed source address (IP + port).
//
// Wire format â€” both request and response are encrypted with ChaCha20-Poly1305
// using a key derived from a well-known constant.  There is no recognisable
// protocol header: from the outside packets look like random noise.
//
// Request ciphertext decrypts to:
//   [8B timestamp_ms big-endian]
//
// Response ciphertext decrypts to:
//   [2B addr_family: 4=IPv4 6=IPv6][4 or 16B IP][2B port big-endian]
//
// Replay protection: requests older than reflectTSWindow seconds are silently
// dropped.  A Â±5 s clock-skew allowance is applied for the future direction.

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"

	"tunnel_cat/dht"
)

const (
	reflectNonceSize = 12   // ChaCha20-Poly1305 nonce
	reflectMaxPkt    = 1500 // UDP MTU; 256 was too small for Announce packets (~280 bytes)
	reflectTSWindow  = 30   // seconds; older requests are dropped

	// Per-source-IP rate limit on the UDP tunnel path.
	// Legitimate clients send at most a handful of packets per second even under
	// load (each RoundTrip is 1â€“3 packets with exponential backoff). A flooder
	// easily exceeds this by orders of magnitude.
	udpRLWindow    = time.Second
	udpRLMax       = 50               // packets allowed per IP per second
	udpRLWarnEvery = 30 * time.Second // log-suppress interval for repeated drops
)

// ipBucket tracks packet count for one source IP within the current window.
type ipBucket struct {
	count       int
	windowStart time.Time
	warnedAt    time.Time
}

// ipRateLimiter is a simple per-source-IP sliding-window rate limiter.
type ipRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*ipBucket
}

func newIPRateLimiter() *ipRateLimiter {
	rl := &ipRateLimiter{buckets: make(map[string]*ipBucket)}
	go rl.cleanup()
	return rl
}

// cleanup removes stale bucket entries once per minute to bound memory usage.
func (rl *ipRateLimiter) cleanup() {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().Add(-2 * udpRLWindow)
		rl.mu.Lock()
		for ip, b := range rl.buckets {
			if b.windowStart.Before(cutoff) {
				delete(rl.buckets, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// allow returns true if the packet from ip should be processed.
// When the rate limit is exceeded it logs once per udpRLWarnEvery to avoid
// filling the journal with drop messages.
func (rl *ipRateLimiter) allow(ip string) bool {
	now := time.Now()
	rl.mu.Lock()
	b := rl.buckets[ip]
	if b == nil {
		rl.buckets[ip] = &ipBucket{count: 1, windowStart: now}
		rl.mu.Unlock()
		return true
	}
	if now.Sub(b.windowStart) >= udpRLWindow {
		b.count = 1
		b.windowStart = now
		rl.mu.Unlock()
		return true
	}
	b.count++
	if b.count <= udpRLMax {
		rl.mu.Unlock()
		return true
	}
	shouldLog := now.Sub(b.warnedAt) >= udpRLWarnEvery
	if shouldLog {
		b.warnedAt = now
	}
	count := b.count
	rl.mu.Unlock()
	if shouldLog {
		logWarnf("udp-reflect: rate-limiting %s (%d pkt/s, limit %d)", ip, count, udpRLMax)
	}
	return false
}

// reflectorKey is derived for DPI obfuscation only â€” it is not a security
// secret.  The same derivation must be used in win-client/core/nat.go.
var reflectorKey = func() []byte {
	h, _ := blake2b.New256(nil)
	h.Write([]byte("snc-udp-reflect-v1"))
	return h.Sum(nil)
}()

// UDPReflector accepts encrypted UDP datagrams and replies with the observed
// source address of the sender.  Datagrams classified as QUIC (see
// quicCIDTracker.classify) are handed to quicConn for the QUIC tunnel
// transport.  Datagrams that authenticate as DHT packets are dispatched to
// dhtH.
type UDPReflector struct {
	conn     *net.UDPConn
	quicConn *quicPacketConn // nil = QUIC tunnel disabled
	quicCIDs *quicCIDTracker // nil = QUIC tunnel disabled
	dhtH     *dhtServer      // nil = DHT disabled
	rl       *ipRateLimiter
}

// newUDPReflector creates a UDPReflector bound to conn.
// quicConn/quicCIDs and dhtH may be nil to disable those handlers.
func newUDPReflector(conn *net.UDPConn, quicConn *quicPacketConn, quicCIDs *quicCIDTracker, dhtH *dhtServer) *UDPReflector {
	return &UDPReflector{conn: conn, quicConn: quicConn, quicCIDs: quicCIDs, dhtH: dhtH, rl: newIPRateLimiter()}
}

// Serve runs the reflector loop in the calling goroutine.
func (r *UDPReflector) Serve() {
	aead, err := chacha20poly1305.New(reflectorKey)
	if err != nil {
		logWarnf("udp-reflect: aead init: %v", err)
		return
	}

	logInfof("udp-reflect: ready on %s", r.conn.LocalAddr())

	buf := make([]byte, reflectMaxPkt)
	for {
		n, src, err := r.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		pkt := buf[:n]

		logDebugf("udp-reflect: recv %d bytes from %s", n, src)

		// QUIC tunnel traffic (new connection attempt or an established
		// connection's short-header packet) → hand to the QUIC transport.
		if r.quicConn != nil && r.quicCIDs.classify(pkt) {
			if !r.rl.allow(src.IP.String()) {
				continue
			}
			cp := make([]byte, len(pkt))
			copy(cp, pkt)
			r.quicConn.deliver(cp, src)
			continue
		}

		// DHT probe: try decrypting as a DHT datagram; on success, dispatch to DHT node.
		// dht.Open is cheap (one AEAD open); failures are expected for non-DHT packets.
		if r.dhtH != nil {
			if _, _, _, err := dht.Open(pkt); err == nil {
				cp := make([]byte, len(pkt))
				copy(cp, pkt)
				r.dhtH.HandleInbound(cp, src)
				continue
			}
		}

		// Must be at least nonce + 8B plaintext + AEAD overhead.
		minLen := reflectNonceSize + 8 + aead.Overhead()
		if len(pkt) < minLen {
			logDebugf("udp-reflect: drop short packet from %s (len=%d min=%d)", src, n, minLen)
			continue
		}

		nonce := pkt[:reflectNonceSize]
		plaintext, err := aead.Open(nil, nonce, pkt[reflectNonceSize:], nil)
		if err != nil {
			logDebugf("udp-reflect: drop bad auth from %s: %v", src, err)
			continue
		}
		if len(plaintext) < 8 {
			logDebugf("udp-reflect: drop short plaintext from %s (len=%d)", src, len(plaintext))
			continue
		}

		tsMs := int64(binary.BigEndian.Uint64(plaintext[:8]))
		ageMs := time.Now().UnixMilli() - tsMs
		if ageMs > int64(reflectTSWindow)*1000 || ageMs < -int64(reflectTSWindow)*1000 {
			logDebugf("udp-reflect: drop replay/skew from %s (age=%dms)", src, ageMs)
			continue
		}

		logDebugf("udp-reflect: valid request from %s age=%dms â†’ replying", src, ageMs)
		r.reply(aead, src)
	}
}

func (r *UDPReflector) reply(aead interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Overhead() int
}, src *net.UDPAddr) {
	// Encode observed address: [2B family][IP bytes][2B port].
	ip4 := src.IP.To4()
	var family uint16 = 6
	ip := src.IP.To16()
	if ip4 != nil {
		family = 4
		ip = ip4
	}

	plain := make([]byte, 2+len(ip)+2)
	binary.BigEndian.PutUint16(plain[0:], family)
	copy(plain[2:], ip)
	binary.BigEndian.PutUint16(plain[2+len(ip):], uint16(src.Port))

	nonce := make([]byte, reflectNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return
	}
	out := aead.Seal(nonce, nonce, plain, nil)

	r.conn.WriteToUDP(out, src) //nolint:errcheck
	logDebugf("udp-reflect: replied to %s â†’ %s:%d", src, src.IP, src.Port)
}
