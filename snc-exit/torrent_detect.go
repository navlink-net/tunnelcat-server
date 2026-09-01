// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import "bytes"

// btHandshakeHeader is the fixed prefix of the BitTorrent peer wire protocol
// handshake: a 1-byte pstrlen (19) followed by the literal protocol string.
// Every real BitTorrent client sends this as the very first bytes on a new
// peer connection (BEP 3), before anything else -- so it's available in the
// seq==0 upload frame's payload, the same place the blacklist/whitelist
// checks already look at the connection's target.
var btHandshakeHeader = []byte("\x13BitTorrent protocol")

// isBitTorrentHandshake reports whether payload opens with a BitTorrent peer
// wire protocol handshake. This only catches the plaintext peer protocol
// (the actual file-transfer connections, which is the traffic that matters
// for egress policy) -- tracker HTTP announces and DHT UDP packets have much
// weaker, easily-confused signatures and are not classified here.
func isBitTorrentHandshake(payload []byte) bool {
	return bytes.HasPrefix(payload, btHandshakeHeader)
}

// btPortRangeLow/High is the classic BitTorrent peer-listening port range
// from BEP 3's original reference implementation (6881-6889 inclusive).
// Every mainstream client (qBittorrent, uTorrent, Transmission, Deluge)
// defaults to Message Stream Encryption (MSE/PE) for peer connections,
// whose first bytes are a Diffie-Hellman public key -- indistinguishable
// from random by design, so isBitTorrentHandshake never matches it. This is
// a known-hard problem (no reliable content signature exists for MSE
// without participating in the full handshake), so port-range is the
// practical fallback signal: not airtight (a client can rebind to any
// port), but it's exactly the heuristic real-world ISP/firewall BT
// classifiers already rely on, and costs nothing extra to check since the
// destination port is already parsed before this point in the request.
// False-positive risk is low -- legitimate services almost never bind this
// specific 9-port range.
const (
	btPortRangeLow  = 6881
	btPortRangeHigh = 6889
)

// isLikelyBitTorrentPort reports whether port falls in the classic BEP-3
// peer-listening range -- a fallback signal for encrypted (MSE) BitTorrent
// connections that isBitTorrentHandshake's payload check cannot see. See
// that range's doc comment for why this heuristic exists.
func isLikelyBitTorrentPort(port int) bool {
	return port >= btPortRangeLow && port <= btPortRangeHigh
}
