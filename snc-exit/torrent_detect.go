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
