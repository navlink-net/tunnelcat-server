// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

// dht_wire.go â€” package-local aliases for dht.Seal/Open/Msg* used by holepunch.go.

import "tunnel_cat/dht"

const (
	dhtMsgHolePunch = dht.MsgHolePunch
	dhtMaxTTL       = dht.MaxTTL
)

func dhtSeal(msgType byte, ttl uint8, payload interface{}) ([]byte, error) {
	return dht.Seal(msgType, ttl, payload)
}

func dhtOpen(pkt []byte) (msgType byte, ttl uint8, rawJSON []byte, err error) {
	return dht.Open(pkt)
}
