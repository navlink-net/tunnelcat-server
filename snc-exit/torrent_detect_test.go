// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import "testing"

func TestIsBitTorrentHandshake(t *testing.T) {
	if !isBitTorrentHandshake([]byte("\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00")) {
		t.Error("expected a real BEP-3 handshake prefix to match")
	}
	if isBitTorrentHandshake([]byte("GET / HTTP/1.1\r\n")) {
		t.Error("expected ordinary HTTP traffic not to match")
	}
	if isBitTorrentHandshake([]byte{}) {
		t.Error("expected an empty payload not to match")
	}
}

func TestIsLikelyBitTorrentPort(t *testing.T) {
	for _, port := range []int{6881, 6885, 6889} {
		if !isLikelyBitTorrentPort(port) {
			t.Errorf("expected port %d to be in range", port)
		}
	}
	for _, port := range []int{80, 443, 6880, 6890, 22, 51413} {
		if isLikelyBitTorrentPort(port) {
			t.Errorf("expected port %d to be outside range", port)
		}
	}
}
