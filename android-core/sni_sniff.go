// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

//go:build linux

package androidcore

import (
	"context"
	"encoding/binary"
)

// sniHintKey is the context key HandleTCP uses to pass a sniffed TLS SNI
// hostname down to appStickyDialer.DialContext, so a blocked-IPv6
// destination can be forward-resolved by its real hostname instead of
// depending on a PTR record existing for that IP.
//
// Why this exists: confirmed live, 2026-08-18, that PTR-based reverse
// lookup (ActiveResolveIPv4 in snc/core) fails outright for hosts with no
// PTR record configured -- e.g. sso.passport.yandex.ru, which ya.ru
// redirects to on every normal login flow, not an edge case. The TLS
// ClientHello Chrome sends carries the real hostname in its SNI extension
// regardless of whether DNS PTR exists for the destination IP, so sniffing
// it is strictly more reliable than PTR whenever the connection is TLS.
type sniHintKey struct{}

func withSNIHint(ctx context.Context, host string) context.Context {
	if host == "" {
		return ctx
	}
	return context.WithValue(ctx, sniHintKey{}, host)
}

func sniHintFrom(ctx context.Context) string {
	host, _ := ctx.Value(sniHintKey{}).(string)
	return host
}

// extractSNI parses a (possibly truncated) TLS ClientHello record and
// returns the server_name extension's hostname, or "" if data isn't a
// ClientHello or has no SNI extension. Never panics on malformed/truncated
// input -- always returns "" instead, since this runs on arbitrary
// attacker-adjacent network bytes (best-effort sniffing, not validation).
func extractSNI(data []byte) string {
	defer func() { recover() }() //nolint:errcheck

	// TLS record header: type(1) + version(2) + length(2).
	if len(data) < 5 || data[0] != 0x16 { // 0x16 = Handshake
		return ""
	}
	recLen := int(binary.BigEndian.Uint16(data[3:5]))
	end := 5 + recLen
	if end > len(data) {
		end = len(data)
	}
	body := data[5:end]

	// Handshake header: msg_type(1) + length(3).
	if len(body) < 4 || body[0] != 0x01 { // 0x01 = ClientHello
		return ""
	}
	body = body[4:]

	// client_version(2) + random(32).
	if len(body) < 34 {
		return ""
	}
	body = body[34:]

	// session_id: length(1) + session_id.
	if len(body) < 1 {
		return ""
	}
	sidLen := int(body[0])
	body = body[1:]
	if len(body) < sidLen {
		return ""
	}
	body = body[sidLen:]

	// cipher_suites: length(2) + suites.
	if len(body) < 2 {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(body[:2]))
	body = body[2:]
	if len(body) < csLen {
		return ""
	}
	body = body[csLen:]

	// compression_methods: length(1) + methods.
	if len(body) < 1 {
		return ""
	}
	cmLen := int(body[0])
	body = body[1:]
	if len(body) < cmLen {
		return ""
	}
	body = body[cmLen:]

	// extensions: length(2) + extensions.
	if len(body) < 2 {
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(body[:2]))
	body = body[2:]
	if len(body) < extLen {
		extLen = len(body)
	}
	extensions := body[:extLen]

	for len(extensions) >= 4 {
		extType := binary.BigEndian.Uint16(extensions[:2])
		length := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if len(extensions) < length {
			return ""
		}
		payload := extensions[:length]
		extensions = extensions[length:]

		if extType != 0x0000 { // server_name
			continue
		}
		// server_name_list: length(2), then entries of type(1)+length(2)+name.
		if len(payload) < 2 {
			return ""
		}
		list := payload[2:]
		for len(list) >= 3 {
			nameType := list[0]
			nameLen := int(binary.BigEndian.Uint16(list[1:3]))
			list = list[3:]
			if len(list) < nameLen {
				return ""
			}
			if nameType == 0 { // host_name
				return string(list[:nameLen])
			}
			list = list[nameLen:]
		}
	}
	return ""
}
