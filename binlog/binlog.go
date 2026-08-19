// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

// Package binlog implements the compact binary log-record framing agreed in
// the 2026-08-15 "human-readable -> machine-readable client logs" design
// discussion. Deliberately a small, standalone package with zero dependency
// on tunnel_cat/snc/core (or anything else) so it's safe to import from
// snc-arbiter directly -- snc/core has a package init() that os.Exit(1)s any
// binary that imports it without a real -ldflags -X Version stamp (see
// snc/core/log.go), which has already bitten snc-control once when it picked
// up an unrelated snc/core import. Nothing here needs that machinery.
//
// Wire format, one record:
//
//	[2B start magic][1B tag][1-10B uvarint payload len][payload][2B CRC16][2B end magic]
//
// Start/end magic let a decoder resynchronize after truncation or a
// mid-record overwrite -- the case that matters most here is
// snc/core's ringBuffer, which silently overwrites the oldest bytes when its
// fixed-capacity buffer wraps. Plain newline-delimited text degrades
// gracefully when that happens (one partial line lost); a naive
// length-prefixed binary format without resync markers would desync every
// record after the wrap point. CRC16 catches the third failure mode start/end
// magic alone can't: a record that's structurally intact (both magics present,
// length looks sane) but has a flipped bit inside it -- without a checksum
// that decodes silently as valid-looking garbage, which is worse than an
// obvious corruption for remote diagnosis.
package binlog

import (
	"bytes"
	"encoding/binary"
)

// Tag categorizes a record's topic so a decoder (or a filtering tool, see
// tools/decode_snc_log.py) can act on the topic without fully decoding every
// record -- the tag byte sits right after the start magic, before the
// length-prefixed payload, specifically so a scanner can read it and decide
// to skip the payload entirely without decoding.
//
// This package stays domain-agnostic on purpose (no VPN/tunnel-specific
// knowledge) -- callers own the mapping from their own log lines to a Tag.
// snc/core's mapping (subsystem log-line prefix -> Tag) lives in
// snc/core/log_tags.go, not here.
type Tag byte

const (
	TagGeneric Tag = 0 // unclassified -- no known mapping for this line's subsystem
	TagTunnel  Tag = 1 // dataplane: tunnel, router, relay, nat, TUN, socks5-adjacent routing
	TagSocks5  Tag = 2 // socks5: local proxy + per-connection routing decisions
	TagBypass  Tag = 3 // bypass: country/CIDR direct-dial bypass decisions
	TagUpload  Tag = 4 // log-upload, conn-stats-upload, bananameter: telemetry uploads
	TagUpdate  Tag = 5 // updater: client self-update
	TagSystem  Tag = 6 // log, watchdog, procfilter, admin-status: process/lifecycle housekeeping

	// TagControlDead is a structured stat record, not a log line: payload is
	// exactly the unreachable control's address (host:port), nothing else.
	// Written to the client's separate, small stats stream (see
	// snc/core/log_upload.go's statsRing) that rides as its own member
	// inside the upload's zip archive -- kept apart from the main log
	// stream specifically so the arbiter can extract just this one small
	// entry without ever decompressing the (possibly large, untrusted-size)
	// main log content. First user of this pattern; any future stat gets
	// its own tag the same way.
	TagControlDead Tag = 7
)

// TagNames maps each known tag to a short display name, for tooling
// (decode_snc_log.py mirrors this list -- keep both in sync).
var TagNames = map[Tag]string{
	TagGeneric:     "generic",
	TagTunnel:      "tunnel",
	TagSocks5:      "socks5",
	TagBypass:      "bypass",
	TagUpload:      "upload",
	TagUpdate:      "update",
	TagSystem:      "system",
	TagControlDead: "control-dead",
}

const (
	startMagic uint16 = 0xC5A7
	endMagic   uint16 = 0x7A5C

	// minRecordLen is the smallest possible on-wire record: 2 (start) + 1
	// (tag) + 1 (shortest uvarint, a zero-length payload) + 2 (crc) + 2 (end).
	minRecordLen = 2 + 1 + 1 + 2 + 2
)

// Header is the fixed marker placed once at the front of an upload payload
// (before gzip) to mark it as binlog-framed. This project's receiving side
// signals format out-of-band via the X-Log-Format request header instead
// (see snc-arbiter/log_upload_client_api.go) so legacy plain-text uploads
// never pay a decompress-and-resniff cost -- Header exists for any other
// caller (an offline tool, a differently-transported client) that doesn't
// have an HTTP header available to carry the same signal.
var Header = []byte("SNCB\x01")

// crc16Table is CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF).
var crc16Table = func() (t [256]uint16) {
	for i := range t {
		crc := uint16(i) << 8
		for j := 0; j < 8; j++ {
			if crc&0x8000 != 0 {
				crc = crc<<1 ^ 0x1021
			} else {
				crc <<= 1
			}
		}
		t[i] = crc
	}
	return t
}()

func crc16(data []byte) uint16 {
	crc := uint16(0xFFFF)
	for _, b := range data {
		crc = crc<<8 ^ crc16Table[byte(crc>>8)^b]
	}
	return crc
}

// AppendRecord frames one record (tag + payload) and appends it to dst,
// returning the extended slice.
func AppendRecord(dst []byte, tag Tag, payload []byte) []byte {
	var lenBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(lenBuf[:], uint64(len(payload)))

	body := make([]byte, 0, 1+n+len(payload))
	body = append(body, byte(tag))
	body = append(body, lenBuf[:n]...)
	body = append(body, payload...)
	crc := crc16(body)

	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], startMagic)
	dst = append(dst, u16[:]...)
	dst = append(dst, body...)
	binary.BigEndian.PutUint16(u16[:], crc)
	dst = append(dst, u16[:]...)
	binary.BigEndian.PutUint16(u16[:], endMagic)
	dst = append(dst, u16[:]...)
	return dst
}

// Record is one decoded, validated binlog record.
type Record struct {
	Tag     Tag
	Payload []byte
}

// DecodeRecords parses a binlog-framed buffer into individual records,
// preserving each one's tag -- this is what a topic filter (e.g.
// decode_snc_log.py's --tag flag) operates on. corrupt counts records
// skipped due to a resync, a bad CRC, or a missing end magic. corrupt > 0
// with non-empty records is expected and fine -- the decoder recovered
// around damage rather than losing the whole buffer; corrupt > 0 with zero
// records likely means data isn't binlog-framed at all.
func DecodeRecords(data []byte) (records []Record, corrupt int) {
	i := 0
	for i < len(data) {
		off := findMagic(data[i:], startMagic)
		if off < 0 {
			break
		}
		i += off
		tag, payload, consumed, ok := decodeOneRecord(data[i:])
		if !ok {
			corrupt++
			i++ // resync: this magic occurrence was a false positive or the
			// record it starts was corrupt/truncated -- advance one byte and
			// keep scanning for the next start magic rather than giving up.
			continue
		}
		records = append(records, Record{Tag: tag, Payload: payload})
		i += consumed
	}
	return records, corrupt
}

// Decode parses a binlog-framed buffer and returns the concatenation of all
// valid records' payloads regardless of tag (which, for records produced by
// snc/core's ring buffer, reconstitutes byte-identical plain-text log
// content), plus the same corrupt count as DecodeRecords. This is what
// snc-arbiter's upload dispatcher uses -- it doesn't filter by topic, it
// just needs the original text back.
func Decode(data []byte) (text []byte, corrupt int) {
	records, corrupt := DecodeRecords(data)
	var out bytes.Buffer
	for _, r := range records {
		out.Write(r.Payload)
	}
	return out.Bytes(), corrupt
}

// decodeOneRecord assumes b begins exactly at a start-magic occurrence. It
// returns the record's tag and payload, the number of bytes consumed (so
// the caller can advance past it), and whether the record validated (magic,
// CRC, end magic all consistent).
func decodeOneRecord(b []byte) (tag Tag, payload []byte, consumed int, ok bool) {
	if len(b) < minRecordLen {
		return 0, nil, 0, false
	}
	pos := 2 // skip start magic (caller already confirmed it's there)
	tag = Tag(b[pos])
	pos++

	payloadLen, n := binary.Uvarint(b[pos:])
	if n <= 0 {
		return 0, nil, 0, false
	}
	pos += n

	bodyEnd := pos + int(payloadLen)
	if payloadLen > uint64(len(b)) || bodyEnd < pos || bodyEnd+4 > len(b) {
		return 0, nil, 0, false // truncated -- not enough bytes for payload+crc+endmagic
	}

	gotCRC := binary.BigEndian.Uint16(b[bodyEnd : bodyEnd+2])
	wantCRC := crc16(b[2:bodyEnd]) // tag + len-varint + payload
	if gotCRC != wantCRC {
		return 0, nil, 0, false
	}
	if binary.BigEndian.Uint16(b[bodyEnd+2:bodyEnd+4]) != endMagic {
		return 0, nil, 0, false
	}

	return tag, b[pos:bodyEnd], bodyEnd + 4, true
}

// findMagic returns the byte offset of the first occurrence of the given
// big-endian uint16 magic value in b, or -1 if not found.
func findMagic(b []byte, magic uint16) int {
	if len(b) < 2 {
		return -1
	}
	hi, lo := byte(magic>>8), byte(magic)
	for i := 0; i+1 < len(b); i++ {
		if b[i] == hi && b[i+1] == lo {
			return i
		}
	}
	return -1
}
