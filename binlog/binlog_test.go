// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package binlog

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	lines := [][]byte{
		[]byte("2026/08/15 12:00:00 [snc] first line\n"),
		[]byte("2026/08/15 12:00:01 [snc] second line, a bit longer than the first\n"),
		[]byte(""), // zero-length payload must be representable
		[]byte("2026/08/15 12:00:02 [snc] third\n"),
	}
	var buf []byte
	for _, l := range lines {
		buf = AppendRecord(buf, TagGeneric, l)
	}

	text, corrupt := Decode(buf)
	if corrupt != 0 {
		t.Fatalf("unexpected corrupt count: %d", corrupt)
	}
	var want bytes.Buffer
	for _, l := range lines {
		want.Write(l)
	}
	if !bytes.Equal(text, want.Bytes()) {
		t.Fatalf("round-trip mismatch:\n got: %q\nwant: %q", text, want.Bytes())
	}
}

func TestDecodeRecordsPreservesTags(t *testing.T) {
	var buf []byte
	buf = AppendRecord(buf, TagSocks5, []byte("socks5 line\n"))
	buf = AppendRecord(buf, TagBypass, []byte("bypass line\n"))
	buf = AppendRecord(buf, TagUpload, []byte("upload line\n"))

	records, corrupt := DecodeRecords(buf)
	if corrupt != 0 {
		t.Fatalf("unexpected corrupt: %d", corrupt)
	}
	want := []Record{
		{Tag: TagSocks5, Payload: []byte("socks5 line\n")},
		{Tag: TagBypass, Payload: []byte("bypass line\n")},
		{Tag: TagUpload, Payload: []byte("upload line\n")},
	}
	if len(records) != len(want) {
		t.Fatalf("got %d records, want %d", len(records), len(want))
	}
	for i, r := range records {
		if r.Tag != want[i].Tag || !bytes.Equal(r.Payload, want[i].Payload) {
			t.Errorf("record %d: got {%v %q}, want {%v %q}", i, r.Tag, r.Payload, want[i].Tag, want[i].Payload)
		}
	}

	// Decode() (used by the arbiter dispatcher) ignores tags and just
	// concatenates every payload in order, regardless of topic.
	text, _ := Decode(buf)
	wantText := "socks5 line\nbypass line\nupload line\n"
	if string(text) != wantText {
		t.Fatalf("Decode() = %q, want %q", text, wantText)
	}
}

func TestResyncAfterRingBufferWrap(t *testing.T) {
	// Simulate what ringBuffer.Write produces after wrapping mid-record: the
	// first record's tail bytes are gone, overwritten by data that now
	// starts mid-buffer. A decoder must recover every intact record after
	// the damage point instead of failing outright.
	var full []byte
	full = AppendRecord(full, TagGeneric, []byte("record A, will be torn\n"))
	full = AppendRecord(full, TagGeneric, []byte("record B, intact\n"))
	full = AppendRecord(full, TagGeneric, []byte("record C, intact\n"))

	// Chop off the first N bytes to simulate a mid-record overwrite/wrap.
	// Whether this specific cut leaves behind a dangling frame that trips
	// the CRC/resync path (corrupt > 0) or happens to land cleanly on the
	// next start magic (corrupt == 0) depends on the exact offset -- either
	// way the decoder must not crash and must recover every intact record
	// after the damage point.
	torn := full[10:]

	text, _ := Decode(torn)
	if !bytes.Contains(text, []byte("record B, intact\n")) || !bytes.Contains(text, []byte("record C, intact\n")) {
		t.Fatalf("expected surviving records to be recovered, got: %q", text)
	}
	if bytes.Contains(text, []byte("record A")) {
		t.Fatalf("torn record A should not have decoded cleanly, got: %q", text)
	}
}

func TestResyncPastSpuriousMagic(t *testing.T) {
	var buf []byte
	buf = AppendRecord(buf, TagGeneric, []byte("first\n"))
	// A start-magic-looking byte pair that isn't a real record (e.g. it
	// could occur by coincidence inside unrelated payload bytes elsewhere in
	// the ring). The decoder must not stop here -- it should fail this
	// candidate record and keep scanning.
	buf = append(buf, 0xC5, 0xA7, 0xDE, 0xAD, 0xBE, 0xEF)
	buf = AppendRecord(buf, TagGeneric, []byte("second\n"))

	text, corrupt := Decode(buf)
	if corrupt == 0 {
		t.Fatalf("expected the spurious magic to be caught and skipped")
	}
	if !bytes.Contains(text, []byte("first\n")) || !bytes.Contains(text, []byte("second\n")) {
		t.Fatalf("expected both real records to survive around the spurious magic: %q", text)
	}
}

func TestCRCCatchesBitFlip(t *testing.T) {
	var buf []byte
	buf = AppendRecord(buf, TagGeneric, []byte("line one\n"))
	buf = AppendRecord(buf, TagGeneric, []byte("line two\n"))

	// Flip one bit inside the first record's payload -- structurally intact
	// (both magics, CRC field, length all still line up), content wrong.
	buf[6] ^= 0x01

	text, corrupt := Decode(buf)
	if corrupt == 0 {
		t.Fatalf("expected the CRC mismatch on record 1 to be caught")
	}
	if bytes.Contains(text, []byte("line one")) {
		t.Fatalf("corrupted record should have been dropped, not silently decoded: %q", text)
	}
	if !bytes.Contains(text, []byte("line two\n")) {
		t.Fatalf("second record should still decode fine: %q", text)
	}
}

func TestEmptyInput(t *testing.T) {
	text, corrupt := Decode(nil)
	if len(text) != 0 || corrupt != 0 {
		t.Fatalf("empty input should decode to nothing cleanly, got text=%q corrupt=%d", text, corrupt)
	}
}

func TestNotBinlogAtAll(t *testing.T) {
	// Plain text with no magic bytes anywhere -- must not crash, and should
	// report zero decodable records (caller uses this signal to distinguish
	// "not binlog" from "binlog with recoverable damage").
	text, corrupt := Decode([]byte("just a normal legacy text log line\n"))
	if len(text) != 0 {
		t.Fatalf("expected no decoded output from non-binlog input, got %q", text)
	}
	_ = corrupt
}
