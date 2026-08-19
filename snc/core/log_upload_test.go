// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"bytes"
	"testing"

	"tunnel_cat/binlog"
)

// TestRingBufferFramesEachRecord verifies the actual production wiring
// point: ringBuffer.WriteRecord frames each payload as one binlog record,
// and Snapshot() returns something binlog.Decode can turn back into the
// original bytes -- this is what StatsRing sends to the arbiter as the
// upload's "stats" zip member (see LogUploader.upload).
func TestRingBufferFramesEachRecord(t *testing.T) {
	rb := newRingBuffer(4096)

	lines := []string{
		"one",
		"two",
		"three",
	}
	for _, l := range lines {
		rb.WriteRecord(binlog.TagControlDead, []byte(l))
	}

	text, corrupt := binlog.Decode(rb.Snapshot())
	if corrupt != 0 {
		t.Fatalf("unexpected corrupt records: %d", corrupt)
	}
	var want bytes.Buffer
	for _, l := range lines {
		want.WriteString(l)
	}
	if !bytes.Equal(text, want.Bytes()) {
		t.Fatalf("decoded snapshot mismatch:\n got: %q\nwant: %q", text, want.Bytes())
	}
}

// TestRingBufferWrapRecoversTailRecords exercises the actual scenario the
// magic/CRC framing was added for: a ring buffer small enough that it wraps
// mid-record during normal operation, tearing an old record in half. The
// decoder must still recover every record written after the wrap, not just
// fail outright on the torn one.
func TestRingBufferWrapRecoversTailRecords(t *testing.T) {
	// Small enough that a handful of records force at least one wrap.
	rb := newRingBuffer(64)

	var lastPayloads []string
	for i := 0; i < 20; i++ {
		l := "line-" + string(rune('A'+i%26)) + "-of-some-length"
		lastPayloads = append(lastPayloads, l)
		rb.WriteRecord(binlog.TagGeneric, []byte(l))
	}

	text, _ := binlog.Decode(rb.Snapshot())
	if len(text) == 0 {
		t.Fatalf("expected some recovered records after wrapping, got none")
	}
	// The most recent write must always survive a wrap intact -- it's always
	// the newest data, never itself torn by a later write.
	last := lastPayloads[len(lastPayloads)-1]
	if !bytes.Contains(text, []byte(last)) {
		t.Fatalf("expected the most recent write %q to survive, got: %q", last, text)
	}
}
