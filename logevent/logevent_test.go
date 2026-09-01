// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package logevent

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"tunnel_cat/binlog"
)

// captureSink stands in for core.WriteStructuredEvent -- captures exactly
// what a real Sink would receive, without pulling in snc/core (would be a
// circular import from this package's own test, same reason production
// code uses the Sink indirection at all).
type captureSink struct {
	tag     binlog.Tag
	payload []byte
}

func (c *captureSink) sink(tag binlog.Tag, payload []byte) error {
	c.tag = tag
	c.payload = append([]byte(nil), payload...)
	return nil
}

func TestEmitRoundTrip(t *testing.T) {
	var cap captureSink
	SetSink(cap.sink)
	defer SetSink(nil)

	Emit(binlog.TagBypass, EventBypassDecision,
		Str(AttrAddr, "8.8.8.8:443"),
		Bool(AttrResult, false),
		Str(AttrReason, BypassDecisionReasonDisabled))

	if cap.tag != binlog.TagBypass {
		t.Fatalf("tag = %v, want TagBypass", cap.tag)
	}
	if len(cap.payload) < 5 {
		t.Fatalf("payload too short: %d bytes", len(cap.payload))
	}

	format, hasMarker := binlog.HasFormatMarker(cap.payload)
	if !hasMarker || format != binlog.FormatStructured {
		t.Fatalf("format marker = %v (hasMarker=%v), want FormatStructured", format, hasMarker)
	}

	gotEvent := Event(binary.BigEndian.Uint32(cap.payload[1:5]))
	if gotEvent != EventBypassDecision {
		t.Fatalf("event id = %d, want %d", gotEvent, EventBypassDecision)
	}

	var m map[string]any
	if err := cbor.Unmarshal(cap.payload[5:], &m); err != nil {
		t.Fatalf("cbor unmarshal: %v", err)
	}

	// Mandatory fields, per the design: no call site can omit these.
	if _, ok := m["ts"]; !ok {
		t.Error("decoded event missing mandatory ts field")
	}
	if _, ok := m["seq"]; !ok {
		t.Error("decoded event missing mandatory seq field")
	}

	// Every attribute Emit was called with must survive round-trip --
	// this is the actual no-analyzability-loss property, checked
	// mechanically rather than just by eye. AttrReason is enum-typed
	// (bypass.decision's "reason" field), so typedEncode compacts it to
	// its index in BypassDecisionReasonDisabled's declared position (0) --
	// this is the intended new behavior, not information loss: a decoder
	// that knows the field's declared value list maps the index straight
	// back to "disabled".
	want := map[string]any{
		AttrAddr:   "8.8.8.8:443",
		AttrResult: false,
		AttrReason: uint64(0),
	}
	for k, wantV := range want {
		gotV, ok := m[k]
		if !ok {
			t.Errorf("decoded event missing key %q", k)
			continue
		}
		if gotV != wantV {
			t.Errorf("key %q = %v (%T), want %v (%T)", k, gotV, gotV, wantV, wantV)
		}
	}
}

// TestTypedEncodeEnumUnknownValueFallsBack proves an enum-typed field whose
// value isn't in the field's declared list (a future value the schema
// hasn't caught up with yet, or a caller-error typo) is left as a plain
// string rather than silently vanishing or panicking -- typedEncode's
// stated fallback contract.
func TestTypedEncodeEnumUnknownValueFallsBack(t *testing.T) {
	m := map[string]any{AttrReason: "not_a_declared_reason"}
	typedEncode(EventBypassDecision, m)
	if m[AttrReason] != "not_a_declared_reason" {
		t.Fatalf("reason = %v (%T), want unchanged string", m[AttrReason], m[AttrReason])
	}
}

// TestTypedEncodeIP proves ip-typed fields compact to raw address bytes.
// No schema field is declared `type: ip` yet (see events.yaml), so this
// injects a synthetic entry into the generated ipFields table for the
// duration of the test rather than depending on one existing -- the
// mechanism itself is what's under test, independent of adoption.
func TestTypedEncodeIP(t *testing.T) {
	const testField = "test_synthetic_ip_field"
	orig := ipFields[EventBypassDecision]
	ipFields[EventBypassDecision] = map[string]bool{testField: true}
	defer func() {
		if orig == nil {
			delete(ipFields, EventBypassDecision)
		} else {
			ipFields[EventBypassDecision] = orig
		}
	}()

	cases := []struct {
		name    string
		in      string
		wantLen int
	}{
		{"ipv4", "192.168.1.1", 4},
		{"ipv6", "2001:db8::1", 16},
		{"not_an_ip", "not-an-ip-address", 0}, // falls back to string, wantLen unused
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := map[string]any{testField: c.in}
			typedEncode(EventBypassDecision, m)
			if c.wantLen == 0 {
				if m[testField] != c.in {
					t.Fatalf("non-IP value = %v (%T), want unchanged string", m[testField], m[testField])
				}
				return
			}
			b, ok := m[testField].([]byte)
			if !ok {
				t.Fatalf("value = %v (%T), want []byte", m[testField], m[testField])
			}
			if len(b) != c.wantLen {
				t.Fatalf("encoded IP length = %d, want %d", len(b), c.wantLen)
			}
			if got := net.IP(b).String(); got != c.in {
				t.Fatalf("round-trip via net.IP = %q, want %q", got, c.in)
			}
		})
	}
}

// TestEmitAdHocKeySurvives proves the escape-hatch property the plan relies
// on: a key not declared in events.yaml at all still round-trips, since
// CBOR's attribute map is self-describing.
func TestEmitAdHocKeySurvives(t *testing.T) {
	var cap captureSink
	SetSink(cap.sink)
	defer SetSink(nil)

	Emit(binlog.TagBypass, EventBypassDecision, Str("totally_undeclared_field", "surprise"))

	var m map[string]any
	if err := cbor.Unmarshal(cap.payload[5:], &m); err != nil {
		t.Fatalf("cbor unmarshal: %v", err)
	}
	if got, ok := m["totally_undeclared_field"]; !ok || got != "surprise" {
		t.Fatalf("ad hoc key lost or wrong: got %v, ok=%v", got, ok)
	}
}

// TestEmitNilSinkDoesNotPanic mirrors Log/TunLog's "discard until
// initialized" contract -- Emit before SetSink must not crash the caller.
func TestEmitNilSinkDoesNotPanic(t *testing.T) {
	SetSink(nil)
	Emit(binlog.TagBypass, EventBypassDecision, Str(AttrAddr, "x"))
}

// TestUnknownEventIDDecodesAsRaw is the client-side half of the "unknown
// event id must never silently vanish" rule from the design refinement --
// a decoder (here: just DecodeRecords + reading the raw id) must still be
// able to see an id it doesn't recognize, not lose the record.
func TestUnknownEventIDDecodesAsRaw(t *testing.T) {
	var cap captureSink
	SetSink(cap.sink)
	defer SetSink(nil)

	Emit(binlog.TagBypass, Event(0xDEADBEEF), Str("k", "v"))

	framed := binlog.AppendRecord(nil, cap.tag, cap.payload)
	records, corrupt := binlog.DecodeRecords(framed)
	if corrupt != 0 {
		t.Fatalf("corrupt = %d, want 0", corrupt)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}
	format, hasMarker := binlog.HasFormatMarker(records[0].Payload)
	if !hasMarker || format != binlog.FormatStructured {
		t.Fatalf("format = %v/%v, want FormatStructured", format, hasMarker)
	}
	gotID := binary.BigEndian.Uint32(records[0].Payload[1:5])
	if gotID != 0xDEADBEEF {
		t.Fatalf("event id = %x, want deadbeef -- unknown id must survive decode, not be dropped", gotID)
	}
	if _, ok := EventNames[Event(gotID)]; ok {
		t.Fatalf("test event id 0xDEADBEEF unexpectedly known -- pick a different sentinel")
	}
}
