// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

// Package logevent is the runtime encode side of the structured binary log
// events design. It owns:
//   - the CBOR encoding of an event's attribute map,
//   - attaching the two fields every structured event MUST carry (ts, seq --
//     never left to a call site to remember, see Emit),
//   - handing the framed [FormatStructured][event id][CBOR] payload to
//     snc/core's WriteStructuredEvent, which owns where the bytes actually
//     land (same rotating log file Log.Printf already writes to).
//
// Event ids and their known attribute-key/enum-value constants
// (events_generated.go) come from tunnel_cat/logschema/events.yaml via
// tunnel_cat/logschema/gen.py -- never hand-add a constant here, edit the
// YAML and regenerate instead.
package logevent

import (
	"encoding/binary"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/fxamacker/cbor/v2"

	"tunnel_cat/binlog"
)

// Sink is where a framed structured-event payload actually gets written --
// deliberately a callback, not a direct import of snc/core (which would be
// a circular import: core's own call sites, e.g. bypass.go, need to call
// Emit, so core must depend on logevent, not the other way around). Set
// once via SetSink, normally from core.InitLogging right after it sets up
// the same rotating log file Log.Printf writes to (see
// core.WriteStructuredEvent, the Sink core actually installs).
type Sink func(tag binlog.Tag, payload []byte) error

var sink Sink

// SetSink installs where Emit's framed payloads get written. Call once,
// during logging setup -- Emit silently drops events before this is called,
// the same "discard until initialized" contract Log/TunLog already have,
// rather than panicking on a logging call made too early.
func SetSink(s Sink) { sink = s }

// Attr is one CBOR attribute map entry. Construct with Str/Bool/Int, not
// directly -- the constructors are what keep the Value's type inside CBOR's
// own supported type model (see events.yaml's doc comment on field types).
type Attr struct {
	Key   string
	Value any
}

func Str(key, val string) Attr       { return Attr{key, val} }
func Bool(key string, val bool) Attr { return Attr{key, val} }
func Int(key string, val int64) Attr { return Attr{key, val} }

// typedEncode rewrites m in place so enum- and ip-typed fields (per
// enumFieldValues/ipFields, generated from events.yaml's own field
// declarations) get a compact CBOR encoding -- an enum value becomes its
// index (uint) into the field's declared value list instead of the literal
// string, and an ip value becomes the raw 4/16 address bytes instead of
// dotted/colon text. Call sites never change: they still pass a plain
// string via Str() for these fields, exactly as before this existed --
// this is the ONE place that knows how to compact it, driven entirely by
// generated schema metadata, so adopting it for a field is just adding
// `enum:` or `type: ip` in events.yaml and regenerating.
//
// Falls back to leaving the value as a plain string whenever it can't
// compact it (value not in the enum's declared list, not a valid-looking
// IP, or not even a string to begin with) -- never drops or fails the
// event over an encoding nicety. This is also exactly what keeps the wire
// format backward compatible with no version/marker bump: CBOR itself
// tells old records (value arrived as text) from new ones (value arrived
// as uint/bytes) apart, so a decoder that knows a field is enum/ip-typed
// can handle both without being told which it's looking at.
func typedEncode(event Event, m map[string]any) {
	if fields, ok := enumFieldValues[event]; ok {
		for key, vals := range fields {
			s, ok := m[key].(string)
			if !ok {
				continue
			}
			for i, v := range vals {
				if v == s {
					m[key] = uint16(i)
					break
				}
			}
		}
	}
	if fields, ok := ipFields[event]; ok {
		for key := range fields {
			s, ok := m[key].(string)
			if !ok {
				continue
			}
			ip := net.ParseIP(s)
			if ip == nil {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				m[key] = []byte(v4)
			} else {
				m[key] = []byte(ip.To16())
			}
		}
	}
}

// seq is a per-process monotonic counter, attached to every event as the
// "seq" attribute -- ts alone can't disambiguate two events with the same
// millisecond timestamp, and unlike ts it can never regress (clock
// adjustments, NTP steps), so it's the more reliable of the two for
// reconstructing true emission order across a burst.
var seq uint64

// Emit encodes attrs (plus the mandatory ts/seq, see the package doc
// comment) as a CBOR map, frames it as a FormatStructured binlog payload
// for event, and writes it to the same log file Log.Printf already writes
// to, under tag. Never returns an error -- a logging call must not be able
// to fail the caller's own operation; encode/write failures are reported
// via Log.Printf instead (the one place in this package still-allowed to
// use the free-text path, since a broken structured-event pipeline must
// still be diagnosable).
func Emit(tag binlog.Tag, event Event, attrs ...Attr) {
	m := make(map[string]any, len(attrs)+2)
	for _, a := range attrs {
		m[a.Key] = a.Value
	}
	typedEncode(event, m)
	// ts/seq are set AFTER attrs, not before: gen.py refuses to generate a
	// schema field literally named "ts" or "seq" (see its validation), but
	// that only catches it at schema-authoring time -- an ad hoc Str/Int
	// attr key (not schema-declared at all, see events.yaml's doc comment
	// on ad hoc keys being intentionally unvalidated) could still collide
	// by accident. Setting these last means the mandatory fields always
	// win the collision instead of silently vanishing -- confirmed by a
	// real instance of exactly this collision during the initial
	// migration (tunnel.post_result's own "seq" field, now renamed to
	// req_seq, briefly overwrote the monotonic counter before this fix).
	m["ts"] = time.Now().UnixMilli()
	m["seq"] = atomic.AddUint64(&seq, 1)

	body, err := cbor.Marshal(m)
	if err != nil {
		log.Printf("logevent: cbor marshal event=%s: %v", EventNames[event], err)
		return
	}

	payload := make([]byte, 1+4+len(body))
	payload[0] = byte(binlog.FormatStructured)
	binary.BigEndian.PutUint32(payload[1:5], uint32(event))
	copy(payload[5:], body)

	if sink == nil {
		return
	}
	if err := sink(tag, payload); err != nil {
		log.Printf("logevent: write event=%s: %v", EventNames[event], err)
	}
}
