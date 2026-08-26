// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// ControlSNILookup, if set, is called with a control node addr (host:port) to
// obtain the SNI hostname to use for that TLS connection. Returns "" when no
// SNI is configured for that addr, preserving the current empty-SNI behaviour.
// Set once at startup via Discoverer.UseAsSNIProvider().
var ControlSNILookup func(addr string) string

// sniFor extracts the SNI for the given addr, handling the nil guard.
func sniFor(addr string) string {
	if ControlSNILookup == nil {
		return ""
	}
	return ControlSNILookup(addr)
}

// ControlFingerprintLookup, if set, is called with a control node addr
// (host:port) to obtain the expected SHA-256 certificate fingerprint (colon-hex)
// for that node, as reported in the arbiter's signed manifest. Returns "" when
// no fingerprint is known for that addr -- see verifyPeerCertFingerprint for how
// that's handled (accept unpinned, matching exits.go's backward-compat rule).
// Set once at startup via Discoverer.UseAsFingerprintProvider().
var ControlFingerprintLookup func(addr string) string

// ControlPinningDisabled kills control-node TLS cert-fingerprint pinning
// fleet-wide when true. TEMPORARY, added 2026-08-14 by explicit instruction:
// cloud.ru control rotation was producing a large, non-decreasing rate of
// "bad certificate" TLS handshake rejections on real client relay-API
// traffic (~70-75% failure on one node, sustained for hours after its
// rotation) -- clients holding a manifest with the pre-rotation fingerprint
// reject the post-rotation cert outright, and the normal self-healing path
// (a fresh manifest fetch updates the pinned value) evidently isn't keeping
// pace with rotation frequency for a large fraction of real traffic. Revert
// this to false once that's understood/fixed -- pinning is real protection
// against a spoofed control presenting an unexpected cert; this is not a
// permanent architecture decision. See fingerprintFor's only caller sites
// (tls.go's newUTLSTransportRaw/newUTLSH1Client) -- flipping this one flag
// is deliberately the entire blast radius, nothing else needed to re-enable.
//
// Defaults to true (disabled) rather than requiring every one of the 5
// client mains to flip it -- that's the "temporarily disable the code"
// instruction taking effect fleet-wide the moment a build with this change
// ships, no per-platform wiring needed. To re-enable, change this back to
// false (or remove the initializer) and redeploy.
var ControlPinningDisabled = true

// fingerprintFor extracts the expected fingerprint for the given addr, handling
// the nil guard. Returns "" (accept any cert) when ControlPinningDisabled.
func fingerprintFor(addr string) string {
	if ControlPinningDisabled || ControlFingerprintLookup == nil {
		return ""
	}
	return ControlFingerprintLookup(addr)
}

// certFingerprint computes the same SHA-256-over-DER, colon-hex, uppercase
// fingerprint format as snc-control/exits.go's verifyExitFingerprint, so a
// value taken from one place (a node's self-reported fingerprint at heartbeat)
// can be compared against the other (a live TLS handshake) byte-for-byte.
func certFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// verifyPeerCertFingerprint returns a tls.Config.VerifyPeerCertificate callback
// that pins the leaf certificate to expectedFP. This is the actual enforcement
// of what the "fingerprint verified via manifest" comments on the
// InsecureSkipVerify sites in this file used to merely assert without doing --
// see the security review this closes (2026-08-07).
//
// An empty expectedFP accepts unconditionally: this is the "not covered by
// pinning yet" case (node hasn't reported a fingerprint, or no manifest fetched
// at all), not a verification failure -- matches the backward-compat behaviour
// snc-control/exits.go already uses for exit nodes. VerifyPeerCertificate still
// fires when InsecureSkipVerify is true, so this works standalone without
// needing a trusted CA chain.
func verifyPeerCertFingerprint(expectedFP string) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if expectedFP == "" {
			return nil
		}
		if len(rawCerts) == 0 {
			return fmt.Errorf("tls: no certificate presented")
		}
		got := certFingerprint(rawCerts[0])
		if got != strings.ToUpper(expectedFP) {
			return fmt.Errorf("tls: certificate fingerprint mismatch: got %s want %s", got, strings.ToUpper(expectedFP))
		}
		return nil
	}
}

// Channel type constants embedded in ClientHello Session ID for server-side
// demultiplexing. The two-byte marker {chMagic, channelType} at sid[0:2]
// identifies an SNC connection; standard TLS 1.3 clients send a random 32-byte
// session ID so accidental collisions are negligible (p ≈ 1/256 per connection).
const (
	chMagic    byte = 0xA7
	ChTunnel   byte = 0x00 // raw TCP proxy to exit; no TLS termination on control
	ChRelayAPI byte = 0x01 // relay tracker HTTP API
	ChSignal   byte = 0x02 // NAT relay reverse-tunnel (yamux)
	ChNATRelay byte = 0x03 // sender routing through a NAT relay node
	// 0x04 was ChParaExit (para-exit yamux reverse-tunnel); feature removed
	// 2026-08-13. Left unassigned rather than reused, since some already-
	// shipped exit builds may still special-case that byte during demux.
)

// utlsPresets is the set of browser fingerprints we rotate between.
// Chrome and Firefox are by far the most common in the wild.
var utlsPresets = []utls.ClientHelloID{
	utls.HelloChrome_Auto,
	utls.HelloChrome_Auto, // 2× weight — Chrome is dominant
	utls.HelloFirefox_Auto,
	utls.HelloEdge_Auto,
	utls.HelloSafari_Auto,
}

func pickPreset() utls.ClientHelloID {
	return utlsPresets[rand.Intn(len(utlsPresets))]
}

// AllUTLSPresets returns the distinct browser presets used by the tunnel transport.
// Useful for diagnostic tools that want to test each preset independently.
func AllUTLSPresets() []utls.ClientHelloID {
	return []utls.ClientHelloID{
		utls.HelloChrome_Auto,
		utls.HelloFirefox_Auto,
		utls.HelloEdge_Auto,
		utls.HelloSafari_Auto,
	}
}

// PresetName returns a short human-readable name for a uTLS preset.
func PresetName(p utls.ClientHelloID) string {
	switch p {
	case utls.HelloChrome_Auto:
		return "Chrome"
	case utls.HelloFirefox_Auto:
		return "Firefox"
	case utls.HelloEdge_Auto:
		return "Edge"
	case utls.HelloSafari_Auto:
		return "Safari"
	default:
		return p.Client + "/" + p.Version
	}
}

// NewUTLSClientWithPreset returns an *http.Client whose TLS connections use the
// given uTLS browser preset. Used by diagnostic tools to test preset compatibility.
func NewUTLSClientWithPreset(preset utls.ClientHelloID) *http.Client {
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: newUTLSTransport(ChTunnel, preset),
	}
}

// utlsRoundTripper routes HTTPS requests through an http2.Transport backed by
// a uTLS dialer, and plain HTTP requests through a plain http.Transport.
type utlsRoundTripper struct {
	h1 *http.Transport
	h2 *http2.Transport
}

func (rt *utlsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" {
		return rt.h2.RoundTrip(req)
	}
	return rt.h1.RoundTrip(req)
}

// newUTLSTransport returns an http.RoundTripper whose TLS handshakes use the
// given browser fingerprint and embed channelType in the Session ID for
// server-side demultiplexing. SNI is empty (RFC 6066, IP-addressed servers).
//
// HTTPS requests use http2.Transport (h2 over uTLS).
// Plain HTTP requests use a standard http.Transport (used by test servers).
func newUTLSTransport(channelType byte, preset utls.ClientHelloID) http.RoundTripper {
	return newUTLSTransportRaw(channelType, preset, nil)
}

// newUTLSTransportRaw is the internal implementation.
// rawDial, if non-nil, is called instead of net.Dialer to obtain the TCP
// connection.
func newUTLSTransportRaw(channelType byte, preset utls.ClientHelloID,
	rawDial func(ctx context.Context, addr string) (net.Conn, error)) http.RoundTripper {

	dialUTLS := func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		var rawConn net.Conn
		var err error
		if rawDial != nil {
			rawConn, err = rawDial(ctx, addr)
		} else {
			d := &net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
				Control:   dialControl,
			}
			rawConn, err = d.DialContext(ctx, network, addr)
		}
		if err != nil {
			return nil, err
		}
		// The manifest's per-addr fingerprint is the *control's* own relay-API
		// cert (see ControlFingerprintLookup doc comment). It only applies to
		// ChRelayAPI connections, which are the only channel control actually
		// TLS-terminates itself (relay_api.go/serveRelayAPI). ChTunnel (and any
		// other non-relay channel) is raw-proxied by control straight through to
		// a PickForClient-selected exit with zero TLS termination on control
		// (snc-control/handler.go tcpProxy.proxyToExit) -- the peer cert on that
		// connection is whichever exit's own cert, which has nothing to do with
		// the control's fingerprint and will not match it except by accident.
		// Pinning ChTunnel against the control's fingerprint was rejecting valid
		// exit certs whenever a control happened to have a manually-entered
		// fingerprint (arbiter admin "fingerprint" field is optional/manual —
		// see admin_node_api.go) -- incident 2026-08-11.
		expectedFP := ""
		if channelType == ChRelayAPI {
			expectedFP = fingerprintFor(addr)
		}
		uconn := utls.UClient(rawConn, &utls.Config{
			ServerName:            sniFor(addr),
			InsecureSkipVerify:    true, //nolint:gosec // no CA chain for self-signed nodes; pinned below instead
			VerifyPeerCertificate: verifyPeerCertFingerprint(expectedFP),
		}, preset)
		if err := uconn.BuildHandshakeState(); err != nil {
			rawConn.Close()
			return nil, err
		}
		if sid := uconn.HandshakeState.Hello.SessionId; len(sid) >= 2 {
			sid[0] = chMagic
			sid[1] = channelType
		}
		if err := uconn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, err
		}
		// http2.Transport, when given a custom DialTLSContext, trusts the
		// returned conn to actually speak h2 -- it never itself checks
		// ConnectionState().NegotiatedProtocol before writing the h2 client
		// preface. If the peer's ALPN landed on "" or "http/1.1" (happens
		// whenever the peer's tls.Config doesn't list "h2" in NextProtos, or
		// -- for a WLWTP self-served connection relayed transparently by a
		// DIFFERENT control node's session, see snc-control's serveRelayAPI --
		// simply doesn't speak h2 for this endpoint), the peer parses our h2
		// preface as garbage and answers with a genuine small HTTP/1.1
		// response, which the h2 stream reader then fails to parse as a frame
		// header -- surfacing as "http2: failed reading the frame payload:
		// frame too large, note that the frame header looked like an
		// HTTP/1.1 header". Confirmed root cause 2026-08-16 on an isolated
		// sandbox control+exit pair with no production traffic involved.
		// Failing the dial cleanly here turns that opaque corruption into an
		// ordinary, retryable dial error -- the same shape as any other
		// unreachable-control failure, letting the existing pool/dialer
		// failover logic route around it instead of misparsing bytes.
		if proto := uconn.ConnectionState().NegotiatedProtocol; proto != "h2" {
			rawConn.Close()
			return nil, fmt.Errorf("uTLS h2 dial %s: peer did not negotiate h2 (ALPN=%q)", addr, proto)
		}
		return uconn, nil
	}

	h2t := &http2.Transport{
		DialTLSContext: dialUTLS,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec
		},
		// Detect dead h2 connections: send a PING if idle, kill if no pong.
		// Without this, stale connections silently absorb new requests until
		// client.Timeout (30s) fires on every stream — the "all controls timeout"
		// pattern seen after long uptime or a brief control restart.
		ReadIdleTimeout: 30 * time.Second,
		PingTimeout:     15 * time.Second,
	}

	h1t := &http.Transport{
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 64,
		IdleConnTimeout:     90 * time.Second,
	}

	return &utlsRoundTripper{h1: h1t, h2: h2t}
}

// NewRelayAPIH1Client returns an *http.Client that uses uTLS (browser fingerprint +
// ChRelayAPI channel ID in Session ID) but HTTP/1.1 only — no h2.
// Use for control-node /p/v1/* endpoints that don't support HTTP/2.
// dialControl is applied so connections bypass the VPN TUN on Android.
func NewRelayAPIH1Client() *http.Client { return newUTLSH1Client(true) }

// NewRelayAPIH1ClientUnpinned is NewRelayAPIH1Client without cert-fingerprint
// pinning. Use only for requests whose content is independently authenticated
// some other way (e.g. the manifest's own Ed25519 signature, verified in
// Discoverer.verify() regardless of which cert served it) -- see
// discovery.go's fetch(), added 2026-08-14 after control-node IP rotation
// repeatedly broke manifest delivery: a rotated control reissues its TLS cert
// along with the new IP, but an existing client's cached manifest still has
// the *old* fingerprint pinned, so every manifest-fetch attempt against that
// control failed with "certificate fingerprint mismatch" until a fresh
// manifest reached the client by some other route (DHT gossip, a different
// control) -- self-inflicted unavailability the signature check alone
// doesn't need. Do not reuse this for anything whose payload isn't already
// signed/otherwise authenticated -- pinning still matters everywhere else.
func NewRelayAPIH1ClientUnpinned() *http.Client { return newUTLSH1Client(false) }

// newUTLSH1Client is the internal implementation used by NewRelayAPIH1Client,
// NewRelayAPIH1ClientUnpinned, and newRelayAPIHTTPClient. pinned selects
// whether the peer cert is checked against ControlFingerprintLookup; when
// false, any cert is accepted (see NewRelayAPIH1ClientUnpinned's doc comment
// for when that's actually safe).
func newUTLSH1Client(pinned bool) *http.Client {
	preset := pickPreset()
	t := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
				Control:   dialControl,
			}
			rawConn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			expectedFP := ""
			if pinned {
				expectedFP = fingerprintFor(addr)
			}
			uconn := utls.UClient(rawConn, &utls.Config{
				ServerName:            sniFor(addr),
				InsecureSkipVerify:    true, //nolint:gosec // no CA chain for self-signed nodes; pinned below instead
				VerifyPeerCertificate: verifyPeerCertFingerprint(expectedFP),
				// Force HTTP/1.1 in ALPN — server speaks h1 only for this channel.
				// Without this, Chrome preset offers h2; if the server agrees,
				// http.Transport silently switches to h2 and gets framing errors.
				NextProtos: []string{"http/1.1"},
			}, preset)
			if err := uconn.BuildHandshakeState(); err != nil {
				rawConn.Close()
				return nil, err
			}
			if sid := uconn.HandshakeState.Hello.SessionId; len(sid) >= 2 {
				sid[0] = chMagic
				sid[1] = ChRelayAPI
			}
			if err := uconn.HandshakeContext(ctx); err != nil {
				rawConn.Close()
				return nil, err
			}
			return uconn, nil
		},
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     60 * time.Second,
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: t}
}
