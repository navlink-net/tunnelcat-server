// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ── parseUDPRelayFrame codec tests ────────────────────────────────────────────

func TestParseUDPRelayFrame_IPv4(t *testing.T) {
	connIDRaw := make([]byte, 16)
	for i := range connIDRaw {
		connIDRaw[i] = byte(i + 1)
	}
	body := []byte("hello")
	// [16B connID][1B 0x04][4B 1.2.3.4][2B 53][4B bLen][body]
	plain := make([]byte, 16+1+4+2+4+len(body))
	copy(plain[:16], connIDRaw)
	plain[16] = 0x04
	copy(plain[17:21], []byte{1, 2, 3, 4})
	binary.BigEndian.PutUint16(plain[21:23], 53)
	binary.BigEndian.PutUint32(plain[23:27], uint32(len(body)))
	copy(plain[27:], body)

	connID, dst, payload, err := parseUDPRelayFrame(plain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if connID != hex.EncodeToString(connIDRaw) {
		t.Errorf("unexpected connID: %s", connID)
	}
	if dst.IP.String() != "1.2.3.4" {
		t.Errorf("unexpected IP: %s", dst.IP)
	}
	if dst.Port != 53 {
		t.Errorf("unexpected port: %d", dst.Port)
	}
	if string(payload) != "hello" {
		t.Errorf("unexpected payload: %q", payload)
	}
}

func TestParseUDPRelayFrame_IPv6(t *testing.T) {
	connIDRaw := make([]byte, 16)
	ip6 := net.ParseIP("2001:db8::1").To16()
	body := []byte("data")
	plain := make([]byte, 16+1+16+2+4+len(body))
	copy(plain[:16], connIDRaw)
	plain[16] = 0x06
	copy(plain[17:33], ip6)
	binary.BigEndian.PutUint16(plain[33:35], 443)
	binary.BigEndian.PutUint32(plain[35:39], uint32(len(body)))
	copy(plain[39:], body)

	_, dst, payload, err := parseUDPRelayFrame(plain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !dst.IP.Equal(net.ParseIP("2001:db8::1")) {
		t.Errorf("unexpected IP: %s", dst.IP)
	}
	if dst.Port != 443 {
		t.Errorf("unexpected port: %d", dst.Port)
	}
	if string(payload) != "data" {
		t.Errorf("unexpected payload: %q", payload)
	}
}

func TestParseUDPRelayFrame_TooShort(t *testing.T) {
	_, _, _, err := parseUDPRelayFrame([]byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for too-short frame")
	}
}

func TestParseUDPRelayFrame_UnknownFamily(t *testing.T) {
	plain := make([]byte, 16+1+4+2+4)
	plain[16] = 0x99 // unknown
	_, _, _, err := parseUDPRelayFrame(plain)
	if err == nil {
		t.Error("expected error for unknown family")
	}
}

// ── serveUDPRelay integration test ────────────────────────────────────────────

// TestServeUDPRelay_EchoUDP verifies the full HTTP handler path:
// encrypted request → parse → UDP dial → send → receive echo → encrypted response.
func TestServeUDPRelay_EchoUDP(t *testing.T) {
	// Start a UDP echo server.
	echoConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer echoConn.Close()
	echoAddr := echoConn.LocalAddr().(*net.UDPAddr)
	go func() {
		buf := make([]byte, 1024)
		for {
			n, src, err := echoConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			echoConn.WriteToUDP(buf[:n], src) //nolint:errcheck
		}
	}()

	// Build a minimal handler (no auth check by using a stub authClient).
	h := &handler{
		auth:    newStubAuthClient(),
		pool:    newSessionPool(),
		udpPool: newUDPSessionPool(),
		selfIPs: map[string]bool{}, // empty: allow loopback destinations in tests
	}

	token := "test-token"
	key := sessionKey(token)

	// Build plaintext: [16B connID][0x04][4B echoIP][2B echoPort][4B bLen][payload]
	connIDRaw := make([]byte, 16)
	payload := []byte("ping")
	ipBytes := echoAddr.IP.To4()
	plain := make([]byte, 16+1+4+2+4+len(payload))
	copy(plain[:16], connIDRaw)
	plain[16] = 0x04
	copy(plain[17:21], ipBytes)
	binary.BigEndian.PutUint16(plain[21:23], uint16(echoAddr.Port))
	binary.BigEndian.PutUint32(plain[23:27], uint32(len(payload)))
	copy(plain[27:], payload)

	encrypted, err := sealTunnelData(key, plain)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/udp/relay", bytesReader(encrypted))
	req.Header.Set("X-Session", token)
	req.RemoteAddr = "127.0.0.1:9999"
	rr := httptest.NewRecorder()

	h.serveUDPRelay(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", rr.Code)
	}

	respBody, _ := io.ReadAll(rr.Body)
	respData, err := openTunnelFrame(key, respBody)
	if err != nil {
		t.Fatalf("decrypt response: %v", err)
	}
	if len(respData) < 4 {
		t.Fatalf("response too short: %d bytes", len(respData))
	}
	// Response data is now a datagram batch: [4B outer_dlen][4B:N][4B:len][data]...
	dLen := binary.BigEndian.Uint32(respData[:4])
	batch := respData[4 : 4+dLen]
	if len(batch) < 4 {
		t.Fatalf("batch too short: %d bytes", len(batch))
	}
	n := binary.BigEndian.Uint32(batch[:4])
	if n != 1 {
		t.Fatalf("expected 1 frame in batch, got %d", n)
	}
	fLen := binary.BigEndian.Uint32(batch[4:8])
	got := batch[8 : 8+fLen]
	if string(got) != "ping" {
		t.Errorf("expected echo 'ping', got %q", got)
	}
}

// TestServeUDPRelay_NoResponse verifies that when the destination returns no
// UDP reply (timeout), the handler returns 200 with a zero-length payload.
func TestServeUDPRelay_NoResponse(t *testing.T) {
	// Bind a UDP port but never respond.
	silentConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer silentConn.Close()
	silentAddr := silentConn.LocalAddr().(*net.UDPAddr)

	h := &handler{
		auth:    newStubAuthClient(),
		pool:    newSessionPool(),
		udpPool: newUDPSessionPool(),
		selfIPs: map[string]bool{},
	}

	token := "test-token-2"
	key := sessionKey(token)

	connIDRaw := make([]byte, 16)
	payload := []byte("query")
	ipBytes := silentAddr.IP.To4()
	plain := make([]byte, 16+1+4+2+4+len(payload))
	copy(plain[:16], connIDRaw)
	plain[16] = 0x04
	copy(plain[17:21], ipBytes)
	binary.BigEndian.PutUint16(plain[21:23], uint16(silentAddr.Port))
	binary.BigEndian.PutUint32(plain[23:27], uint32(len(payload)))
	copy(plain[27:], payload)

	encrypted, err := sealTunnelData(key, plain)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/udp/relay", bytesReader(encrypted))
	req.Header.Set("X-Session", token)
	req.RemoteAddr = "127.0.0.1:9999"
	rr := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		h.serveUDPRelay(rr, req)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not return within 5s")
	}

	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", rr.Code)
	}

	respBody, _ := io.ReadAll(rr.Body)
	respData, err := openTunnelFrame(key, respBody)
	if err != nil {
		t.Fatalf("decrypt response: %v", err)
	}
	// Response is now a batch: [4B outer_dlen][4B:N=0] when no datagrams arrived.
	dLen := binary.BigEndian.Uint32(respData[:4])
	batch := respData[4 : 4+dLen]
	n := binary.BigEndian.Uint32(batch[:4])
	if n != 0 {
		t.Errorf("expected 0 frames in batch, got %d", n)
	}
}

// ── test helpers ──────────────────────────────────────────────────────────────

// newStubAuthClient returns an authClient backed by an httptest server that
// always returns user="testuser" for any token.
func newStubAuthClient() *authClient {
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"user":"testuser","client_id":"test"}`)) //nolint:errcheck
	}))
	// Note: stub server is intentionally not closed — it will be cleaned up by the
	// GC / process exit during test runs.  For production code newAuthClient is
	// always paired with a real arbiter URL.
	return newAuthClient(stub.URL, "")
}

func bytesReader(b []byte) io.Reader {
	return &bytesReaderImpl{data: b}
}

type bytesReaderImpl struct {
	data []byte
	pos  int
}

func (r *bytesReaderImpl) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
