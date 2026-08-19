// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newStubServer builds a minimal tunnel server using the new encrypted protocol.
// It handles upload frames (polling mode — returns data in the ACK response) and
// returns 404 for stream-open frames (streaming is tested separately).
func newStubServer(t *testing.T) *httptest.Server {
	t.Helper()
	pool := map[string]net.Conn{}
	var mu sync.Mutex

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Session")
		if token != "test-token" {
			http.NotFound(w, r)
			return
		}
		key := sessionKey(token)

		body, _ := io.ReadAll(r.Body)
		plain, err := openFrame(key, body)
		if err != nil || len(plain) < 1 {
			http.NotFound(w, r)
			return
		}

		switch plain[0] {
		case frameTypeStreamOpen:
			// not supported in the stub — streaming tests use a dedicated server
			http.NotFound(w, r)

		case frameTypeUpload:
			connID, seq, target, payload, err := parseUploadFrame(plain)
			if err != nil {
				http.NotFound(w, r)
				return
			}

			mu.Lock()
			conn := pool[connID]
			mu.Unlock()

			if seq == 0 {
				conn, err = net.DialTimeout("tcp", target, 2*time.Second)
				if err != nil {
					w.WriteHeader(http.StatusBadGateway)
					return
				}
				mu.Lock()
				pool[connID] = conn
				mu.Unlock()
			} else if conn == nil {
				http.NotFound(w, r)
				return
			}

			if len(payload) > 0 {
				conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond)) //nolint:errcheck
				conn.Write(payload)                                            //nolint:errcheck
			}

			// read target→client bytes (up to 200 ms) and include in ACK
			conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)) //nolint:errcheck
			buf := make([]byte, 65536)
			var response []byte
			for {
				n, err := conn.Read(buf)
				if n > 0 {
					response = append(response, buf[:n]...)
				}
				if err != nil {
					break
				}
			}

			resp, err := buildUploadResponse(key, response)
			if err != nil {
				http.Error(w, "internal", 500)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write(resp) //nolint:errcheck

		default:
			http.NotFound(w, r)
		}
	})
	return httptest.NewServer(handler)
}

// echoTCP starts a local TCP echo server and returns its address and a stop func.
func echoTCP(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// ── tests ─────────────────────────────────────────────────────────────────────

// TestDoPostRespectsPerCallTimeout is the low-level proof behind Dial's
// dialProbeTimeout: a per-call timeout passed to doPost must actually bound
// that call, instead of the request only ever being bounded by td.client's
// blanket 30s Timeout (the 2026-08-12 incident where a stuck connection
// attempt stalled a full 30s during a brief control-node blip).
func TestDoPostRespectsPerCallTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second) // longer than the short timeout below, well under the 30s default
	}))
	defer srv.Close()

	auth := NewAuthenticator(srv.URL, "key", "user", "pass")
	auth.token = "test-token"
	td := NewTunnelDialer(auth)

	start := time.Now()
	_, err := td.doPost("/x", []byte("probe"), false, false, 500*time.Millisecond)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
	if elapsed > 2*time.Second {
		t.Errorf("doPost took %v to fail with a 500ms timeout â€” per-call timeout not applied (fell back to the 30s default)", elapsed)
	}
}

// TestIsTransportFailure locks down the error-text classification that
// decides whether a failed request is attributable to the connection itself
// being broken (worth reporting via SetTransportFailHook) versus a normal
// application-level rejection that should NOT evict the control.
func TestIsTransportFailure(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil is not a transport failure", nil, false},
		{"ALPN-mismatch frame corruption", errors.New(`Post "https://x/": http2: failed reading the frame payload: http2: frame too large, note that the frame header looked like an HTTP/1.1 header`), true},
		{"clean h2-not-negotiated dial failure (the fix's own error shape)", errors.New(`uTLS h2 dial 1.2.3.4:443: peer did not negotiate h2 (ALPN="")`), true},
		{"h2 connection force closed", errors.New("http2: client connection force closed via ClientConn.Close"), true},
		{"h2 connection lost", errors.New("http2: client connection lost"), true},
		{"broken pipe on write", errors.New(`write tcp 1.2.3.4:1->5.6.7.8:443: write: broken pipe`), true},
		{"connection reset", errors.New("read tcp: connection reset by peer"), true},
		{"unexpected EOF", errors.New("unexpected EOF"), true},
		{"invalid credentials is NOT a transport failure", fmt.Errorf("%w: login: no session token in response: {\"error\":\"invalid credentials\"}", ErrAuthRejected), false},
		{"plain 404 is NOT a transport failure", &controlHTTPError{status: http.StatusNotFound}, false},
		{"ordinary context deadline exceeded is NOT a transport failure", context.DeadlineExceeded, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isTransportFailure(c.err); got != c.want {
				t.Errorf("isTransportFailure(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

// stubRoundTripper returns a canned error for every request -- used to force
// client.Do to fail with a specific, controlled error text without needing a
// real broken h2 exchange.
type stubRoundTripper struct{ err error }

func (s stubRoundTripper) RoundTrip(*http.Request) (*http.Response, error) { return nil, s.err }

// TestDoPostFiresTransportFailHookOnlyForTransportErrors verifies doPost
// reports to onTransportFail exactly when isTransportFailure says so -- not
// on every error, and not on none.
func TestDoPostFiresTransportFailHookOnlyForTransportErrors(t *testing.T) {
	t.Run("transport error fires the hook", func(t *testing.T) {
		auth := NewAuthenticator("https://example.invalid", "key", "user", "pass")
		auth.token = "test-token"
		td := NewTunnelDialer(auth)
		td.client.Transport = stubRoundTripper{err: errors.New("http2: client connection lost")}

		fired := false
		td.SetTransportFailHook(func() { fired = true })

		_, err := td.doPost("/x", []byte("probe"), false, false, time.Second)
		if err == nil {
			t.Fatal("expected an error from the stub transport")
		}
		if !fired {
			t.Error("expected onTransportFail to fire for a transport-level error, it did not")
		}
	})

	t.Run("ordinary dial-context error does not fire the hook", func(t *testing.T) {
		auth := NewAuthenticator("https://example.invalid", "key", "user", "pass")
		auth.token = "test-token"
		td := NewTunnelDialer(auth)
		td.client.Transport = stubRoundTripper{err: context.DeadlineExceeded}

		fired := false
		td.SetTransportFailHook(func() { fired = true })

		_, err := td.doPost("/x", []byte("probe"), false, false, time.Second)
		if err == nil {
			t.Fatal("expected an error from the stub transport")
		}
		if fired {
			t.Error("onTransportFail fired for a non-transport error — would evict a control for an unrelated failure")
		}
	})
}

func TestTunnelDialAndEcho(t *testing.T) {
	echoAddr, stop := echoTCP(t)
	defer stop()

	srv := newStubServer(t)
	defer srv.Close()

	auth := NewAuthenticator(srv.URL, "key", "user", "pass")
	auth.token = "test-token"

	// Use polling mode so the stub can return data inline (no streaming goroutine).
	dialer := NewTunnelDialerPolling(auth)
	conn, err := dialer.Dial(echoAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello-tunnel")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}

	buf := make([]byte, 256)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:len(msg)]) != string(msg) {
		t.Errorf("echo mismatch: got %q want %q", buf[:n], msg)
	}
}

func TestSealOpenRoundtrip(t *testing.T) {
	key := sessionKey("my-session-token")
	plain := []byte("hello encrypted world")

	ct, err := sealFrame(key, plain)
	if err != nil {
		t.Fatalf("sealFrame: %v", err)
	}
	got, err := openFrame(key, ct)
	if err != nil {
		t.Fatalf("openFrame: %v", err)
	}
	if string(got) != string(plain) {
		t.Errorf("roundtrip: got %q want %q", got, plain)
	}
}

func TestSealOpenWrongKey(t *testing.T) {
	key1 := sessionKey("token-a")
	key2 := sessionKey("token-b")

	ct, _ := sealFrame(key1, []byte("secret"))
	if _, err := openFrame(key2, ct); err == nil {
		t.Error("expected decryption failure with wrong key")
	}
}

func TestBuildUploadPlainRoundtrip(t *testing.T) {
	connID := newConnID()
	plain := buildUploadPlain(connID, 3, "example.com:443", []byte("payload"))

	gotConnID, gotSeq, gotTarget, gotPayload, err := parseUploadFrame(plain)
	if err != nil {
		t.Fatalf("parseUploadFrame: %v", err)
	}
	if gotConnID != connID {
		t.Errorf("connID: got %q want %q", gotConnID, connID)
	}
	if gotSeq != 3 {
		t.Errorf("seq: got %d want 3", gotSeq)
	}
	if gotTarget != "example.com:443" {
		t.Errorf("target: got %q want %q", gotTarget, "example.com:443")
	}
	if string(gotPayload) != "payload" {
		t.Errorf("payload: got %q want %q", gotPayload, "payload")
	}
}

func TestBuildStreamOpenPlain(t *testing.T) {
	connID := newConnID()
	plain := buildStreamOpenPlain(connID)
	if len(plain) != 1+16 {
		t.Fatalf("stream-open plain len: got %d want %d", len(plain), 1+16)
	}
	if plain[0] != frameTypeStreamOpen {
		t.Errorf("frame type: got 0x%02x want 0x%02x", plain[0], frameTypeStreamOpen)
	}
	got := hex.EncodeToString(plain[1:17])
	if got != connID {
		t.Errorf("connID in frame: got %q want %q", got, connID)
	}
}

func TestBuildUploadResponseRoundtrip(t *testing.T) {
	key := sessionKey("tok")
	data := []byte("response data")

	ct, err := buildUploadResponse(key, data)
	if err != nil {
		t.Fatalf("buildUploadResponse: %v", err)
	}
	// total length must be at least: 12 (nonce) + 16 (tag) + 4 (dlen) + minPadding
	if len(ct) < 12+16+4+minPadding {
		t.Errorf("response too short: %d bytes", len(ct))
	}
	got, err := parseResponse(key, ct)
	if err != nil {
		t.Fatalf("parseResponse: %v", err)
	}
	if string(got) != string(data) {
		t.Errorf("data roundtrip: got %q want %q", got, data)
	}
}

func TestBuildUploadResponseEmpty(t *testing.T) {
	key := sessionKey("tok")
	ct, err := buildUploadResponse(key, nil)
	if err != nil {
		t.Fatalf("buildUploadResponse: %v", err)
	}
	got, err := parseResponse(key, ct)
	if err != nil {
		t.Fatalf("parseResponse: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected nil data, got %d bytes", len(got))
	}
}

func TestFramedDecryptReader(t *testing.T) {
	key := sessionKey("stream-key")
	chunks := [][]byte{
		[]byte("hello "),
		[]byte("world"),
		[]byte("!"),
	}

	// Build a wire stream (as the server would)
	var wire []byte
	var lenBuf [4]byte
	for _, chunk := range chunks {
		ct, err := sealFrame(key, chunk)
		if err != nil {
			t.Fatalf("sealFrame: %v", err)
		}
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(ct)))
		wire = append(wire, lenBuf[:]...)
		wire = append(wire, ct...)
	}

	r := newFramedDecryptReader(io.NopCloser(bytes.NewReader(wire)), key, "test-conn")
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "hello world!" {
		t.Errorf("got %q", got)
	}
}

func TestHostOf(t *testing.T) {
	cases := [][2]string{
		{"https://example.com/foo", "example.com"},
		{"http://127.0.0.1:8080", "127.0.0.1:8080"},
		{"https://sub.domain.com", "sub.domain.com"},
	}
	for _, c := range cases {
		got := hostOf(c[0])
		if got != c[1] {
			t.Errorf("hostOf(%q) = %q, want %q", c[0], got, c[1])
		}
	}
}

func TestTunnelConnIDIsUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := newConnID()
		if seen[id] {
			t.Fatalf("duplicate conn ID: %s", id)
		}
		if len(id) != 32 { // 16 bytes → 32 hex chars
			t.Fatalf("connID length: got %d want 32", len(id))
		}
		seen[id] = true
	}
}

func TestTunnelConnSeqMonotonicallyIncreases(t *testing.T) {
	c := newTunnelConn(newConnID(), func(seq int64, _ []byte) ([]byte, error) {
		return nil, nil
	}, nil, 0)
	for i := int64(0); i < 10; i++ {
		got := c.NextSeq()
		if got != i {
			t.Errorf("NextSeq %d: got %d", i, got)
		}
	}
}

func TestTunnelRotatesPaths(t *testing.T) {
	echoAddr, stop := echoTCP(t)
	defer stop()

	paths := map[string]int{}
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths[r.URL.Path]++
		mu.Unlock()

		token := r.Header.Get("X-Session")
		key := sessionKey(token)
		body, _ := io.ReadAll(r.Body)
		plain, err := openFrame(key, body)
		if err != nil || len(plain) < 1 || plain[0] != frameTypeUpload {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, seq, target, _, _ := parseUploadFrame(plain)
		if seq == 0 {
			// connect to echo, ignore conn
			net.DialTimeout("tcp", target, time.Second) //nolint:errcheck
		}
		resp, _ := buildUploadResponse(key, nil)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(resp) //nolint:errcheck
	}))
	defer srv.Close()

	auth := NewAuthenticator(srv.URL, "", "", "")
	auth.token = "tok"

	for i := 0; i < 20; i++ {
		d := NewTunnelDialerPolling(auth)
		conn, err := d.Dial(echoAddr)
		if err == nil {
			conn.Close()
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(paths) < 2 {
		t.Errorf("expected both paths to appear, got: %v", paths)
	}
}


func TestAdaptiveJitter(t *testing.T) {
	rng := rand.New(rand.NewSource(42))

	// Real-time load: IRI below busy threshold → always zero.
	for i := 0; i < 50; i++ {
		if j := adaptiveJitter(5*time.Millisecond, rng); j != 0 {
			t.Fatalf("expected 0 jitter at IRI=5ms, got %v", j)
		}
	}

	// Zero IRI (first request) → treated as full-IRI, must be ≥ 0 and ≤ jitterMax.
	for i := 0; i < 50; i++ {
		j := adaptiveJitter(0, rng)
		if j < 0 || j > jitterMax {
			t.Fatalf("zero-IRI jitter out of range: %v", j)
		}
	}

	// Full idle: IRI well above jitterFullIRI → jitter ∈ [0, jitterMax].
	var sum time.Duration
	const n = 200
	for i := 0; i < n; i++ {
		j := adaptiveJitter(5*time.Second, rng)
		if j < 0 || j > jitterMax {
			t.Fatalf("full-idle jitter out of range: %v", j)
		}
		sum += j
	}
	avg := sum / n
	// Average should be roughly jitterMax/2 ± wide margin.
	if avg < jitterMax/5 || avg > jitterMax*9/10 {
		t.Errorf("full-idle average jitter %v looks wrong (want ~%v)", avg, jitterMax/2)
	}

	// Mid-range IRI → jitter must be strictly less than at full idle.
	var midSum time.Duration
	for i := 0; i < n; i++ {
		midSum += adaptiveJitter(jitterBusyIRI+10*time.Millisecond, rng)
	}
	midAvg := midSum / n
	if midAvg >= avg {
		t.Errorf("mid-IRI avg jitter (%v) should be less than full-idle avg (%v)", midAvg, avg)
	}
}

// ── classifyDialErr / FailRatio ──────────────────────────────────────────────

func newTestDialer(t *testing.T) *TunnelDialer {
	t.Helper()
	auth := NewAuthenticator("https://example.invalid", "key", "user", "pass")
	return NewTunnelDialer(auth)
}

func TestClassifyDialErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string // "success", "failure", or "neutral"
	}{
		{"nil err is success", nil, "success"},
		{"404 is neutral (per-target rejection)", &controlHTTPError{status: http.StatusNotFound}, "neutral"},
		{"non-404 HTTP status is success (control reachable)", &controlHTTPError{status: http.StatusInternalServerError}, "success"},
		{"401 is success (control reachable)", &controlHTTPError{status: http.StatusUnauthorized}, "success"},
		{"plain transport error is failure", errors.New("http2: client connection lost"), "failure"},
		{"client timeout text is failure (no isDialTimeout carve-out anymore)",
			errors.New(`Post "https://x/": net/http: request canceled (Client.Timeout exceeded while awaiting headers)`), "failure"},
		{"wrapped context.DeadlineExceeded is failure", fmt.Errorf("dial: %w", context.DeadlineExceeded), "failure"},
		{"connection refused is failure", errors.New("dial tcp 1.2.3.4:443: connect: connection refused"), "failure"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			td := newTestDialer(t)
			td.classifyDialErr(c.err)

			switch c.want {
			case "success":
				if len(td.dialWindow) != 1 || !td.dialWindow[0].success {
					t.Errorf("expected one recorded success, got window=%+v", td.dialWindow)
				}
			case "failure":
				if len(td.dialWindow) != 1 || td.dialWindow[0].success {
					t.Errorf("expected one recorded failure, got window=%+v", td.dialWindow)
				}
			case "neutral":
				if len(td.dialWindow) != 0 {
					t.Errorf("expected no outcome recorded, got window=%+v", td.dialWindow)
				}
			}
		})
	}
}

func TestClassifyDialErrRetrySequenceRecordsEachAttempt(t *testing.T) {
	// Mirrors the real-world connID=beb59d8e case from production logs: two
	// real failures (timeout, then http2-lost) followed by a success on the
	// third attempt. Before the Part B fix, only the final success was
	// recorded; now every attempt must land in the window.
	td := newTestDialer(t)

	td.classifyDialErr(errors.New(`net/http: request canceled (Client.Timeout exceeded while awaiting headers)`))
	td.classifyDialErr(errors.New("http2: client connection lost"))
	td.classifyDialErr(nil) // final attempt succeeds

	if len(td.dialWindow) != 3 {
		t.Fatalf("expected 3 recorded outcomes, got %d: %+v", len(td.dialWindow), td.dialWindow)
	}
	wantSuccess := []bool{false, false, true}
	for i, o := range td.dialWindow {
		if o.success != wantSuccess[i] {
			t.Errorf("outcome[%d]: got success=%v, want %v", i, o.success, wantSuccess[i])
		}
	}
}

func TestFailRatioNoData(t *testing.T) {
	td := newTestDialer(t)
	if r := td.FailRatio(); r != 0 {
		t.Errorf("expected 0 with no samples, got %v", r)
	}
}

func TestFailRatioBelowMinSamplesOrSpan(t *testing.T) {
	td := newTestDialer(t)
	// All outcomes recorded "now" — fewer than dialWinMinSamples won't even
	// reach the span check; once there are enough samples they still span
	// well under dialWinMinSpan (10s), so the ratio must stay 0 either way.
	td.recordDialFailure()
	td.recordDialFailure()
	if r := td.FailRatio(); r != 0 {
		t.Errorf("expected 0 below dialWinMinSamples, got %v", r)
	}
	td.recordDialFailure()
	if r := td.FailRatio(); r != 0 {
		t.Errorf("expected 0 below dialWinMinSpan even with enough samples, got %v", r)
	}
}

func TestFailRatioComputesOnceEnoughData(t *testing.T) {
	td := newTestDialer(t)
	now := time.Now()
	// Seed the window directly so span/sample guards are satisfied without
	// sleeping in the test: 4 samples spanning 11s, 2 failures.
	td.dialWindow = []dialOutcome{
		{at: now.Add(-11 * time.Second), success: false},
		{at: now.Add(-8 * time.Second), success: true},
		{at: now.Add(-4 * time.Second), success: false},
		{at: now, success: true},
	}
	if r := td.FailRatio(); r != 0.5 {
		t.Errorf("expected ratio 0.5, got %v", r)
	}
}

func TestFailRatioPrunesOldSamples(t *testing.T) {
	td := newTestDialer(t)
	now := time.Now()
	td.dialWindow = []dialOutcome{
		{at: now.Add(-dialWinSize - time.Second), success: false}, // outside the window, must be pruned
		{at: now.Add(-8 * time.Second), success: true},
		{at: now.Add(-4 * time.Second), success: true},
		{at: now, success: true},
	}
	if r := td.FailRatio(); r != 0 {
		t.Errorf("expected 0 after pruning the stale failure, got %v", r)
	}
	if len(td.dialWindow) != 3 {
		t.Errorf("expected stale sample to be pruned from dialWindow, got %d entries", len(td.dialWindow))
	}
}

// ── refreshToken / SetAuthFailHook ───────────────────────────────────────────

// TestRefreshTokenFiresAuthFailHookAfterThreshold verifies that two
// consecutive transient (non-rejection) login failures against the same
// fixed control node fire onAuthFail exactly once, and that a subsequent
// successful login still completes normally (refreshToken keeps retrying
// underneath even after the hook fires).
func TestRefreshTokenFiresAuthFailHookAfterThreshold(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&attempts, 1)
		if n <= 2 {
			// Generic server error, unrelated to "invalid credentials"/"key expired"
			// — must be treated as transient, not a rejection.
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, "boom") //nolint:errcheck
			return
		}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"session":"tok-after-recovery"}`) //nolint:errcheck
	}))
	defer srv.Close()

	auth := NewAuthenticator(srv.URL, "key", "user", "pass")
	auth.token = "expired-token"
	td := NewTunnelDialer(auth)

	fired := make(chan struct{}, 1)
	td.SetAuthFailHook(func() {
		select {
		case fired <- struct{}{}:
		default:
		}
	})

	done := make(chan error, 1)
	go func() { done <- td.refreshToken("expired-token") }()

	select {
	case <-fired:
	case err := <-done:
		t.Fatalf("refreshToken returned (err=%v) before onAuthFail fired", err)
	case <-time.After(10 * time.Second):
		t.Fatal("onAuthFail did not fire within 10s (threshold is 2 attempts, first backoff is 5s)")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("refreshToken returned error after recovery: %v", err)
		}
		if got := auth.Token(); got != "tok-after-recovery" {
			t.Errorf("expected token to update to the recovered value, got %q", got)
		}
	case <-time.After(15 * time.Second):
		// The 2nd failure (which fires onAuthFail) is followed by a 10s
		// backoff before the 3rd, successful attempt — give it that plus
		// margin rather than the tighter window used for the fire signal.
		t.Fatal("refreshToken did not return after the server started succeeding")
	}

	if n := atomic.LoadInt32(&attempts); n < 3 {
		t.Errorf("expected at least 3 login attempts, got %d", n)
	}
}

// TestRefreshTokenAuthRejectionNeverFiresAuthFailHook verifies that a
// definitive credential rejection (wrong password) never fires onAuthFail —
// that failure mode is an account problem, not a reason to distrust the node.
//
// refreshToken only gives up on a rejection after authRejectWindow (3
// minutes), which is too long to wait out synchronously in a test — instead
// this lets it run in the background for a few retry cycles (well past the
// 2-attempt onAuthFail threshold, at 5s+10s backoff) and asserts the hook
// never fired in that window. The goroutine is abandoned once the test
// returns; that's fine, it holds no resources this test package cares about.
func TestRefreshTokenAuthRejectionNeverFiresAuthFailHook(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":"invalid credentials"}`) //nolint:errcheck
	}))
	defer srv.Close()

	auth := NewAuthenticator(srv.URL, "key", "user", "wrong-pass")
	auth.token = "expired-token"
	td := NewTunnelDialer(auth)

	fired := int32(0)
	td.SetAuthFailHook(func() { atomic.AddInt32(&fired, 1) })

	go func() { td.refreshToken("expired-token") }() //nolint:errcheck

	time.Sleep(18 * time.Second) // several retry cycles past the 2-attempt threshold
	if atomic.LoadInt32(&fired) != 0 {
		t.Errorf("onAuthFail must not fire for credential rejection, fired %d time(s)", fired)
	}
}
