// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	minPadding = 512

	frameTypeUpload     byte = 0x00
	frameTypeStreamOpen byte = 0x01
)

// tunnelPaths are rotated per-request to vary the apparent upload endpoint.
var tunnelPaths = []string{"/api/media/upload", "/api/content/submit"}

// ── crypto helpers ────────────────────────────────────────────────────────────

// sessionKey derives a 32-byte ChaCha20-Poly1305 key from the session token.
func sessionKey(token string) []byte {
	k := blake2b.Sum256([]byte(token))
	return k[:]
}

// sealFrame encrypts plaintext with a random 12-byte nonce prepended.
// Wire format: [12B nonce][ChaCha20-Poly1305 ciphertext+tag].
func sealFrame(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := crand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// openFrame decrypts a [12B nonce][ciphertext+tag] blob.
func openFrame(key, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	if len(data) < aead.NonceSize() {
		return nil, fmt.Errorf("frame too short: %d bytes", len(data))
	}
	nonce := data[:aead.NonceSize()]
	return aead.Open(nil, nonce, data[aead.NonceSize():], nil)
}

// ── frame builders ────────────────────────────────────────────────────────────

// buildUploadPlain constructs the plaintext for an upload frame.
//
//	[1B 0x00][16B conn_id][4B seq_be][2B target_len_be][target][payload]
func buildUploadPlain(connIDHex string, seq uint32, target string, payload []byte) []byte {
	tgt := []byte(target)
	buf := make([]byte, 1+16+4+2+len(tgt)+len(payload))
	i := 0
	buf[i] = frameTypeUpload
	i++
	if b, err := hex.DecodeString(connIDHex); err == nil {
		copy(buf[i:], b)
	}
	i += 16
	binary.BigEndian.PutUint32(buf[i:], seq)
	i += 4
	binary.BigEndian.PutUint16(buf[i:], uint16(len(tgt)))
	i += 2
	copy(buf[i:], tgt)
	i += len(tgt)
	copy(buf[i:], payload)
	return buf
}

// buildStreamOpenPlain constructs the plaintext for a stream-open frame.
//
//	[1B 0x01][16B conn_id]
func buildStreamOpenPlain(connIDHex string) []byte {
	buf := make([]byte, 1+16)
	buf[0] = frameTypeStreamOpen
	if b, err := hex.DecodeString(connIDHex); err == nil {
		copy(buf[1:], b)
	}
	return buf
}

// parseResponse decrypts and parses a non-streaming upload-ACK response.
// Plaintext: [4B dlen_be][data][padding].  Returns the actual data bytes.
func parseResponse(key, body []byte) ([]byte, error) {
	if len(body) == 0 {
		return nil, nil
	}
	plain, err := openFrame(key, body)
	if err != nil {
		return nil, fmt.Errorf("response decrypt: %w", err)
	}
	if len(plain) < 4 {
		return nil, fmt.Errorf("response frame too short")
	}
	dlen := binary.BigEndian.Uint32(plain[:4])
	if dlen == 0 {
		return nil, nil
	}
	if int(dlen) > len(plain)-4 {
		return nil, fmt.Errorf("response dlen %d > available %d", dlen, len(plain)-4)
	}
	return plain[4 : 4+dlen], nil
}

// ── streaming decryption ──────────────────────────────────────────────────────

// framedDecryptReader wraps a streaming response body and transparently decrypts
// length-prefixed encrypted frames produced by the server's streamToClient.
//
// Each frame on the wire: [4B total_enc_len_be][12B nonce][ciphertext].
type framedDecryptReader struct {
	src    io.ReadCloser
	key    []byte
	buf    []byte
	connID string
}

func newFramedDecryptReader(src io.ReadCloser, key []byte, connID string) *framedDecryptReader {
	return &framedDecryptReader{src: src, key: key, connID: connID}
}

func (r *framedDecryptReader) Read(p []byte) (int, error) {
	if len(r.buf) > 0 {
		n := copy(p, r.buf)
		r.buf = r.buf[n:]
		return n, nil
	}
	var lenBuf [4]byte
	if _, err := io.ReadFull(r.src, lenBuf[:]); err != nil {
		return 0, err
	}
	frameLen := binary.BigEndian.Uint32(lenBuf[:])
	if frameLen > 1<<20 { // 1 MB sanity cap
		return 0, fmt.Errorf("stream frame too large: %d", frameLen)
	}
	frame := make([]byte, frameLen)
	if _, err := io.ReadFull(r.src, frame); err != nil {
		return 0, err
	}
	plain, err := openFrame(r.key, frame)
	if err != nil {
		return 0, fmt.Errorf("stream decrypt: %w", err)
	}
	r.buf = plain
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	if n > 0 {
		TunnelMonitor.RecordTunnelRecv(r.connID, n)
	}
	return n, nil
}

func (r *framedDecryptReader) Close() error { return r.src.Close() }

// ── Authenticator ─────────────────────────────────────────────────────────────

// keyAuthInfo holds the canonical key fields needed to send an authenticateKey request.
type keyAuthInfo struct {
	username      string
	servers       []string
	controlNodes  []string
	arbiterPubkey string
	nodeID        string
	apiKey        string
	clientID      string
	keyID         string
	authSig       string
}

// ErrAuthRejected is returned by Login when the control server responded but
// explicitly refused the credentials (no session token in response). It is
// distinct from a network error where the server was unreachable entirely.
// Callers use errors.Is to distinguish transient network failures from
// definitive credential rejections.
var ErrAuthRejected = errors.New("auth rejected")

// ErrAuthTransient marks a login attempt that failed because the arbiter was
// briefly unreachable from the node terminating the request (status 503 with
// "transient":true — see snc-exit/auth.go authenticate/deferredOrTransient),
// not because the credentials were rejected. Callers must retry (optionally
// via the control-cache fallback, see tryAuthViaControlCache) rather than
// treat this as ErrAuthRejected — the latter would make the user re-enter
// their key over what is, architecturally, a momentary blip.
var ErrAuthTransient = errors.New("auth transient: arbiter unavailable")

// ErrNoConnection marks a login attempt that failed at the network/transport
// level (dial timeout, connection refused, DNS failure, ...) rather than
// getting any response from a control node to classify as rejected or
// transient. This is the "control node(s) unreachable" case — e.g. a stale
// cached control address the client hasn't refreshed away from yet.
var ErrNoConnection = errors.New("no connection")

// classifyAuthError turns a non-200 login response into either
// ErrAuthTransient (the node serving the request flagged the arbiter as
// briefly unreachable — {"error":"arbiter_unavailable","transient":true},
// status 503; see snc-exit/auth.go deferredOrTransient) or ErrAuthRejected
// (an actual credential rejection). op labels the wrapped error message.
func classifyAuthError(status int, raw []byte, op string) error {
	if status == http.StatusServiceUnavailable {
		var probe struct {
			Transient bool `json:"transient"`
		}
		if json.Unmarshal(raw, &probe) == nil && probe.Transient {
			return fmt.Errorf("%w: %s: status %d: %s", ErrAuthTransient, op, status, raw)
		}
	}
	return fmt.Errorf("%w: %s: status %d: %s", ErrAuthRejected, op, status, raw)
}

// Authenticator handles login and session-token management.
type Authenticator struct {
	serverURL string
	apiKey    string
	username  string
	password  string
	session   *Session
	client    *http.Client
	token     string
	// Device-binding fields sent to the arbiter during login (M4+).
	keyID      string // from KeyData.KeyID; empty for legacy keys
	deviceID   string // stable per-device UUID loaded from disk
	deviceName string // human-readable label, e.g. "Windows PC" or "Android"
	// Key-based auth (M5+): non-nil when the key carries an AuthSig.
	keyAuth *keyAuthInfo
	// Pending per-user notifications delivered in the key-auth response.
	pendingNotifs []Notification
	// transportFailureHook, if set, is called when a login attempt fails with
	// an error attributable to the transport itself (see isTransportFailure)
	// rather than a normal auth rejection -- lets a caller with its own pool
	// of connections (e.g. a custom SetDialFunc transport) stop reusing a
	// control whose session establishes fine but corrupts every actual
	// exchange (confirmed possible via an ALPN mismatch, 2026-08-16), so it
	// leaves rotation instead of looking permanently healthy forever.
	transportFailureHook func()
}

// SetTransportFailureHook registers a callback fired when a login request
// fails with a transport-level error (see isTransportFailure) as opposed to
// a normal credential rejection. nil clears any existing hook.
func (a *Authenticator) SetTransportFailureHook(fn func()) {
	a.transportFailureHook = fn
}

// isTransportFailure reports whether err indicates the underlying connection
// itself is broken -- corrupted framing, a forcibly closed/lost HTTP/2
// connection, or a failed write -- as opposed to a normal application-level
// response (bad credentials, 404, etc). These are the error shapes an ALPN
// mismatch produces (see snc-control/handler.go's serveRelayAPI fix,
// 2026-08-16): the connection LOOKS fine at dial time but every request over
// it fails this way, so callers use this to signal their own transport/pool
// to stop reusing that connection instead of retrying blindly.
func isTransportFailure(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "frame too large") ||
		strings.Contains(s, "client connection force closed") ||
		strings.Contains(s, "client connection lost") ||
		strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "unexpected EOF") ||
		strings.Contains(s, "peer did not negotiate h2")
}

// SetDeviceInfo stores the key_id and device identity so they are included in
// the next login request to the arbiter for device-binding enforcement.
func (a *Authenticator) SetDeviceInfo(keyID, deviceID, deviceName string) {
	a.keyID = keyID
	a.deviceID = deviceID
	a.deviceName = deviceName
}

// ServerURL returns the control this Authenticator logs in through.
func (a *Authenticator) ServerURL() string { return a.serverURL }

// SetKeyAuth configures key-based authentication from a parsed key.
// If kd.AuthSig is empty (V1 key or legacy), password auth is used as the sole mechanism.
func (a *Authenticator) SetDialFunc(fn func(ctx context.Context, addr string) (net.Conn, error)) {
	a.client = &http.Client{
		Timeout:   30 * time.Second,
		Transport: newUTLSTransportRaw(ChTunnel, pickPreset(), fn),
	}
}

// ClearDialFunc resets auth connections to direct TCP (removes any transport override).
// Must be called when switching away from a custom SetDialFunc transport.
func (a *Authenticator) ClearDialFunc() {
	a.client = &http.Client{
		Timeout:   30 * time.Second,
		Transport: newUTLSTransport(ChTunnel, pickPreset()),
	}
}

// SetHTTPClientForPreset replaces the authenticator's HTTP client with one that
// uses the given uTLS browser preset. Used by diagnostic tools to test each
// preset independently against the same server.
func (a *Authenticator) SetHTTPClientForPreset(preset utls.ClientHelloID) {
	a.client = NewUTLSClientWithPreset(preset)
}

func (a *Authenticator) SetKeyAuth(kd *KeyData) {
	if kd.AuthSig == "" {
		return
	}
	a.keyAuth = &keyAuthInfo{
		username:      kd.Username,
		servers:       kd.Servers,
		controlNodes:  kd.ControlNodes,
		arbiterPubkey: kd.ArbiterPubkey,
		nodeID:        kd.NodeID,
		apiKey:        kd.APIKey,
		clientID:      kd.ClientID,
		keyID:         kd.KeyID,
		authSig:       kd.AuthSig,
	}
}

// NewAuthenticator returns an Authenticator ready to login.
func NewAuthenticator(serverURL, apiKey, username, password string) *Authenticator {
	return &Authenticator{
		serverURL: strings.TrimRight(serverURL, "/"),
		apiKey:    apiKey,
		username:  username,
		password:  password,
		session:   NewSession(nil),
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: newUTLSTransport(ChTunnel, pickPreset()),
		},
	}
}

// Login authenticates and stores the session token.
// Key auth (V2) and password auth are launched in parallel; whichever
// succeeds first wins.  Both must fail for Login to return an error.
func (a *Authenticator) Login() error {
	n := 0
	if a.keyAuth != nil {
		n++
	}
	if a.password != "" {
		n++
	}
	if n == 0 {
		return fmt.Errorf("login: no valid auth method available")
	}

	type res struct {
		tok string
		err error
	}
	ch := make(chan res, n)

	if a.keyAuth != nil {
		go func() {
			tok, err := a.doKeyAuth()
			if err != nil {
				Log.Printf("tunnel: key auth failed (%v)", err)
			}
			ch <- res{tok, err}
		}()
	}
	if a.password != "" {
		go func() {
			tok, err := a.doPasswordAuth()
			ch <- res{tok, err}
		}()
	}

	var errs []string
	hasRejection := false
	hasTransient := false
	for i := 0; i < n; i++ {
		r := <-ch
		if r.err == nil {
			a.token = r.tok
			return nil
		}
		switch {
		case errors.Is(r.err, ErrAuthRejected):
			hasRejection = true
		case errors.Is(r.err, ErrAuthTransient):
			hasTransient = true
		}
		errs = append(errs, r.err.Error())
	}

	// Both attempts came back transient (arbiter unreachable from the exit,
	// no deferred cache there either) — try control's cache before giving up.
	// A different exit may have a cached login for this device even though
	// ours doesn't. Control never asks the arbiter directly or holds its
	// address for any purpose — only an exit's read-only cache, ever.
	if hasTransient && !hasRejection {
		if tok, cacheErr := a.tryAuthViaControlCache(); cacheErr == nil {
			Log.Printf("tunnel: login served from control's deferred-auth cache")
			a.token = tok
			return nil
		} else {
			Log.Printf("tunnel: control auth-cache fallback failed: %v", cacheErr)
		}
	}

	err := fmt.Errorf("login: %s", strings.Join(errs, "; "))
	if hasRejection {
		return fmt.Errorf("%w: %v", ErrAuthRejected, err)
	}
	if hasTransient {
		return fmt.Errorf("%w: %v", ErrAuthTransient, err)
	}
	return fmt.Errorf("%w: %v", ErrNoConnection, err)
}

// LoginViaUDP authenticates using a hole-punched UDP relay connection.
// The relay transparently forwards the auth request to its control via TCP.
// Use when direct TCP to controls is blocked but UDP relay is reachable.
func (a *Authenticator) LoginViaUDP(relay *UDPRelayConn) error {
	n := 0
	if a.keyAuth != nil {
		n++
	}
	if a.password != "" {
		n++
	}
	if n == 0 {
		return fmt.Errorf("login-udp: no valid auth method available")
	}

	type res struct {
		tok string
		err error
	}
	ch := make(chan res, n)

	if a.keyAuth != nil {
		go func() {
			body := a.buildKeyAuthBody()
			tok, err := a.sendAuthViaUDP(relay, body, "key-auth-udp")
			if err != nil {
				Log.Printf("tunnel: key auth (UDP) failed: %v", err)
			}
			ch <- res{tok, err}
		}()
	}
	if a.password != "" {
		go func() {
			body := a.buildPasswordAuthBody()
			tok, err := a.sendAuthViaUDP(relay, body, "password-auth-udp")
			ch <- res{tok, err}
		}()
	}

	var errs []string
	hasRejection := false
	for i := 0; i < n; i++ {
		r := <-ch
		if r.err == nil {
			a.token = r.tok
			return nil
		}
		if errors.Is(r.err, ErrAuthRejected) {
			hasRejection = true
		}
		errs = append(errs, r.err.Error())
	}
	err := fmt.Errorf("login-udp: %s", strings.Join(errs, "; "))
	if hasRejection {
		return fmt.Errorf("%w: %v", ErrAuthRejected, err)
	}
	return fmt.Errorf("%w: %v", ErrNoConnection, err)
}

// sendAuthViaUDP sends a pre-built auth body via UDP relay and parses the session token.
func (a *Authenticator) sendAuthViaUDP(relay *UDPRelayConn, body []byte, label string) (string, error) {
	_, raw, err := relay.RoundTrip("/", "", body)
	if err != nil {
		return "", fmt.Errorf("%s: %w", label, err)
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("%w: %s: parse: %v body=%s", ErrAuthRejected, label, err, raw)
	}
	var tok string
	if s, ok := result["session"]; ok {
		json.Unmarshal(s, &tok) //nolint:errcheck
	}
	if tok == "" {
		return "", fmt.Errorf("%w: %s: no session token: %s", ErrAuthRejected, label, raw)
	}
	return tok, nil
}

// buildKeyAuthBody constructs the key-auth JSON payload.
func (a *Authenticator) buildKeyAuthBody() []byte {
	ka := a.keyAuth
	payload := map[string]interface{}{
		".command": "authenticateKey",
		"username": ka.username,
		"node_id":  ka.nodeID,
		"auth_sig": ka.authSig,
	}
	if len(ka.servers) > 0 {
		payload["servers"] = ka.servers
	}
	if len(ka.controlNodes) > 0 {
		payload["control_nodes"] = ka.controlNodes
	}
	if ka.arbiterPubkey != "" {
		payload["arbiter_pubkey"] = ka.arbiterPubkey
	}
	if ka.apiKey != "" {
		payload["api_key"] = ka.apiKey
	}
	if ka.clientID != "" {
		payload["client_id"] = ka.clientID
	}
	if ka.keyID != "" {
		payload["key_id"] = ka.keyID
	}
	if a.deviceID != "" {
		payload["device_id"] = a.deviceID
	}
	if a.deviceName != "" {
		payload["device_name"] = a.deviceName
	}
	body, _ := json.Marshal(payload)
	return body
}

// buildPasswordAuthBody constructs the password-auth JSON payload.
func (a *Authenticator) buildPasswordAuthBody() []byte {
	payload := map[string]string{
		".command": "verifyPassword",
		"path":     "users",
		"user":     a.username,
		"password": a.password,
		"key":      a.apiKey,
	}
	if a.keyID != "" {
		payload["key_id"] = a.keyID
	}
	if a.deviceID != "" {
		payload["device_id"] = a.deviceID
	}
	if a.deviceName != "" {
		payload["device_name"] = a.deviceName
	}
	body, _ := json.Marshal(payload)
	return body
}

// doKeyAuth sends an authenticateKey request and returns the session token.
func (a *Authenticator) doKeyAuth() (string, error) {
	ka := a.keyAuth
	payload := map[string]interface{}{
		".command": "authenticateKey",
		"username": ka.username,
		"node_id":  ka.nodeID,
		"auth_sig": ka.authSig,
	}
	if len(ka.servers) > 0 {
		payload["servers"] = ka.servers
	}
	if len(ka.controlNodes) > 0 {
		payload["control_nodes"] = ka.controlNodes
	}
	if ka.arbiterPubkey != "" {
		payload["arbiter_pubkey"] = ka.arbiterPubkey
	}
	if ka.apiKey != "" {
		payload["api_key"] = ka.apiKey
	}
	if ka.clientID != "" {
		payload["client_id"] = ka.clientID
	}
	if ka.keyID != "" {
		payload["key_id"] = ka.keyID
	}
	if a.deviceID != "" {
		payload["device_id"] = a.deviceID
	}
	if a.deviceName != "" {
		payload["device_name"] = a.deviceName
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", a.serverURL+"/", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range a.session.Headers(hostOf(a.serverURL)) {
		req.Header.Set(k, v)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		if isTransportFailure(err) && a.transportFailureHook != nil {
			a.transportFailureHook()
		}
		return "", fmt.Errorf("key-auth: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", classifyAuthError(resp.StatusCode, raw, "key-auth")
	}

	var result map[string]json.RawMessage
	if err := json.Unmarshal(raw, &result); err != nil {
		// Server responded 200 but with non-JSON — treat as a credential
		// rejection, not a network error (the transport layer succeeded).
		return "", fmt.Errorf("%w: key-auth: parse: %v: body=%s", ErrAuthRejected, err, raw)
	}
	var tok string
	if s, ok := result["session"]; ok {
		json.Unmarshal(s, &tok) //nolint:errcheck
	}
	if tok == "" {
		return "", fmt.Errorf("%w: key-auth: no session token in response: %s", ErrAuthRejected, raw)
	}
	// Capture any per-user notifications the arbiter attached to this response.
	if n, ok := result["notifications"]; ok {
		var notifs []Notification
		if json.Unmarshal(n, &notifs) == nil && len(notifs) > 0 {
			a.pendingNotifs = notifs
		}
	}
	return tok, nil
}

// doPasswordAuth sends a verifyPassword request and returns the session token.
func (a *Authenticator) doPasswordAuth() (string, error) {
	payload := map[string]string{
		".command": "verifyPassword",
		"path":     "users",
		"user":     a.username,
		"password": a.password,
		"key":      a.apiKey,
	}
	if a.keyID != "" {
		payload["key_id"] = a.keyID
	}
	if a.deviceID != "" {
		payload["device_id"] = a.deviceID
	}
	if a.deviceName != "" {
		payload["device_name"] = a.deviceName
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", a.serverURL+"/", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range a.session.Headers(hostOf(a.serverURL)) {
		req.Header.Set(k, v)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		if isTransportFailure(err) && a.transportFailureHook != nil {
			a.transportFailureHook()
		}
		return "", fmt.Errorf("login: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", classifyAuthError(resp.StatusCode, raw, "login")
	}

	var result map[string]interface{}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("%w: login: parse: %v: body=%s", ErrAuthRejected, err, raw)
	}
	tok := ""
	if s, ok := result["session"].(string); ok {
		tok = s
	} else if data, ok := result["data"].(map[string]interface{}); ok {
		tok, _ = data["session"].(string)
	}
	if tok == "" {
		return "", fmt.Errorf("%w: login: no session token in response: %s", ErrAuthRejected, raw)
	}
	return tok, nil
}

// Token returns the current session token.
func (a *Authenticator) Token() string { return a.token }

// DrainNotifications returns and clears any per-user notifications received
// in the most recent key-auth response.  Returns nil if none are pending.
func (a *Authenticator) DrainNotifications() []Notification {
	if len(a.pendingNotifs) == 0 {
		return nil
	}
	out := a.pendingNotifs
	a.pendingNotifs = nil
	return out
}

// AdoptToken pre-fills the session token without calling Login.
// Used when migrating an existing session to a new control node — the arbiter
// token is valid on any control, so re-authentication is unnecessary.
func (a *Authenticator) AdoptToken(tok string) { a.token = tok }

// NewAuthenticatorWithToken creates an Authenticator that already holds a
// session token — no Login() call required.  The token was obtained externally
// (e.g. via ProxyValidate on behalf of a SOCKS5 user in BlackBadger mode).
func NewAuthenticatorWithToken(serverURL, apiKey, token string) *Authenticator {
	a := &Authenticator{
		serverURL: strings.TrimRight(serverURL, "/"),
		apiKey:    apiKey,
		session:   NewSession(nil),
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: newUTLSTransport(ChTunnel, pickPreset()),
		},
	}
	a.token = token
	return a
}

// ProxyValidate sends a proxy credential validation request to the arbiter
// (via the control node) on behalf of a SOCKS5 user.  It uses this
// authenticator's own session token to authenticate the call and returns the
// session token issued for the validated user.
//
// Used by BlackBadger: the BB instance authenticates the call with its own
// token; the returned token belongs to the end-user and is used in X-Session
// for all tunnel connections on their behalf.
func (a *Authenticator) ProxyValidate(username, password string) (string, error) {
	body, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	req, err := http.NewRequest("POST", a.serverURL+"/api/auth/proxy-validate", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Session", a.token)
	resp, err := a.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("proxy-validate: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return "", classifyAuthError(resp.StatusCode, raw, "proxy-validate")
	}
	var result struct {
		Session string `json:"session"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("proxy-validate: parse: %w", err)
	}
	if result.Session == "" {
		return "", fmt.Errorf("proxy-validate: empty session in response")
	}
	return result.Session, nil
}

// tryAuthViaControlCache asks control's deferred-auth fallback
// (POST /p/v1/auth/cached, see snc-control/relay_api.go authCached) for a
// cached login keyed by this device's device_id. Used as a second chance when
// the primary exit-terminated login attempt comes back ErrAuthTransient — the
// exit serving the tunnel had no arbiter access *and* no cached login of its
// own, but a different exit (queried by control, which never talks to the
// arbiter directly or holds its address, under any circumstances) might.
//
// serverURL doubles as the relay-API base: the same control address routed to
// a different handler via the ChRelayAPI uTLS channel (see relay.go FetchMyIP).
func (a *Authenticator) tryAuthViaControlCache() (string, error) {
	if a.deviceID == "" {
		return "", fmt.Errorf("auth-cache: no device_id available")
	}
	body, _ := json.Marshal(map[string]string{"device_id": a.deviceID})
	req, err := http.NewRequest("POST", a.serverURL+"/p/v1/auth/cached", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := newUTLSH1Client(true).Do(req)
	if err != nil {
		return "", fmt.Errorf("auth-cache: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("auth-cache: status %d: %s", resp.StatusCode, raw)
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", fmt.Errorf("auth-cache: parse: %w", err)
	}
	var tok string
	if s, ok := result["session"]; ok {
		json.Unmarshal(s, &tok) //nolint:errcheck
	}
	if tok == "" {
		return "", fmt.Errorf("auth-cache: no session token in cached response")
	}
	return tok, nil
}

// Token returns the current session token used by the dialer.
func (td *TunnelDialer) Token() string { return td.auth.token }

// Auth returns the authenticator used by this dialer.
func (td *TunnelDialer) Auth() *Authenticator { return td.auth }

// rngIntn returns a random int in [0,n) using td.rng under td.rngMu.
// Multiple goroutines call send() concurrently (pipeline), so rng must be protected.
func (td *TunnelDialer) rngIntn(n int) int {
	td.rngMu.Lock()
	v := td.rng.Intn(n)
	td.rngMu.Unlock()
	return v
}

// nextJitter computes an adaptive jitter duration under td.rngMu.
func (td *TunnelDialer) nextJitter(iri time.Duration) time.Duration {
	td.rngMu.Lock()
	j := adaptiveJitter(iri, td.rng)
	td.rngMu.Unlock()
	return j
}

// PostUDPFrame sends a UDP datagram to dst via the encrypted tunnel and returns
// any inbound datagrams that arrived within the server's short drain window.
func (td *TunnelDialer) PostUDPFrame(connIDHex string, dst *net.UDPAddr, body []byte) ([][]byte, error) {
	plain, err := buildUDPRelayPlain(connIDHex, dst, body)
	if err != nil {
		return nil, err
	}
	if len(body) > 0 {
		TunnelMonitor.RecordTunnelSent(connIDHex, len(body))
	}
	data, err := td.doPost("/api/udp/relay", plain, true, false, 0)
	if err != nil {
		return nil, err
	}
	frames, err := decodeDatagramBatch(data)
	if err == nil {
		for _, f := range frames {
			if len(f) > 0 {
				TunnelMonitor.RecordTunnelRecv(connIDHex, len(f))
				break // one frame is enough to confirm inbound is alive
			}
		}
	}
	return frames, err
}

// DrainUDPFrames long-polls the exit for inbound datagrams on an existing UDP
// session without sending any outbound data. The client's drain goroutine calls
// this continuously to receive server-initiated datagrams (QUIC ACKs, SRTP, etc.)
func (td *TunnelDialer) DrainUDPFrames(connIDHex string, dst *net.UDPAddr) ([][]byte, error) {
	plain, err := buildUDPRelayPlain(connIDHex, dst, nil)
	if err != nil {
		return nil, err
	}
	data, err := td.doPost("/api/udp/drain", plain, true, false, 0)
	if err != nil {
		return nil, err
	}
	return decodeDatagramBatch(data)
}

// decodeDatagramBatch decodes a [4B:N][4B:len][data]... batch into frames.
func decodeDatagramBatch(data []byte) ([][]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if len(data) < 4 {
		return nil, fmt.Errorf("batch too short: %d bytes", len(data))
	}
	n := int(binary.BigEndian.Uint32(data[:4]))
	o := 4
	frames := make([][]byte, 0, n)
	for i := range n {
		if o+4 > len(data) {
			return nil, fmt.Errorf("batch truncated at frame %d", i)
		}
		flen := int(binary.BigEndian.Uint32(data[o:]))
		o += 4
		if o+flen > len(data) {
			return nil, fmt.Errorf("batch frame %d truncated", i)
		}
		frames = append(frames, data[o:o+flen])
		o += flen
	}
	return frames, nil
}

// ── TunnelDialer ──────────────────────────────────────────────────────────────

// dialOutcome records a single Dial() or stream-death result for the rolling eviction window.
type dialOutcome struct {
	at      time.Time
	success bool
}

// TunnelDialer creates TunnelConns through a Camerlengo/arbiter server.
// tunnelPipelineWidth is the number of upload frames that may be in-flight
// simultaneously on a single TunnelConn in streaming mode.  Higher values
// improve throughput on high-latency links at the cost of server-side reorder
// buffering.  The server must support seq-reordering (see snc-exit/sessions.go).
const tunnelPipelineWidth = 8

// dialProbeTimeout bounds the seq-0 "connection establishment" POST in Dial —
// short on purpose, see the comment at its call site.
const dialProbeTimeout = 8 * time.Second

type TunnelDialer struct {
	auth            *Authenticator
	client          *http.Client
	streamClient    *http.Client // no Timeout — used for long-lived streaming responses
	rng             *rand.Rand
	rngMu           sync.Mutex // protects rng; multiple goroutines call send() concurrently
	reAuthMu        sync.Mutex
	streaming       bool
	udpRelay        *UDPRelayConn                                                   // non-nil → use UDP transport for doPost (M4.5)
	rawDialOverride atomic.Pointer[func(context.Context, string) (net.Conn, error)] // non-nil → overrides direct TCP dialer

	// cancelCtx is cancelled when DataFailHook fires so all in-flight HTTP
	// requests (doPost and openStreamPost) abort immediately instead of waiting
	// for their own timeouts.  cancel is safe to call multiple times.
	cancelCtx context.Context
	cancel    context.CancelFunc

	hookMu            sync.RWMutex
	onActivity        func()                                    // called on every POST; set via SetActivityHook
	onReAuthWarning   func()                                    // called on first re-auth failure
	onReAuthRecovered func()                                    // called when re-auth succeeds after a warning
	onFatalError      func(error)                               // called once when re-auth is permanently exhausted
	onDataFail        func()                                    // called when consecutive Dial failures reach the threshold
	onFirstFail       func()                                    // called immediately on the very first Dial failure (no grace, no threshold); used for instant pool eviction
	onUDPFailed       func()                                    // called once when UDP relay marks itself failed; triggers TCP fallback + pool rebuild
	onAuthFail        func()                                    // called once when refreshToken sees consecutive transient (non-rejection) login failures; lets the caller evict this dialer and rotate to another control instead of retrying the same one for up to serverErrorWindow
	onRTTUpdate       func(serverURL string, rtt time.Duration) // called after each successful POST
	onTransportFail   func()                                    // called (every time, not once) when doPost fails with isTransportFailure(err); see Authenticator.transportFailureHook's doc comment for why this exists separately from onDataFail/onFirstFail

	lastPostMu sync.Mutex
	lastPostAt time.Time // time the previous doPost was entered; zero = never

	dialWinMu     sync.Mutex
	dialWindow    []dialOutcome // rolling 30-second outcome window (Dial + stream deaths)
	firstWinFired bool          // true while ≥50% of window samples failed (soft tier active)
	dataWinFired  bool          // true while ≥80% of window samples failed (hard tier active)

	lastDataAt  int64 // atomic unix nanoseconds; updated on each successful POST response
	activeConns int32 // atomic count of open Dial() connections; decremented on Close()

	// trafficRTT tracks the EMA of observed POST round-trip times (nanoseconds).
	// Updated atomically; only published after trafficRTTMinSamples samples.
	trafficRTTNanos int64 // atomic
	trafficRTTCount int32 // atomic sample counter

	clientIP atomic.Value // stores string; set via SetClientIP
	clientCC atomic.Value // stores string; set via SetClientCC

	// loadFactor is the arbiter-supplied bonus/malus coefficient for this
	// dialer's control, refreshed periodically from Router.LoadFactorFor
	// (see main_*.go's pool-refill loop). Stores float64; unset/<=0 means
	// "no data yet", which LoadFactor() reports back as 0 so callers apply
	// their own neutral default (matches routerNode.LoadFactor's convention
	// -- see effectiveLoadFactor in router.go).
	loadFactor atomic.Value
}

const (
	trafficRTTAlpha      = 0.15 // EMA smoothing factor
	trafficRTTMinSamples = 5    // samples required before publishing RTT
)

// SetDataFailHook sets a callback invoked when ≥80% of dial/stream outcomes
// in the rolling 30-second window fail (hard eviction tier: data-dead ban).
// The threshold parameter is ignored; eviction is governed by dataFailRatio.
func (td *TunnelDialer) SetDataFailHook(threshold int, fn func()) {
	td.hookMu.Lock()
	td.onDataFail = fn
	td.hookMu.Unlock()
}

// SetFirstFailHook sets a callback invoked when ≥50% of dial/stream outcomes
// in the rolling 30-second window fail (soft eviction tier: flap penalty,
// control remains eligible for future path selection).
func (td *TunnelDialer) SetFirstFailHook(fn func()) {
	td.hookMu.Lock()
	td.onFirstFail = fn
	td.hookMu.Unlock()
}

// SetUDPFailedHook registers a callback invoked once when the UDP relay
// exceeds its consecutive-error threshold.  The router uses this to mark the
// control as TCP-only and trigger a pool rebuild.
func (td *TunnelDialer) SetUDPFailedHook(fn func()) {
	td.hookMu.Lock()
	td.onUDPFailed = fn
	td.hookMu.Unlock()
}

// SetAuthFailHook registers a callback invoked once per refreshToken run,
// after authFailThreshold consecutive transient (non-rejection) login
// failures against this dialer's fixed control node. Unlike onFatalError
// (which only fires after the full 3-hour server-unavailable window is
// exhausted, or after 3 minutes of definitive credential rejection),
// this fires fast enough to be useful for pool-based failover: the caller
// can evict this dialer and let the pool try a different, already
// quality-ranked control candidate, while refreshToken's own retry loop
// against this node keeps running underneath as a fallback in case no
// other candidate is available. Never fires for isAuthRejection errors
// (wrong password / expired key) since those are an account problem, not
// a reason to distrust this particular node.
func (td *TunnelDialer) SetAuthFailHook(fn func()) {
	td.hookMu.Lock()
	td.onAuthFail = fn
	td.hookMu.Unlock()
}

// LastActivity returns the time of the most recent tunnel POST, or zero if none.
func (td *TunnelDialer) LastActivity() time.Time {
	td.lastPostMu.Lock()
	t := td.lastPostAt
	td.lastPostMu.Unlock()
	return t
}

// SetActivityHook sets a callback invoked on every tunnel POST.
// Intended for DecoyManager.MarkActivity; safe to call at any time.
func (td *TunnelDialer) SetActivityHook(fn func()) {
	td.hookMu.Lock()
	td.onActivity = fn
	td.hookMu.Unlock()
}

// SetReAuthWarningHook registers a callback invoked on the first re-auth
// failure.  Intended to show a visual warning to the user.
func (td *TunnelDialer) SetReAuthWarningHook(fn func()) {
	td.hookMu.Lock()
	td.onReAuthWarning = fn
	td.hookMu.Unlock()
}

// SetReAuthRecoveredHook registers a callback invoked when re-auth succeeds
// after a prior warning.  Intended to clear the visual warning.
func (td *TunnelDialer) SetReAuthRecoveredHook(fn func()) {
	td.hookMu.Lock()
	td.onReAuthRecovered = fn
	td.hookMu.Unlock()
}

// SetFatalErrorHook registers a callback invoked once when re-authentication
// is permanently exhausted.  The hook is called in a new goroutine so it may
// block (e.g. to trigger a disconnect+reconnect cycle).
func (td *TunnelDialer) SetFatalErrorHook(fn func(error)) {
	td.hookMu.Lock()
	td.onFatalError = fn
	td.hookMu.Unlock()
}

// SetClientIP records the client's real public IP, included in every tunnel
// POST as X-Client-IP so the exit can look up the correct country for stats.
func (td *TunnelDialer) SetClientIP(ip string) { td.clientIP.Store(ip) }

// SetClientCC records the device-detected country code, included in every
// tunnel POST as X-Client-CC so the exit can avoid routing traffic through
// an exit in the client's own country.
func (td *TunnelDialer) SetClientCC(cc string) { td.clientCC.Store(cc) }

// SetRTTUpdateHook registers a callback invoked after each successful POST with
// the server URL and the current EMA traffic RTT.  The hook fires only once
// trafficRTTMinSamples samples have been collected so early noise is suppressed.
// Intended to feed live RTT measurements back into the Router.
func (td *TunnelDialer) SetRTTUpdateHook(fn func(serverURL string, rtt time.Duration)) {
	td.hookMu.Lock()
	td.onRTTUpdate = fn
	td.hookMu.Unlock()
}

// SetTransportFailHook registers a callback invoked every time doPost fails
// with an error isTransportFailure classifies as the connection itself being
// broken (as opposed to a normal control HTTP error) -- lets a caller with
// its own connection pool react to a control whose session establishes fine
// but corrupts every actual exchange (see isTransportFailure's doc comment).
func (td *TunnelDialer) SetTransportFailHook(fn func()) {
	td.hookMu.Lock()
	td.onTransportFail = fn
	td.hookMu.Unlock()
}

// TrafficRTT returns the current EMA of observed POST round-trip times, or 0
// if fewer than trafficRTTMinSamples samples have been recorded.
func (td *TunnelDialer) TrafficRTT() time.Duration {
	if atomic.LoadInt32(&td.trafficRTTCount) < trafficRTTMinSamples {
		return 0
	}
	return time.Duration(atomic.LoadInt64(&td.trafficRTTNanos))
}

// ServerURL returns the server URL this dialer POSTs to.
func (td *TunnelDialer) ServerURL() string { return td.auth.serverURL }

// SetLoadFactor stores the current arbiter-supplied bonus/malus coefficient
// for this dialer's control. Call whenever the manifest refreshes (see
// Router.LoadFactorFor); a non-positive value is ignored (keeps whatever was
// last set, or the zero-value "no data" default).
func (td *TunnelDialer) SetLoadFactor(f float64) {
	if f <= 0 {
		return
	}
	td.loadFactor.Store(f)
}

// LoadFactor returns the last value set via SetLoadFactor, or 0 if never set
// -- callers apply their own neutral default (see pickWeight in
// dialer_pool.go), matching routerNode.LoadFactor's convention.
func (td *TunnelDialer) LoadFactor() float64 {
	f, _ := td.loadFactor.Load().(float64)
	return f
}

// recordTrafficRTT updates the EMA with a new sample and fires onRTTUpdate
// once enough samples have been collected.
func (td *TunnelDialer) recordTrafficRTT(d time.Duration) {
	old := atomic.LoadInt64(&td.trafficRTTNanos)
	var newVal int64
	if old == 0 {
		newVal = int64(d)
	} else {
		newVal = int64(trafficRTTAlpha*float64(d) + (1-trafficRTTAlpha)*float64(old))
	}
	atomic.StoreInt64(&td.trafficRTTNanos, newVal)
	count := atomic.AddInt32(&td.trafficRTTCount, 1)

	if count >= trafficRTTMinSamples {
		td.hookMu.RLock()
		hook := td.onRTTUpdate
		td.hookMu.RUnlock()
		if hook != nil {
			hook(td.auth.serverURL, time.Duration(newVal))
		}
	}
}

// NewTunnelDialer returns a TunnelDialer with streaming enabled.
func NewTunnelDialer(auth *Authenticator) *TunnelDialer {
	return newTunnelDialer(auth, true)
}

// NewTunnelDialerPolling returns a TunnelDialer using legacy polling mode.
func NewTunnelDialerPolling(auth *Authenticator) *TunnelDialer {
	return newTunnelDialer(auth, false)
}

// NewUDPRelayDialer returns a polling TunnelDialer that sends all tunnel POST
// requests over the hole-punched UDP relay connection instead of HTTP/TCP.
// The relay peer transparently forwards each request to Control and returns the
// response.  Streaming is disabled because UDP is datagram-oriented.
func NewUDPRelayDialer(relay *UDPRelayConn, auth *Authenticator) *TunnelDialer {
	td := newTunnelDialer(auth, false)
	td.udpRelay = relay
	return td
}

func newTunnelDialer(auth *Authenticator, streaming bool) *TunnelDialer {
	td := &TunnelDialer{
		auth:      auth,
		rng:       rand.New(rand.NewSource(time.Now().UnixNano())),
		streaming: streaming,
	}
	// rawDial checks for a dial override atomically on every connection attempt.
	// When no override is set the standard net.Dialer path is used (zero overhead).
	rawDial := func(ctx context.Context, addr string) (net.Conn, error) {
		if fn := td.rawDialOverride.Load(); fn != nil {
			return (*fn)(ctx, addr)
		}
		d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: dialControl}
		return d.DialContext(ctx, "tcp", addr)
	}
	rt := newUTLSTransportRaw(ChTunnel, pickPreset(), rawDial)
	td.client = &http.Client{Timeout: 30 * time.Second, Transport: rt}
	td.streamClient = &http.Client{Transport: rt}
	td.cancelCtx, td.cancel = context.WithCancel(context.Background())
	return td
}

// SetDialFunc routes all new TCP connections through fn instead of direct TCP.
// Lets a caller inject a custom dialer (e.g. an alternate transport).
// The function is stored atomically; in-flight requests on the old path complete normally.
func (td *TunnelDialer) SetDialFunc(fn func(ctx context.Context, addr string) (net.Conn, error)) {
	td.rawDialOverride.Store(&fn)
}

// ClearDialFunc removes a dial function override previously set by SetDialFunc,
// reverting to direct TCP.
func (td *TunnelDialer) ClearDialFunc() {
	td.rawDialOverride.Store(nil)
}

// Dial opens a tunnel connection to target (host:port).
func (td *TunnelDialer) Dial(target string) (net.Conn, error) {
	connID := newConnID()
	Log.Printf("tunnel: Dial %s connID=%.8s", target, connID)

	send := func(s int64, payload []byte) ([]byte, error) {
		path := tunnelPaths[td.rngIntn(len(tunnelPaths))]
		// only embed target on the first request (seq=0); subsequent sends omit it
		tgt := ""
		if s == 0 {
			tgt = target
		}
		plain := buildUploadPlain(connID, uint32(s), tgt, payload)
		if len(payload) > 0 {
			TunnelMonitor.RecordTunnelSent(connID, len(payload))
		}
		// seq 0 is connection establishment: always a small probe, so it can
		// afford a much shorter timeout than the 30s default meant for large
		// in-flight transfers. Without this, a control node that's merely slow
		// (not down) leaves a brand-new connection attempt hanging for the
		// full 30s before Dial's own retry loop even gets a chance to run —
		// see the 2026-08-12 incident where this stalled a video connection
		// for 30s during a ~3s control blip. Once seq>0 the connection is
		// already live and mid-transfer, where the full timeout is correct.
		timeout := time.Duration(0)
		if s == 0 {
			timeout = dialProbeTimeout
		}
		resp, err := td.doPost(path, plain, true, true, timeout)
		if err != nil {
			Log.Printf("tunnel: POST error control=%s seq=%d target=%s: %v", td.auth.serverURL, s, target, err)
		} else {
			if len(resp) > 0 {
				TunnelMonitor.RecordTunnelRecv(connID, len(resp))
			}
			Log.Printf("tunnel: POST ok seq=%d target=%s payload=%dB", s, target, len(payload))
		}
		return resp, err
	}

	var streamFn func(context.Context) (io.ReadCloser, error)
	if td.streaming {
		streamFn = func(ctx context.Context) (io.ReadCloser, error) {
			return td.openStreamPost(ctx, connID)
		}
	}

	pipeWidth := 0
	if td.streaming {
		pipeWidth = tunnelPipelineWidth
	}
	conn := newTunnelConn(connID, send, streamFn, pipeWidth)
	// Escalate stream-loop give-up to the dialer's sustained-failure counter.
	// Use recordStreamDead (not recordDialFailure) so that one destination's
	// stream dying does not instantly evict the control node via onFirstFail.
	conn.onStreamDead = td.recordStreamDead

	// renewStream: when the stream loop exhausts flap/error retries, mark the
	// current control as failing and return a fresh streamFn.  Capped at 3
	// renewals per connection to avoid infinite loops on a broken path.
	if td.streaming {
		renewals := 0
		conn.renewStream = func() (func(context.Context) (io.ReadCloser, error), bool) {
			const maxRenewals = 3
			if renewals >= maxRenewals {
				return nil, false
			}
			renewals++
			td.recordStreamDead() // tell the pool this path is degraded
			newFn := func(ctx context.Context) (io.ReadCloser, error) {
				return td.openStreamPost(ctx, connID)
			}
			return newFn, true
		}
	}

	// Retry the initial probe up to 2 times on transient network errors.
	// DPI resets individual TCP connections; the control itself is up.
	// HTTP errors (app-layer, e.g. exit unreachable) are not retried.
	//
	// Every attempt (not just the final one) is classified into the eviction/
	// weighting window via classifyDialErr — a connection that fails twice and
	// only succeeds on the third try still surfaces those two real failures,
	// instead of the retry silently collapsing them into one clean success.
	resp, err := send(0, nil)
	td.classifyDialErr(err)
	if err != nil {
		var httpErr *controlHTTPError
		if !errors.As(err, &httpErr) {
			for attempt := 1; attempt < 3 && err != nil && !errors.As(err, &httpErr); attempt++ {
				Log.Printf("tunnel: Dial %s attempt %d failed (%v) — retrying", target, attempt, err)
				time.Sleep(300 * time.Millisecond)
				resp, err = send(0, nil)
				td.classifyDialErr(err)
				httpErr = nil // reset for next errors.As check
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target, err)
	}
	if len(resp) > 0 {
		conn.readMu.Lock()
		conn.readBuf = append(conn.readBuf, resp...)
		conn.readMu.Unlock()
	}
	Log.Printf("tunnel: Dial %s established connID=%.8s initial-resp=%dB", target, connID, len(resp))
	conn.seq.Store(1)
	atomic.AddInt32(&td.activeConns, 1)
	conn.onClose = func() { atomic.AddInt32(&td.activeConns, -1) }
	conn.startStreamLoop()
	return conn, nil
}

const (
	dialWinSize       = 30 * time.Second // rolling window duration for eviction decisions
	dialWinMinSamples = 3                // minimum outcome count before evaluating ratio
	dialWinMinSpan    = 10 * time.Second // window must span this long before firing; prevents
	// a burst of failures in the first second from instantly evicting a healthy control
	firstFailRatio = 0.50 // soft tier threshold: flap penalty + pool eviction
	dataFailRatio  = 0.80 // hard tier threshold: data-dead ban
)

func (td *TunnelDialer) recordDialSuccess() { td.recordDialOutcome(true) }
func (td *TunnelDialer) recordDialFailure() { td.recordDialOutcome(false) }

// classifyDialErr records the outcome of one send(0, nil) dial attempt into
// the dialer's rolling eviction/weighting window. Called once per attempt —
// including retries — so a connection that fails once or twice before
// eventually succeeding still surfaces those failures instead of the retry
// masking them as a single clean success.
//
//	HTTP non-404 — control reachable, app-layer error (401, 5xx)      → success
//	HTTP 404     — exit rejected this specific target (blacklist,
//	               expired session, or the exit's own bounded dial
//	               budget expired); the control itself is healthy     → neutral
//	Everything else (timeout, EOF, RST, connection refused, http2
//	               connection lost) — the exit guarantees a real HTTP
//	               response within its own bounded dial-decision
//	               budget (snc-exit/handler.go: dialDecisionBudget),
//	               well under this client's own HTTP timeout, so the
//	               absence of any response can only mean the
//	               control/exit path itself is broken                 → failure
func (td *TunnelDialer) classifyDialErr(err error) {
	if err == nil {
		td.recordDialSuccess()
		return
	}
	var httpErr *controlHTTPError
	switch {
	case errors.As(err, &httpErr) && httpErr.status != http.StatusNotFound:
		td.recordDialSuccess()
	case errors.As(err, &httpErr): // 404 — per-target rejection, neutral
	default:
		td.recordDialFailure()
	}
}

// LastDataTime returns the last time this dialer received a successful POST
// response.  Returns zero if no data has been received yet.
func (td *TunnelDialer) LastDataTime() time.Time {
	ns := atomic.LoadInt64(&td.lastDataAt)
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// OpenConns returns the number of currently open tunnel connections on this dialer.
// Used by the pool to detect when a draining dialer has fully drained.
func (td *TunnelDialer) OpenConns() int {
	return int(atomic.LoadInt32(&td.activeConns))
}

// recordStreamDead escalates a stream loop give-up to the shared outcome window —
// same weight as a Dial failure.
func (td *TunnelDialer) recordStreamDead() { td.recordDialOutcome(false) }

// recordDialOutcome appends a Dial/stream outcome to the rolling window and fires
// eviction hooks when the failure ratio crosses the configured thresholds.
//   - Soft tier (onFirstFail, ≥50%): flap penalty + pool eviction.
//   - Hard tier (onDataFail, ≥80%): data-dead ban + cancel in-flight requests.
//
// Both flags reset automatically when the ratio recovers below their threshold,
// allowing re-triggering if the control degrades again after a recovery.
func (td *TunnelDialer) recordDialOutcome(success bool) {
	if success {
		atomic.StoreInt64(&td.lastDataAt, time.Now().UnixNano())
	}

	td.hookMu.RLock()
	firstFailFn := td.onFirstFail
	dataFailFn := td.onDataFail
	td.hookMu.RUnlock()

	td.dialWinMu.Lock()
	now := time.Now()
	cutoff := now.Add(-dialWinSize)
	j := 0
	for j < len(td.dialWindow) && td.dialWindow[j].at.Before(cutoff) {
		j++
	}
	if j > 0 {
		td.dialWindow = td.dialWindow[j:]
	}
	td.dialWindow = append(td.dialWindow, dialOutcome{at: now, success: success})

	total := len(td.dialWindow)
	fails := 0
	for _, o := range td.dialWindow {
		if !o.success {
			fails++
		}
	}

	var fireFirst, fireData bool
	winSpan := now.Sub(td.dialWindow[0].at)
	if total >= dialWinMinSamples && winSpan >= dialWinMinSpan {
		ratio := float64(fails) / float64(total)
		if ratio >= firstFailRatio {
			if !td.firstWinFired {
				td.firstWinFired = true
				fireFirst = true
			}
		} else {
			td.firstWinFired = false
		}
		if ratio >= dataFailRatio {
			if !td.dataWinFired {
				td.dataWinFired = true
				fireData = true
			}
		} else {
			td.dataWinFired = false
		}
	}
	td.dialWinMu.Unlock()

	if fireFirst {
		Log.Printf("tunnel: %d/%d dial outcomes failed over %.0fs — firing first-fail hook",
			fails, total, winSpan.Seconds())
		if firstFailFn != nil {
			firstFailFn()
		}
	}
	if fireData {
		Log.Printf("tunnel: %d/%d dial outcomes failed over %.0fs — firing data-fail hook",
			fails, total, winSpan.Seconds())
		// No td.cancel() here: eviction (dialerPool.Evict) stops new connections from
		// using this dialer; existing TunnelConns must complete or timeout on their own.
		// Cancelling the dialer context would kill healthy in-flight uploads as collateral.
		if dataFailFn != nil {
			dataFailFn()
		}
	}
}

// FailRatio returns this dialer's current failure ratio over the same rolling
// window recordDialOutcome scores eviction against. Returns 0 (full quality)
// when there isn't yet enough data to judge — dialWinMinSamples/dialWinMinSpan,
// the same guards recordDialOutcome uses before firing eviction — so a fresh or
// quiet dialer is never penalized on too little information. Used by
// DialerPool.Pick to smoothly deprioritize a struggling-but-not-yet-evicted
// control instead of only the binary evict/keep decision the hooks give.
func (td *TunnelDialer) FailRatio() float64 {
	td.dialWinMu.Lock()
	defer td.dialWinMu.Unlock()

	now := time.Now()
	cutoff := now.Add(-dialWinSize)
	j := 0
	for j < len(td.dialWindow) && td.dialWindow[j].at.Before(cutoff) {
		j++
	}
	if j > 0 {
		td.dialWindow = td.dialWindow[j:]
	}

	total := len(td.dialWindow)
	if total < dialWinMinSamples {
		return 0
	}
	if now.Sub(td.dialWindow[0].at) < dialWinMinSpan {
		return 0
	}
	fails := 0
	for _, o := range td.dialWindow {
		if !o.success {
			fails++
		}
	}
	return float64(fails) / float64(total)
}

// isAuthRejection returns true when the login error is a definitive credential
// rejection — wrong password or expired key.  Transient arbiter errors
// ("internal error", network failures) return false; the caller applies the
// longer server-unavailable window (3 h) for those. "invalid key" is
// classified separately -- see isInvalidKeyRejection.
func isAuthRejection(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, `"invalid credentials"`) || strings.Contains(s, `"key expired"`)
}

// isInvalidKeyRejection returns true for "invalid key" specifically --
// today (verified against snc-arbiter/handler.go's handleKeyAuth) this
// string is only ever produced by a live, reachable arbiter that actually
// ran ed25519.Verify on the AuthSig and got a definitive no; no transient/
// deferred/cache-fallback path on the way there can produce it. It used to
// be lumped in with the 3-hour transient window on the theory that it might
// reflect a brief key-issuance race or arbiter hiccup rather than a
// genuinely broken key -- kept as its own, shorter window (see
// invalidKeyWindow) rather than moving it to the 3-minute authRejectWindow
// outright, so that theoretical race still gets a real chance to clear.
// Real-world evidence argues the window should be much shorter than 3h,
// though: one client (2026-08-16) sent 4000+ consecutive "invalid key"
// attempts over more than an hour with zero recoveries -- a broken key
// does not self-heal, and 3h of silent hammering before surfacing any
// error to the user is too long.
func isInvalidKeyRejection(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), `"invalid key"`)
}

// refreshToken re-authenticates if the current token matches badToken.
//
// Retry policy:
//   - Arbiter unavailable / genuinely transient errors (network, "internal
//     error", empty body): retry silently for up to 3 hours. onReAuthWarning
//     fires only when the 3-hour deadline is exhausted, just before the
//     fatal hook.
//   - Definitive credential rejection ("invalid credentials", "key expired"):
//     give up after 3 minutes; onReAuthWarning fires on first such rejection.
//   - "invalid key" (bad AuthSig, isInvalidKeyRejection): give up after 10
//     minutes -- longer than a credential rejection (kept in case this ever
//     reflects a brief key-issuance race rather than a truly broken key),
//     but far short of the 3-hour transient window a broken key was
//     previously given, which just meant hours of silent retries against a
//     key that was never going to start working.
func (td *TunnelDialer) refreshToken(badToken string) error {
	td.reAuthMu.Lock()
	if td.auth.token != badToken {
		td.reAuthMu.Unlock()
		return nil
	}
	tokenPreview := badToken
	if len(tokenPreview) > 8 {
		tokenPreview = tokenPreview[:8]
	}
	Log.Printf("tunnel: token expired (%s…), re-authenticating", tokenPreview)

	const (
		authRejectWindow  = 3 * time.Minute  // definitive credential rejection: give up
		invalidKeyWindow  = 10 * time.Minute // "invalid key" (bad AuthSig): give up -- see isInvalidKeyRejection
		serverErrorWindow = 3 * time.Hour    // arbiter unavailable: wait up to 3 h for recovery
	)
	// authFailThreshold: how many consecutive transient (non-rejection) login
	// failures against this fixed node before onAuthFail fires. >1 so a single
	// blip (e.g. one dropped packet) never evicts a node that's actually fine
	// — see SetAuthFailHook.
	const authFailThreshold = 2
	backoff := 5 * time.Second
	var rejectDeadline time.Time
	serverDeadline := time.Now().Add(serverErrorWindow)
	warned := false
	consecutiveTransient := 0
	authFailFired := false
	for {
		err := td.auth.Login()
		if err == nil {
			Log.Printf("tunnel: re-auth OK, new token=%s…", td.auth.token[:8])
			if warned {
				td.hookMu.RLock()
				recoverHook := td.onReAuthRecovered
				td.hookMu.RUnlock()
				if recoverHook != nil {
					go recoverHook()
				}
			}
			td.reAuthMu.Unlock()
			return nil
		}
		now := time.Now()
		fireWarn := func() {
			if !warned {
				warned = true
				td.hookMu.RLock()
				warnHook := td.onReAuthWarning
				td.hookMu.RUnlock()
				if warnHook != nil {
					go warnHook()
				}
			}
		}
		rejection := isAuthRejection(err)
		invalidKey := !rejection && isInvalidKeyRejection(err)
		if rejection || invalidKey {
			// Not a node-health signal — a wrong password (or bad AuthSig)
			// fails identically on every node — so neither ever counts
			// toward onAuthFail.
			consecutiveTransient = 0
			// Definitive rejection: warn immediately, give up after
			// authRejectWindow (credentials) or the longer invalidKeyWindow
			// (bad AuthSig -- see isInvalidKeyRejection for why it gets its
			// own, longer-than-credentials-but-far-short-of-3h window).
			fireWarn()
			if rejectDeadline.IsZero() {
				window := authRejectWindow
				if invalidKey {
					window = invalidKeyWindow
				}
				rejectDeadline = now.Add(window)
			}
			if now.After(rejectDeadline) {
				ferr := fmt.Errorf("re-auth: %w", err)
				td.hookMu.RLock()
				fatalHook := td.onFatalError
				td.hookMu.RUnlock()
				td.reAuthMu.Unlock()
				if fatalHook != nil {
					go fatalHook(ferr)
				}
				return ferr
			}
		} else {
			consecutiveTransient++
			if !authFailFired && consecutiveTransient >= authFailThreshold {
				authFailFired = true
				td.hookMu.RLock()
				authFailHook := td.onAuthFail
				td.hookMu.RUnlock()
				if authFailHook != nil {
					go authFailHook()
				}
			}
		}
		if !rejection && !invalidKey && now.After(serverDeadline) {
			// 3-hour arbiter window exhausted: warn then give up.
			fireWarn()
			ferr := fmt.Errorf("re-auth: server unavailable: %w", err)
			td.hookMu.RLock()
			fatalHook := td.onFatalError
			td.hookMu.RUnlock()
			td.reAuthMu.Unlock()
			if fatalHook != nil {
				go fatalHook(ferr)
			}
			return ferr
		}
		Log.Printf("tunnel: re-auth failed (%v), retrying in %v", err, backoff)
		// Release the lock during sleep so other goroutines can proceed with the
		// current (expired) token — they will get a 404 and queue here too, but
		// only the first one actually drives the re-auth loop.  On wake, re-check
		// whether a concurrent goroutine already succeeded.
		td.reAuthMu.Unlock()
		time.Sleep(backoff)
		if backoff < 30*time.Second {
			backoff *= 2
		}
		td.reAuthMu.Lock()
		if td.auth.token != badToken {
			// Another goroutine refreshed while we slept.
			td.reAuthMu.Unlock()
			return nil
		}
	}
}

// doPost encrypts plaintext with the current session key and POSTs it.
// Decrypts and returns the response data.  Retries once after re-auth on 401.
// If retryOn404 is true, a 404 also triggers re-auth (used for control-plane
// endpoints where 404 means "session not found"); set false for UDP relay/drain
// where 404 means "endpoint or protocol not supported" and re-auth won't help.
// controlHTTPError is returned by doPost when the control node responded with
// a non-2xx HTTP status.  It proves the control is reachable; the failure is
// at the application layer (e.g. exit could not connect to the tunnel target),
// not a transport-layer control failure.  Callers that update the data-fail
// counter must NOT count this as evidence that the control is dead.
type controlHTTPError struct{ status int }

func (e *controlHTTPError) Error() string { return fmt.Sprintf("control HTTP %d", e.status) }

// streamHTTPError is returned by openStreamPost when the control responds with
// a non-200 status code.  A 404 from the exit means the connection was already
// closed by the remote side — no point retrying, give up immediately.
// closeReason (from the exit's X-Close-Reason header, see snc-exit/handler.go's
// stream-open 404 branch) distinguishes why: "target-closed" is a normal
// completion (the real destination closed on its own after serving the
// request), "not-found" is a genuine rejection (the exit's session watchdog
// evicted it after sessionTimeout with no data ever coming back, or the exit
// never had this connID at all) -- see session.go's giveUp, the only place
// that reads this field, for what counts as a rejected session.
type streamHTTPError struct {
	status      int
	closeReason string
}

func (e *streamHTTPError) Error() string { return fmt.Sprintf("stream HTTP %d", e.status) }

// doPost sends one encrypted tunnel frame. timeout, if non-zero, bounds this
// specific call tighter than td.client's default 30s (used for the seq-0
// connection-establishment probe in Dial — see dialProbeTimeout); zero keeps
// today's behavior (bounded only by td.client.Timeout).
func (td *TunnelDialer) doPost(path string, plaintext []byte, allowRetry bool, retryOn404 bool, timeout time.Duration) ([]byte, error) {
	// Adaptive jitter: measure time since the previous POST and sleep for a
	// proportional random delay.  High load (short IRI) → near-zero jitter.
	// Low load (long IRI) → up to jitterMax delay for traffic camouflage.
	td.lastPostMu.Lock()
	iri := time.Duration(0)
	if !td.lastPostAt.IsZero() {
		iri = time.Since(td.lastPostAt)
	}
	td.lastPostAt = time.Now()
	td.lastPostMu.Unlock()
	if j := td.nextJitter(iri); j > 0 {
		time.Sleep(j)
	}

	td.hookMu.RLock()
	hook := td.onActivity
	td.hookMu.RUnlock()
	if hook != nil {
		hook()
	}
	// Snapshot the token once — body encryption key and X-Session header must
	// use the same token. A concurrent refreshToken call can update td.auth.token
	// between two separate reads, causing key/token mismatch → decrypt fail → 404.
	token := td.auth.token
	key := sessionKey(token)
	body, err := sealFrame(key, plaintext)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}

	if td.udpRelay != nil {
		if td.udpRelay.Failed() {
			// UDP channel has exceeded its error threshold — fire hook once and
			// fall through to TCP for this and all subsequent calls.
			td.hookMu.Lock()
			fn := td.onUDPFailed
			td.onUDPFailed = nil // fire only once
			td.hookMu.Unlock()
			if fn != nil {
				Log.Printf("tunnel: UDP relay failed — falling back to TCP, notifying router")
				go fn()
			}
		} else {
			status, raw, err := td.udpRelay.RoundTrip(path, token, body)
			if err != nil {
				return nil, fmt.Errorf("udp-relay: %w", err)
			}
			shouldRetry := allowRetry && (status == http.StatusUnauthorized || (status == http.StatusNotFound && retryOn404))
			if shouldRetry {
				if rerr := td.refreshToken(token); rerr != nil {
					return nil, rerr
				}
				return td.doPost(path, plaintext, false, retryOn404, timeout)
			}
			if status != http.StatusOK {
				return nil, fmt.Errorf("tunnel POST %s: %w", path, &controlHTTPError{status})
			}
			Log.Printf("tunnel: udp-relay response status=%d body=%dB", status, len(raw))
			return parseResponse(key, raw)
		}
	}

	ctx := td.cancelCtx
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, "POST", td.auth.serverURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Session", token)
	if ip, _ := td.clientIP.Load().(string); ip != "" {
		req.Header.Set("X-Client-IP", ip)
	}
	if cc, _ := td.clientCC.Load().(string); cc != "" {
		req.Header.Set("X-Client-CC", cc)
	}
	for k, v := range td.auth.session.Headers(hostOf(td.auth.serverURL)) {
		if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}

	t0 := time.Now()
	resp, err := td.client.Do(req)
	if err != nil {
		if isTransportFailure(err) {
			td.hookMu.RLock()
			fn := td.onTransportFail
			td.hookMu.RUnlock()
			if fn != nil {
				fn()
			}
		}
		return nil, err
	}
	defer resp.Body.Close()

	shouldRetry := allowRetry && (resp.StatusCode == http.StatusUnauthorized || (resp.StatusCode == http.StatusNotFound && retryOn404))
	if shouldRetry {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		if rerr := td.refreshToken(token); rerr != nil {
			return nil, rerr
		}
		return td.doPost(path, plaintext, false, retryOn404, timeout)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tunnel POST %s: %w", path, &controlHTTPError{resp.StatusCode})
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// Record full round-trip (request sent → response body received) as traffic RTT.
	// Excludes jitter sleep and auth retries so only clean data-plane samples land here.
	td.recordTrafficRTT(time.Since(t0))
	Log.Printf("tunnel: post raw response status=%d body=%dB", resp.StatusCode, len(raw))
	return parseResponse(key, raw)
}

// openStreamPost opens a long-lived streaming POST for connID and returns
// a decrypting reader over the response body.
func (td *TunnelDialer) openStreamPost(ctx context.Context, connID string) (io.ReadCloser, error) {
	path := tunnelPaths[td.rngIntn(len(tunnelPaths))]
	token := td.auth.token
	key := sessionKey(token)
	body, err := sealFrame(key, buildStreamOpenPlain(connID))
	if err != nil {
		return nil, err
	}

	// Derive request context from both the per-stream ctx and the dialer-level
	// cancelCtx so that DataFailHook immediately aborts all streaming reads.
	reqCtx, reqCancel := context.WithCancel(td.cancelCtx)
	go func() {
		defer reqCancel()
		select {
		case <-ctx.Done():
		case <-reqCtx.Done():
		}
	}()
	req, err := http.NewRequestWithContext(reqCtx, "POST", td.auth.serverURL+path, bytes.NewReader(body))
	if err != nil {
		reqCancel()
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Session", token)
	if ip, _ := td.clientIP.Load().(string); ip != "" {
		req.Header.Set("X-Client-IP", ip)
	}
	if cc, _ := td.clientCC.Load().(string); cc != "" {
		req.Header.Set("X-Client-CC", cc)
	}
	for k, v := range td.auth.session.Headers(hostOf(td.auth.serverURL)) {
		if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}

	resp, err := td.streamClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		reason := resp.Header.Get("X-Close-Reason")
		resp.Body.Close()
		return nil, &streamHTTPError{status: resp.StatusCode, closeReason: reason}
	}
	return newFramedDecryptReader(resp.Body, key, connID), nil
}

// parseUploadFrame parses a decrypted upload-frame plaintext (used in tests and relay stubs).
// Plaintext: [1B 0x00][16B conn_id][4B seq_be][2B target_len_be][target][payload]
func parseUploadFrame(plain []byte) (connID string, seq uint32, target string, payload []byte, err error) {
	if len(plain) < 1+16+4+2 {
		return "", 0, "", nil, fmt.Errorf("frame too short")
	}
	if plain[0] != frameTypeUpload {
		return "", 0, "", nil, fmt.Errorf("unexpected type 0x%02x", plain[0])
	}
	connID = hex.EncodeToString(plain[1:17])
	seq = binary.BigEndian.Uint32(plain[17:21])
	tgtLen := int(binary.BigEndian.Uint16(plain[21:23]))
	if tgtLen > len(plain)-23 {
		return "", 0, "", nil, fmt.Errorf("target length overflow")
	}
	target = string(plain[23 : 23+tgtLen])
	payload = plain[23+tgtLen:]
	return
}

// buildUploadResponse encrypts an upload-ACK response (used in tests and relay stubs).
// Plaintext: [4B dlen_be][data][random padding to minPadding].
func buildUploadResponse(key, data []byte) ([]byte, error) {
	dlen := len(data)
	padLen := minPadding
	if dlen > padLen {
		padLen = dlen
	}
	plain := make([]byte, 4+padLen)
	binary.BigEndian.PutUint32(plain[:4], uint32(dlen))
	copy(plain[4:], data)
	if dlen < padLen {
		crand.Read(plain[4+dlen:]) //nolint:errcheck
	}
	return sealFrame(key, plain)
}

func hostOf(serverURL string) string {
	s := strings.TrimPrefix(serverURL, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}
