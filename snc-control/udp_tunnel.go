// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

// udpTunnelHandler receives SNCU frames from clients over UDP and forwards
// them to the pinned exit node via UDP (exit's udpExitHandler on port 443).
// The exit processes each frame and returns an SNCU response; the control
// relays it back to the original client.
//
// Wire format (must match win-client/core/udp_relay.go and snc-exit/udp_tunnel.go):
//
//	Request:  [4B magic SNCU][4B req_id][1B=0x01][2B path_len][path][2B token_len][token][4B body_len][body]
//	Response: [4B magic SNCU][4B req_id][1B=0x02][2B status][4B body_len][body]
//
// Clients use TCP first; UDP is a fallback when TCP is blocked (e.g. by ТСПУ).
// Request routing:
//   - /p/v1/ping  → answered directly (no exit needed)
//   - /p/v1/*     → forwarded to the control's own relay API handler (local call)
//   - everything else → relayed to a pinned exit node via UDP
//
// Per-client exit pinning: each UDP source address is bound to a specific exit
// for udpSessionTTL so that session-stateful exit handlers see consistent traffic.
// If the exit fails, the session is evicted and the next request picks a new exit.
//
// One exitForwarder (connected UDP socket + pending-map + read loop) is maintained
// per live exit address and shared across all client sessions for that exit.

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	udpTunnelMagic        = uint32(0x534E4355) // 'SNCU'
	udpTunnelTypeRequest  = byte(0x01)
	udpTunnelTypeResponse = byte(0x02)
	udpSessionTTL         = 60 * time.Second
	udpSessionGCInterval  = 30 * time.Second
	udpTunnelMaxFrame     = 65536
	udpExitRoundTripTO    = 800 * time.Millisecond // total timeout per exit round-trip (≥ udpExitReadTimeout + 2×RTT)
	udpExitMaxRetries     = 2
)

// ── exitForwarder — one per live exit address ─────────────────────────────────

type exitResp struct {
	status int
	body   []byte
}

type exitForwarder struct {
	conn *net.UDPConn // connected UDP socket to exit:443

	mu      sync.Mutex
	pending map[uint32]chan exitResp
	rng     *rand.Rand

	once   sync.Once
	stopCh chan struct{}
}

func newExitForwarder(exitAddr string) (*exitForwarder, error) {
	if _, _, err := net.SplitHostPort(exitAddr); err != nil {
		exitAddr = exitAddr + ":443"
	}
	c, err := net.Dial("udp", exitAddr)
	if err != nil {
		return nil, err
	}
	f := &exitForwarder{
		conn:    c.(*net.UDPConn),
		pending: make(map[uint32]chan exitResp),
		rng:     rand.New(rand.NewSource(time.Now().UnixNano())), //nolint:gosec
		stopCh:  make(chan struct{}),
	}
	go f.readLoop()
	return f, nil
}

func (f *exitForwarder) readLoop() {
	buf := make([]byte, udpTunnelMaxFrame)
	for {
		f.conn.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
		n, err := f.conn.Read(buf)
		select {
		case <-f.stopCh:
			return
		default:
		}
		if err != nil {
			continue
		}
		data := buf[:n]
		if len(data) < 15 || binary.BigEndian.Uint32(data) != udpTunnelMagic {
			continue
		}
		if data[8] != udpTunnelTypeResponse {
			continue
		}
		reqID := binary.BigEndian.Uint32(data[4:])
		status := int(binary.BigEndian.Uint16(data[9:]))
		bLen := int(binary.BigEndian.Uint32(data[11:]))
		if 15+bLen > len(data) {
			continue
		}
		body := make([]byte, bLen)
		copy(body, data[15:15+bLen])

		f.mu.Lock()
		ch := f.pending[reqID]
		f.mu.Unlock()
		if ch != nil {
			select {
			case ch <- exitResp{status, body}:
			default:
			}
		}
	}
}

// roundTrip forwards one SNCU frame to the exit and waits for the response.
// Retries up to udpExitMaxRetries on timeout.
func (f *exitForwarder) roundTrip(path, token string, body []byte) (int, []byte, error) {
	f.mu.Lock()
	var reqID uint32
	for {
		reqID = f.rng.Uint32()
		if _, exists := f.pending[reqID]; !exists {
			break
		}
	}
	ch := make(chan exitResp, 1)
	f.pending[reqID] = ch
	f.mu.Unlock()

	defer func() {
		f.mu.Lock()
		delete(f.pending, reqID)
		f.mu.Unlock()
	}()

	frame := udpTunnelEncodeRequest(reqID, path, token, body)
	for attempt := 0; attempt <= udpExitMaxRetries; attempt++ {
		if _, err := f.conn.Write(frame); err != nil {
			return 0, nil, err
		}
		select {
		case resp := <-ch:
			return resp.status, resp.body, nil
		case <-time.After(udpExitRoundTripTO):
			logDebugf("udp-tunnel: exit timeout attempt=%d/%d reqID=%d", attempt+1, udpExitMaxRetries+1, reqID)
		case <-f.stopCh:
			return 0, nil, net.ErrClosed
		}
	}
	return 0, nil, &net.OpError{Op: "udp-exit", Err: &timeoutError{}}
}

func (f *exitForwarder) close() {
	f.once.Do(func() {
		close(f.stopCh)
		f.conn.Close()
	})
}

type timeoutError struct{}

func (e *timeoutError) Error() string   { return "udp-exit: retries exhausted" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

// ── per-client session ────────────────────────────────────────────────────────

type udpClientSession struct {
	exitAddr string
	lastSeen time.Time
}

// ── main handler ──────────────────────────────────────────────────────────────

type udpTunnelHandler struct {
	conn     *net.UDPConn
	exits    *ExitRegistry
	relayAPI http.Handler // control-local handler for /p/v1/* requests

	mu       sync.Mutex
	sessions map[string]*udpClientSession // key: src.String()

	exitsMu      sync.Mutex
	exitForwarders map[string]*exitForwarder // key: exit addr
}

func newUDPTunnelHandler(conn *net.UDPConn, exits *ExitRegistry, relayAPI http.Handler) *udpTunnelHandler {
	return &udpTunnelHandler{
		conn:           conn,
		exits:          exits,
		relayAPI:       relayAPI,
		sessions:       make(map[string]*udpClientSession),
		exitForwarders: make(map[string]*exitForwarder),
	}
}

// udpResponseRecorder captures the HTTP response from a local handler call.
type udpResponseRecorder struct {
	code    int
	headers http.Header
	body    bytes.Buffer
}

func newUDPResponseRecorder() *udpResponseRecorder {
	return &udpResponseRecorder{code: 200, headers: make(http.Header)}
}

func (r *udpResponseRecorder) Header() http.Header        { return r.headers }
func (r *udpResponseRecorder) WriteHeader(c int)          { r.code = c }
func (r *udpResponseRecorder) Write(b []byte) (int, error) { return r.body.Write(b) }

// handle processes a single SNCU datagram from src.
func (h *udpTunnelHandler) handle(src *net.UDPAddr, data []byte) {
	if len(data) < 9 {
		return
	}
	reqID := binary.BigEndian.Uint32(data[4:8])
	if data[8] != udpTunnelTypeRequest {
		return
	}
	path, token, body, ok := udpTunnelDecodeRequest(data)
	if !ok {
		logDebugf("udp-tunnel: malformed frame from %s", src)
		return
	}
	logDebugf("udp-tunnel: req from %s reqID=%d path=%s", src, reqID, path)

	if path == "/p/v1/ping" {
		h.handlePing(src, reqID)
		return
	}
	if strings.HasPrefix(path, "/p/v1/") && h.relayAPI != nil {
		go h.handleRelayAPI(src, reqID, path, token, body)
		return
	}
	go h.forward(src, reqID, path, token, body)
}

// handleRelayAPI dispatches a /p/v1/* SNCU request to the control's own relay
// API handler without going through an exit.
func (h *udpTunnelHandler) handleRelayAPI(src *net.UDPAddr, reqID uint32, path, token string, body []byte) {
	method := http.MethodGet
	if len(body) > 0 {
		method = http.MethodPost
	}
	u, err := url.ParseRequestURI(path)
	if err != nil {
		h.sendResponse(src, reqID, 400, nil)
		return
	}
	req := &http.Request{
		Method:     method,
		URL:        u,
		Header:     make(http.Header),
		RemoteAddr: src.String(),
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
	if token != "" {
		req.Header.Set("X-Session", token)
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	rec := newUDPResponseRecorder()
	h.relayAPI.ServeHTTP(rec, req)
	h.sendResponse(src, reqID, rec.code, rec.body.Bytes())
}

func (h *udpTunnelHandler) handlePing(src *net.UDPAddr, reqID uint32) {
	if h.exits != nil && h.exits.anyAlive() {
		h.sendResponse(src, reqID, 200, []byte(`{"ok":true}`))
	} else {
		// No alive exits — return 503 so clients treat this control as unreachable.
		// Mirrors the TCP ping handler which returns an empty body for the same condition.
		h.sendResponse(src, reqID, 503, nil)
	}
}

func (h *udpTunnelHandler) forward(src *net.UDPAddr, reqID uint32, path, token string, body []byte) {
	exitAddr := h.pinExit(src.String())
	if exitAddr == "" {
		h.sendResponse(src, reqID, 503, nil)
		return
	}
	fwd, err := h.getOrCreateForwarder(exitAddr)
	if err != nil {
		logWarnf("udp-tunnel: forwarder for %s: %v", exitAddr, err)
		h.evictSession(src.String())
		h.sendResponse(src, reqID, 503, nil)
		return
	}
	status, respBody, err := fwd.roundTrip(path, token, body)
	if err != nil {
		logWarnf("udp-tunnel: forward %s→%s path=%s: %v", src, exitAddr, path, err)
		h.evictSession(src.String())
		h.sendResponse(src, reqID, 503, nil)
		return
	}
	h.sendResponse(src, reqID, status, respBody)
}

func (h *udpTunnelHandler) pinExit(srcKey string) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if sess, ok := h.sessions[srcKey]; ok && time.Since(sess.lastSeen) < udpSessionTTL {
		sess.lastSeen = time.Now()
		return sess.exitAddr
	}
	delete(h.sessions, srcKey)
	exit, err := h.exits.PickFor("")
	if err != nil {
		return ""
	}
	h.sessions[srcKey] = &udpClientSession{exitAddr: exit.Addr, lastSeen: time.Now()}
	return exit.Addr
}

func (h *udpTunnelHandler) evictSession(srcKey string) {
	h.mu.Lock()
	delete(h.sessions, srcKey)
	h.mu.Unlock()
}

func (h *udpTunnelHandler) getOrCreateForwarder(exitAddr string) (*exitForwarder, error) {
	h.exitsMu.Lock()
	defer h.exitsMu.Unlock()
	if f, ok := h.exitForwarders[exitAddr]; ok {
		return f, nil
	}
	f, err := newExitForwarder(exitAddr)
	if err != nil {
		return nil, err
	}
	h.exitForwarders[exitAddr] = f
	return f, nil
}

func (h *udpTunnelHandler) sendResponse(dst *net.UDPAddr, reqID uint32, status int, body []byte) {
	frame := udpTunnelEncodeResponse(reqID, status, body)
	if _, err := h.conn.WriteToUDP(frame, dst); err != nil {
		logDebugf("udp-tunnel: write response to %s: %v", dst, err)
	}
}

// gc evicts sessions idle longer than udpSessionTTL. Run in a goroutine.
func (h *udpTunnelHandler) gc() {
	ticker := time.NewTicker(udpSessionGCInterval)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		h.mu.Lock()
		for k, sess := range h.sessions {
			if now.Sub(sess.lastSeen) > udpSessionTTL {
				delete(h.sessions, k)
			}
		}
		h.mu.Unlock()
	}
}

// ── Frame codec (wire format shared with win-client/core/udp_relay.go) ────────

func udpTunnelDecodeRequest(data []byte) (path, token string, body []byte, ok bool) {
	if len(data) < 9+2+2+4 {
		return
	}
	o := 9
	pLen := int(binary.BigEndian.Uint16(data[o:]))
	o += 2
	if o+pLen+2 > len(data) {
		return
	}
	path = string(data[o : o+pLen])
	o += pLen
	tLen := int(binary.BigEndian.Uint16(data[o:]))
	o += 2
	if o+tLen+4 > len(data) {
		return
	}
	token = string(data[o : o+tLen])
	o += tLen
	bLen := int(binary.BigEndian.Uint32(data[o:]))
	o += 4
	if o+bLen > len(data) {
		return
	}
	body = data[o : o+bLen]
	ok = true
	return
}

func udpTunnelEncodeResponse(reqID uint32, status int, body []byte) []byte {
	buf := make([]byte, 4+4+1+2+4+len(body))
	o := 0
	binary.BigEndian.PutUint32(buf[o:], udpTunnelMagic)
	o += 4
	binary.BigEndian.PutUint32(buf[o:], reqID)
	o += 4
	buf[o] = udpTunnelTypeResponse
	o++
	binary.BigEndian.PutUint16(buf[o:], uint16(status))
	o += 2
	binary.BigEndian.PutUint32(buf[o:], uint32(len(body)))
	o += 4
	copy(buf[o:], body)
	return buf
}

func udpTunnelEncodeRequest(reqID uint32, path, token string, body []byte) []byte {
	pb, tb := []byte(path), []byte(token)
	buf := make([]byte, 4+4+1+2+len(pb)+2+len(tb)+4+len(body))
	o := 0
	binary.BigEndian.PutUint32(buf[o:], udpTunnelMagic)
	o += 4
	binary.BigEndian.PutUint32(buf[o:], reqID)
	o += 4
	buf[o] = udpTunnelTypeRequest
	o++
	binary.BigEndian.PutUint16(buf[o:], uint16(len(pb)))
	o += 2
	o += copy(buf[o:], pb)
	binary.BigEndian.PutUint16(buf[o:], uint16(len(tb)))
	o += 2
	o += copy(buf[o:], tb)
	binary.BigEndian.PutUint32(buf[o:], uint32(len(body)))
	o += 4
	copy(buf[o:], body)
	return buf
}
