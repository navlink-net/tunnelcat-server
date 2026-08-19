// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

// Command mockserver is a local mock control/exit for testing SDK adapters
// (and cmd/tunneld) with zero real credentials and zero network access.
//
// It implements just enough of tunnelcat-core's wire protocol to satisfy
// Authenticator.Login() (accepts any username/password/apiKey — this is a
// mock, not an auth system) and one round of data-plane traffic, relaying
// decrypted upload frames to the actual TCP target the client asked for.
// The relay logic mirrors tunnelcat-core's own tunnel_test.go stub server,
// built on the exported SessionKey/SealFrame/OpenFrame/ParseUploadFrame/
// BuildUploadResponse helpers instead of reimplementing the framing.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	core "github.com/kostiakhait/tunnelcat-core"
)

type loginRequest struct {
	Command string `json:".command"`
}

func randomToken() string {
	b := make([]byte, 16)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}

type mockServer struct {
	mu     sync.Mutex
	tokens map[string]bool
	pool   map[string]net.Conn
	poolMu sync.Mutex
}

func newMockServer() *mockServer {
	return &mockServer{
		tokens: make(map[string]bool),
		pool:   make(map[string]net.Conn),
	}
}

func (m *mockServer) issueToken() string {
	tok := randomToken()
	m.mu.Lock()
	m.tokens[tok] = true
	m.mu.Unlock()
	return tok
}

func (m *mockServer) validToken(tok string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tokens[tok]
}

// handleLogin answers both verifyPassword and authenticateKey commands the
// same way: issue a fresh session token for any credentials. This is a
// mock — it does no real authentication.
func (m *mockServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var req loginRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	switch req.Command {
	case "verifyPassword", "authenticateKey":
		tok := m.issueToken()
		log.Printf("mockserver: issued session for %s", req.Command)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"session": tok}) //nolint:errcheck
	default:
		http.Error(w, "unknown command", http.StatusBadRequest)
	}
}

// handleData handles the decoy upload endpoints, decrypting the frame,
// relaying to the requested TCP target, and encrypting the ACK response.
// Mirrors tunnelcat-core's tunnel_test.go newStubServer.
func (m *mockServer) handleData(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Session")
	if !m.validToken(token) {
		http.NotFound(w, r)
		return
	}
	key := core.SessionKey(token)

	body, _ := io.ReadAll(r.Body)
	plain, err := core.OpenFrame(key, body)
	if err != nil || len(plain) < 1 {
		http.NotFound(w, r)
		return
	}

	if plain[0] != core.FrameTypeUpload {
		http.NotFound(w, r) // stream-open frames not supported by this mock
		return
	}

	connID, seq, target, payload, err := core.ParseUploadFrame(plain)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	m.poolMu.Lock()
	conn := m.pool[connID]
	m.poolMu.Unlock()

	if seq == 0 {
		conn, err = net.DialTimeout("tcp", target, 2*time.Second)
		if err != nil {
			log.Printf("mockserver: dial %s: %v", target, err)
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		m.poolMu.Lock()
		m.pool[connID] = conn
		m.poolMu.Unlock()
	} else if conn == nil {
		http.NotFound(w, r)
		return
	}

	if len(payload) > 0 {
		conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond)) //nolint:errcheck
		conn.Write(payload)                                           //nolint:errcheck
	}

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

	resp, err := core.BuildUploadResponse(key, response)
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(resp) //nolint:errcheck
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8443", "address to listen on")
	flag.Parse()

	m := newMockServer()
	mux := http.NewServeMux()
	mux.HandleFunc("/", m.handleLogin)
	mux.HandleFunc("/api/media/upload", m.handleData)
	mux.HandleFunc("/api/content/submit", m.handleData)

	log.Printf("mockserver listening on http://%s (no TLS — for local testing only)", *addr)
	if err := http.ListenAndServe(*addr, mux); err != nil { //nolint:gosec
		log.Fatal(err)
	}
}
