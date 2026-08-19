// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

const sessionTimeout = 30 * time.Second

// reorderBufMax is the maximum number of out-of-order frames held per
// connection.  Must be >= tunnelPipelineWidth (currently 8) on the client.
const reorderBufMax = 32

type session struct {
	conn     net.Conn
	lastSeen time.Time
	username string
	bytesUp  int64
	country  string

	// targetClosed is set when the target TCP connection sent EOF/RST while
	// streaming to the client.  Subsequent stream-open requests for this
	// connID return 404 so the client closes the tunnel conn gracefully
	// instead of entering an endless flap loop.
	//
	// 2026-08-17: a transparent redial (swap in a fresh dial to the same
	// target and keep the connID alive) was tried and reverted -- the exit
	// has no visibility into what's layered on top of this raw byte relay
	// (TLS session state, HTTP keep-alive framing, etc.), so silently
	// swapping the backing socket for a connID the client believes is still
	// one continuous stream can hand the client's still-in-progress TLS
	// session to a destination socket that never did a handshake, which the
	// destination resets immediately -- indistinguishable from the original
	// symptom this was meant to fix, or worse. Safe recovery requires the
	// client itself to know the connection died and reconnect from scratch
	// (new connID, new TLS handshake), which is exactly what a clean 404 +
	// giveUp already gives it.
	targetClosed bool

	// reorderMu serialises writes to conn and protects the reorder buffer.
	// Frames may arrive out of order when the client uses pipeline sends.
	reorderMu   sync.Mutex
	reorderBuf  map[uint32][]byte // seq → payload for buffered out-of-order frames
	reorderNext uint32            // next seq expected; starts at 1 (seq 0 = connect)
}

type sessionPool struct {
	mu   sync.Mutex
	pool map[string]*session
}

func newSessionPool() *sessionPool {
	p := &sessionPool{pool: make(map[string]*session)}
	go p.watchdog()
	return p
}

// getOrCreate returns the existing connection for connID, or dials a new one.
func (p *sessionPool) getOrCreate(connID, host string, port int, username string) (net.Conn, error) {
	p.mu.Lock()
	if s := p.pool[connID]; s != nil {
		s.lastSeen = time.Now()
		p.mu.Unlock()
		return s.conn, nil
	}
	p.mu.Unlock()

	// Dial outside the lock — may block up to 10 s.
	// net.JoinHostPort correctly brackets IPv6 literals: [::1]:80
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	// Double-check: another goroutine may have dialled while we were blocked.
	if s := p.pool[connID]; s != nil {
		conn.Close()
		s.lastSeen = time.Now()
		return s.conn, nil
	}
	p.pool[connID] = &session{
		conn:        conn,
		lastSeen:    time.Now(),
		username:    username,
		reorderBuf:  make(map[uint32][]byte),
		reorderNext: 1,
	}
	return conn, nil
}

// store registers a pre-established connection under connID.
// Used when the connection was opened outside the pool (e.g. a peer-exit forward).
func (p *sessionPool) store(connID string, conn net.Conn, username string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if old := p.pool[connID]; old != nil {
		old.conn.Close()
	}
	p.pool[connID] = &session{
		conn:        conn,
		lastSeen:    time.Now(),
		username:    username,
		reorderBuf:  make(map[uint32][]byte),
		reorderNext: 1,
	}
}

// get returns the connection for connID and bumps last_seen, or nil.
// Returns nil if the session does not exist or the target already closed.
func (p *sessionPool) get(connID string) net.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.pool[connID]
	if s == nil || s.targetClosed {
		return nil
	}
	s.lastSeen = time.Now()
	return s.conn
}

// closeReason explains a nil get(), for callers that need to tell a
// genuine rejection (session evicted by the watchdog -- see sessionTimeout
// -- or never existed at all) apart from a normal completion (the real
// target closed the connection on its own, markTargetClosed) before they
// reply to the client. Empty string means the session is actually live
// (get() would not have returned nil).
func (p *sessionPool) closeReason(connID string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.pool[connID]
	if s == nil {
		return "not-found"
	}
	if s.targetClosed {
		return "target-closed"
	}
	return ""
}

// markTargetClosed flags the session so future stream-open requests return
// 404.  Called when streamToClient exits due to a real target error (not
// the idle deadline), preventing endless stream flap loops.
func (p *sessionPool) markTargetClosed(connID string) {
	p.mu.Lock()
	if s := p.pool[connID]; s != nil {
		s.targetClosed = true
	}
	p.mu.Unlock()
}

func (p *sessionPool) recordActivity(connID string) {
	p.mu.Lock()
	if s := p.pool[connID]; s != nil {
		s.lastSeen = time.Now()
	}
	p.mu.Unlock()
}

func (p *sessionPool) close(connID string) {
	p.mu.Lock()
	s := p.pool[connID]
	delete(p.pool, connID)
	p.mu.Unlock()
	if s != nil {
		s.conn.Close()
	}
}

// addBytesUp increments the upload byte counter for a connection.
func (p *sessionPool) addBytesUp(connID string, n int64) {
	p.mu.Lock()
	if s := p.pool[connID]; s != nil {
		s.bytesUp += n
	}
	p.mu.Unlock()
}

// setCountry sets the client country code for a connection.
func (p *sessionPool) setCountry(connID, cc string) {
	p.mu.Lock()
	if s := p.pool[connID]; s != nil {
		s.country = cc
	}
	p.mu.Unlock()
}

// getSession returns the session for connID (bumping lastSeen), or nil.
// Unlike get, it returns the full session so the caller can use deliverInOrder.
func (p *sessionPool) getSession(connID string) *session {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.pool[connID]
	if s == nil {
		return nil
	}
	s.lastSeen = time.Now()
	return s
}

// deliverInOrder writes payload at seq to s.conn in sequence order.
// Frames that arrive out of order are buffered until their turn comes.
// Returns an error if the write to conn fails or the buffer is full.
func (s *session) deliverInOrder(seq uint32, payload []byte) error {
	s.reorderMu.Lock()
	defer s.reorderMu.Unlock()

	if seq < s.reorderNext {
		return nil // duplicate frame, already delivered
	}
	if seq > s.reorderNext {
		if len(s.reorderBuf) >= reorderBufMax {
			return fmt.Errorf("reorder buffer full (next=%d arrived=%d)", s.reorderNext, seq)
		}
		buf := make([]byte, len(payload))
		copy(buf, payload)
		s.reorderBuf[seq] = buf
		return nil
	}

	// seq == reorderNext: deliver this frame then drain any now-in-order buffered frames.
	if len(payload) > 0 {
		if _, err := s.conn.Write(payload); err != nil {
			return err
		}
	}
	s.reorderNext++
	for {
		next, ok := s.reorderBuf[s.reorderNext]
		if !ok {
			break
		}
		delete(s.reorderBuf, s.reorderNext)
		if len(next) > 0 {
			if _, err := s.conn.Write(next); err != nil {
				return err
			}
		}
		s.reorderNext++
	}
	return nil
}

// snapshot returns the session metadata needed for stats reporting.
func (p *sessionPool) snapshot(connID string) (username, country string, bytesUp int64, ok bool) {
	p.mu.Lock()
	s := p.pool[connID]
	p.mu.Unlock()
	if s == nil {
		return "", "", 0, false
	}
	return s.username, s.country, s.bytesUp, true
}

func (p *sessionPool) watchdog() {
	for {
		time.Sleep(10 * time.Second)
		now := time.Now()
		p.mu.Lock()
		var stale []string
		for id, s := range p.pool {
			if now.Sub(s.lastSeen) > sessionTimeout {
				stale = append(stale, id)
			}
		}
		for _, id := range stale {
			p.pool[id].conn.Close()
			delete(p.pool, id)
			logInfof("session: evicted idle conn=%.8s", id)
		}
		p.mu.Unlock()
	}
}
