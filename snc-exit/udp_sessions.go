// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"fmt"
	"net"
	"sync"
	"time"
)

const udpSessionTimeout = 60 * time.Second

type udpSessionKey struct {
	connID string
	dst    string // "ip:port"
}

type udpSession struct {
	conn     *net.UDPConn
	lastSeen time.Time
	username string
	recvCh   chan []byte // inbound datagrams from the remote host
}

// readLoop continuously reads datagrams from conn and feeds them into recvCh.
// Runs as a goroutine for the lifetime of the session.
func (s *udpSession) readLoop() {
	buf := make([]byte, 65536)
	for {
		s.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)) //nolint:errcheck
		n, err := s.conn.Read(buf)
		if err != nil {
			if isUDPTimeout(err) {
				continue
			}
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		select {
		case s.recvCh <- pkt:
		default:
			logDebugf("udp-session: recv buffer full, dropping datagram")
		}
	}
}

// DrainRecv waits up to maxWait for the first datagram then non-blockingly
// drains up to max datagrams from the receive buffer.
func (s *udpSession) DrainRecv(maxWait time.Duration, max int) [][]byte {
	var out [][]byte
	deadline := time.Now().Add(maxWait)
	for len(out) < max {
		if len(out) == 0 {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return out
			}
			select {
			case pkt := <-s.recvCh:
				out = append(out, pkt)
			case <-time.After(remaining):
				return out
			}
		} else {
			select {
			case pkt := <-s.recvCh:
				out = append(out, pkt)
			default:
				return out
			}
		}
	}
	return out
}

type udpSessionPool struct {
	mu   sync.Mutex
	pool map[udpSessionKey]*udpSession
}

func newUDPSessionPool() *udpSessionPool {
	p := &udpSessionPool{pool: make(map[udpSessionKey]*udpSession)}
	go p.watchdog()
	return p
}

func (p *udpSessionPool) getOrCreate(key udpSessionKey, dst *net.UDPAddr, username string) (*udpSession, error) {
	p.mu.Lock()
	if s := p.pool[key]; s != nil {
		s.lastSeen = time.Now()
		p.mu.Unlock()
		return s, nil
	}
	p.mu.Unlock()

	conn, err := net.DialUDP("udp", nil, dst)
	if err != nil {
		return nil, fmt.Errorf("udp dial %s: %w", dst, err)
	}

	s := &udpSession{
		conn:     conn,
		lastSeen: time.Now(),
		username: username,
		recvCh:   make(chan []byte, 256),
	}
	go s.readLoop()

	p.mu.Lock()
	defer p.mu.Unlock()
	if existing := p.pool[key]; existing != nil {
		conn.Close()
		existing.lastSeen = time.Now()
		return existing, nil
	}
	p.pool[key] = s
	return s, nil
}

func (p *udpSessionPool) recordActivity(key udpSessionKey) {
	p.mu.Lock()
	if s := p.pool[key]; s != nil {
		s.lastSeen = time.Now()
	}
	p.mu.Unlock()
}

func (p *udpSessionPool) close(key udpSessionKey) {
	p.mu.Lock()
	s := p.pool[key]
	delete(p.pool, key)
	p.mu.Unlock()
	if s != nil {
		s.conn.Close()
	}
}

func (p *udpSessionPool) watchdog() {
	for {
		time.Sleep(15 * time.Second)
		now := time.Now()
		p.mu.Lock()
		var stale []udpSessionKey
		for k, s := range p.pool {
			if now.Sub(s.lastSeen) > udpSessionTimeout {
				stale = append(stale, k)
			}
		}
		for _, k := range stale {
			p.pool[k].conn.Close()
			delete(p.pool, k)
			logInfof("udp-session: evicted idle conn=%.8s dst=%s", k.connID, k.dst)
		}
		p.mu.Unlock()
	}
}

func isUDPTimeout(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}
