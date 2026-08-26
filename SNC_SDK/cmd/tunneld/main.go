// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

// Command tunneld is the subprocess every non-iOS SDK adapter drives: a
// small daemon that wraps tunnelcat-server's Authenticator/TunnelDialer/
// SOCKS5Server behind a duplex, newline-delimited JSON-RPC protocol on a
// local Unix domain socket (also supported natively by net.Listen("unix",
// ...) on Windows 10 1803+, so no separate named-pipe implementation is
// needed). See docs/IPC.md for the wire contract.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	core "tunnel_cat/snc/core"
)

type request struct {
	ID     int             `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

type response struct {
	ID     int    `json:"id"`
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

type event struct {
	Event string `json:"event"`
	State string `json:"state,omitempty"`
	Error string `json:"error,omitempty"`
}

type connectParams struct {
	Server    string `json:"server"`
	APIKey    string `json:"apikey"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	SocksAddr string `json:"socksAddr"`
	// PollingOnly selects TunnelDialer's legacy upload/ACK-polling mode
	// instead of the default streaming mode. Real control/exit servers
	// support streaming; cmd/mockserver (and tunnelcat-server's own test
	// stub server) only implement polling, so set this to true when
	// connecting through the mock.
	PollingOnly bool `json:"pollingOnly"`
}

type statusResult struct {
	Connected bool   `json:"connected"`
	SocksAddr string `json:"socksAddr,omitempty"`
	UptimeSec int64  `json:"uptimeSec,omitempty"`
	State     string `json:"state"`
}

// daemon holds the single active tunnel session (tunneld serves one session
// per process, matching how every adapter spawns its own instance).
type daemon struct {
	mu sync.Mutex

	auth      *core.Authenticator
	dialer    *core.TunnelDialer
	socks     *core.SOCKS5Server
	ln        net.Listener
	socksAddr string
	connected bool
	startedAt time.Time
	lastState string

	subscribers   map[chan []byte]struct{}
	subscribersMu sync.Mutex
}

func newDaemon() *daemon {
	return &daemon{subscribers: make(map[chan []byte]struct{})}
}

func (d *daemon) broadcast(ev event) {
	b, _ := json.Marshal(ev)
	b = append(b, '\n')
	d.subscribersMu.Lock()
	defer d.subscribersMu.Unlock()
	for ch := range d.subscribers {
		select {
		case ch <- b:
		default: // slow subscriber; drop rather than block the daemon
		}
	}
}

func (d *daemon) setState(state, errMsg string) {
	d.mu.Lock()
	d.lastState = state
	d.mu.Unlock()
	d.broadcast(event{Event: "state", State: state, Error: errMsg})
}

func (d *daemon) handleConnect(p connectParams) (any, error) {
	d.mu.Lock()
	if d.connected {
		d.mu.Unlock()
		return nil, fmt.Errorf("already connected; call disconnect first")
	}
	d.mu.Unlock()

	d.setState("connecting", "")

	auth := core.NewAuthenticator(p.Server, p.APIKey, p.Username, p.Password)
	if err := auth.Login(); err != nil {
		d.setState("error", err.Error())
		return nil, fmt.Errorf("login: %w", err)
	}

	var dialer *core.TunnelDialer
	if p.PollingOnly {
		dialer = core.NewTunnelDialerPolling(auth)
	} else {
		dialer = core.NewTunnelDialer(auth)
	}
	socksAddr := p.SocksAddr
	if socksAddr == "" {
		socksAddr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", socksAddr)
	if err != nil {
		d.setState("error", err.Error())
		return nil, fmt.Errorf("listen %s: %w", socksAddr, err)
	}
	socks := core.NewSOCKS5Server("", dialer)
	go func() {
		if err := socks.Serve(ln); err != nil {
			log.Printf("socks5 serve: %v", err)
		}
	}()

	d.mu.Lock()
	d.auth = auth
	d.dialer = dialer
	d.socks = socks
	d.ln = ln
	d.socksAddr = ln.Addr().String()
	d.connected = true
	d.startedAt = time.Now()
	d.mu.Unlock()

	d.setState("connected", "")
	return statusResult{Connected: true, SocksAddr: ln.Addr().String(), State: "connected"}, nil
}

func (d *daemon) handleDisconnect() (any, error) {
	d.mu.Lock()
	if !d.connected {
		d.mu.Unlock()
		return map[string]bool{"ok": true}, nil
	}
	if d.socks != nil {
		d.socks.Close()
	}
	if d.ln != nil {
		d.ln.Close()
	}
	d.connected = false
	d.auth, d.dialer, d.socks, d.ln, d.socksAddr = nil, nil, nil, nil, ""
	d.mu.Unlock()

	// setState locks d.mu itself; must be called after unlocking above,
	// same pattern as handleConnect/handleReconnect (sync.Mutex isn't
	// reentrant — calling it while still holding the lock deadlocks).
	d.setState("disconnected", "")
	return map[string]bool{"ok": true}, nil
}

func (d *daemon) handleStatus() (any, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	r := statusResult{Connected: d.connected, SocksAddr: d.socksAddr, State: d.lastState}
	if d.connected {
		r.UptimeSec = int64(time.Since(d.startedAt).Seconds())
	}
	if r.State == "" {
		r.State = "idle"
	}
	return r, nil
}

func (d *daemon) handleReconnect() (any, error) {
	d.mu.Lock()
	auth := d.auth
	d.mu.Unlock()
	if auth == nil {
		return nil, fmt.Errorf("not connected")
	}
	d.setState("connecting", "")
	if err := auth.Login(); err != nil {
		d.setState("error", err.Error())
		return nil, fmt.Errorf("login: %w", err)
	}
	d.setState("connected", "")
	return map[string]bool{"ok": true}, nil
}

func (d *daemon) dispatch(req request) (any, error) {
	switch req.Method {
	case "connect":
		var p connectParams
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &p); err != nil {
				return nil, fmt.Errorf("bad params: %w", err)
			}
		}
		return d.handleConnect(p)
	case "disconnect":
		return d.handleDisconnect()
	case "status":
		return d.handleStatus()
	case "reconnect":
		return d.handleReconnect()
	default:
		return nil, fmt.Errorf("unknown method %q", req.Method)
	}
}

func (d *daemon) handleConn(c net.Conn) {
	defer c.Close()

	events := make(chan []byte, 16)
	d.subscribersMu.Lock()
	d.subscribers[events] = struct{}{}
	d.subscribersMu.Unlock()
	defer func() {
		d.subscribersMu.Lock()
		delete(d.subscribers, events)
		d.subscribersMu.Unlock()
	}()

	writes := make(chan []byte, 16)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case b, ok := <-writes:
				if !ok {
					return
				}
				if _, err := c.Write(b); err != nil {
					return
				}
			case b := <-events:
				if _, err := c.Write(b); err != nil {
					return
				}
			}
		}
	}()

	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var req request
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			b, _ := json.Marshal(response{Error: fmt.Sprintf("bad request: %v", err)})
			writes <- append(b, '\n')
			continue
		}
		result, err := d.dispatch(req)
		resp := response{ID: req.ID}
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.Result = result
		}
		b, _ := json.Marshal(resp)
		select {
		case writes <- append(b, '\n'):
		case <-done:
			return
		}
	}
	close(writes)
	<-done
}

func main() {
	socketPath := flag.String("socket", "", "path to the Unix domain socket to listen on (required)")
	flag.Parse()

	if *socketPath == "" {
		fmt.Fprintln(os.Stderr, "tunneld: -socket is required")
		os.Exit(2)
	}
	os.Remove(*socketPath) //nolint:errcheck // stale socket from a prior crash

	ln, err := net.Listen("unix", *socketPath)
	if err != nil {
		log.Fatalf("listen %s: %v", *socketPath, err)
	}
	defer ln.Close()

	d := newDaemon()
	log.Printf("tunneld listening on %s", *socketPath)

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatalf("accept: %v", err)
		}
		go d.handleConn(c)
	}
}
