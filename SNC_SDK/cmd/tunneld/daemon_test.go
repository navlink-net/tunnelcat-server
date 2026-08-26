// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	core "tunnel_cat/snc/core"
)

// newTestMockServer is a minimal inline mirror of cmd/mockserver's login
// handling — just enough for daemon.handleConnect's Login() to succeed.
// Data-plane relaying isn't needed here since these tests only exercise
// connect/status/disconnect/reconnect, not actual SOCKS5 traffic.
func newTestMockServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Command string `json:".command"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		switch req.Command {
		case "verifyPassword", "authenticateKey":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"session": "test-token"}) //nolint:errcheck
		default:
			http.Error(w, "unknown command", http.StatusBadRequest)
		}
	}))
}

// dispatchWithTimeout guards against the kind of self-deadlock this test
// suite exists to catch (see handleDisconnect's history: calling setState
// while still holding d.mu deadlocked every disconnect call).
func dispatchWithTimeout(t *testing.T, d *daemon, req request) (any, error) {
	t.Helper()
	type out struct {
		result any
		err    error
	}
	ch := make(chan out, 1)
	go func() {
		result, err := d.dispatch(req)
		ch <- out{result, err}
	}()
	select {
	case o := <-ch:
		return o.result, o.err
	case <-time.After(5 * time.Second):
		t.Fatalf("dispatch(%q) did not return within 5s (deadlock?)", req.Method)
		return nil, nil
	}
}

func TestConnectStatusDisconnect(t *testing.T) {
	srv := newTestMockServer(t)
	defer srv.Close()

	d := newDaemon()

	connectParamsJSON, _ := json.Marshal(connectParams{
		Server:      srv.URL,
		APIKey:      "x",
		Username:    "u",
		Password:    "p",
		SocksAddr:   "127.0.0.1:0",
		PollingOnly: true,
	})

	result, err := dispatchWithTimeout(t, d, request{ID: 1, Method: "connect", Params: connectParamsJSON})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	sr, ok := result.(statusResult)
	if !ok || !sr.Connected {
		t.Fatalf("connect: unexpected result %#v", result)
	}

	result, err = dispatchWithTimeout(t, d, request{ID: 2, Method: "status"})
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if sr, ok := result.(statusResult); !ok || !sr.Connected {
		t.Fatalf("status: unexpected result %#v", result)
	}

	// This is the call that used to deadlock (setState called while
	// holding d.mu from within handleDisconnect's now-removed `defer
	// d.mu.Unlock()`). If handleDisconnect regresses, this line hangs
	// and dispatchWithTimeout's 5s guard fails the test instead of the
	// whole `go test` run timing out silently.
	result, err = dispatchWithTimeout(t, d, request{ID: 3, Method: "disconnect"})
	if err != nil {
		t.Fatalf("disconnect: %v", err)
	}
	if m, ok := result.(map[string]bool); !ok || !m["ok"] {
		t.Fatalf("disconnect: unexpected result %#v", result)
	}

	// disconnect again (already-disconnected path) must also not hang.
	if _, err := dispatchWithTimeout(t, d, request{ID: 4, Method: "disconnect"}); err != nil {
		t.Fatalf("second disconnect: %v", err)
	}
}

func TestUnknownMethod(t *testing.T) {
	d := newDaemon()
	_, err := dispatchWithTimeout(t, d, request{ID: 1, Method: "bogus"})
	if err == nil {
		t.Fatal("expected error for unknown method")
	}
}

// ensure the core import is actually exercised (compile-time sanity check
// that this package still depends on the real tunnelcat-server module, not a
// stale copy).
var _ = core.SessionKey
