// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

//go:build ios

// Command lib-ios is tunnelcat-server's iOS SDK adapter — compiled as a static
// c-archive (go build -buildmode=c-archive) and linked directly into an iOS
// app/extension target, since iOS sandboxing forbids spawning subprocesses
// (the mechanism every other SDK adapter uses via cmd/tunneld).
//
// Modeled on a proven pattern for exactly this constraint: it runs a SOCKS5
// server on 127.0.0.1:0 and exposes the port via TCGetSocksPort — no
// TUN/raw-packet handling, since tunnelcat-server has no iOS packet-tunnel
// primitive. An app embeds this as a WKWebView SOCKS5 proxy (iOS 17+
// WKWebsiteDataStore.proxyConfigurations) or any other SOCKS5-consuming
// component.
//
// Exported C entry points (called from Swift via a bridging header — see
// sdk/swift/ios/Bridging-Header.h):
//
//	TCStart(server, apikey, username, password, logDir, dataDir) → int32 (0=ok, -1=err)
//	TCStop()
//	TCGetStatus()    → *char  (JSON {"state":...,"error":...}; free with TCFreeString)
//	TCFreeString(*char)
//	TCGetSocksPort() → int32  (0 if not yet listening)
//	TCReconnect()
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"unsafe"

	core "tunnel_cat/snc/core"
)

const (
	stateIdle       = "idle"
	stateConnecting = "connecting"
	stateConnected  = "connected"
	stateError      = "error"
)

var (
	gMu       sync.Mutex
	gState    atomic.Value // string
	gErrorMsg atomic.Value // string

	gAuth    *core.Authenticator
	gDialer  *core.TunnelDialer
	gSocks   *core.SOCKS5Server
	gSocksLn net.Listener
)

func init() {
	gState.Store(stateIdle)
	gErrorMsg.Store("")
}

//export TCStart
func TCStart(cServer, cAPIKey, cUsername, cPassword, cLogDir, cDataDir *C.char) C.int {
	gMu.Lock()
	defer gMu.Unlock()

	if gState.Load().(string) == stateConnecting || gState.Load().(string) == stateConnected {
		return -1
	}

	server := C.GoString(cServer)
	apiKey := C.GoString(cAPIKey)
	username := C.GoString(cUsername)
	password := C.GoString(cPassword)
	logDir := C.GoString(cLogDir)
	dataDir := C.GoString(cDataDir)

	if logDir != "" {
		os.MkdirAll(logDir, 0700) //nolint:errcheck
	}
	if dataDir != "" {
		os.MkdirAll(dataDir, 0700) //nolint:errcheck
	}

	gState.Store(stateConnecting)
	gErrorMsg.Store("")

	auth := core.NewAuthenticator(server, apiKey, username, password)
	if err := auth.Login(); err != nil {
		gState.Store(stateError)
		gErrorMsg.Store(err.Error())
		return -1
	}

	dialer := core.NewTunnelDialer(auth)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		gState.Store(stateError)
		gErrorMsg.Store(err.Error())
		return -1
	}
	socks := core.NewSOCKS5Server("", dialer)
	go socks.Serve(ln) //nolint:errcheck

	gAuth, gDialer, gSocks, gSocksLn = auth, dialer, socks, ln
	gState.Store(stateConnected)
	return 0
}

//export TCStop
func TCStop() {
	gMu.Lock()
	defer gMu.Unlock()
	if gSocks != nil {
		gSocks.Close()
	}
	if gSocksLn != nil {
		gSocksLn.Close()
	}
	gAuth, gDialer, gSocks, gSocksLn = nil, nil, nil, nil
	gState.Store(stateIdle)
	gErrorMsg.Store("")
}

//export TCGetStatus
func TCGetStatus() *C.char {
	type statusJSON struct {
		State string `json:"state"`
		Error string `json:"error,omitempty"`
	}
	b, _ := json.Marshal(statusJSON{
		State: gState.Load().(string),
		Error: gErrorMsg.Load().(string),
	})
	return C.CString(string(b))
}

//export TCFreeString
func TCFreeString(s *C.char) {
	C.free(unsafe.Pointer(s))
}

//export TCGetSocksPort
func TCGetSocksPort() C.int {
	gMu.Lock()
	ln := gSocksLn
	gMu.Unlock()
	if ln == nil {
		return 0
	}
	if addr, ok := ln.Addr().(*net.TCPAddr); ok {
		return C.int(addr.Port)
	}
	return 0
}

//export TCReconnect
func TCReconnect() {
	gMu.Lock()
	auth := gAuth
	gMu.Unlock()
	if auth == nil {
		return
	}
	gState.Store(stateConnecting)
	if err := auth.Login(); err != nil {
		gState.Store(stateError)
		gErrorMsg.Store(err.Error())
		return
	}
	gState.Store(stateConnected)
}

func main() {} // required for -buildmode=c-archive
