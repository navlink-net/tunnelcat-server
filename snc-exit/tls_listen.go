// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/tls"
	"net"
	"net/http"

	"golang.org/x/net/http2"
)

// serveTLS opens a TCP listener on addr, terminates TLS with tlsCfg, and
// serves httpHandler over it with HTTP/2 enabled.
//
// Until 2026-08-13 this exit also demultiplexed incoming connections here
// (peeking the TLS ClientHello to route para-exit yamux reverse-tunnels
// separately from normal HTTP traffic — see git history for demux.go). That
// dispatch existed solely for the para-exit feature; now that it's removed,
// every connection takes the plain HTTP path again.
func serveTLS(tlsCfg *tls.Config, addr string, httpHandler http.Handler) error {
	cfg := tlsCfg.Clone()
	cfg.NextProtos = append([]string{"h2", "http/1.1"}, cfg.NextProtos...)
	httpSrv := &http.Server{Handler: httpHandler}
	http2.ConfigureServer(httpSrv, nil) //nolint:errcheck
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	logInfof("exit: listening on %s", addr)
	return httpSrv.Serve(tls.NewListener(ln, cfg))
}
