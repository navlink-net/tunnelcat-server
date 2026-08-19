// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

//go:build integration

package core

import (
	"flag"
	"io"
	"net"
	"testing"
	"time"
)

// Run with: go test -tags=integration -server=http://127.0.0.1:PORT
var serverFlag = flag.String("server", "", "Camerlengo server URL (required for integration tests)")
var apiKeyFlag = flag.String("apikey", "01Az8nB8mB4cCV", "API key")
var userFlag = flag.String("user", "tunnel_test_user", "Username")
var passFlag = flag.String("pass", "tunnel_test_pass_XkZ9", "Password")

func TestIntegrationSOCKS5ThroughCamerlengo(t *testing.T) {
	if *serverFlag == "" {
		t.Skip("-server flag required")
	}

	auth := NewAuthenticator(*serverFlag, *apiKeyFlag, *userFlag, *passFlag)
	if err := auth.Login(); err != nil {
		t.Fatalf("Login: %v", err)
	}
	t.Logf("Session token: %s", auth.Token())

	dialer := NewTunnelDialer(auth)

	// Start local echo server as target
	echoAddr, stop := echoTCP(t)
	defer stop()

	socks := NewSOCKS5Server("127.0.0.1:0", dialer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go socks.Serve(ln)

	c := dialSOCKS5(t, ln.Addr().String(), echoAddr)
	defer c.Close()

	msg := []byte("integration-hello")
	if _, err := c.Write(msg); err != nil {
		t.Fatal("Write:", err)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	n, err := io.ReadAtLeast(c, buf, len(msg))
	if err != nil {
		t.Fatal("Read:", err)
	}
	if string(buf[:len(msg)]) != string(msg) {
		t.Errorf("echo mismatch: got %q want %q", buf[:n], msg)
	}
}
