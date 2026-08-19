// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

//go:build linux

package androidcore

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const publicIPServiceURL = "https://checkip.amazonaws.com"

// DetectPublicIP returns the device's public IPv4 address.
func DetectPublicIP(client *http.Client) (string, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, publicIPServiceURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", publicIPServiceURL, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(data))
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("unexpected response: %q", ip)
	}
	return ip, nil
}

// localNICAddr returns the first non-loopback, non-link-local IPv4 address
// found on any network interface.  Used to bind UDP hole-punch sockets to the
// physical NIC rather than the TUN interface.  Returns "" if none found.
// Binding to a specific NIC address ensures the UDP packet leaves via the
// physical interface even before protect() is called on the socket — a safety
// net for the brief window between socket creation and protect completion.
func localNICAddr() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip4 := ip.To4(); ip4 != nil && !ip4.IsLoopback() && !ip4.IsLinkLocalUnicast() {
				return ip4.String()
			}
		}
	}
	return ""
}

// NewProtectedHTTPClient returns an HTTP client whose TCP connections are
// routed through Protect.DialControl, bypassing the VPN TUN interface.
//
// Why InsecureSkipVerify: Go's TLS stack looks for CA bundles at standard Linux
// paths (/etc/ssl/certs, /etc/pki/tls/certs, etc.). These paths don't exist on
// Android — the system CAs live in the APK and are only accessible through the
// Java KeyStore API, which is not available in a Go subprocess. Without a CA
// bundle every HTTPS request would fail with "x509: certificate signed by unknown
// authority". InsecureSkipVerify is safe here because:
//  - Our own control/exit nodes are authenticated by their Ed25519 key embedded in
//    the SNC key string, not by the TLS certificate chain.
//  - The only third-party HTTPS call is checkip.amazonaws.com for IP detection,
//    which returns a non-sensitive plain-text string and is guarded against
//    injection by net.ParseIP.
func NewProtectedHTTPClient() *http.Client {
	dialer := &net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   Protect.DialControl,
	}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ForceAttemptHTTP2:     false,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // linux/amd64 binary has no Android CA bundle
	}
	return &http.Client{Transport: transport, Timeout: 20 * time.Second}
}
