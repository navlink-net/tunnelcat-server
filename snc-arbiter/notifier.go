// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

// relayAPISNIPool must match relayAPISNIPool in snc-control/handler.go.
var relayAPISNIPool = []string{
	"ctrl.cdn-assets.net",
	"api.cdn-relay.net",
	"mgmt.edge-static.net",
	"admin.cdn-cache.net",
	"svc.static-assets.net",
}

// Notifier pushes a signed refresh signal to all live exits and controls
// whenever the node topology changes (approve / reject / suspend / heartbeat expiry).
//
// Exits receive:  POST https://<exit>/p/node/v1/refresh    (plain TLS)
// Controls receive: POST https://<control>/p/v1/refresh    (SNI snc-relay.internal)
//
// The request body is {"ts":<unix>} signed with the arbiter's Ed25519 key.
// Recipients verify the signature and timestamp before acting.
type Notifier struct {
	db         *DB
	signer     *signingKey
	exitClient *http.Client // for exits    — plain TLS, skip verify (self-signed ok)
	ctrlClient *http.Client // for controls — SNI snc-relay.internal, skip verify
}

func newNotifier(db *DB, signer *signingKey) *Notifier {
	exitClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
	ctrlClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         relayAPISNIPool[rand.Intn(len(relayAPISNIPool))],
				InsecureSkipVerify: true, //nolint:gosec
			},
		},
	}
	return &Notifier{db: db, signer: signer, exitClient: exitClient, ctrlClient: ctrlClient}
}

// NotifyAll pushes a refresh to all live exits and controls.
// Runs in a background goroutine so callers are not blocked.
func (n *Notifier) NotifyAll() {
	go n.notifyAll()
}

func (n *Notifier) notifyAll() {
	body, sig, err := n.buildRefreshPayload()
	if err != nil {
		logWarnf("notifier: build payload: %v", err)
		return
	}

	exits, err := n.db.liveNodes("exit")
	if err != nil {
		logWarnf("notifier: list exits: %v", err)
	}
	for _, node := range exits {
		go n.notify(n.exitClient, exitRefreshURL(node.Addr), body, sig)
	}

	controls, err := n.db.liveNodes("control")
	if err != nil {
		logWarnf("notifier: list controls: %v", err)
	}
	for _, node := range controls {
		go n.notify(n.ctrlClient, controlRefreshURL(node.Addr), body, sig)
	}
}

// buildRefreshPayload returns the JSON body and its Ed25519 signature (base64url).
func (n *Notifier) buildRefreshPayload() ([]byte, string, error) {
	body, err := json.Marshal(map[string]int64{"ts": time.Now().Unix()})
	if err != nil {
		return nil, "", fmt.Errorf("marshal: %w", err)
	}
	sig := ed25519.Sign(n.signer.priv, body)
	return body, base64.RawURLEncoding.EncodeToString(sig), nil
}

func (n *Notifier) notify(client *http.Client, url string, body []byte, sig string) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		logWarnf("notifier: build request %s: %v", url, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Arbiter-Sig", sig)

	resp, err := client.Do(req)
	if err != nil {
		logWarnf("notifier: POST %s: %v", url, err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logWarnf("notifier: POST %s status=%d", url, resp.StatusCode)
		return
	}
	logDebugf("notifier: refreshed %s", url)
}

// exitRefreshURL builds the refresh endpoint URL for an exit node.
func exitRefreshURL(addr string) string {
	addr = strings.TrimPrefix(addr, "https://")
	addr = strings.TrimPrefix(addr, "http://")
	if _, _, err := splitHostPort(addr); err != nil {
		addr = addr + ":443"
	}
	return "https://" + addr + "/p/node/v1/refresh"
}

// controlRefreshURL builds the refresh endpoint URL for a control node.
// Control's management API is reached via SNI snc-relay.internal on port 443.
func controlRefreshURL(addr string) string {
	addr = strings.TrimPrefix(addr, "https://")
	addr = strings.TrimPrefix(addr, "http://")
	if _, _, err := splitHostPort(addr); err != nil {
		addr = addr + ":443"
	}
	return "https://" + addr + "/p/v1/refresh"
}

// splitHostPort is a thin wrapper so we avoid importing net in the URL helpers.
func splitHostPort(addr string) (host, port string, err error) {
	// Use strings to detect whether a port is present.
	// A valid host:port has exactly one colon (IPv4) or brackets (IPv6).
	// We just need to know if a port is already there.
	if strings.HasPrefix(addr, "[") {
		// IPv6 with port: [::1]:443
		end := strings.LastIndex(addr, ":")
		if end > 0 {
			return addr[:end], addr[end+1:], nil
		}
		return addr, "", fmt.Errorf("no port")
	}
	parts := strings.Split(addr, ":")
	if len(parts) == 2 {
		return parts[0], parts[1], nil
	}
	return addr, "", fmt.Errorf("no port")
}
