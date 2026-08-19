// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"bufio"
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	minPadding    = 512
	maxDelayMS    = 50
	streamMaxSecs = 30
	streamIdleMS  = 50

	// dialDecisionBudget bounds the total time from receiving a connect request
	// to sending a response (success or 404) — primary dial plus the entire
	// peer-fallback chain. Must stay comfortably under the client's HTTP
	// timeout (30s, snc/core/tunnel.go) so "no response at all" unambiguously
	// signals a broken control path rather than a slow-but-alive exit.
	dialDecisionBudget = 15 * time.Second

	frameTypeUpload     byte = 0x00
	frameTypeStreamOpen byte = 0x01
)

var tunnelPaths = map[string]bool{
	"/api/media/upload":   true,
	"/api/content/submit": true,
	"/api/udp/relay":      true,
	"/api/udp/drain":      true,
}

const manifestTTL = 5 * time.Minute

type handler struct {
	auth      *authClient
	pool      *sessionPool
	udpPool   *udpSessionPool
	selfIPs   map[string]bool
	proxy     *httputil.ReverseProxy
	cidrCache *cidrCache
	nodeProx  *nodeProxy
	wl        *whitelistCache
	svcBlocks *serviceBlockCache  // per-service region-dial restrictions; nil = disabled
	anonBoot  *anonBootstrapCache // shared no-account bootstrap token + destination allowlist; nil = disabled
	bl        *blacklistCache     // exit address blacklist; nil = disabled
	stats     *StatsCollector
	peers     *PeerRegistry   // peer exit nodes for geo-routing and fallback
	peerAuth  *peerAuthCache  // validates incoming peer tokens
	myRegion  string          // this exit's own ISO region code (e.g. "EU", "RU")
	nodeToken string          // this exit's node token, sent in X-Peer-Token to peers
	probeDB   *WhitelistProbe // nil if capability probing is unavailable

	torrentAllowed *torrentAllowedCache // arbiter-controlled, blacklist model (default allowed); a nil *pointer* is treated as "not allowed" (defensive fallback for the arbiter-integration-missing case, distinct from the cache's own pre-fetch default)

	providerTag string // e.g. "HETZNER"; matched against service-region-block rules alongside myRegion

	manifestMu      sync.Mutex
	manifestData    []byte
	manifestFetched time.Time

	// clubManifest* mirrors manifest* above but keyed per club slug — an
	// independent, parallel cache (see club_handler.go), never touching the
	// general manifest cache fields.
	clubManifestMu      sync.Mutex
	clubManifestData    map[string][]byte
	clubManifestFetched map[string]time.Time
}

func newHandler(arbiterURL, nodeToken string, cidrC *cidrCache) *handler {
	target, err := url.Parse(strings.TrimRight(arbiterURL, "/"))
	if err != nil {
		logErrorf("invalid --arbiter URL %q: %v", arbiterURL, err)
		os.Exit(1)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	origDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		origDirector(req)
		req.Host = target.Host
	}
	auth := newAuthClient(arbiterURL, nodeToken)
	return &handler{
		auth:                auth,
		pool:                newSessionPool(),
		udpPool:             newUDPSessionPool(),
		selfIPs:             getSelfIPs(),
		proxy:               proxy,
		cidrCache:           cidrC,
		stats:               newStatsCollector(arbiterURL, nodeToken),
		peerAuth:            newPeerAuthCache(auth),
		nodeToken:           nodeToken,
		clubManifestData:    make(map[string][]byte),
		clubManifestFetched: make(map[string]time.Time),
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status  int
	written int64 // bytes written to the response -- see wireBytes doc comment
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *statusRecorder) Write(b []byte) (int, error) {
	n, err := sr.ResponseWriter.Write(b)
	sr.written += int64(n)
	return n, err
}

// countingReader tallies bytes read from an underlying io.Reader.
type countingReader struct {
	r    io.Reader
	read int64
}

func (cr *countingReader) Read(b []byte) (int, error) {
	n, err := cr.r.Read(b)
	cr.read += int64(n)
	return n, err
}

func (sr *statusRecorder) Flush() {
	if f, ok := sr.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack delegates to the underlying ResponseWriter so that handlers that
// require connection hijacking (e.g. peer-connect) work correctly even when
// wrapped by statusRecorder.
func (sr *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := sr.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying ResponseWriter does not support hijack")
	}
	return hj.Hijack()
}

// wireBytesPaths are the endpoints that carry real relayed user traffic --
// the same conceptual channel control's controlBytesTotal measures (its raw
// client<->exit TCP relay connection). exitBytesTotal used to be tallied
// deep inside the tunnel-frame protocol's payload handling (RecordBytes,
// post-frame-parse, target-connection bytes only) -- a different layer than
// control's wire-level count, and it silently excluded /api/udp/relay
// entirely (never called RecordBytes at all). Counting at the HTTP
// request/response boundary here, for exactly the paths that mirror what
// control's relay channel carries, makes the two numbers comparable again.
// peer/connect is deliberately excluded: control never dials a peer exit
// directly, so control's count can't see that traffic either -- counting it
// here would reintroduce an asymmetry in the other direction.
var wireBytesPaths = map[string]bool{
	"/api/udp/relay": true,
	"/api/udp/drain": true,
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

	countWire := wireBytesPaths[r.URL.Path] || (r.Method == http.MethodPost && tunnelPaths[r.URL.Path])
	var cr *countingReader
	if countWire && r.Body != nil {
		cr = &countingReader{r: r.Body}
		r.Body = io.NopCloser(cr)
	}

	if r.Method == http.MethodPost && r.URL.Path == "/api/udp/relay" {
		h.serveUDPRelay(rec, r)
	} else if r.Method == http.MethodPost && r.URL.Path == "/api/udp/drain" {
		h.serveUDPDrain(rec, r)
	} else if r.Method == http.MethodGet && r.URL.Path == "/api/peer/capabilities" {
		h.servePeerCapabilities(rec, r)
	} else if r.Method == http.MethodPost && r.URL.Path == "/api/peer/connect" {
		h.servePeerConnect(rec, r)
	} else if r.Method == http.MethodPost && tunnelPaths[r.URL.Path] {
		h.handleTunnel(rec, r)
	} else if strings.HasPrefix(r.URL.Path, "/p/node/v1/") && h.nodeProx != nil {
		h.nodeProx.ServeHTTP(rec, r)
	} else if r.URL.Path == "/p/v1/probe" && r.Method == http.MethodGet && h.nodeProx != nil {
		h.nodeProx.serveProbe(rec, r)
	} else if r.URL.Path == "/p/v1/ping" && r.Method == http.MethodGet {
		w.WriteHeader(http.StatusOK)
	} else if r.URL.Path == "/api/manifest" && r.Method == http.MethodGet {
		h.serveManifest(rec, r)
	} else if r.URL.Path == "/api/club-manifest" && r.Method == http.MethodGet {
		h.serveClubManifest(rec, r)
	} else if r.URL.Path == "/api/bypass/cidr" && r.Method == http.MethodGet {
		h.serveCIDR(rec, r)
	} else if r.Method == http.MethodPost && r.URL.Path == "/api/auth/proxy-validate" {
		h.serveAuth(rec, r, "proxy-validate")
	} else if r.Method == http.MethodPost && r.URL.Path == "/" {
		h.serveRootCommand(rec, r)
	} else {
		h.proxy.ServeHTTP(rec, r)
	}

	if countWire {
		var reqBytes int64
		if cr != nil {
			reqBytes = cr.read
		}
		exitBytesTotal.Add(reqBytes + rec.written)
	}

	dur := time.Since(start).Round(time.Millisecond)
	if tunnelPaths[r.URL.Path] {
		logDebugf("http: %s %s %s status=%d dur=%s", r.Method, r.URL.Path, remoteIP(r), rec.status, dur)
	} else {
		logInfof("http: %s %s %s status=%d dur=%s", r.Method, r.URL.Path, remoteIP(r), rec.status, dur)
	}
}

// serveRootCommand inspects a POST "/" body for a Camerlengo-style ".command"
// and routes login commands (authenticateKey, verifyPassword) through the
// cached/deferred auth path instead of the raw arbiter reverse proxy. Any
// other command is forwarded unchanged — the arbiter remains the single
// source of truth for everything that isn't login.
func (h *handler) serveRootCommand(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, `{"error":"read body"}`, http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))

	var meta struct {
		Command string `json:".command"`
	}
	json.Unmarshal(body, &meta) //nolint:errcheck

	switch meta.Command {
	case "authenticateKey", "verifyPassword":
		h.serveAuthBody(w, r, meta.Command, body)
	default:
		h.proxy.ServeHTTP(w, r)
	}
}

// serveAuth handles a login command whose body has already been read off r
// (proxy-validate, which has its own dedicated route).
func (h *handler) serveAuth(w http.ResponseWriter, r *http.Request, command string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, `{"error":"read body"}`, http.StatusBadRequest)
		return
	}
	h.serveAuthBody(w, r, command, body)
}

// serveAuthBody runs an auth command through authClient.authenticate's
// cached/deferred path (see auth.go) — the fix for the catch-all reverse
// proxy that used to send every login straight to the arbiter with no
// resilience to brief outages.
func (h *handler) serveAuthBody(w http.ResponseWriter, r *http.Request, command string, body []byte) {
	clientIP := remoteIP(r)
	raw, status := h.auth.authenticate(r, command, body)
	logDebugf("auth: %s ip=%s status=%d", command, clientIP, status)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(raw) //nolint:errcheck
}

func (h *handler) serveCIDR(w http.ResponseWriter, r *http.Request) {
	if h.cidrCache == nil {
		http.NotFound(w, r)
		return
	}
	token := r.Header.Get("X-Session")
	if _, _, denied, transient := h.auth.validateSession(token); denied || transient {
		if denied {
			logWarnf("cidr: denied ip=%s token=%.8s…", remoteIP(r), token)
			http.NotFound(w, r)
		} else {
			http.Error(w, `{"error":"arbiter_unavailable"}`, http.StatusServiceUnavailable)
		}
		return
	}
	ipStr := r.URL.Query().Get("ip")
	if ipStr == "" {
		ipStr = remoteIP(r)
	}
	data := h.cidrCache.Lookup(ipStr)
	if data == nil {
		logDebugf("cidr: no country match for ip=%s", ipStr)
		http.NotFound(w, r)
		return
	}
	logInfof("cidr: serving bypass list for ip=%s", ipStr)
	w.Header().Set("Content-Type", "application/json")
	w.Write(data) //nolint:errcheck
}

func (h *handler) serveManifest(w http.ResponseWriter, r *http.Request) {
	data, err := h.cachedManifest()
	if err != nil {
		logWarnf("manifest: %v", err)
		http.Error(w, `{"error":"manifest unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data) //nolint:errcheck
}

func (h *handler) cachedManifest() ([]byte, error) {
	h.manifestMu.Lock()
	defer h.manifestMu.Unlock()

	if len(h.manifestData) > 0 && time.Since(h.manifestFetched) < manifestTTL {
		age := time.Since(h.manifestFetched).Round(time.Second)
		logDebugf("manifest: cache hit age=%s size=%d bytes", age, len(h.manifestData))
		return h.manifestData, nil
	}

	fetchStart := time.Now()
	data, err := h.auth.fetchManifest()
	if err == nil && len(data) == 0 {
		err = fmt.Errorf("manifest: empty response from arbiter")
	}
	if err != nil {
		if len(h.manifestData) > 0 {
			staleAge := time.Since(h.manifestFetched).Round(time.Second)
			logWarnf("manifest: refresh failed (%v), serving stale data age=%s", err, staleAge)
			return h.manifestData, nil
		}
		return nil, err
	}
	h.manifestData = data
	h.manifestFetched = time.Now()
	logInfof("manifest: fetched from arbiter size=%d bytes dur=%s", len(data), time.Since(fetchStart).Round(time.Millisecond))
	return data, nil
}

func (h *handler) handleTunnel(w http.ResponseWriter, r *http.Request) {
	clientIP := remoteIP(r)
	logDebugf("tunnel: %s %s ip=%s ua=%.40s", r.Method, r.URL.Path, clientIP, r.UserAgent())

	token := r.Header.Get("X-Session")

	// Anon-bootstrap check comes first, before any arbiter-backed session
	// validation: the bootstrap token is a fixed, shared value baked into
	// clients, not a per-user session, so there's nothing for the arbiter
	// to look up, and checking it here avoids the just-fixed "unknown token
	// → denied" verdict (see sessions.go's Validate doc comment) ever being
	// asked about a token the arbiter never issued in the first place.
	isAnon := h.anonBoot != nil && h.anonBoot.IsBootstrapToken(token)

	var username, clientID string
	if !isAnon {
		var denied, transient bool
		username, clientID, denied, transient = h.auth.validateSession(token)
		if denied {
			logWarnf("tunnel: denied ip=%s token=%.8s… → 404", clientIP, token)
			send404(w)
			return
		}
		if transient {
			logWarnf("tunnel: arbiter unreachable, no cache for ip=%s token=%.8s… → 503", clientIP, token)
			http.Error(w, `{"error":"arbiter_unavailable"}`, http.StatusServiceUnavailable)
			return
		}
	}
	logDebugf("tunnel: auth ok user=%s client_id=%s ip=%s anon=%v", username, clientID, clientIP, isAnon)

	key := sessionKey(token)
	rawBody, _ := io.ReadAll(r.Body)
	plain, err := openTunnelFrame(key, rawBody)
	if err != nil {
		logWarnf("tunnel: decrypt fail ip=%s user=%s: %v", clientIP, username, err)
		send404(w)
		return
	}
	if len(plain) < 1 {
		send404(w)
		return
	}

	switch plain[0] {

	case frameTypeStreamOpen:
		if len(plain) < 1+16 {
			send404(w)
			return
		}
		connID := hex.EncodeToString(plain[1:17])
		sock := h.pool.get(connID)
		if sock == nil {
			reason := h.pool.closeReason(connID)
			logWarnf("tunnel: stream unknown-conn conn=%.8s user=%s reason=%s", connID, username, reason)
			// X-Close-Reason lets the client tell a genuine rejection
			// (reason=not-found -- evicted by the watchdog after sessionTimeout
			// with no data at all, or a connID the exit never had) apart from a
			// normal completion (reason=target-closed -- the real destination
			// closed the connection on its own after successfully serving the
			// request) for its own rejected-sessions stat. Purely informational:
			// still a plain 404, still gives up immediately either way (see
			// tunnel_cat/snc/core/session.go's giveUp).
			w.Header().Set("X-Close-Reason", reason)
			send404(w)
			return
		}
		h.pool.recordActivity(connID)
		streamStart := time.Now()
		logInfof("tunnel: stream open conn=%.8s user=%s ip=%s", connID, username, clientIP)
		n, targetClosed := h.streamToClient(w, connID, sock, key)
		logInfof("tunnel: stream close conn=%.8s user=%s dur=%s bytes=%d targetClosed=%v",
			connID, username, time.Since(streamStart).Round(time.Millisecond), n, targetClosed)
		if targetClosed {
			h.pool.markTargetClosed(connID)
			// n == 0 means the target connection closed/errored without ever
			// sending back a single byte -- couldn't get a response, not a
			// normal "target finished serving the request and closed" case.
			if n == 0 && h.stats != nil {
				h.stats.RecordRejectedSession()
			}
		}
		if h.stats != nil && n > 0 {
			_, country, bytesUp, ok := h.pool.snapshot(connID)
			if ok {
				h.stats.RecordBytes(username, country, bytesUp, n)
			}
		}

	case frameTypeUpload:
		connID, seq, target, payload, err := parseUploadFrame(plain)
		if err != nil {
			logWarnf("tunnel: bad upload frame ip=%s: %v", clientIP, err)
			send404(w)
			return
		}
		logDebugf("tunnel: upload conn=%.8s seq=%d user=%s payload=%d", connID, seq, username, len(payload))

		var sock net.Conn
		if seq == 0 {
			// dialDeadline bounds every stage below (same-country redirect, geo-routing,
			// whitelist-peer, primary dial, fallback-peer) combined — see dialDecisionBudget.
			dialDeadline := time.Now().Add(dialDecisionBudget)
			targetHost, portStr, err := net.SplitHostPort(target)
			if err != nil {
				send404(w)
				return
			}
			port, err := strconv.Atoi(portStr)
			if err != nil {
				send404(w)
				return
			}
			if h.selfIPs[targetHost] {
				logWarnf("tunnel: routing loop target=%s:%d — rejecting", targetHost, port)
				send404(w)
				return
			}
			if ip := net.ParseIP(targetHost); ip != nil {
				if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
					logWarnf("tunnel: non-routable target=%s:%d — rejecting", targetHost, port)
					send404(w)
					return
				}
			}
			// Blacklist check: blocked addresses are logged and silently dropped.
			// Not reported to arbiter as failures so they don't appear in the dashboard.
			if h.bl != nil && h.bl.IsBlacklisted(targetHost) {
				logInfof("blacklist: blocked user=%s target=%s:%d", username, targetHost, port)
				send404(w)
				return
			}

			// Anon-bootstrap sessions may only reach the admin-configured
			// destination allowlist (shortnerdcat.navlink.net + navlink.net by
			// default) -- everything else is rejected outright, same as an
			// unknown token, so the shared bootstrap token can't be used as a
			// general-purpose free tunnel.
			if isAnon {
				targetIP := ""
				if ip := net.ParseIP(targetHost); ip != nil {
					targetIP = targetHost
				}
				if h.anonBoot == nil || !h.anonBoot.IsAllowed(targetHost, targetIP) {
					logWarnf("anon-bootstrap: target=%s:%d not in allowlist — rejecting", targetHost, port)
					send404(w)
					return
				}
			}

			// Derive client's country: device-reported CC (X-Client-CC) takes
			// priority over IP geolocation — a user may be in a different country
			// than their ISP's routing suggests (roaming, CGNAT, etc.).
			noForward := r.Header.Get("X-No-Forward") == "1"
			clientCC := strings.ToUpper(strings.TrimSpace(r.Header.Get("X-Client-CC")))
			if clientCC == "" {
				// Fallback: derive from X-Client-IP or the TCP source address.
				clientLookupIP := r.Header.Get("X-Client-IP")
				if clientLookupIP == "" {
					clientLookupIP = clientIP
				}
				if h.cidrCache != nil {
					clientCC = h.cidrCache.lookupCountry(clientLookupIP)
				}
			}

			// Torrent redirect: this exit only sees the connection's opening
			// payload here (seq==0), which for a real BitTorrent peer
			// connection is always the wire-protocol handshake (BEP 3) --
			// the client sends it first, before anything else. If detected
			// and this exit doesn't allow torrent egress, forward through a
			// peer that does; if none is available, reject outright rather
			// than silently letting it through on a non-allowing exit.
			if sock == nil && (h.torrentAllowed == nil || !h.torrentAllowed.SelfAllowed()) && isBitTorrentHandshake(payload) {
				redirected := false
				if !noForward && h.peers != nil && h.torrentAllowed != nil {
					for _, peer := range h.peers.ShufflePeers() {
						if time.Now().After(dialDeadline) {
							logWarnf("tunnel: torrent redirect user=%s target=%s — dial budget exhausted, giving up", username, target)
							break
						}
						if h.selfIPs[peer.Addr] || peer.Region == clientCC || !h.torrentAllowed.IsAllowed(peer.Addr) {
							continue
						}
						conn, err := dialPeer(&peer, target, h.nodeToken, dialDeadline)
						if err != nil {
							logWarnf("tunnel: torrent redirect failed user=%s target=%s peer=%s: %v — trying next peer", username, target, peer.Addr, err)
							continue
						}
						logInfof("tunnel: torrent redirect user=%s conn=%.8s target=%s peer=%s (this exit does not allow torrent egress)", username, connID, target, peer.Addr)
						h.pool.store(connID, conn, username)
						sock = conn
						redirected = true
						break
					}
				}
				if !redirected {
					logInfof("tunnel: torrent rejected user=%s target=%s — this exit does not allow torrent egress and no allowing peer was available", username, target)
					send404(w)
					return
				}
			}

			// Same-country redirect: if this exit is in the client's own country,
			// traffic must not egress here — forward through a peer in another region.
			// Try every available peer in random order; fall back to direct only if
			// all peers fail.
			myRegion := ""
			if h.peers != nil {
				myRegion = h.peers.MyRegion()
			}
			if sock == nil && !noForward && clientCC != "" && myRegion != "" && myRegion == clientCC && h.peers != nil {
				for _, peer := range h.peers.ShufflePeers() {
					if time.Now().After(dialDeadline) {
						logWarnf("tunnel: same-country redirect user=%s target=%s — dial budget exhausted, giving up", username, target)
						break
					}
					if h.selfIPs[peer.Addr] || peer.Region == clientCC {
						continue
					}
					conn, err := dialPeer(&peer, target, h.nodeToken, dialDeadline)
					if err != nil {
						logWarnf("tunnel: same-country redirect failed user=%s target=%s peer=%s: %v — trying next peer", username, target, peer.Addr, err)
						continue
					}
					logInfof("tunnel: same-country redirect user=%s conn=%.8s target=%s peer=%s (client=%s exit=%s)", username, connID, target, peer.Addr, clientCC, myRegion)
					h.pool.store(connID, conn, username)
					sock = conn
					break
				}
				if sock == nil {
					logWarnf("tunnel: same-country client=%s exit=%s — all peers failed, falling back to direct user=%s target=%s", clientCC, myRegion, username, target)
				}
			}

			// Service-region-block redirect: some destinations are known unreachable
			// from this exit's own region regardless of tunnel/exit health (e.g.
			// Telegram voice CIDRs from RU — RKN blocks the route, not us). If this
			// exit's region is on the admin-configured block list for the target,
			// forward through a peer whose own region isn't blocked for it instead.
			// Independent of geo-routing below: that one matches the *destination's*
			// country by CIDR (useless for services like Telegram whose IPs aren't
			// geo-tagged to any one country); this one is admin-declared per service.
			if sock == nil && !noForward && h.svcBlocks != nil && h.peers != nil && (myRegion != "" || h.providerTag != "") {
				targetIP := ""
				if ip := net.ParseIP(targetHost); ip != nil {
					targetIP = targetHost
				}
				blockedHere := h.svcBlocks.IsBlockedForRegion(targetHost, targetIP, myRegion) ||
					(h.providerTag != "" && h.svcBlocks.IsBlockedForRegion(targetHost, targetIP, h.providerTag))
				if blockedHere {
					for _, peer := range h.peers.ShufflePeers() {
						if time.Now().After(dialDeadline) {
							logWarnf("tunnel: region-block redirect user=%s target=%s — dial budget exhausted, giving up", username, target)
							break
						}
						if h.selfIPs[peer.Addr] || peer.Region == clientCC || h.svcBlocks.IsBlockedForRegion(targetHost, targetIP, peer.Region) {
							continue
						}
						conn, err := dialPeer(&peer, target, h.nodeToken, dialDeadline)
						if err != nil {
							logWarnf("tunnel: region-block redirect failed user=%s target=%s peer=%s: %v — trying next peer", username, target, peer.Addr, err)
							continue
						}
						logInfof("tunnel: region-block redirect user=%s conn=%.8s target=%s peer=%s (exit region %s is blocked for this destination)", username, connID, target, peer.Addr, myRegion)
						h.pool.store(connID, conn, username)
						sock = conn
						break
					}
					if sock == nil {
						logWarnf("tunnel: region-block exit=%s target=%s — no unblocked peer available, falling back to direct (will likely fail) user=%s", myRegion, target, username)
					}
				}
			}

			// Geo-routing: if a live peer exit exists in the destination country,
			// forward through it. Tries all peers in that region (shuffled) until
			// one succeeds; falls back to direct if all fail.
			// Skips peers in the client's own country so traffic never egresses there.
			if sock == nil && !noForward && h.peers != nil && myRegion != "" && h.cidrCache != nil {
				if targetCC := h.cidrCache.lookupCountry(targetHost); targetCC != "" && targetCC != myRegion {
					for _, peer := range h.peers.ShufflePeers() {
						if time.Now().After(dialDeadline) {
							logWarnf("tunnel: geo-peer user=%s target=%s — dial budget exhausted, giving up", username, target)
							break
						}
						if peer.Region != targetCC || h.selfIPs[peer.Addr] || peer.Region == clientCC {
							continue
						}
						conn, err := dialPeer(&peer, target, h.nodeToken, dialDeadline)
						if err != nil {
							logWarnf("tunnel: geo-peer dial failed user=%s target=%s peer=%s: %v — trying next", username, target, peer.Addr, err)
							continue
						}
						logInfof("tunnel: geo-peer user=%s conn=%.8s target=%s peer=%s region=%s", username, connID, target, peer.Addr, targetCC)
						h.pool.store(connID, conn, username)
						sock = conn
						break
					}
				}
			}

			// Whitelist peer-routing: if the target is whitelisted but this exit
			// cannot reach it (blocked by the remote service), forward through a
			// peer exit that can.
			if sock == nil && !noForward && h.wl != nil && h.probeDB != nil && h.peers != nil {
				if h.wl.IsWhitelisted(targetHost, "") && !h.probeDB.CanReach(targetHost) {
					for _, peer := range h.peers.PeersCapableOf(targetHost) {
						if time.Now().After(dialDeadline) {
							logWarnf("tunnel: whitelist-peer user=%s target=%s — dial budget exhausted, giving up", username, target)
							break
						}
						if h.selfIPs[peer.Addr] || peer.Region == clientCC {
							continue
						}
						conn, err := dialPeer(&peer, target, h.nodeToken, dialDeadline)
						if err != nil {
							logWarnf("tunnel: whitelist-peer dial failed user=%s target=%s peer=%s: %v — trying next", username, target, peer.Addr, err)
							continue
						}
						logInfof("tunnel: whitelist-peer user=%s conn=%.8s target=%s peer=%s", username, connID, target, peer.Addr)
						h.pool.store(connID, conn, username)
						sock = conn
						break
					}
					if sock == nil {
						logWarnf("tunnel: whitelist-peer user=%s target=%s — no capable peer, falling through", username, target)
					}
				}
			}

			if sock == nil && time.Now().After(dialDeadline) {
				logWarnf("tunnel: connect user=%s target=%s:%d — dial budget exhausted before primary dial, giving up", username, targetHost, port)
				send404(w)
				return
			}

			if sock == nil {
				conn, err := h.pool.getOrCreate(connID, targetHost, port, username)
				if err != nil {
					// Blocking fallback: if direct connect fails, try every peer exit
					// in random order, skipping self and any exit in the client's own
					// country (traffic must never egress through the client's country).
					if !noForward && h.peers != nil {
						for _, peer := range h.peers.ShufflePeers() {
							if time.Now().After(dialDeadline) {
								logWarnf("tunnel: fallback-peer user=%s target=%s — dial budget exhausted, giving up", username, target)
								break
							}
							if h.selfIPs[peer.Addr] || peer.Region == clientCC {
								continue
							}
							pconn, perr := dialPeer(&peer, target, h.nodeToken, dialDeadline)
							if perr == nil {
								logInfof("tunnel: fallback-peer user=%s conn=%.8s target=%s peer=%s", username, connID, target, peer.Addr)
								h.pool.store(connID, pconn, username)
								sock = pconn
								break
							}
							logWarnf("tunnel: fallback-peer dial failed user=%s target=%s peer=%s: %v — trying next peer", username, target, peer.Addr, perr)
						}
					}
					if sock == nil {
						logErrorf("tunnel: connect failed user=%s target=%s:%d: %v", username, targetHost, port, err)
						if h.stats != nil {
							h.stats.RecordRejectedSession()
						}
						send404(w)
						return
					}
				} else {
					logInfof("tunnel: connect user=%s conn=%.8s target=%s:%d ip=%s", username, connID, targetHost, port, clientIP)
					sock = conn
					// Record client country for stats; also stored above in clientCC.
					if h.stats != nil && clientCC != "" {
						h.pool.setCountry(connID, clientCC)
					}
				}
			}
		} else {
			sess := h.pool.getSession(connID)
			if sess == nil {
				send404(w)
				return
			}
			sock = sess.conn
			if len(payload) > 0 {
				if err := sess.deliverInOrder(seq, payload); err != nil {
					logWarnf("tunnel: send failed conn=%.8s user=%s: %v", connID, username, err)
					h.pool.close(connID)
					if h.stats != nil {
						h.stats.RecordRejectedSession()
					}
					send404(w)
					return
				}
				h.pool.addBytesUp(connID, int64(len(payload)))
			}
		}
		h.pool.recordActivity(connID)
		time.Sleep(time.Duration(rand.Int63n(int64(maxDelayMS))) * time.Millisecond)

		resp, err := buildUploadResponse(key, nil)
		if err != nil {
			send404(w)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(resp) //nolint:errcheck

	default:
		logWarnf("tunnel: unknown frame type 0x%02x ip=%s", plain[0], clientIP)
		send404(w)
	}
}

// streamToClient holds the HTTP response open and streams bytes from the target
// socket to the client as encrypted length-prefixed frames.
// Frame format: [4B total_enc_len_be][12B nonce][ciphertext].
// streamMaxSecs is a hang/idle guard, not a lifetime cap on active transfer:
// it only closes the response after streamMaxSecs with *zero* bytes read
// from the target, and resets on every real read so a busy connection (a
// download, a long-lived XHR/websocket-ish poll) is never force-cut just
// because it's been open a while. Forcing a cut on active transfers was the
// bug -- see git history around 2026-08-17 for the incident this fixed: a
// blanket 30s cutoff periodically dropped and reopened the client-exit
// stream underneath perfectly healthy connections, and the reopen raced
// against the destination's own idle-connection timeout closing the real
// target socket in the gap, killing long-lived connections outright (most
// visibly against destinations with short server-side idle timeouts).
// Returns (bytes sent, targetClosed): targetClosed is true when the target
// socket returned a real error (EOF/RST), false when the idle deadline was
// reached normally (no data at all).  The caller uses targetClosed to mark
// the session so that a subsequent stream-open first tries redial (see
// sessions.go) before giving up.
func (h *handler) streamToClient(w http.ResponseWriter, connID string, sock net.Conn, key []byte) (int64, bool) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		send404(w)
		return 0, false
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)

	idleDeadline := time.Now().Add(streamMaxSecs * time.Second)
	buf := make([]byte, 65536)
	var lenBuf [4]byte
	var total int64

	for time.Now().Before(idleDeadline) {
		h.pool.recordActivity(connID)                                         // keep session alive while stream is open, even if target is idle
		sock.SetReadDeadline(time.Now().Add(streamIdleMS * time.Millisecond)) //nolint:errcheck
		n, err := sock.Read(buf)
		if n > 0 {
			idleDeadline = time.Now().Add(streamMaxSecs * time.Second) // real data flowed -- this is not a hang, keep the stream open
			total += int64(n)
			ct, cerr := sealTunnelData(key, buf[:n])
			if cerr != nil {
				return total, true
			}
			binary.BigEndian.PutUint32(lenBuf[:], uint32(len(ct)))
			w.Write(lenBuf[:]) //nolint:errcheck
			w.Write(ct)        //nolint:errcheck
			flusher.Flush()
		}
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return total, true
		}
	}
	return total, false
}

// ── tunnel crypto helpers ─────────────────────────────────────────────────────

// sessionKey derives a 32-byte ChaCha20-Poly1305 key from the session token.
func sessionKey(token string) []byte {
	k := blake2b.Sum256([]byte(token))
	return k[:]
}

// sealTunnelData encrypts plain with a random nonce.
// Wire: [12B nonce][ciphertext+tag].
func sealTunnelData(key, plain []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := crand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plain, nil), nil
}

// openTunnelFrame decrypts a [12B nonce][ciphertext+tag] blob.
func openTunnelFrame(key, data []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	if len(data) < aead.NonceSize() {
		return nil, fmt.Errorf("frame too short: %d bytes", len(data))
	}
	nonce := data[:aead.NonceSize()]
	return aead.Open(nil, nonce, data[aead.NonceSize():], nil)
}

// parseUploadFrame parses a decrypted upload frame.
// Plaintext: [1B 0x00][16B conn_id][4B seq_be][2B target_len_be][target][payload]
func parseUploadFrame(plain []byte) (connID string, seq uint32, target string, payload []byte, err error) {
	if len(plain) < 1+16+4+2 {
		return "", 0, "", nil, fmt.Errorf("frame too short")
	}
	if plain[0] != frameTypeUpload {
		return "", 0, "", nil, fmt.Errorf("unexpected type 0x%02x", plain[0])
	}
	connID = hex.EncodeToString(plain[1:17])
	seq = binary.BigEndian.Uint32(plain[17:21])
	tgtLen := int(binary.BigEndian.Uint16(plain[21:23]))
	if tgtLen > len(plain)-23 {
		return "", 0, "", nil, fmt.Errorf("target length overflow")
	}
	target = string(plain[23 : 23+tgtLen])
	payload = plain[23+tgtLen:]
	return
}

// buildUploadResponse encrypts an upload ACK.
// Plaintext: [4B dlen_be][data][random padding to minPadding].
func buildUploadResponse(key []byte, data []byte) ([]byte, error) {
	dlen := len(data)
	padLen := minPadding
	if dlen > padLen {
		padLen = dlen
	}
	plain := make([]byte, 4+padLen)
	binary.BigEndian.PutUint32(plain[:4], uint32(dlen))
	copy(plain[4:], data)
	if dlen < padLen {
		crand.Read(plain[4+dlen:]) //nolint:errcheck
	}
	return sealTunnelData(key, plain)
}

// ── misc helpers ──────────────────────────────────────────────────────────────

func send404(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)
}

func remoteIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
}

// servePeerCapabilities handles GET /api/peer/capabilities.
// Returns this exit's whitelist reachability map so peer exits can route
// whitelisted traffic to nodes that can actually reach the target service.
func (h *handler) servePeerCapabilities(w http.ResponseWriter, r *http.Request) {
	peerToken := r.Header.Get("X-Peer-Token")
	if _, ok := h.peerAuth.Validate(peerToken); !ok {
		logWarnf("peer-capabilities: auth fail token=%.8s… ip=%s", peerToken, remoteIP(r))
		send404(w)
		return
	}
	var caps map[string]bool
	if h.probeDB != nil {
		caps = h.probeDB.Capabilities()
	} else {
		caps = map[string]bool{}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"capabilities": caps}) //nolint:errcheck
}

func (h *handler) serveUDPRelay(w http.ResponseWriter, r *http.Request) {
	clientIP := remoteIP(r)
	token := r.Header.Get("X-Session")
	username, _, denied, transient := h.auth.validateSession(token)
	if denied {
		logWarnf("udp-relay: denied ip=%s token=%.8s…", clientIP, token)
		send404(w)
		return
	}
	if transient {
		http.Error(w, `{"error":"arbiter_unavailable"}`, http.StatusServiceUnavailable)
		return
	}

	key := sessionKey(token)
	rawBody, _ := io.ReadAll(r.Body)
	plain, err := openTunnelFrame(key, rawBody)
	if err != nil {
		logWarnf("udp-relay: decrypt fail ip=%s user=%s: %v", clientIP, username, err)
		send404(w)
		return
	}

	connID, dst, payload, err := parseUDPRelayFrame(plain)
	if err != nil {
		logWarnf("udp-relay: bad frame ip=%s user=%s: %v", clientIP, username, err)
		send404(w)
		return
	}

	if h.selfIPs[dst.IP.String()] {
		logWarnf("udp-relay: routing loop dst=%s user=%s", dst, username)
		send404(w)
		return
	}

	poolKey := udpSessionKey{connID: connID, dst: dst.String()}
	sess, err := h.udpPool.getOrCreate(poolKey, dst, username)
	if err != nil {
		logWarnf("udp-relay: dial failed user=%s dst=%s: %v", username, dst, err)
		send404(w)
		return
	}

	if len(payload) > 0 {
		sess.conn.SetWriteDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
		if _, err := sess.conn.Write(payload); err != nil {
			logWarnf("udp-relay: write failed user=%s dst=%s: %v", username, dst, err)
			h.udpPool.close(poolKey)
			send404(w)
			return
		}
	}

	// Drain up to 32 inbound datagrams, waiting at most 100ms for the first one.
	// Short wait keeps DNS request-response snappy while collecting QUIC ACKs.
	frames := sess.DrainRecv(100*time.Millisecond, 32)
	h.udpPool.recordActivity(poolKey)

	batch := encodeDatagramBatch(frames)
	resp, err := buildUploadResponse(key, batch)
	if err != nil {
		send404(w)
		return
	}
	logDebugf("udp-relay: user=%s conn=%.8s dst=%s payload=%d frames=%d", username, connID, dst, len(payload), len(frames))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(resp) //nolint:errcheck
}

// serveUDPDrain is a long-poll endpoint that returns buffered inbound datagrams
// for an existing UDP session without sending anything outbound. The client's
// drain goroutine calls this continuously to receive server-initiated datagrams
// (QUIC ACKs, SRTP, etc.) that arrive between TX requests.
func (h *handler) serveUDPDrain(w http.ResponseWriter, r *http.Request) {
	clientIP := remoteIP(r)
	token := r.Header.Get("X-Session")
	username, _, denied, transient := h.auth.validateSession(token)
	if denied {
		logWarnf("udp-drain: denied ip=%s token=%.8s…", clientIP, token)
		send404(w)
		return
	}
	if transient {
		http.Error(w, `{"error":"arbiter_unavailable"}`, http.StatusServiceUnavailable)
		return
	}

	key := sessionKey(token)
	rawBody, _ := io.ReadAll(r.Body)
	plain, err := openTunnelFrame(key, rawBody)
	if err != nil {
		logWarnf("udp-drain: decrypt fail ip=%s user=%s: %v", clientIP, username, err)
		send404(w)
		return
	}

	connID, dst, _, err := parseUDPRelayFrame(plain)
	if err != nil {
		logWarnf("udp-drain: bad frame ip=%s user=%s: %v", clientIP, username, err)
		send404(w)
		return
	}

	poolKey := udpSessionKey{connID: connID, dst: dst.String()}
	sess, err := h.udpPool.getOrCreate(poolKey, dst, username)
	if err != nil {
		logWarnf("udp-drain: dial failed user=%s dst=%s: %v", username, dst, err)
		send404(w)
		return
	}

	// Long-poll: wait up to 500ms for datagrams, then return whatever is buffered.
	frames := sess.DrainRecv(500*time.Millisecond, 64)
	h.udpPool.recordActivity(poolKey)

	batch := encodeDatagramBatch(frames)
	resp, err := buildUploadResponse(key, batch)
	if err != nil {
		send404(w)
		return
	}
	logDebugf("udp-drain: user=%s conn=%.8s dst=%s frames=%d", username, connID, dst, len(frames))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(resp) //nolint:errcheck
}

// encodeDatagramBatch packs N datagrams into [4B:N][4B:len][data]... format.
func encodeDatagramBatch(frames [][]byte) []byte {
	size := 4
	for _, f := range frames {
		size += 4 + len(f)
	}
	out := make([]byte, size)
	binary.BigEndian.PutUint32(out[:4], uint32(len(frames)))
	o := 4
	for _, f := range frames {
		binary.BigEndian.PutUint32(out[o:], uint32(len(f)))
		o += 4
		copy(out[o:], f)
		o += len(f)
	}
	return out
}

// parseUDPRelayFrame parses the plaintext of a /api/udp/relay request.
// Format: [16B conn_id][1B family 0x04/0x06][4/16B ip][2B port][4B body_len][body]
func parseUDPRelayFrame(plain []byte) (connID string, dst *net.UDPAddr, payload []byte, err error) {
	if len(plain) < 16+1+4+2+4 {
		return "", nil, nil, fmt.Errorf("frame too short: %d bytes", len(plain))
	}
	connID = hex.EncodeToString(plain[:16])
	family := plain[16]
	o := 17
	var ipBytes []byte
	switch family {
	case 0x04:
		if o+4 > len(plain) {
			return "", nil, nil, fmt.Errorf("truncated IPv4")
		}
		ipBytes = make([]byte, 4)
		copy(ipBytes, plain[o:o+4])
		o += 4
	case 0x06:
		if o+16 > len(plain) {
			return "", nil, nil, fmt.Errorf("truncated IPv6")
		}
		ipBytes = make([]byte, 16)
		copy(ipBytes, plain[o:o+16])
		o += 16
	default:
		return "", nil, nil, fmt.Errorf("unknown family 0x%02x", family)
	}
	if o+2+4 > len(plain) {
		return "", nil, nil, fmt.Errorf("truncated port/length")
	}
	port := int(binary.BigEndian.Uint16(plain[o:]))
	o += 2
	bLen := int(binary.BigEndian.Uint32(plain[o:]))
	o += 4
	if o+bLen > len(plain) {
		return "", nil, nil, fmt.Errorf("body length overflow: bLen=%d remaining=%d", bLen, len(plain)-o)
	}
	dst = &net.UDPAddr{IP: net.IP(ipBytes), Port: port}
	payload = plain[o : o+bLen]
	return
}

// servePeerConnect handles POST /api/peer/connect from a peer exit (Exit1).
// It authenticates Exit1 via X-Peer-Token, dials the requested target, then
// hijacks the HTTP connection and pipes bidirectionally — the hijacked TCP
// becomes the net.Conn that Exit1 wraps as a peerConn in its session pool.
func (h *handler) servePeerConnect(w http.ResponseWriter, r *http.Request) {
	peerIP := remoteIP(r)

	// Loop guard: Exit1 must set X-No-Forward so we never chain further.
	if r.Header.Get("X-No-Forward") != "1" {
		logWarnf("peer-connect: missing X-No-Forward from %s — rejecting", peerIP)
		http.Error(w, "X-No-Forward required", http.StatusBadRequest)
		return
	}

	peerToken := r.Header.Get("X-Peer-Token")
	peerAddr, ok := h.peerAuth.Validate(peerToken)
	if !ok {
		logWarnf("peer-connect: auth fail token=%.8s… ip=%s", peerToken, peerIP)
		send404(w)
		return
	}

	var req struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 512)).Decode(&req); err != nil || req.Target == "" {
		logWarnf("peer-connect: bad body from peer=%s ip=%s: %v", peerAddr, peerIP, err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Reject targets that would loop back to this exit.
	targetHost, _, _ := net.SplitHostPort(req.Target)
	if h.selfIPs[targetHost] {
		logWarnf("peer-connect: routing loop target=%s from peer=%s", req.Target, peerAddr)
		send404(w)
		return
	}

	targetConn, err := net.DialTimeout("tcp", req.Target, 10*time.Second)
	if err != nil {
		logWarnf("peer-connect: dial target=%s peer=%s: %v", req.Target, peerAddr, err)
		http.Error(w, "target unreachable", http.StatusBadGateway)
		return
	}

	// Upgrade: hijack the HTTP connection and hand it to the pipe.
	hj, ok := w.(http.Hijacker)
	if !ok {
		targetConn.Close()
		logErrorf("peer-connect: ResponseWriter does not support hijack")
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	clientConn, buf, err := hj.Hijack()
	if err != nil {
		targetConn.Close()
		logErrorf("peer-connect: hijack: %v", err)
		return
	}

	// Flush any buffered writes, then signal ready.
	buf.Flush()                                         //nolint:errcheck
	clientConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")) //nolint:errcheck

	logInfof("peer-connect: pipe open peer=%s target=%s", peerAddr, req.Target)
	start := time.Now()
	done := make(chan int64, 2)
	go func() { n, _ := io.Copy(targetConn, clientConn); done <- n }()
	go func() { n, _ := io.Copy(clientConn, targetConn); done <- n }()
	up := <-done
	targetConn.Close()
	clientConn.Close()
	down := <-done
	logInfof("peer-connect: pipe close peer=%s target=%s dur=%s up=%d down=%d bytes",
		peerAddr, req.Target, time.Since(start).Round(time.Millisecond), up, down)
}

func getSelfIPs() map[string]bool {
	ips := map[string]bool{
		"127.0.0.1": true,
		"::1":       true,
		"localhost": true,
	}
	hostname, _ := os.Hostname()
	if hostname != "" {
		addrs, _ := net.LookupHost(hostname)
		for _, a := range addrs {
			ips[a] = true
		}
	}
	return ips
}
