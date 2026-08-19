// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/acme/autocert"
)

func defaultCertDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/var/lib/snc-exit/certs"
	}
	return filepath.Join(home, ".snc-exit", "certs")
}

func main() {
	listen := flag.String("listen", ":443", "address to listen on (host:port)")
	arbiterURL := flag.String("arbiter", "", "arbiter base URL (required)")
	arbiterToken := flag.String("arbiter-token", "", "node token issued by arbiter (required)")
	arbiterPubkeyHex := flag.String("arbiter-pubkey", "", "arbiter Ed25519 pubkey hex (for /p/node/v1/refresh signature verification)")
	controlCacheDir := flag.String("control-cache-dir", "", "directory for caching snc-control binary; empty = control update serving disabled")
	logFile := flag.String("log", "", "log file path (rotated at 10 MB × 5 files); stderr only if empty")
	domain := flag.String("domain", "", "domain name for automatic Let's Encrypt TLS (e.g. vpn.example.com)")
	certFile := flag.String("tls-cert", "", "TLS certificate file (PEM); use with --tls-key for manual cert")
	keyFile := flag.String("tls-key", "", "TLS private key file (PEM); use with --tls-cert for manual cert")
	certDir := flag.String("cert-dir", defaultCertDir(), "directory to cache TLS certificates (Let's Encrypt or self-signed)")
	noTLS := flag.Bool("no-tls", false, "disable TLS and serve plain HTTP (not recommended)")
	bananameterNodeID := flag.String("bananameter-node-id", "", "shared BananaMeter node_id for the periodic tunnel-diagnostics probe; empty = probe disabled")
	bananameterNodeKey := flag.String("bananameter-node-key", "", "shared BananaMeter node_key for the periodic tunnel-diagnostics probe; empty = probe disabled")
	providerTag := flag.String("provider-tag", "", "hosting-provider tag for this node (e.g. \"HETZNER\"); matched against admin-configured service-region-block rules the same way --region is, so a rule can target a provider across all its regions instead of one region at a time")
	flag.Parse()

	if *arbiterURL == "" || *arbiterToken == "" {
		fmt.Fprintln(os.Stderr, "error: --arbiter and --arbiter-token are required")
		os.Exit(1)
	}

	if err := initLogging(*logFile); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	startupBanner(*listen, *arbiterURL)
	startDataPlaneProber()
	startExitLogUploader(*arbiterURL, *arbiterToken)
	newBananameterProber(*arbiterURL, *arbiterToken, *bananameterNodeID, *bananameterNodeKey).Start()

	logInfof("arbiter: heartbeat → %s", *arbiterURL)
	// fingerprint is set after TLS config is resolved below; heartbeat is started there.
	// probe is wired in below after the whitelist is initialized.
	var heartbeatStarted bool
	var exitProbe *WhitelistProbe
	startHeartbeatOnce := func(fp string) {
		if !heartbeatStarted {
			heartbeatStarted = true
			startArbiterHeartbeat(*arbiterURL, *arbiterToken, fp, exitProbe)
		}
	}

	cidrC := newCIDRCache(*arbiterURL, *arbiterToken)
	cidrC.Start()

	h := newHandler(*arbiterURL, *arbiterToken, cidrC)
	h.providerTag = strings.ToUpper(strings.TrimSpace(*providerTag))

	peers := newPeerRegistry(h.auth)
	peers.Start()
	h.peers = peers

	// Node proxy: unauthenticated (but TLS) endpoints for control nodes.
	var arbiterPubkey ed25519.PublicKey
	if *arbiterPubkeyHex != "" {
		b, err := hex.DecodeString(*arbiterPubkeyHex)
		if err != nil || len(b) != ed25519.PublicKeySize {
			logErrorf("--arbiter-pubkey: invalid hex or wrong length")
			os.Exit(1)
		}
		arbiterPubkey = ed25519.PublicKey(b)
	}
	if *controlCacheDir != "" {
		if err := os.MkdirAll(*controlCacheDir, 0755); err != nil {
			logErrorf("control-cache-dir: %v", err)
			os.Exit(1)
		}
	}
	// certDir backs whitelist/service-blocks/anon-bootstrap disk caches and
	// probe.db below -- create it unconditionally here. Previously this was
	// only done inside the autocert/self-signed TLS branches further down,
	// so exits running with --tls-cert/--tls-key (manual Let's Encrypt certs,
	// e.g. deploy/setup/exit.sh's certbot flow) never got the directory and
	// silently ran with in-memory-only caches (disk-cache writes failing with
	// ENOENT every refresh, logged as warnings).
	if err := os.MkdirAll(*certDir, 0700); err != nil {
		logErrorf("cert-dir: %v", err)
		os.Exit(1)
	}
	cc := newControlCache(*arbiterURL, *arbiterToken, *controlCacheDir)
	cc.Start()
	h.nodeProx = newNodeProxy(
		*arbiterURL, *arbiterToken,
		arbiterPubkey,
		*controlCacheDir,
		h.auth,
		h.cachedManifest,
		cc.Refresh,
	)

	wl := newWhitelistCache(*arbiterURL, *arbiterToken, arbiterPubkey,
		filepath.Join(*certDir, "whitelist-cache.json"))
	wl.Start()
	h.wl = wl

	svcBlocks := newServiceBlockCache(*arbiterURL, *arbiterToken, arbiterPubkey,
		filepath.Join(*certDir, "service-blocks-cache.json"))
	svcBlocks.Start()
	h.svcBlocks = svcBlocks

	torrentAllowed := newTorrentAllowedCache(*arbiterURL, *arbiterToken, arbiterPubkey)
	torrentAllowed.Start()
	h.torrentAllowed = torrentAllowed

	anonBoot := newAnonBootstrapCache(*arbiterURL, *arbiterToken, arbiterPubkey,
		filepath.Join(*certDir, "anon-bootstrap-cache.json"))
	anonBoot.Start()
	h.anonBoot = anonBoot

	if probe, err := newWhitelistProbe(filepath.Join(*certDir, "probe.db")); err != nil {
		logWarnf("whitelist-probe: init failed: %v — capability routing disabled", err)
	} else {
		exitProbe = probe
		probe.Start(wl)
		h.probeDB = probe
	}

	bl := newBlacklistCache(*arbiterURL, *arbiterToken, arbiterPubkey)
	bl.Start()
	h.bl = bl

	// UDP tunnel listener (same port as TCP; independent of TLS).
	if udpPC, err := net.ListenPacket("udp", *listen); err != nil {
		logWarnf("udp-exit: failed to start listener on %s: %v", *listen, err)
	} else {
		go newUDPExitHandler(udpPC.(*net.UDPConn), h).serve()
		logInfof("udp-exit: listening on %s", *listen)
	}

	switch {
	case *noTLS:
		logWarnf("tls: disabled (--no-tls) — running plain HTTP on %s", *listen)
		startHeartbeatOnce("")
		if err := http.ListenAndServe(*listen, h); err != nil {
			logErrorf("fatal: %v", err)
			os.Exit(1)
		}

	case *certFile != "" && *keyFile != "":
		logInfof("tls: manual cert=%s key=%s", *certFile, *keyFile)
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			logErrorf("tls: load cert: %v", err)
			os.Exit(1)
		}
		startHeartbeatOnce(tlsCertFP(cert))
		tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
		if err := serveTLS(tlsCfg, *listen, h); err != nil {
			logErrorf("fatal: %v", err)
			os.Exit(1)
		}

	case *domain != "":
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(*domain),
			Cache:      autocert.DirCache(*certDir),
		}
		go func() {
			logInfof("tls: HTTP-01 challenge listener on :80")
			if err := http.ListenAndServe(":80", m.HTTPHandler(nil)); err != nil {
				logWarnf("tls: HTTP listener: %v", err)
			}
		}()
		// Fingerprint unknown at startup for autocert (cert fetched lazily); send empty.
		startHeartbeatOnce("")
		logInfof("tls: autocert domain=%s cert-dir=%s", *domain, *certDir)
		if err := serveTLS(m.TLSConfig(), *listen, h); err != nil {
			logErrorf("fatal: %v", err)
			os.Exit(1)
		}

	default:
		// No domain — self-signed cert, generated once and reused.
		tlsCfg, err := selfSignedTLSConfig(*certDir)
		if err != nil {
			logErrorf("tls: self-signed cert: %v", err)
			os.Exit(1)
		}
		if len(tlsCfg.Certificates) > 0 {
			startHeartbeatOnce(tlsCertFP(tlsCfg.Certificates[0]))
		} else {
			startHeartbeatOnce("")
		}
		if err := serveTLS(tlsCfg, *listen, h); err != nil {
			logErrorf("fatal: %v", err)
			os.Exit(1)
		}
	}
}

// tlsCertFP returns the SHA-256 fingerprint (colon-hex) of the leaf certificate.
func tlsCertFP(cert tls.Certificate) string {
	if len(cert.Certificate) == 0 {
		return ""
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return ""
	}
	h := sha256.Sum256(leaf.Raw)
	parts := make([]string, len(h))
	for i, b := range h {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}
