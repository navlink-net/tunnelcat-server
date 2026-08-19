// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	listen := flag.String("listen", ":443", "TCP address to listen on (host:port)")
	health := flag.String("health", "", "deprecated, unused")
	// arbiter is accepted and IMMEDIATELY DISCARDED -- deliberately not stored
	// anywhere. Control must never hold the arbiter's address for any reason
	// (see the 2026-08-10 audit: a direct control->arbiter dial was found and
	// removed from bananameter_probe.go, and every arbiterURL field that
	// merely stored the value without using it was stripped from
	// ExitRegistry/relayAPIHandler/ProbeSiteRegistry). This flag stays only
	// because every already-deployed control node's systemd unit passes
	// --arbiter in ExecStart; removing the flag outright would crash-loop the
	// whole fleet on next restart. Never wire this value into anything.
	_ = flag.String("arbiter", "", "deprecated, ignored — control never contacts the arbiter directly, only through exits")
	certDir := flag.String("cert-dir", "/var/lib/snc/certs", "directory for relay-API TLS cert/key (self-signed fallback)")
	certFile := flag.String("tls-cert", "", "TLS certificate file (PEM); use with --tls-key")
	keyFile := flag.String("tls-key", "", "TLS private key file (PEM); use with --tls-cert")
	token := flag.String("token", "", "node token issued by arbiter (required)")
	pubkeyHex := flag.String("pubkey", "", "arbiter Ed25519 pubkey hex (for exit-list signature verification)")
	nodeIP := flag.String("ip", "", "this node's public IP address (used for region auto-detection via CIDR/reverse-DNS)")
	region := flag.String("region", "", "override ISO-3166 region code (skips auto-detection)")
	updateDir := flag.String("update-dir", "", "directory with client update files (version, client, client.sha256); empty = disabled")
	updatePort := flag.String("update-port", ":8090", "HTTPS address for client update files; empty = disabled")
	version := flag.String("version", "", "current binary version string (e.g. 20260415); used for self-update check")
	logFile := flag.String("log", "", "log file path (rotated); stderr only if empty")
	exitsFlag := flag.String("exits", "", "comma-separated bootstrap exit addresses written at deploy time (e.g. 1.2.3.4:443,5.6.7.8:443)")
	bananameterNodeID := flag.String("bananameter-node-id", "", "shared BananaMeter node_id for the periodic tunnel-diagnostics probe; empty = probe disabled")
	bananameterNodeKey := flag.String("bananameter-node-key", "", "shared BananaMeter node_key for the periodic tunnel-diagnostics probe; empty = probe disabled")
	bananameterProberUser := flag.String("bananameter-prober-user", "", "dedicated service-account username used to log in through each exit for the bananameter probe; empty = probe disabled")
	bananameterProberPass := flag.String("bananameter-prober-pass", "", "dedicated service-account password for the bananameter probe; empty = probe disabled")
	flag.Parse()

	if err := initLogging(*logFile); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	startupBanner(*listen)

	var pubkey ed25519.PublicKey
	if *pubkeyHex != "" {
		b, err := hex.DecodeString(*pubkeyHex)
		if err != nil || len(b) != ed25519.PublicKeySize {
			logErrorf("--pubkey: invalid hex or wrong length (need 64 hex chars = 32 bytes)")
			os.Exit(1)
		}
		pubkey = ed25519.PublicKey(b)
		logInfof("arbiter pubkey loaded (%d bytes)", len(pubkey))
	} else {
		logWarnf("--pubkey not set: exit list signature verification disabled (dev mode)")
	}

	cacheFile := "/var/cache/snc-control/exits.json"
	exits := newExitRegistry(*token, pubkey, cacheFile)
	if *region != "" {
		// Manual override takes priority over auto-detection.
		exits.SetMyRegion(*region)
	}
	if *exitsFlag != "" {
		exits.LoadBootstrap(strings.Split(*exitsFlag, ","))
	}
	exits.LoadCached()
	exits.Start(60 * time.Second)

	newControlBananameterProber(exits, *token, *bananameterNodeID, *bananameterNodeKey,
		*bananameterProberUser, *bananameterProberPass).Start()

	probeSites := newProbeSiteRegistry(*token, "/var/cache/snc-control/probe-sites.json", exits)
	probeSites.Start(2 * time.Hour)

	exits.StartHealthChecker(probeSites)

	// CIDR cache: always start so proxyToExit can look up client countries.
	// Also used for control's own region auto-detection when --ip is set.
	cidrC := newCIDRCache(*token, exits)
	cidrC.Start()

	// Auto-detect region from --ip unless overridden by --region.
	if *region == "" && *nodeIP != "" {
		parsed := net.ParseIP(*nodeIP)
		if parsed == nil {
			logErrorf("--ip: invalid IP address %q", *nodeIP)
			os.Exit(1)
		}
		go func() {
			cc := detectRegionByIP(cidrC, parsed)
			if cc != "" {
				exits.SetMyRegion(cc)
			} else {
				logWarnf("region: auto-detect failed for IP %s — no region filter applied", *nodeIP)
			}
		}()
	}

	// Relay tracker API — served on port 443 alongside the TCP proxy.
	// Demuxed by TLS SNI: connections with SNI == relayAPISNI go here;
	// all other TLS connections are proxied verbatim to an exit node.
	var tlsCfg *tls.Config
	if *certFile != "" && *keyFile != "" {
		logInfof("tls: manual cert=%s key=%s", *certFile, *keyFile)
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			logErrorf("tls: load cert: %v", err)
			os.Exit(1)
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}}
	} else {
		var err error
		tlsCfg, err = selfSignedTLSConfig(*certDir)
		if err != nil {
			logErrorf("tls: %v", err)
			os.Exit(1)
		}
	}
	var cc *clientCache
	if *updateDir != "" && *token != "" {
		cc = newClientCache(*token, *updateDir, exits)
	}

	authC := newAuthCache(*token, exits)

	relayAPIH := newRelayAPIHandler(*updateDir, pubkey, func() {
		if err := exits.ForceRefresh(); err != nil {
			logWarnf("refresh: exit list reload: %v", err)
		}
	}, exits, *token, authC)
	if cc != nil {
		relayAPIH.onClientCacheRefresh = cc.Refresh
	}
	relayAPIH.contentChunks = newContentChunkCache(exits, *token)
	relayAPIH.startManifestPoller()
	relayAPIH.startClubManifestPoller()

	contentReg := newContentManifestRegistry(exits, *token, "/var/cache/snc-control/content-manifest.json")
	contentReg.LoadCached()
	contentReg.Start(contentManifestPollInterval)

	if *token != "" {
		// Watchdog: exit(1) if heartbeat stalls for >5 min so systemd restarts us.
		// Covers disk-I/O stalls that freeze the logger and all goroutines with it.
		startWatchdog(5 * time.Minute)
		startHeartbeat(exits, *token)
		startControlLogUploader(exits, *token)
	} else {
		logWarnf("--token not set: heartbeat and log upload disabled")
	}

	if *version != "" {
		exe, err := os.Executable()
		if err != nil {
			logWarnf("updater: executable: %v", err)
		} else {
			logInfof("updater: starting (version=%s binary=%s)", *version, exe)
			newControlUpdater(exits, *version, exe).Start()
		}
	} else {
		logWarnf("--version not set: self-update disabled")
	}

	if cc != nil {
		logInfof("client-cache: starting (dir=%s)", *updateDir)
		cc.Start()
	}

	if *updateDir != "" && *updatePort != "" {
		go startUpdateHTTP(*updatePort, *updateDir, *certFile, *keyFile)
	}

	_ = health // flag kept for backwards compatibility with existing deployments

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		logErrorf("listen %s: %v", *listen, err)
		os.Exit(1)
	}
	logInfof("TCP proxy listening on %s → exits (relay API pool: %d SNIs)", *listen, len(relayAPISNIPool))

	// UDP myip service on the same port number.
	// Client sends any datagram; server replies with the client's IP as plain text.
	udpAddr, _ := net.ResolveUDPAddr("udp", *listen)
	udpLn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		logErrorf("udp listen %s: %v", *listen, err)
		os.Exit(1)
	}
	logInfof("UDP reflector+tunnel+DHT listening on %s", *listen)
	tunnelH := newUDPTunnelHandler(udpLn, exits, relayAPIH)
	go tunnelH.gc()
	dhtSrv := newDHTServer(udpLn, *nodeIP)
	relayAPIH.onNewManifest = dhtSrv.SetManifest
	contentReg.OnNew = dhtSrv.SetContent
	go newUDPReflector(udpLn, tunnelH, dhtSrv).Serve()

	proxy := newTCPProxy(exits, relayAPIH, tlsCfg, cidrC, *token)
	exits.onDead = proxy.closeExitConns

	for {
		conn, err := ln.Accept()
		if err != nil {
			logErrorf("accept: %v", err)
			os.Exit(1)
		}
		go proxy.handle(conn)
	}
}
