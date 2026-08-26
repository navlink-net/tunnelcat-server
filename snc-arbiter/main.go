// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"
)

func defaultCertDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/var/lib/snc-arbiter/certs"
	}
	return filepath.Join(home, ".snc-arbiter", "certs")
}

func defaultDB() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/var/lib/snc-arbiter/arbiter.db"
	}
	return filepath.Join(home, ".snc-arbiter", "arbiter.db")
}

func defaultSignKey() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/var/lib/snc-arbiter/arbiter.ed25519"
	}
	return filepath.Join(home, ".snc-arbiter", "arbiter.ed25519")
}

func main() {
	// ── keygen subcommand ─────────────────────────────────────────────────────
	// Usage: snc-arbiter keygen [--sign-key path]
	// Generates an Ed25519 key pair, saves the private key to --sign-key path,
	// and prints the public key in hex (for --pubkey flag of snc-control).
	if len(os.Args) > 1 && os.Args[1] == "keygen" {
		runKeygen(os.Args[2:])
		return
	}

	// ── serve subcommand (default) ────────────────────────────────────────────
	listen := flag.String("listen", ":443", "network control-plane address (host:port)")
	webListen := flag.String("web-listen", ":8080", "web/UI plane address — behind nginx (host:port); empty = disabled")
	authWith := flag.String("auth-with", "", "Camerlengo base URL for user auth (required)")
	apiKey := flag.String("api-key", "01Az8nB8mB4cCV", "Camerlengo API key")
	domain := flag.String("domain", "", "domain for Let's Encrypt TLS")
	certFile := flag.String("tls-cert", "", "TLS cert PEM (manual)")
	keyFile := flag.String("tls-key", "", "TLS key PEM (manual)")
	certFile2 := flag.String("tls-cert2", "", "second TLS cert PEM, selected by SNI when present (optional -- for a seamless IP-cert-to-domain-cert transition, see selectCertBySNI)")
	keyFile2 := flag.String("tls-key2", "", "second TLS key PEM (optional, pairs with --tls-cert2)")
	certDir := flag.String("cert-dir", defaultCertDir(), "TLS cert cache directory")
	noTLS := flag.Bool("no-tls", false, "serve plain HTTP (dev only)")
	dbPath := flag.String("db", defaultDB(), "SQLite database path")
	signKey := flag.String("sign-key", defaultSignKey(), "Ed25519 private key path for signing node lists")
	cidrOff := flag.Bool("no-cidr", false, "disable automatic CIDR download (bypass endpoint will return 404)")
	updateDir := flag.String("update-dir", "", "directory with update binaries (snc-control, snc-control.sha256, version); empty = disabled")
	appsAssetsDir := flag.String("apps-assets-dir", "", "shared sshfs-mounted directory for app-store icons/binaries (e.g. /mnt/remote/navlink/apps/assets), also served as static files by the app host; empty = app submission uploads disabled")
	contentDir := flag.String("content-dir", "", "directory mirrored to all clients via the content-manifest (torrent-like distribution); empty = disabled")
	uploadKey := flag.String("upload-key", "", "secret key required to upload client binaries via /admin/downloads/upload (empty = require admin session only)")
	peerArbiters := flag.String("peer-arbiters", "", "comma-separated base URLs of fellow arbiter cluster nodes (e.g. https://167.233.213.155) to replicate uploaded client binaries to; empty = no replication")
	appLogKey := flag.String("app-log-key", "", "bearer key embedded in client APKs for direct app-log upload via /api/log/app-upload (empty = disabled)")
	bananameterClientKey := flag.String("bananameter-client-key", "", "bearer key embedded in every client build for /api/bananameter/client-result (empty = disabled)")
	logUploadClientKey := flag.String("log-upload-client-key", "", "bearer key embedded in every client build for /api/log/client-upload (empty = disabled)")
	connStatsClientKey := flag.String("conn-stats-client-key", "", "legacy per-feature key; superseded by --client-telemetry-key before this feature shipped to any real client, safe to leave unset")
	clientTelemetryKey := flag.String("client-telemetry-key", "", "shared bearer key new client builds embed for every client-facing telemetry endpoint (app-log, bananameter, log-upload, conn-stats); empty = only legacy per-endpoint keys (if set) are accepted")
	logFile := flag.String("log", "", "log file path (rotated); stderr only if empty")
	arbiterURL := flag.String("arbiter-url", "", "public URL of this arbiter, written into provisioned node configs (e.g. https://navlink.net)")
	setupDir := flag.String("setup-dir", "/var/lib/snc/setup", "directory with setup scripts (common.sh, exit.sh, control.sh) for node provisioning")
	nodeBinDir := flag.String("node-bin-dir", "", "directory with snc-exit and snc-control binaries for node provisioning; empty = provisioning disabled")
	sshKeyFile := flag.String("ssh-key", "/var/lib/snc/arbiter_id_ed25519", "SSH private key used by provisioner to connect to managed nodes")
	serversDir := flag.String("servers-dir", "", "directory with arbiter.txt/control.txt/exit.txt for torrent-seed's tracker list; empty = torrent-seed step disabled")
	torrentDir := flag.String("torrent-dir", "", "directory with sync-and-publish.sh + torrent-seed-sync unit files; empty = torrent-seed step disabled")
	blackbadgerBin := flag.String("blackbadger-bin", "", "path to the blackbadger binary; empty = blackbadger step disabled (control nodes only)")
	blackbadgerKey := flag.String("blackbadger-key", "", "shared SNC key installed into every BlackBadger instance; empty = blackbadger step disabled")
	torrentSeedManifestURL := flag.String("torrent-seed-manifest-url", "", "URL of the torrent-seed fleet's published manifest.json (client software magnets); empty = TorrentMagnets field disabled")
	torrentSeedDataDir := flag.String("torrent-seed-data-dir", "", "TORRENT_DATA_DIR of a co-located torrent-seed.sh install (same value as that script's own TORRENT_DATA_DIR, e.g. /var/lib/torrent-seed) -- if set, this arbiter periodically writes its own signed manifest into <dir>/downloads/ and a matching .torrent into <dir>/torrents/ so the already-running transmission-daemon there picks it up and seeds it; empty = TorrentManifestMagnet field disabled")
	torrentTrackersFile := flag.String("torrent-trackers-file", "", "path to torrent-seed.sh's tracker host list (same file as its own TRACKER_LIST_FILE, e.g. /etc/torrent-seed/trackers.txt, one host per line) -- used to build the announce-list for this arbiter's own manifest torrent; empty = manifest torrent has no announce-list (DHT/PEX only)")
	flag.Parse()

	if *authWith == "" {
		fmt.Fprintln(os.Stderr, "error: --auth-with is required")
		os.Exit(1)
	}

	if err := initLoggingWithRing(*logFile); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	startupBanner(*listen, *authWith)

	// Ensure directories exist. dbPath may be a Postgres DSN instead of a
	// filesystem path -- filepath.Dir() on a DSN produces garbage, so only
	// create a directory for it when it's an actual SQLite file path.
	dirs := []string{filepath.Dir(*signKey)}
	if !isPostgresDSN(*dbPath) {
		dirs = append(dirs, filepath.Dir(*dbPath))
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			logErrorf("mkdir %s: %v", dir, err)
			os.Exit(1)
		}
	}

	db, err := openDB(*dbPath)
	if err != nil {
		logErrorf("db: %v", err)
		os.Exit(1)
	}
	logInfof("db: opened %s", *dbPath)

	signer, err := loadOrGenSigningKey(*signKey)
	if err != nil {
		logErrorf("signing key: %v", err)
		os.Exit(1)
	}
	logInfof("signing: pubkey = %s", signer.pubkeyHex())

	auth := newAuthClient(*authWith, *apiKey)
	sessions := newSessionManager(db, auth, signer)
	sessions.StartRefresher()
	h := newHandler(db, auth, signer, sessions, *authWith)
	h.updateDir = *updateDir
	h.appsAssetsDir = *appsAssetsDir
	h.contentDir = *contentDir
	h.torrentSeedManifestURL = *torrentSeedManifestURL
	h.torrentSeedDataDir = *torrentSeedDataDir
	h.torrentTrackersFile = *torrentTrackersFile
	if h.torrentSeedManifestURL != "" || h.torrentSeedDataDir != "" {
		h.startTorrentMagnets()
	}
	h.uploadKey = *uploadKey
	for _, p := range strings.Split(*peerArbiters, ",") {
		if p = strings.TrimSpace(p); p != "" {
			h.peerArbiters = append(h.peerArbiters, p)
		}
	}
	h.appLogKey = *appLogKey
	h.bananameterClientKey = *bananameterClientKey
	h.logUploadClientKey = *logUploadClientKey
	h.connStatsClientKey = *connStatsClientKey
	h.clientTelemetryKey = *clientTelemetryKey
	h.notifier = newNotifier(db, signer)
	h.loadNotificationsFromDB()
	h.startWLWTPPortRotator()
	h.StartLoadFactorTicker(5 * time.Minute)

	// ── Node provisioner (SSH deploy) ─────────────────────────────────────────
	if *nodeBinDir != "" {
		sshSigner, err := loadOrGenArbiterSSHKey(*sshKeyFile)
		if err != nil {
			logWarnf("ssh key %s: %v — node provisioning disabled", *sshKeyFile, err)
		} else {
			publine := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(sshSigner.PublicKey())))
			logInfof("ssh: arbiter pubkey = %s", publine)
			url := *arbiterURL
			if url == "" && *domain != "" {
				url = "https://" + *domain
			}
			h.provisioner = newProvisioner(db, sshSigner, *setupDir, *nodeBinDir, url, signer.pubkeyHex(),
				*serversDir, *torrentDir, *blackbadgerBin, *blackbadgerKey)
			logInfof("provisioner: ready (setup=%s bins=%s)", *setupDir, *nodeBinDir)
		}
	} else {
		logInfof("provisioner: disabled (--node-bin-dir not set)")
	}
	if !IsMounted(remoteLogBase) {
		logErrorf("remote storage not mounted: %s is inaccessible — start mnt-remote.service", remoteLogBase)
		os.Exit(1)
	}
	h.logs = newNodeLogStore(remoteLogBase)
	h.logs.StartCleanup()
	startArbiterLogUploader(h.logs)
	h.startStatsArchiver()
	h.startUsageSampler()
	if !*cidrOff {
		logInfof("cidr: starting auto-download (RU, US, CN, IR, EU); refresh every 4h")
		StartCIDRRefresher(h, 4*time.Hour)
	} else {
		logInfof("cidr: auto-download disabled (--no-cidr)")
	}

	// ── Web plane (plain HTTP, behind nginx) ─────────────────────────────────
	if *webListen != "" {
		web := &webPlane{h}
		go func() {
			logInfof("web: listening on %s (plain HTTP, behind nginx)", *webListen)
			if err := http.ListenAndServe(*webListen, web); err != nil {
				logErrorf("web: fatal: %v", err)
				os.Exit(1)
			}
		}()
	}

	// ── Network control plane ─────────────────────────────────────────────────
	switch {
	case *noTLS:
		logWarnf("tls: disabled (--no-tls) — running plain HTTP on %s", *listen)
		if err := http.ListenAndServe(*listen, h); err != nil {
			logErrorf("fatal: %v", err)
			os.Exit(1)
		}

	case *certFile != "" && *keyFile != "" && *certFile2 != "" && *keyFile2 != "":
		logInfof("tls: dual manual cert cert1=%s cert2=%s (selected by SNI)", *certFile, *certFile2)
		tlsCfg, err := dualCertTLSConfig(*certFile, *keyFile, *certFile2, *keyFile2)
		if err != nil {
			logErrorf("tls: dual cert: %v", err)
			os.Exit(1)
		}
		srv := &http.Server{Addr: *listen, Handler: h, TLSConfig: tlsCfg}
		if err := srv.ListenAndServeTLS("", ""); err != nil {
			logErrorf("fatal: %v", err)
			os.Exit(1)
		}

	case *certFile != "" && *keyFile != "":
		logInfof("tls: manual cert=%s key=%s", *certFile, *keyFile)
		if err := http.ListenAndServeTLS(*listen, *certFile, *keyFile, h); err != nil {
			logErrorf("fatal: %v", err)
			os.Exit(1)
		}

	case *domain != "":
		if err := os.MkdirAll(*certDir, 0700); err != nil {
			logErrorf("cert-dir: %v", err)
			os.Exit(1)
		}
		m := newAutocertManager(*domain, *certDir)
		go func() {
			logInfof("tls: HTTP-01 challenge listener on :80")
			if err := http.ListenAndServe(":80", m.HTTPHandler(nil)); err != nil {
				logWarnf("tls: HTTP-01 listener: %v", err)
			}
		}()
		logInfof("tls: autocert domain=%s cert-dir=%s", *domain, *certDir)
		srv := &http.Server{Addr: *listen, Handler: h, TLSConfig: m.TLSConfig()}
		if err := srv.ListenAndServeTLS("", ""); err != nil {
			logErrorf("fatal: %v", err)
			os.Exit(1)
		}

	default:
		tlsCfg, err := selfSignedTLSConfig(*certDir)
		if err != nil {
			logErrorf("tls: self-signed: %v", err)
			os.Exit(1)
		}
		srv := &http.Server{Addr: *listen, Handler: h, TLSConfig: tlsCfg}
		if err := srv.ListenAndServeTLS("", ""); err != nil {
			logErrorf("fatal: %v", err)
			os.Exit(1)
		}
	}
}
