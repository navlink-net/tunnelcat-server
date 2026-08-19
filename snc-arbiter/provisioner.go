// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type jobKind string

const (
	jobFull     jobKind = "full"     // initial deploy: install software, configure, start service
	jobToken    jobKind = "token"    // push token to already-deployed node and restart service
	jobTeardown jobKind = "teardown" // stop+disable the managed service on a node being decommissioned
)

type deployJob struct {
	kind   jobKind
	nodeID int64
	// full deploy only — held in memory, never persisted:
	authMethod string // "password" | "key" | "arbiter"
	password   string
	privKey    []byte
	// teardown only — captured at enqueue time since the DB row may already be gone
	// by the time the queue drains it:
	sshHost  string
	sshUser  string
	nodeType string
}

// provisioner manages an async queue of SSH node deployments.
type provisioner struct {
	db               *DB
	arbiterSigner    ssh.Signer // installed on all managed nodes; used for reconnection
	setupDir         string     // contains common.sh, exit.sh, control.sh, torrent-seed.sh, blackbadger.sh
	nodeBinDir       string     // contains snc-exit, snc-control binaries
	arbiterURL       string     // public URL of this arbiter (written into node env files)
	signingPubkeyHex string     // Ed25519 signing pubkey hex (written into node env files)
	queue            chan deployJob

	// torrent-seed (opentracker + transmission + publish nginx site) — installed
	// on every node type, best-effort. Empty serversDir/torrentDir disables it.
	serversDir string // contains arbiter.txt, control.txt, exit.txt (tracker announce list source)
	torrentDir string // contains sync-and-publish.sh, torrent-seed-sync.{service,timer}

	// BlackBadger (SOCKS5-SNC proxy) — installed on control nodes only,
	// best-effort. Empty blackbadgerBin/blackbadgerKey disables it.
	blackbadgerBin string // local path to the blackbadger binary
	blackbadgerKey string // shared SNC activation key installed into every instance
}

func newProvisioner(db *DB, signer ssh.Signer, setupDir, nodeBinDir, arbiterURL, sigPubkeyHex,
	serversDir, torrentDir, blackbadgerBin, blackbadgerKey string) *provisioner {
	p := &provisioner{
		db:               db,
		arbiterSigner:    signer,
		setupDir:         setupDir,
		nodeBinDir:       nodeBinDir,
		arbiterURL:       arbiterURL,
		signingPubkeyHex: sigPubkeyHex,
		serversDir:       serversDir,
		torrentDir:       torrentDir,
		blackbadgerBin:   blackbadgerBin,
		blackbadgerKey:   blackbadgerKey,
		queue:            make(chan deployJob, 64),
	}
	go p.worker()
	return p
}

// EnqueueFull schedules a full SSH deploy for nodeID.
// SSH credentials are held in memory only and never written to disk.
func (p *provisioner) EnqueueFull(nodeID int64, authMethod, password string, privKey []byte) {
	p.db.setDeployStatus(nodeID, "queued")
	p.queue <- deployJob{kind: jobFull, nodeID: nodeID, authMethod: authMethod, password: password, privKey: privKey}
}

// EnqueueTokenPush schedules a token update on an already-provisioned node.
// Connects using the arbiter's own SSH key (installed during initial deploy).
func (p *provisioner) EnqueueTokenPush(nodeID int64) {
	p.queue <- deployJob{kind: jobToken, nodeID: nodeID}
}

// EnqueueTeardown schedules stopping and disabling the managed service on a node
// being decommissioned. sshHost/sshUser/nodeType are captured by the caller before
// deleting the DB row, since the row is gone by the time this job runs.
// No-op if sshHost is empty (node was never SSH-provisioned by us).
func (p *provisioner) EnqueueTeardown(nodeID int64, sshHost, sshUser, nodeType string) {
	if sshHost == "" {
		return
	}
	p.queue <- deployJob{kind: jobTeardown, nodeID: nodeID, sshHost: sshHost, sshUser: sshUser, nodeType: nodeType}
}

func (p *provisioner) worker() {
	for job := range p.queue {
		var err error
		switch job.kind {
		case jobFull:
			err = p.runFull(job)
		case jobToken:
			err = p.runTokenPush(job)
		case jobTeardown:
			err = p.runTeardown(job)
		}
		if err != nil {
			logWarnf("provisioner: node=%d kind=%s: %v", job.nodeID, job.kind, err)
		}
	}
}

// ── Full deploy ───────────────────────────────────────────────────────────────

func (p *provisioner) runFull(job deployJob) error {
	p.db.setDeployStatus(job.nodeID, "running")
	if err := p.doFull(job); err != nil {
		p.db.setDeployStatus(job.nodeID, "failed")
		p.appendLog(job.nodeID, "ERROR: "+err.Error())
		return err
	}
	return nil
}

func (p *provisioner) doFull(job deployJob) error {
	info, err := p.db.getNodeProvisionInfo(job.nodeID)
	if err != nil {
		return fmt.Errorf("load node: %w", err)
	}
	user := info.SSHUser
	if user == "" {
		user = "root"
	}

	p.appendLog(job.nodeID, fmt.Sprintf("Connecting to %s@%s via SSH...", user, info.SSHHost))
	client, err := p.connect(info.SSHHost, user, job.authMethod, job.password, job.privKey)
	if err != nil {
		return fmt.Errorf("ssh connect %s@%s: %w", user, info.SSHHost, err)
	}
	defer client.Close()
	p.appendLog(job.nodeID, "Connected.")

	// Append the arbiter's key to authorized_keys so future reconnects (token push,
	// teardown) can authenticate — for root directly, for other accounts via sudo.
	// Pre-existing keys (the operator's own) are always kept: this pipeline never
	// owns the only path onto a box, since the arbiter's key/DB is itself a single
	// point of failure.
	homeDir := "~"
	if user == "root" {
		homeDir = "/root"
	}
	arbiterPubline := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(p.arbiterSigner.PublicKey())))
	addKeyCmd := fmt.Sprintf(
		`mkdir -p %s/.ssh && chmod 700 %s/.ssh && grep -qF %q %s/.ssh/authorized_keys 2>/dev/null || printf '%%s\n' %q >> %s/.ssh/authorized_keys; chmod 600 %s/.ssh/authorized_keys`,
		homeDir, homeDir, arbiterPubline, homeDir, arbiterPubline, homeDir, homeDir)
	if err := p.runCmd(client, job.nodeID, addKeyCmd); err != nil {
		return fmt.Errorf("add arbiter key to %s's authorized_keys: %w", user, err)
	}
	p.appendLog(job.nodeID, fmt.Sprintf("arbiter key added to %s's authorized_keys (existing keys kept).", user))

	// Disable password authentication.
	disablePwCmd := sudoWrap(`sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && `+
		`grep -q '^PasswordAuthentication no' /etc/ssh/sshd_config || echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config && `+
		`systemctl reload sshd 2>/dev/null || service ssh reload`, user)
	if err := p.runCmd(client, job.nodeID, disablePwCmd); err != nil {
		p.appendLog(job.nodeID, "WARN: could not disable password auth: "+err.Error())
	} else {
		p.appendLog(job.nodeID, "Password authentication disabled.")
	}

	// Upload binary (to /tmp first — always writable regardless of connecting user).
	binName := "snc-" + info.Type
	p.appendLog(job.nodeID, fmt.Sprintf("Uploading %s...", binName))
	if err := p.uploadFile(client, job.nodeID, filepath.Join(p.nodeBinDir, binName), "/tmp/"+binName+".new"); err != nil {
		return fmt.Errorf("upload binary: %w", err)
	}
	installBinCmd := sudoWrap(fmt.Sprintf(`mv /tmp/%s.new /usr/local/bin/%s && chmod +x /usr/local/bin/%s`, binName, binName, binName), user)
	if err := p.runCmd(client, job.nodeID, installBinCmd); err != nil {
		return fmt.Errorf("install binary: %w", err)
	}
	p.appendLog(job.nodeID, "Binary installed.")

	// Run common.sh.
	p.appendLog(job.nodeID, "Running common.sh...")
	if err := p.runScript(client, job.nodeID, filepath.Join(p.setupDir, "common.sh"), nil, user); err != nil {
		return fmt.Errorf("common.sh: %w", err)
	}

	// Run service-specific setup script with env vars.
	scriptName := info.Type + ".sh"
	p.appendLog(job.nodeID, fmt.Sprintf("Running %s...", scriptName))
	env := p.buildEnv(info)
	if err := p.runScript(client, job.nodeID, filepath.Join(p.setupDir, scriptName), env, user); err != nil {
		return fmt.Errorf("%s: %w", scriptName, err)
	}

	// Auxiliary services (torrent-seed on control/arbiter, BlackBadger on
	// control only) — best-effort: log and continue, never fail the main
	// deploy over these.
	//
	// Never on exit: exit nodes are internet-facing egress with the least
	// spare RAM/conntrack headroom of the three roles, and torrent-seed opens
	// well-known BitTorrent ports (6969, 51413) that get hit by constant bot
	// scanning. On 2026-08-05 this filled nf_conntrack on every exit node
	// torrent-seed had been installed on, dropping all new connections
	// (SSH, the snc-exit tunnel protocol itself) until each box was rebooted.
	if info.Type != "exit" {
		if err := p.runTorrentSeed(client, job.nodeID, user); err != nil {
			p.appendLog(job.nodeID, "WARN: torrent-seed: "+err.Error())
		}
	}
	if info.Type == "control" {
		if err := p.runBlackBadger(client, job.nodeID, user); err != nil {
			p.appendLog(job.nodeID, "WARN: blackbadger: "+err.Error())
		}
	}

	// Start the service only if the node already has a token (admin fast-path).
	// Pending nodes wait for the admin to approve; token-push will start the service then.
	if info.Token != "" {
		svcName := "snc-" + info.Type
		if err := p.runCmd(client, job.nodeID, sudoWrap("systemctl start "+svcName, user)); err != nil {
			return fmt.Errorf("start service: %w", err)
		}
		p.appendLog(job.nodeID, "Service started.")
		p.db.setDeployStatus(job.nodeID, "done")
	} else {
		p.appendLog(job.nodeID, "Node pending approval — service will start after token is pushed.")
		p.db.setDeployStatus(job.nodeID, "token_pending")
	}
	return nil
}

// ── Auxiliary services ───────────────────────────────────────────────────────

// runTorrentSeed uploads and runs torrent-seed.sh (opentracker + transmission +
// a static-file publish site over the node's own TLS cert). No-op if
// serversDir/torrentDir aren't configured. Mirrors the relative directory
// layout torrent-seed.sh expects (../servers, ../torrent next to itself).
func (p *provisioner) runTorrentSeed(client *ssh.Client, nodeID int64, user string) error {
	if p.serversDir == "" || p.torrentDir == "" {
		return nil
	}
	const root = "/tmp/snc-provision-torrent"
	if err := p.runCmd(client, nodeID, fmt.Sprintf("mkdir -p %s/setup %s/servers %s/torrent", root, root, root)); err != nil {
		return fmt.Errorf("mkdir remote tree: %w", err)
	}
	files := map[string]string{
		filepath.Join(p.setupDir, "torrent-seed.sh"):             root + "/setup/torrent-seed.sh",
		filepath.Join(p.serversDir, "arbiter.txt"):               root + "/servers/arbiter.txt",
		filepath.Join(p.serversDir, "control.txt"):               root + "/servers/control.txt",
		filepath.Join(p.serversDir, "exit.txt"):                  root + "/servers/exit.txt",
		filepath.Join(p.torrentDir, "sync-and-publish.sh"):       root + "/torrent/sync-and-publish.sh",
		filepath.Join(p.torrentDir, "torrent-seed-sync.service"): root + "/torrent/torrent-seed-sync.service",
		filepath.Join(p.torrentDir, "torrent-seed-sync.timer"):   root + "/torrent/torrent-seed-sync.timer",
	}
	for local, remote := range files {
		if _, err := os.Stat(local); err != nil {
			continue // servers/*.txt entries are optional — script tolerates missing ones
		}
		if err := p.uploadFile(client, nodeID, local, remote); err != nil {
			return fmt.Errorf("upload %s: %w", filepath.Base(local), err)
		}
	}
	runCmd := fmt.Sprintf("chmod +x %s/setup/torrent-seed.sh && bash %s/setup/torrent-seed.sh", root, root)
	if err := p.runCmd(client, nodeID, sudoWrap(runCmd, user)); err != nil {
		return err
	}
	p.appendLog(nodeID, "torrent-seed installed (opentracker + transmission + publish site).")
	return nil
}

// runBlackBadger uploads the blackbadger binary + blackbadger.sh and starts the
// service. No-op if blackbadgerBin/blackbadgerKey aren't configured.
func (p *provisioner) runBlackBadger(client *ssh.Client, nodeID int64, user string) error {
	if p.blackbadgerBin == "" || p.blackbadgerKey == "" {
		return nil
	}
	if err := p.uploadFile(client, nodeID, p.blackbadgerBin, "/tmp/blackbadger.new"); err != nil {
		return fmt.Errorf("upload binary: %w", err)
	}
	installCmd := "mv /tmp/blackbadger.new /usr/local/bin/blackbadger && chmod +x /usr/local/bin/blackbadger"
	if err := p.runCmd(client, nodeID, sudoWrap(installCmd, user)); err != nil {
		return fmt.Errorf("install binary: %w", err)
	}
	scriptPath := filepath.Join(p.setupDir, "blackbadger.sh")
	const remoteScript = "/tmp/snc-provision-blackbadger.sh"
	if err := p.uploadFile(client, nodeID, scriptPath, remoteScript); err != nil {
		return fmt.Errorf("upload blackbadger.sh: %w", err)
	}
	keyEscaped := strings.ReplaceAll(p.blackbadgerKey, "'", `'\''`)
	runCmd := fmt.Sprintf("chmod +x %s && BB_SNC_KEY='%s' bash %s && systemctl start blackbadger",
		remoteScript, keyEscaped, remoteScript)
	if err := p.runCmd(client, nodeID, sudoWrap(runCmd, user)); err != nil {
		return err
	}
	p.appendLog(nodeID, "BlackBadger installed and started.")
	return nil
}

// ── Token push ────────────────────────────────────────────────────────────────

func (p *provisioner) runTokenPush(job deployJob) error {
	info, err := p.db.getNodeProvisionInfo(job.nodeID)
	if err != nil {
		return fmt.Errorf("load node: %w", err)
	}
	if info.SSHHost == "" || info.DeployStatus != "token_pending" {
		return nil // node was not provisioned by us, nothing to do
	}
	if info.Token == "" {
		return fmt.Errorf("node %d has no token yet", job.nodeID)
	}

	user := info.SSHUser
	if user == "" {
		user = "root"
	}
	p.appendLog(job.nodeID, "Pushing token to node via SSH...")
	client, err := p.connect(info.SSHHost, user, "arbiter", "", nil)
	if err != nil {
		return fmt.Errorf("ssh connect %s@%s: %w", user, info.SSHHost, err)
	}
	defer client.Close()

	envFile := "/etc/snc/" + info.Type + ".env"
	// exit.sh uses SNC_ARBITER_TOKEN; control.sh uses SNC_TOKEN.
	var updateCmd string
	if info.Type == "exit" {
		updateCmd = fmt.Sprintf(
			`sed -i 's/^SNC_ARBITER_TOKEN=.*/SNC_ARBITER_TOKEN=%s/' %s`,
			info.Token, envFile)
	} else {
		updateCmd = fmt.Sprintf(
			`sed -i 's/^SNC_TOKEN=.*/SNC_TOKEN=%s/' %s`,
			info.Token, envFile)
	}
	updateCmd += fmt.Sprintf(` && systemctl start snc-%s`, info.Type)
	updateCmd = sudoWrap(updateCmd, user)

	if err := p.runCmd(client, job.nodeID, updateCmd); err != nil {
		return fmt.Errorf("push token: %w", err)
	}
	p.appendLog(job.nodeID, "Token pushed, service started.")
	p.db.setDeployStatus(job.nodeID, "done")
	return nil
}

// ── Teardown ──────────────────────────────────────────────────────────────────

// runTeardown stops and disables the managed service on a node being decommissioned,
// using the arbiter's own SSH key (installed during the initial deploy). Best-effort:
// the DB row is already gone by the time this runs, so failures are logged, not surfaced.
func (p *provisioner) runTeardown(job deployJob) error {
	user := job.sshUser
	if user == "" {
		user = "root"
	}
	client, err := p.connect(job.sshHost, user, "arbiter", "", nil)
	if err != nil {
		logWarnf("teardown: node=%d ssh connect %s@%s: %v", job.nodeID, user, job.sshHost, err)
		return err
	}
	defer client.Close()

	svc := "snc-" + job.nodeType
	cmd := sudoWrap(fmt.Sprintf("systemctl stop %s; systemctl disable %s", svc, svc), user)
	if err := p.runCmd(client, job.nodeID, cmd); err != nil {
		logWarnf("teardown: node=%d stop/disable %s: %v", job.nodeID, svc, err)
		return err
	}
	logInfof("teardown: node=%d %s@%s — %s stopped and disabled", job.nodeID, user, job.sshHost, svc)
	return nil
}

// ── SSH helpers ───────────────────────────────────────────────────────────────

func (p *provisioner) connect(host, user, authMethod, password string, privKey []byte) (*ssh.Client, error) {
	if user == "" {
		user = "root"
	}
	var auth []ssh.AuthMethod
	switch authMethod {
	case "password":
		auth = append(auth, ssh.Password(password))
	case "key":
		signer, err := ssh.ParsePrivateKey(privKey)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		auth = append(auth, ssh.PublicKeys(signer))
	case "arbiter":
		auth = append(auth, ssh.PublicKeys(p.arbiterSigner))
	default:
		return nil, fmt.Errorf("unknown auth method %q", authMethod)
	}

	addr := host
	if _, _, err := net.SplitHostPort(host); err != nil {
		addr = net.JoinHostPort(host, "22")
	}
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec -- admin-provided IPs
		Timeout:         60 * time.Second,
	}
	return ssh.Dial("tcp", addr, cfg)
}

// sudoWrap wraps cmd in a non-interactive sudo shell when user is not root.
// Requires passwordless sudo for user on the target host.
func sudoWrap(cmd, user string) string {
	if user == "" || user == "root" {
		return cmd
	}
	return "sudo -n bash -c " + shellSingleQuote(cmd)
}

func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func (p *provisioner) runCmd(client *ssh.Client, nodeID int64, cmd string) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	var buf bytes.Buffer
	sess.Stdout = &buf
	sess.Stderr = &buf
	err = sess.Run(cmd)
	for _, line := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if line != "" {
			p.appendLog(nodeID, "  "+line)
		}
	}
	return err
}

// runScript uploads script to /tmp on the remote and executes it with env vars.
// user selects whether the exec line is sudo-wrapped ("" or "root" = run as-is).
func (p *provisioner) runScript(client *ssh.Client, nodeID int64, localPath string, env map[string]string, user string) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", localPath, err)
	}
	remotePath := "/tmp/snc-provision-" + filepath.Base(localPath)
	if err := p.uploadBytes(client, data, remotePath); err != nil {
		return err
	}
	if err := p.runCmd(client, nodeID, "chmod +x "+remotePath); err != nil {
		return err
	}
	var envPrefix strings.Builder
	for k, v := range env {
		escaped := strings.ReplaceAll(v, "'", `'\''`)
		fmt.Fprintf(&envPrefix, "%s='%s' ", k, escaped)
	}
	return p.runCmd(client, nodeID, sudoWrap(envPrefix.String()+remotePath, user))
}

func (p *provisioner) uploadFile(client *ssh.Client, nodeID int64, localPath, remotePath string) error {
	p.appendLog(nodeID, fmt.Sprintf("  uploading %s → %s", filepath.Base(localPath), remotePath))
	data, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", localPath, err)
	}
	return p.uploadBytes(client, data, remotePath)
}

func (p *provisioner) uploadBytes(client *ssh.Client, data []byte, remotePath string) error {
	sess, err := client.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	sess.Stdin = bytes.NewReader(data)
	return sess.Run(fmt.Sprintf("cat > '%s'", remotePath))
}

func (p *provisioner) appendLog(nodeID int64, line string) {
	logInfof("provision[%d]: %s", nodeID, line)
	ts := time.Now().Format("15:04:05")
	p.db.appendNodeDeployLog(nodeID, ts+" "+line+"\n")
}

func (p *provisioner) buildEnv(info *nodeProvisionInfo) map[string]string {
	host, _, err := net.SplitHostPort(info.Addr)
	if err != nil {
		host = info.Addr
	}
	env := map[string]string{
		"SNC_HOST":          host,
		"SNC_EMAIL":         info.OwnerEmail,
		"SNC_ARBITER":       p.arbiterURL,
		"SNC_PUBKEY":        p.signingPubkeyHex,
		"SNC_ARBITER_TOKEN": info.Token, // exit.sh
		"SNC_TOKEN":         info.Token, // control.sh
	}
	if info.Type == "control" {
		// Control nodes never talk to the arbiter directly — they bootstrap
		// through a known exit. Without this, a freshly deployed control node
		// has no exit to reach and can't route any traffic.
		if exits, err := p.db.listApprovedNodes("exit"); err == nil && len(exits) > 0 {
			addrs := make([]string, len(exits))
			for i, n := range exits {
				addrs[i] = n.Addr
			}
			env["SNC_EXITS"] = strings.Join(addrs, ",")
		}
	}
	return env
}
