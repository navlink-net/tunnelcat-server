// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	anatorrent "github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/metainfo"
	"golang.org/x/time/rate"
)

// ── feature gate ─────────────────────────────────────────────────────────────
//
// Not a user-facing feature: there is no client UI or local settings toggle
// for this at all. The only control is the arbiter's manifest-level
// torrent_enabled kill switch (see admin_torrent_enabled.go), read directly
// via TorrentManifestAllowed() -- a process-global atomic set by
// Discoverer.setControls, same pattern as ipv6TunnelDisabled. This lets the
// feature be turned off fleet-wide without a client release; there is
// nothing for platform code to wire up locally.

// ── engine ────────────────────────────────────────────────────────────────
//
// Deliberately DIRECT, not tunnel-routed: this engine's purpose is to make
// client machines additional peers in the same swarm the server fleet's
// opentracker/transmission-daemon boxes already seed shortnerdcat binaries
// through (see deploy/setup/torrent-seed.sh and
// snc-arbiter --torrent-dir). That swarm exists specifically so software
// distribution survives the known seed/tracker server IPs being blocked --
// routing this client's own torrent traffic through the VPN tunnel would
// make it just another dependent of the same infrastructure it's meant to
// backstop, defeating the point. So: real DHT, real PEX, real (HTTP+UDP)
// tracker announces, inbound peer connections accepted -- all using the
// host's normal network path, independent of whether the tunnel is
// connected at all.
type TorrentEngine struct {
	dataDir string

	mu      sync.Mutex
	client  *anatorrent.Client
	downLim *rate.Limiter
	upLim   *rate.Limiter
	paused  map[metainfo.Hash]bool
}

// NewTorrentEngine constructs an engine that will store downloaded data
// under dataDir. Start() still must be called (and TorrentManifestAllowed()
// must be true) before it does anything.
func NewTorrentEngine(dataDir string) *TorrentEngine {
	return &TorrentEngine{
		dataDir: dataDir,
		paused:  make(map[metainfo.Hash]bool),
	}
}

// Start brings up the underlying torrent.Client if the manifest currently
// allows it. Safe to call repeatedly; a no-op once already running.
//
// localIP is called once, synchronously, to get the host's real NIC IP
// (same value BypassManager.SetLocalIP records, read back via its LocalIP()
// getter) -- pass nil or have it return "" if no bypass IP is available
// (e.g. bypass detection hasn't finished yet); the engine then falls back
// to letting the OS pick, same as before this parameter existed.
//
// Every socket this engine opens (DHT/uTP listener, outbound peer dials,
// HTTP+UDP tracker announces) gets bound to that address instead of letting
// the OS pick a source address -- on Windows/Mac/Linux, once this app's own
// TUN adapter becomes the default route, an unbound dial gets swept into
// OUR OWN tunnel despite this whole engine being deliberately designed to
// run outside it (see this file's top doc comment: "independent of whether
// the tunnel is connected at all"). Confirmed live, 2026-08-28: hundreds of
// real DHT/tracker/peer connections showed up in the client's own tunnel
// relay log (socks5: CONNECT ...:6969 etc.) instead of going out directly,
// competing for the same limited tunnel bandwidth as everything else routed
// through it (email, browsing, ...). This mirrors BypassManager.
// BypassDialer/DialUDP's exact mechanism (LocalAddr binding, same
// dialControl hook) rather than inventing a second one.
func (e *TorrentEngine) Start(localIP func() string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !TorrentManifestAllowed() {
		return fmt.Errorf("torrent: feature disabled (manifest_allowed=false)")
	}
	if e.client != nil {
		return nil
	}

	cfg := anatorrent.NewDefaultClientConfig()
	cfg.DataDir = e.dataDir
	// ListenPort=0 -- OS picks a free ephemeral port for both the TCP peer
	// listener and the DHT/uTP UDP socket, same convention as net.Listen
	// with port 0. Critical so a second SNC client instance on the same
	// machine (dev+prod build, or the user running it twice) never fights
	// this one for a fixed port -- the library's own default (42069) is
	// fixed and would collide.
	cfg.ListenPort = 0
	cfg.Seed = true // upload to any peer, not just ones we ourselves completed a download from

	var ip string
	if localIP != nil {
		ip = localIP()
	}
	if ip != "" {
		cfg.ListenHost = func(string) string { return ip }
		bindDialer := &net.Dialer{
			Timeout:   15 * time.Second,
			LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip)},
			Control:   dialControl,
		}
		cfg.TrackerDialContext = bindDialer.DialContext
		cfg.HTTPDialContext = bindDialer.DialContext
	} else {
		Log.Printf("torrent: no bypass NIC IP available yet -- sockets unbound, may route through the tunnel until bypass detection finishes")
	}

	e.downLim = rate.NewLimiter(rate.Inf, 1<<20)
	e.upLim = rate.NewLimiter(rate.Inf, 1<<20)
	cfg.DownloadRateLimiter = e.downLim
	cfg.UploadRateLimiter = e.upLim

	cl, err := anatorrent.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("torrent: start: %w", err)
	}
	e.client = cl
	Log.Printf("torrent: engine started, data_dir=%s listen=%s", e.dataDir, cl.ListenAddrs())
	return nil
}

// Stop tears down the underlying torrent.Client, dropping all torrents.
// Safe to call when not running.
func (e *TorrentEngine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.client == nil {
		return
	}
	e.client.Close()
	e.client = nil
	e.paused = make(map[metainfo.Hash]bool)
	Log.Printf("torrent: engine stopped")
}

// TorrentDefaultDownloadBps/TorrentDefaultUploadBps: the rate cap every
// platform's main_*.go applies via SetRateLimits right after Start().
// Single shared source of truth so the three call sites (win/mac/linux)
// can't drift apart. Added 2026-08-28: the engine has always started with
// no limit at all (its internal limiters default to rate.Inf) and nothing
// in any client ever called SetRateLimits -- confirmed live, the real
// TorrentEngine (DHT+PEX+tracker announces, Seed=true, deliberately DIRECT
// per this file's own doc comment) ran fully unthrottled on every platform
// since it was added, competing for the host's whole network capacity.
// 1MB/s down / 256KB/s up is deliberately conservative for a background,
// invisible-to-the-user swarm contribution -- not tuned against a specific
// benchmark, just picked to be clearly non-disruptive; revisit if seeding
// throughput for the software-distribution swarm needs to be higher.
const (
	TorrentDefaultDownloadBps int64 = 1 << 20         // 1 MB/s
	TorrentDefaultUploadBps   int64 = 256 * (1 << 10) // 256 KB/s
)

// SetRateLimits sets global download/upload caps in bytes/sec. 0 = unlimited.
// A no-op if the engine hasn't been Start()ed yet -- call again after Start.
func (e *TorrentEngine) SetRateLimits(downBps, upBps int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.downLim != nil {
		e.downLim.SetLimit(bpsToLimit(downBps))
	}
	if e.upLim != nil {
		e.upLim.SetLimit(bpsToLimit(upBps))
	}
}

func bpsToLimit(bps int64) rate.Limit {
	if bps <= 0 {
		return rate.Inf
	}
	return rate.Limit(bps)
}

// AddMagnet adds a torrent from a magnet URI (e.g. one of the
// torrent-seed.sh-published magnets -- see manifest.json on the seed
// fleet). Fails if the engine isn't running (see Start).
func (e *TorrentEngine) AddMagnet(uri string) (metainfo.Hash, error) {
	e.mu.Lock()
	cl := e.client
	e.mu.Unlock()
	if cl == nil {
		return metainfo.Hash{}, fmt.Errorf("torrent: engine not running")
	}
	t, err := cl.AddMagnet(uri)
	if err != nil {
		return metainfo.Hash{}, fmt.Errorf("torrent: add magnet: %w", err)
	}
	go func() {
		<-t.GotInfo()
		t.DownloadAll()
	}()
	return t.InfoHash(), nil
}

// AddTorrentFile adds a torrent from a local .torrent file path.
func (e *TorrentEngine) AddTorrentFile(path string) (metainfo.Hash, error) {
	e.mu.Lock()
	cl := e.client
	e.mu.Unlock()
	if cl == nil {
		return metainfo.Hash{}, fmt.Errorf("torrent: engine not running")
	}
	t, err := cl.AddTorrentFromFile(path)
	if err != nil {
		return metainfo.Hash{}, fmt.Errorf("torrent: add file: %w", err)
	}
	t.DownloadAll()
	return t.InfoHash(), nil
}

// TorrentItem is a snapshot of one torrent's current state.
type TorrentItem struct {
	InfoHash   string  `json:"infoHash"`
	Name       string  `json:"name"`
	Length     int64   `json:"length"`     // total bytes; 0 until metadata arrives
	Downloaded int64   `json:"downloaded"` // bytes completed so far
	Progress   float64 `json:"progress"`   // 0..1; 0 if Length unknown
	NumPeers   int     `json:"numPeers"`
	Paused     bool    `json:"paused"`
	Done       bool    `json:"done"`
	HaveInfo   bool    `json:"haveInfo"` // false while still fetching metadata
}

// List returns a snapshot of every torrent currently known to the engine.
func (e *TorrentEngine) List() []TorrentItem {
	e.mu.Lock()
	cl := e.client
	paused := e.paused
	e.mu.Unlock()
	if cl == nil {
		return nil
	}
	var out []TorrentItem
	for _, t := range cl.Torrents() {
		item := TorrentItem{
			InfoHash: t.InfoHash().HexString(),
			Paused:   paused[t.InfoHash()],
		}
		select {
		case <-t.GotInfo():
			item.HaveInfo = true
			item.Name = t.Name()
			item.Length = t.Length()
			item.Downloaded = t.BytesCompleted()
			if item.Length > 0 {
				item.Progress = float64(item.Downloaded) / float64(item.Length)
			}
			item.Done = item.Length > 0 && item.Downloaded >= item.Length
		default:
			item.Name = t.InfoHash().HexString()
		}
		item.NumPeers = t.Stats().TotalPeers
		out = append(out, item)
	}
	return out
}

// Pause stops downloading/uploading a torrent without removing it.
func (e *TorrentEngine) Pause(infoHash metainfo.Hash) error {
	t, ok := e.findTorrent(infoHash)
	if !ok {
		return fmt.Errorf("torrent: %s not found", infoHash.HexString())
	}
	t.DisallowDataDownload()
	t.DisallowDataUpload()
	e.mu.Lock()
	e.paused[infoHash] = true
	e.mu.Unlock()
	return nil
}

// Resume re-enables a previously paused torrent.
func (e *TorrentEngine) Resume(infoHash metainfo.Hash) error {
	t, ok := e.findTorrent(infoHash)
	if !ok {
		return fmt.Errorf("torrent: %s not found", infoHash.HexString())
	}
	t.AllowDataDownload()
	t.AllowDataUpload()
	e.mu.Lock()
	delete(e.paused, infoHash)
	e.mu.Unlock()
	return nil
}

// Remove drops a torrent from the engine. deleteData also removes its files
// on disk (best-effort; errors are logged, not returned, since the torrent
// is dropped from the client regardless).
func (e *TorrentEngine) Remove(infoHash metainfo.Hash, deleteData bool) error {
	t, ok := e.findTorrent(infoHash)
	if !ok {
		return fmt.Errorf("torrent: %s not found", infoHash.HexString())
	}
	t.Drop()
	e.mu.Lock()
	delete(e.paused, infoHash)
	e.mu.Unlock()
	if deleteData {
		removeTorrentData(e.dataDir, t)
	}
	return nil
}

func (e *TorrentEngine) findTorrent(infoHash metainfo.Hash) (*anatorrent.Torrent, bool) {
	e.mu.Lock()
	cl := e.client
	e.mu.Unlock()
	if cl == nil {
		return nil, false
	}
	for _, t := range cl.Torrents() {
		if t.InfoHash() == infoHash {
			return t, true
		}
	}
	return nil, false
}

// removeTorrentData best-effort deletes a completed torrent's files under
// dataDir. Separated out mainly so the deletion logic (single file vs.
// multi-file torrent layout) has one place to be gotten right rather than
// being inlined into Remove.
func removeTorrentData(dataDir string, t *anatorrent.Torrent) {
	select {
	case <-t.GotInfo():
	default:
		return // never got metadata -- nothing on disk to remove
	}
	info := t.Info()
	if info == nil {
		return
	}
	// A torrent's data lives at dataDir/<info.Name> whether it's a single
	// file or a multi-file directory (anacrolix/torrent's own on-disk
	// layout convention) -- one RemoveAll covers both cases.
	target := filepath.Join(dataDir, info.Name)
	if err := os.RemoveAll(target); err != nil {
		Log.Printf("torrent: delete data %s: %v", target, err)
	}
}
