// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/anacrolix/torrent/bencode"
	"github.com/anacrolix/torrent/metainfo"
)

// torrent_magnets.go surfaces two pieces of torrent-swarm info in the
// signed manifest, alongside the pre-existing torrent_enabled kill switch
// (admin_torrent_enabled.go) and the unrelated content-manifest feature
// (content_manifest.go):
//
//  1. TorrentMagnets: magnet links for every client-software package the
//     torrent-seed fleet already seeds (see deploy/setup/torrent-seed.sh /
//     sync-and-publish.sh, which republish these + a manifest.json every 15
//     min). Fetched from torrentSeedManifestURL, a plain public HTTPS GET --
//     same read-only isolation principle sync-and-publish.sh itself uses,
//     no new trust relationship.
//  2. TorrentManifestMagnet: a magnet for this arbiter's OWN current signed
//     control-node manifest, so a client that can't reach any control/exit
//     at all can still recover a manifest via the torrent swarm. Built
//     in-process (BuildFromFilePath + GeneratePieces) and dropped into a
//     co-located torrent-seed.sh install's downloads/+torrents/ dirs so its
//     already-running transmission-daemon picks it up and seeds it --
//     reuses that daemon rather than running a second one from Go.
//
// Both refresh on a timer (not per-request) since re-signing the manifest
// on every fetch would mean a new infohash every time -- pointless churn
// for something meant to be found via a stable swarm.

type torrentMagnetsState struct {
	mu                  sync.RWMutex
	softwareMagnets     map[string]string // product/platform slug -> magnet URI, from torrentSeedManifestURL
	manifestMagnet      string            // magnet for this arbiter's own last-published manifest torrent
	manifestTorrentPath string            // watch-dir path of the last-published .torrent, for cleanup on the next publish
}

func (h *handler) softwareTorrentMagnets() map[string]string {
	h.torrentMagnetsState.mu.RLock()
	defer h.torrentMagnetsState.mu.RUnlock()
	if len(h.torrentMagnetsState.softwareMagnets) == 0 {
		return nil
	}
	out := make(map[string]string, len(h.torrentMagnetsState.softwareMagnets))
	for k, v := range h.torrentMagnetsState.softwareMagnets {
		out[k] = v
	}
	return out
}

func (h *handler) manifestTorrentMagnet() string {
	h.torrentMagnetsState.mu.RLock()
	defer h.torrentMagnetsState.mu.RUnlock()
	return h.torrentMagnetsState.manifestMagnet
}

// startTorrentMagnets launches whichever background refresh loops are
// configured. Called once from main() when either flag is set.
func (h *handler) startTorrentMagnets() {
	if h.torrentSeedManifestURL != "" {
		go h.softwareMagnetsRefreshLoop()
	}
	if h.torrentSeedDataDir != "" {
		go h.manifestTorrentRefreshLoop()
	}
}

// ── software package magnets ────────────────────────────────────────────

const torrentSeedManifestRefreshInterval = 5 * time.Minute

// seedManifestEntry mirrors one product's entry in torrent-seed.sh's
// published manifest.json (see sync-and-publish.sh's publish step).
type seedManifestEntry struct {
	Magnet     string `json:"magnet"`
	TorrentURL string `json:"torrentUrl"`
	SHA256     string `json:"sha256"`
}

func (h *handler) softwareMagnetsRefreshLoop() {
	fetch := func() {
		magnets, err := fetchSeedManifest(h.torrentSeedManifestURL)
		if err != nil {
			logWarnf("torrent-magnets: fetch %s: %v", h.torrentSeedManifestURL, err)
			return
		}
		h.torrentMagnetsState.mu.Lock()
		h.torrentMagnetsState.softwareMagnets = magnets
		h.torrentMagnetsState.mu.Unlock()
		logInfof("torrent-magnets: refreshed %d software magnet(s) from %s", len(magnets), h.torrentSeedManifestURL)
	}
	fetch()
	t := time.NewTicker(torrentSeedManifestRefreshInterval)
	defer t.Stop()
	for range t.C {
		fetch()
	}
}

func fetchSeedManifest(url string) (map[string]string, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url) //nolint:gosec // url is operator-configured, not user input
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var raw map[string]seedManifestEntry
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(raw))
	for slug, e := range raw {
		if e.Magnet != "" {
			out[slug] = e.Magnet
		}
	}
	return out, nil
}

// ── this arbiter's own manifest, as a torrent ───────────────────────────

const manifestTorrentRefreshInterval = 15 * time.Minute

func (h *handler) manifestTorrentRefreshLoop() {
	refresh := func() {
		if err := h.publishManifestTorrent(); err != nil {
			logWarnf("torrent-magnets: publish manifest torrent: %v", err)
		}
	}
	refresh()
	t := time.NewTicker(manifestTorrentRefreshInterval)
	defer t.Stop()
	for range t.C {
		refresh()
	}
}

// torrentTrackerPort matches TORRENT_TRACKER_HTTP_PORT/TORRENT_TRACKER_UDP_PORT's
// default in sync-and-publish.sh (both 6969) -- the arbiter has no way to
// know if an operator overrode those on a given box, so this assumes the
// fleet-wide default every existing seed box actually runs.
const torrentTrackerPort = "6969"

// loadAnnounceList reads torrentTrackersFile (one host per line, same file
// sync-and-publish.sh's own TRACKER_LIST_FILE points at) and builds a
// BEP12 multi-tracker announce-list -- both http and udp per host, exactly
// mirroring that script's own ANNOUNCE_ARGS construction, so a client
// following this manifest's magnet reaches the same tracker set the
// software-package torrents already use. Returns nil (no announce-list,
// DHT/PEX only) if torrentTrackersFile is unset or unreadable.
func (h *handler) loadAnnounceList() [][]string {
	if h.torrentTrackersFile == "" {
		return nil
	}
	f, err := os.Open(h.torrentTrackersFile)
	if err != nil {
		logWarnf("torrent-magnets: read trackers file %s: %v", h.torrentTrackersFile, err)
		return nil
	}
	defer f.Close()
	var list [][]string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		host := strings.TrimSpace(sc.Text())
		if host == "" {
			continue
		}
		list = append(list,
			[]string{fmt.Sprintf("http://%s:%s/announce", host, torrentTrackerPort)},
			[]string{fmt.Sprintf("udp://%s:%s/announce", host, torrentTrackerPort)},
		)
	}
	return list
}

// publishManifestTorrent signs a fresh "controls" manifest, writes it into
// <torrentSeedDataDir>/downloads/manifest.json (the same DOWNLOADS_DIR a
// co-located torrent-seed.sh install already uses), builds a .torrent for
// it, and drops that into <torrentSeedDataDir>/torrents/ (WATCH_DIR) --
// transmission-daemon there is already running in watch mode (see
// sync-and-publish.sh) and picks up new/changed .torrent files
// automatically, matching them against files already present in its
// download-dir so it can start seeding immediately without re-downloading
// its own content from itself.
func (h *handler) publishManifestTorrent() error {
	controls, err := h.db.liveNodes("control")
	if err != nil {
		return err
	}
	data, err := h.signer.signList("controls", controls, h.regionFnWithOverrides(controls))
	if err != nil {
		return err
	}

	downloadsDir := filepath.Join(h.torrentSeedDataDir, "downloads")
	torrentsDir := filepath.Join(h.torrentSeedDataDir, "torrents")
	if err := os.MkdirAll(downloadsDir, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(torrentsDir, 0755); err != nil {
		return err
	}

	srcPath := filepath.Join(downloadsDir, "manifest.json")
	if err := os.WriteFile(srcPath, data, 0644); err != nil {
		return err
	}

	info := metainfo.Info{PieceLength: 16 * 1024}
	if err := info.BuildFromFilePath(srcPath); err != nil {
		return err
	}
	mi := metainfo.MetaInfo{}
	mi.SetDefaults()
	mi.AnnounceList = h.loadAnnounceList()
	if len(mi.AnnounceList) > 0 {
		mi.Announce = mi.AnnounceList[0][0]
	}
	infoBytes, err := bencode.Marshal(info)
	if err != nil {
		return err
	}
	mi.InfoBytes = infoBytes
	infoHash := mi.HashInfoBytes()

	// Filename includes the infohash so every content change (the manifest
	// changes on essentially every publish -- node list rotation, TS,
	// signature) produces a distinct filename. transmission-daemon's
	// watch-folder only reacts to a file being CREATED, not an existing
	// path being overwritten in place -- reusing a fixed "manifest.torrent"
	// name meant only the very first publish was ever picked up.
	torrentPath := filepath.Join(torrentsDir, fmt.Sprintf("manifest-%s.torrent", infoHash.HexString()[:16]))
	f, err := os.Create(torrentPath)
	if err != nil {
		return err
	}
	writeErr := mi.Write(f)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}

	magnet := mi.Magnet(&infoHash, &info).String()

	h.torrentMagnetsState.mu.Lock()
	prevPath := h.torrentMagnetsState.manifestTorrentPath
	h.torrentMagnetsState.manifestMagnet = magnet
	h.torrentMagnetsState.manifestTorrentPath = torrentPath
	h.torrentMagnetsState.mu.Unlock()

	// Best-effort cleanup of the previous version's .torrent file from the
	// watch dir -- transmission has already ingested it into its own
	// internal torrent list by this point (see the CREATE-event note
	// above), so removing it here only tidies the watch folder; it does
	// NOT stop transmission from continuing to track/seed the prior
	// version. Not attempted: telling transmission to actually drop the
	// stale version via its RPC API, since that needs the daemon's RPC
	// credentials, which this arbiter has no access to and shouldn't need.
	if prevPath != "" && prevPath != torrentPath {
		if err := os.Remove(prevPath); err != nil && !os.IsNotExist(err) {
			logWarnf("torrent-magnets: remove stale %s: %v", prevPath, err)
		}
	}

	logInfof("torrent-magnets: published manifest torrent infohash=%s", infoHash.HexString())
	return nil
}
