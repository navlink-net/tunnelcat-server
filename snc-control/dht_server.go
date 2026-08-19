// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

// dht_server.go â€” DHT bootstrap node for snc-control.
//
// The control participates in the client DHT mesh as a bootstrap/relay-list
// node.  It does NOT announce itself as a relay (controls have public IPs and
// are reachable directly); it DOES respond to PING, FIND_NODE, and GET_RELAYS
// so that fresh clients can bootstrap even when their peers.json cache is cold.
//
// Packet demux: the UDPReflector in udp_reflector.go tries dht.Open() on every
// inbound datagram; if auth succeeds, it calls dhtSrv.HandleInbound instead of
// the reflector reply path.  The DHT node never calls ReadFromUDP on the shared
// socket â€” it only writes replies.

import (
	"crypto/rand"
	"log"
	"net"
	"os"

	"tunnel_cat/dht"
)

// dhtServer wraps a dht.Node configured for control-node operation.
type dhtServer struct {
	node *dht.Node
}

// newDHTServer creates and starts the DHT maintenance goroutine.
// conn is the shared UDP socket (owned by UDPReflector; shared for writes only).
// ownIP is the control's public IP address; pass "" to fall back to conn.LocalAddr().
func newDHTServer(conn *net.UDPConn, ownIP string) *dhtServer {
	var id dht.ID
	if _, err := rand.Read(id[:]); err != nil {
		logErrorf("dht-server: generate node ID: %v", err)
		os.Exit(1)
	}
	logger := log.New(os.Stderr, "[dht] ", log.LstdFlags|log.Lmsgprefix)
	// No peersPath (controls don't persist the DHT routing table across restarts).
	// No encryptFn/decryptFn (both nil â†’ no-op).
	node := dht.NewNode(id, conn, "", logger, nil, nil)
	if ownIP != "" {
		_, port, _ := net.SplitHostPort(conn.LocalAddr().String())
		node.SetOwnAddr(net.JoinHostPort(ownIP, port))
		logInfof("dht-server: own addr=%s:%s", ownIP, port)
	}
	logInfof("dht-server: started node_id=%s", id)
	node.StartMaintenance()
	return &dhtServer{node: node}
}

// HandleInbound dispatches a raw inbound DHT datagram (already identified as
// DHT by a successful dht.Open check in the reflector).
func (s *dhtServer) HandleInbound(pkt []byte, src *net.UDPAddr) {
	s.node.HandleInbound(pkt, src)
}

// Bootstrap seeds the DHT routing table from known peers (e.g. other controls).
func (s *dhtServer) Bootstrap(seeds []string) {
	s.node.Bootstrap(seeds)
}

// SetManifest tells the DHT node about the latest signed manifest so it can
// gossip the manifest timestamp to connecting clients.
func (s *dhtServer) SetManifest(raw []byte, ts int64) {
	s.node.SetManifest(raw, ts)
}

// SetContent tells the DHT node about the latest signed content-mirror
// manifest so it can gossip it on the independent content-manifest channel.
// Controls never claim "complete" (they don't download the actual mirrored
// files, only relay the manifest+chunks on demand) â€” see mirror.go.
func (s *dhtServer) SetContent(raw []byte, ts int64) {
	s.node.SetContent(raw, ts)
}
