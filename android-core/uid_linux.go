// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

//go:build linux

package androidcore

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	snc "tunnel_cat/snc/core"
)

// UidClient asks Kotlin which Android app (by Linux UID) owns a given
// TCP/UDP 4-tuple, via ConnectivityManager.getConnectionOwnerUid -- the
// Android-blessed API for exactly this, granted to the app holding the
// active VpnService role (the same privilege level that already lets this
// app call VpnService.Builder.addDisallowedApplication for the per-app
// bypass feature -- see ExcludedApps/SNCVpnService.kt).
//
// Replaces an earlier attempt (lookupUID, removed 2026-08-17) that read
// /proc/net/tcp directly: that approach is silently non-functional on
// Android 11+, which restricts unprivileged processes to seeing only their
// own socket entries there. Confirmed live, 2026-08-17: it returned -1 for
// 100% of lookups across two full real-device sessions -- which, combined
// with PickForUID treating an unresolved UID like any other value, meant
// every app's traffic was being pinned to the SAME single control (every
// connection "matched" every other on uid=-1), the exact "whole VPN on one
// control" outcome this feature was explicitly built to avoid.
//
// Kotlin owns the server side (SNCVpnService.uidLoop); Go connects at
// startup and reuses the connection -- same shape as ProtectClient
// (protect_linux.go), deliberately mirrored (mutex-serialized round-trips,
// per-call reconnect-and-retry-once, hang watchdog) since that's the
// pattern already proven reliable on real devices, unlike the /proc/net/tcp
// scrape it replaces.
//
// Wire protocol: Go sends one text line
// "<proto> <srcIP> <srcPort> <dstIP> <dstPort>\n" (proto is "tcp" or
// "udp"); Kotlin replies "<uid>\n" (uid is -1 if it can't be resolved).
type UidClient struct {
	mu         sync.Mutex
	conn       *net.UnixConn
	reader     *bufio.Reader
	socketPath string

	// activeConn/callStart let the watchdog observe an in-progress call
	// without acquiring mu (which would deadlock while a call holds mu
	// during I/O) -- same pattern as ProtectClient.
	activeConn atomic.Pointer[net.UnixConn]
	callStart  atomic.Int64
}

var UID = &UidClient{}

// Connect dials the Kotlin uid-lookup socket. Called at startup with retry,
// same as ProtectClient.Connect.
func (u *UidClient) Connect(socketPath string) error {
	conn, err := u.dial(socketPath)
	if err != nil {
		return err
	}
	u.mu.Lock()
	u.conn = conn
	u.reader = bufio.NewReader(conn)
	u.socketPath = socketPath
	u.mu.Unlock()
	return nil
}

func (u *UidClient) dial(socketPath string) (*net.UnixConn, error) {
	netName := socketPath
	if strings.HasPrefix(socketPath, "@") {
		netName = "\x00" + socketPath[1:]
	}
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: netName, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("uid: dial %s: %w", socketPath, err)
	}
	return conn, nil
}

// reconnectLocked closes the current connection (if any) and re-dials.
// Must be called with u.mu held.
func (u *UidClient) reconnectLocked() error {
	if u.conn != nil {
		u.conn.Close()
		u.conn = nil
	}
	if u.socketPath == "" {
		return fmt.Errorf("uid: no socket path for reconnect")
	}
	conn, err := u.dial(u.socketPath)
	if err != nil {
		return err
	}
	u.conn = conn
	u.reader = bufio.NewReader(conn)
	return nil
}

// StartWatchdog forcibly closes a connection that's been unresponsive for
// more than 2s, unblocking a goroutine stuck reading a response so it takes
// the reconnect-and-retry path. Shorter timeout than ProtectClient's 5s --
// a UID lookup sits on the hot path of every new connection (unlike protect,
// which is comparatively rare), so a hung lookup should give up faster.
func (u *UidClient) StartWatchdog(stopCh <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				start := u.callStart.Load()
				if start == 0 {
					continue
				}
				if time.Since(time.Unix(0, start)) < 2*time.Second {
					continue
				}
				if conn := u.activeConn.Load(); conn != nil {
					snc.Log.Printf("uid: watchdog: call hung -- closing conn to unblock")
					conn.Close()
				}
			case <-stopCh:
				return
			}
		}
	}()
}

// Lookup returns the Linux UID owning the given 4-tuple, or -1 if it can't
// be resolved (no client connected, an I/O error, or Kotlin itself couldn't
// resolve it). proto is "tcp" or "udp".
func (u *UidClient) Lookup(proto string, srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.lookupLocked(proto, srcIP, srcPort, dstIP, dstPort, true)
}

// lookupLocked performs the round-trip under u.mu. allowRetry enables a
// single reconnect+retry on I/O error, same pattern as
// ProtectClient.protectFDLocked.
func (u *UidClient) lookupLocked(proto string, srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16, allowRetry bool) int {
	if u.conn == nil {
		if err := u.reconnectLocked(); err != nil {
			return -1
		}
	}

	u.activeConn.Store(u.conn)
	u.callStart.Store(time.Now().UnixNano())
	defer func() {
		u.callStart.Store(0)
		u.activeConn.Store(nil)
	}()

	u.conn.SetDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	line := fmt.Sprintf("%s %s %d %s %d\n", proto, srcIP.String(), srcPort, dstIP.String(), dstPort)
	if _, err := u.conn.Write([]byte(line)); err != nil {
		if !allowRetry {
			return -1
		}
		if u.reconnectLocked() != nil {
			return -1
		}
		return u.lookupLocked(proto, srcIP, srcPort, dstIP, dstPort, false)
	}

	resp, err := u.reader.ReadString('\n')
	if err != nil {
		if !allowRetry {
			return -1
		}
		if u.reconnectLocked() != nil {
			return -1
		}
		return u.lookupLocked(proto, srcIP, srcPort, dstIP, dstPort, false)
	}
	uid, err := strconv.Atoi(strings.TrimSpace(resp))
	if err != nil {
		return -1
	}
	return uid
}
