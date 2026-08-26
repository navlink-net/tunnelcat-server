// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

//go:build linux

package androidcore

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"tunnel_cat/binlog"
	"tunnel_cat/logevent"
)

// ProtectClient serializes VpnService.protect(fd) round-trips over a Unix socket.
// Kotlin owns the server side; Go connects at startup and reuses the connection.
//
// Background: Android routes all traffic from a VPN process through the VPN's own
// TUN interface by default. Without protection, every socket opened by snc-core
// (tunnel connections to controls, DNS lookups, WildCat HTTP requests) would loop
// back through the TUN and be intercepted by itself â€” a routing loop that kills
// connectivity entirely. VpnService.protect(fd) marks a socket's fd as exempt from
// VPN routing, making it use the physical NIC instead. The only way to call a Java
// method from a Go subprocess is via IPC â€” hence this Unix socket.
//
// Wire protocol: Go sends 1-byte marker + SCM_RIGHTS(fd); Kotlin responds \x01 on success.
// SCM_RIGHTS passes the fd across the process boundary as a kernel ancillary message;
// no userspace serialisation of the file descriptor number is involved, which means
// the fd remains valid in the Kotlin process even if the Go fd is later closed.
//
// Reliability layers â€” needed because protect is called from every concurrent dialer:
//
//  1. mu serializes all round-trips so acks are never interleaved (race-free protocol).
//     Without this, two goroutines could send fds simultaneously and then each read
//     the other's ack, causing permanent protocol desync.
//  2. Per-call reconnect: on any I/O error the connection is closed, re-dialed, and
//     the call retried once â€” handles transient errors and protocol desync after a timeout.
//  3. Watchdog goroutine: independently closes a connection that has been unresponsive
//     for >5 s, unblocking a goroutine stuck in io.ReadFull even if its deadline never
//     fired. The unblocked goroutine then triggers the per-call reconnect path above.
//     The watchdog reads activeConn without holding mu to avoid deadlocking the I/O path.
type ProtectClient struct {
	mu         sync.Mutex
	conn       *net.UnixConn
	socketPath string

	// activeConn and callStart let the watchdog observe an in-progress call without
	// acquiring mu (which would deadlock while the call holds mu during I/O).
	activeConn atomic.Pointer[net.UnixConn]
	callStart  atomic.Int64 // UnixNano when current call started; 0 when idle
}

var Protect = &ProtectClient{}

// Connect dials the Kotlin protect socket. Called at startup with retry.
// socketPath may use "@name" prefix for Linux abstract Unix namespace
// (Android's LocalServerSocket uses abstract namespace by default â€” the socket
// exists only in the kernel and is not visible as a file, which avoids
// permission and cleanup issues on Android's restrictive /data partition).
func (p *ProtectClient) Connect(socketPath string) error {
	conn, err := p.dial(socketPath)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.conn = conn
	p.socketPath = socketPath
	p.mu.Unlock()
	return nil
}

func (p *ProtectClient) dial(socketPath string) (*net.UnixConn, error) {
	netName := socketPath
	if strings.HasPrefix(socketPath, "@") {
		// Abstract Unix socket: replace @ prefix with null byte.
		netName = "\x00" + socketPath[1:]
	}
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: netName, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("protect: dial %s: %w", socketPath, err)
	}
	return conn, nil
}

// reconnectLocked closes the current connection (if any) and re-dials.
// Must be called with p.mu held.
func (p *ProtectClient) reconnectLocked() error {
	if p.conn != nil {
		p.conn.Close()
		p.conn = nil
	}
	if p.socketPath == "" {
		return fmt.Errorf("protect: no socket path for reconnect")
	}
	logevent.Emit(binlog.TagSystem, logevent.EventProtectReconnecting,
		logevent.Str("socket_path", p.socketPath))
	conn, err := p.dial(p.socketPath)
	if err != nil {
		return err
	}
	p.conn = conn
	logevent.Emit(binlog.TagSystem, logevent.EventProtectReconnected)
	return nil
}

// StartWatchdog starts a background goroutine that forcibly closes a connection
// that has been unresponsive for more than 5 s. Closing the connection unblocks
// any goroutine stuck in io.ReadFull, which then triggers per-call reconnect.
// The goroutine exits when stopCh is closed.
func (p *ProtectClient) StartWatchdog(stopCh <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				start := p.callStart.Load()
				if start == 0 {
					continue
				}
				elapsed := time.Since(time.Unix(0, start))
				if elapsed < 5*time.Second {
					continue
				}
				conn := p.activeConn.Load()
				if conn == nil {
					continue
				}
				logevent.Emit(binlog.TagSystem, logevent.EventProtectWatchdogHung,
					logevent.Int("elapsed_ms", elapsed.Round(time.Millisecond).Milliseconds()))
				conn.Close()
			case <-stopCh:
				return
			}
		}
	}()
}

// DialControl implements core.SetDialControl â€” called for every new outbound socket.
// Registered globally via snc.SetDialControl so the core library's internal dialers
// (TunnelDialer, WildCat REST client, DHT UDP) automatically bypass the TUN without
// knowing anything about Android's VPN model.
func (p *ProtectClient) DialControl(network, address string, c syscall.RawConn) error {
	var fd int = -1
	if err := c.Control(func(raw uintptr) { fd = int(raw) }); err != nil {
		return err
	}
	if fd < 0 {
		return nil
	}
	return p.protectFD(fd)
}

func (p *ProtectClient) protectFD(fd int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.protectFDLocked(fd, true)
}

// protectFDLocked performs the protect round-trip under p.mu.
// allowRetry enables a single reconnect+retry on I/O error.
func (p *ProtectClient) protectFDLocked(fd int, allowRetry bool) error {
	if p.conn == nil {
		if err := p.reconnectLocked(); err != nil {
			logevent.Emit(binlog.TagSystem, logevent.EventProtectNoSocket,
				logevent.Int("fd", int64(fd)))
			return nil
		}
	}

	// Publish the active conn and start time for the watchdog.
	p.activeConn.Store(p.conn)
	p.callStart.Store(time.Now().UnixNano())
	defer func() {
		p.callStart.Store(0)
		p.activeConn.Store(nil)
	}()

	t0 := time.Now()
	oob := unix.UnixRights(fd)
	p.conn.SetDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck

	if _, _, err := p.conn.WriteMsgUnix([]byte{1}, oob, nil); err != nil {
		logevent.Emit(binlog.TagSystem, logevent.EventProtectIoError,
			logevent.Int("fd", int64(fd)),
			logevent.Int("elapsed_ms", time.Since(t0).Round(time.Millisecond).Milliseconds()),
			logevent.Str("stage", logevent.ProtectIoErrorStageSend),
			logevent.Str("err", err.Error()))
		if !allowRetry {
			return fmt.Errorf("protect: send fd: %w", err)
		}
		if rerr := p.reconnectLocked(); rerr != nil {
			logevent.Emit(binlog.TagSystem, logevent.EventProtectReconnectAfterError,
				logevent.Str("stage", logevent.ProtectIoErrorStageSend),
				logevent.Str(logevent.AttrResult, logevent.ProtectReconnectAfterErrorResultError),
				logevent.Str("err", rerr.Error()))
			return fmt.Errorf("protect: send fd: %w", err)
		}
		logevent.Emit(binlog.TagSystem, logevent.EventProtectReconnectAfterError,
			logevent.Str("stage", logevent.ProtectIoErrorStageSend),
			logevent.Str(logevent.AttrResult, logevent.ProtectReconnectAfterErrorResultOk))
		return p.protectFDLocked(fd, false)
	}

	ack := make([]byte, 1)
	if _, err := io.ReadFull(p.conn, ack); err != nil {
		logevent.Emit(binlog.TagSystem, logevent.EventProtectIoError,
			logevent.Int("fd", int64(fd)),
			logevent.Int("elapsed_ms", time.Since(t0).Round(time.Millisecond).Milliseconds()),
			logevent.Str("stage", logevent.ProtectIoErrorStageAck),
			logevent.Str("err", err.Error()))
		if !allowRetry {
			return fmt.Errorf("protect: ack: %w", err)
		}
		if rerr := p.reconnectLocked(); rerr != nil {
			logevent.Emit(binlog.TagSystem, logevent.EventProtectReconnectAfterError,
				logevent.Str("stage", logevent.ProtectIoErrorStageAck),
				logevent.Str(logevent.AttrResult, logevent.ProtectReconnectAfterErrorResultError),
				logevent.Str("err", rerr.Error()))
			return fmt.Errorf("protect: ack: %w", err)
		}
		logevent.Emit(binlog.TagSystem, logevent.EventProtectReconnectAfterError,
			logevent.Str("stage", logevent.ProtectIoErrorStageAck),
			logevent.Str(logevent.AttrResult, logevent.ProtectReconnectAfterErrorResultOk))
		return p.protectFDLocked(fd, false)
	}

	if ack[0] != 1 {
		logevent.Emit(binlog.TagSystem, logevent.EventProtectNack,
			logevent.Int("fd", int64(fd)),
			logevent.Int("elapsed_ms", time.Since(t0).Round(time.Millisecond).Milliseconds()),
			logevent.Int("ack_byte", int64(ack[0])))
		return fmt.Errorf("protect: nack from Kotlin")
	}
	logevent.Emit(binlog.TagSystem, logevent.EventProtectOk,
		logevent.Int("fd", int64(fd)),
		logevent.Int("elapsed_ms", time.Since(t0).Round(time.Millisecond).Milliseconds()))
	return nil
}
