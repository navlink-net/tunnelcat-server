// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"os"
	"sync/atomic"
	"time"
)

// lastHeartbeatAt is the Unix timestamp of the most recent heartbeat attempt.
// It is stored at the very top of the heartbeat send() closure — before any
// call to the logger — so the watchdog can fire even when the log writer is
// blocked on a disk-I/O stall (which holds the rotator mutex and freezes every
// goroutine that tries to log).
var lastHeartbeatAt atomic.Int64

// startWatchdog launches a background goroutine that terminates the process
// with os.Exit(1) if no heartbeat has been recorded within deadline.  systemd
// then restarts the process via Restart=on-failure.
//
// All watchdog output goes directly to os.Stderr (raw write, bypassing the
// logger) so it works even when the log writer is stuck.
func startWatchdog(deadline time.Duration) {
	lastHeartbeatAt.Store(time.Now().Unix())
	interval := deadline / 3
	if interval < 30*time.Second {
		interval = 30 * time.Second
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			last := time.Unix(lastHeartbeatAt.Load(), 0)
			if age := time.Since(last); age > deadline {
				// Use raw stderr write — the logger may be deadlocked.
				os.Stderr.WriteString("watchdog: no heartbeat for " + age.Round(time.Second).String() + " — exiting for systemd restart\n") //nolint:errcheck
				os.Exit(1)
			}
		}
	}()
}
