// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"sync"
	"time"
)

var (
	pingLoadMu        sync.Mutex
	pingLoadLastBytes int64
	pingLoadLastTime  time.Time
)

// pingLoadSample computes this exit's current delivery speed (Mbps) since
// the last call, plus current CPU/mem utilization -- a fresh, direct signal
// for snc-control's own routing decisions. Served from /p/v1/ping, which
// snc-control already GETs every 10s for health probing (see
// snc-control/exit_health.go's probeOne) -- riding along on that existing
// probe instead of going through the arbiter's own heartbeat/load-factor
// pipeline (30s heartbeat -> 5min recompute -> 60s control poll, ~6min
// worst-case staleness, and a signal computed for the admin dashboard's
// historical record, not for routing).
//
// Deliberately separate byte-delta state from the arbiter heartbeat's own
// 30s window (startArbiterHeartbeat in arbiter.go) -- this one must reflect
// the actual ~10s cadence it's really measured over, not borrow a
// stats-purposed average computed on a different clock.
func pingLoadSample() (bwMbps, cpuPct, memPct float64) {
	now := time.Now()
	total := exitBytesTotal.Load()

	pingLoadMu.Lock()
	if !pingLoadLastTime.IsZero() {
		elapsed := now.Sub(pingLoadLastTime).Seconds()
		if elapsed > 0 && total > pingLoadLastBytes {
			bwMbps = float64(total-pingLoadLastBytes) * 8 / elapsed / 1e6
		}
	}
	pingLoadLastBytes = total
	pingLoadLastTime = now
	pingLoadMu.Unlock()

	cpuPct, memPct, _ = collectSysMetrics()
	return bwMbps, cpuPct, memPct
}
