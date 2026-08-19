// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// collectSysMetrics reads host CPU/memory/disk utilization from /proc and
// syscall.Statfs. CPU % is a delta between successive calls (cpuPrev), so
// the very first call after process start returns 0 for cpuPct.
func collectSysMetrics() (cpuPct, memPct, diskPct float64) {
	cpuPct = readCPUPct()
	memPct = readMemPct()
	diskPct = readDiskPct("/")
	return
}

var cpuPrevMu sync.Mutex
var cpuPrevTotal, cpuPrevIdle uint64

func readCPUPct() float64 {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return 0
	}
	fields := strings.Fields(sc.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0
	}

	var total, idle uint64
	for i, field := range fields[1:] {
		v, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			continue
		}
		total += v
		if i == 3 { // idle is the 4th value
			idle = v
		}
	}

	cpuPrevMu.Lock()
	defer cpuPrevMu.Unlock()
	prevTotal, prevIdle := cpuPrevTotal, cpuPrevIdle
	cpuPrevTotal, cpuPrevIdle = total, idle
	if prevTotal == 0 || total <= prevTotal {
		return 0
	}

	totalDelta := total - prevTotal
	idleDelta := idle - prevIdle
	if totalDelta == 0 {
		return 0
	}
	pct := (float64(totalDelta) - float64(idleDelta)) / float64(totalDelta) * 100
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return pct
}

func readMemPct() float64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()

	var totalKB, availKB uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			totalKB = parseMeminfoValue(line)
		case strings.HasPrefix(line, "MemAvailable:"):
			availKB = parseMeminfoValue(line)
		}
	}
	if totalKB == 0 {
		return 0
	}
	return (float64(totalKB) - float64(availKB)) / float64(totalKB) * 100
}

func parseMeminfoValue(line string) uint64 {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	v, _ := strconv.ParseUint(fields[1], 10, 64)
	return v
}

func readDiskPct(path string) float64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0
	}
	if st.Blocks == 0 {
		return 0
	}
	used := st.Blocks - st.Bfree
	return float64(used) / float64(st.Blocks) * 100
}
