// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

const (
	ipv6StateRefreshInterval = 5 * time.Minute
	ipv6StateFetchTimeout    = 10 * time.Second
)

// ipv6SysctlPaths disables IPv6 for all interfaces already up (all) and any
// interface added afterward (default). Writing "all" does NOT retroactively
// need a per-interface loop -- the kernel applies it live to every existing
// interface's IPv6 config, same as `sysctl -w net.ipv6.conf.all.disable_ipv6=1`.
var ipv6SysctlPaths = []string{
	"/proc/sys/net/ipv6/conf/all/disable_ipv6",
	"/proc/sys/net/ipv6/conf/default/disable_ipv6",
}

// ipv6StateCache polls the arbiter's admin_ipv6.go kill switch and applies it
// directly to the OS network stack -- not just to this process's own dials.
// Real system tools on this box (apt, certbot, curl, dig -- anything that
// isn't our own Go code) have no way to honor an app-level "don't use IPv6"
// flag; disabling it in the kernel is the only fix that covers all of them,
// which matters on fleets where DNS still returns AAAA but there's no real
// IPv6 route at all (confirmed 2026-08-19, see deploy/setup/common.sh's
// gai.conf fix for the client-visible half of the same underlying problem).
//
// Requires CAP_NET_ADMIN (see exit.sh's systemd unit) -- /proc/sys/net/ipv6/*
// writes are gated by that capability in the kernel's own netns sysctl
// permission check, not by root/DAC, so the unprivileged snc user can do
// this the same way it already manages iptables rules live.
type ipv6StateCache struct {
	arbiterURL string
	nodeToken  string
	client     *http.Client

	lastKnown atomic.Bool // last value successfully applied; default true (enabled) until first fetch
}

func newIPv6StateCache(arbiterURL, nodeToken string) *ipv6StateCache {
	c := &ipv6StateCache{
		arbiterURL: strings.TrimRight(arbiterURL, "/"),
		nodeToken:  nodeToken,
		client:     &http.Client{Timeout: ipv6StateFetchTimeout},
	}
	c.lastKnown.Store(true)
	return c
}

// Start fetches immediately, applies the result, then refreshes periodically.
func (c *ipv6StateCache) Start() {
	go func() {
		c.refresh()
		t := time.NewTicker(ipv6StateRefreshInterval)
		defer t.Stop()
		for range t.C {
			c.refresh()
		}
	}()
}

func (c *ipv6StateCache) refresh() {
	enabled, err := c.fetch()
	if err != nil {
		logWarnf("ipv6-state: fetch failed, keeping last known state (enabled=%v): %v", c.lastKnown.Load(), err)
		return
	}
	if c.lastKnown.Swap(enabled) == enabled {
		return // no change, skip the sysctl writes
	}
	applyIPv6SystemState(enabled)
}

func (c *ipv6StateCache) fetch() (bool, error) {
	req, err := http.NewRequest(http.MethodGet, c.arbiterURL+"/api/ipv6-enabled", nil)
	if err != nil {
		return false, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-Node-Token", c.nodeToken)

	resp, err := c.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("GET /api/ipv6-enabled: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("arbiter status %d", resp.StatusCode)
	}
	var wire struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<10)).Decode(&wire); err != nil {
		return false, fmt.Errorf("decode: %w", err)
	}
	return wire.Enabled, nil
}

// applyIPv6SystemState writes disable_ipv6=0/1 to every path in
// ipv6SysctlPaths. Best-effort per path -- logs and continues rather than
// aborting the whole apply if one write fails (e.g. a hardened kernel that
// doesn't expose one of the two knobs), since a partial application is still
// better than none.
func applyIPv6SystemState(enabled bool) {
	val := []byte("1\n") // disable_ipv6=1 means IPv6 OFF
	if enabled {
		val = []byte("0\n")
	}
	ok := 0
	for _, p := range ipv6SysctlPaths {
		if err := os.WriteFile(p, val, 0644); err != nil {
			logWarnf("ipv6-state: write %s: %v", p, err)
			continue
		}
		ok++
	}
	state := "disabled"
	if enabled {
		state = "enabled"
	}
	logInfof("ipv6-state: system IPv6 %s (%d/%d sysctl paths written)", state, ok, len(ipv6SysctlPaths))
}
