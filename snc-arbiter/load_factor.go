// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// This file computes and serves the per-node "load" bonus/malus coefficient
// that rides along in the existing signed manifest (client-facing control
// list, signing.go's manifestNode.Load) and exit list (snc-control/exits.go's
// ExitNode.Load) -- both fields already existed and were already parsed by
// clients/controls, but nodes.load was never written by anything, so they
// were always 0. This is the write side.
//
// See TODO.md / the 2026-08-11 traffic-imbalance analysis: RTT-only routing
// is latency-greedy, not load-balancing -- those are different objectives
// that only weakly correlate. This coefficient is a second, independent
// signal (relative last-hour traffic share within a node's own type+region
// competition group) that the client Router and snc-control's exit Pick()
// multiply into their existing RTT-based scores, so an above-average-loaded
// node gets deprioritised and a below-average one gets a bonus -- without
// touching the regional hard filter or breaking established sessions (both
// explicit constraints).

// loadFactorValues is the plain (mutex-free) snapshot of the tuning knobs --
// safe to copy, embed in template data, etc. loadFactorConfig (below) is the
// live cached version handler holds; loadFactorSnapshot() converts one to
// the other.
type loadFactorValues struct {
	Enabled bool

	ControlMin float64
	ControlMax float64
	ExitMin    float64
	ExitMax    float64
}

// loadFactorConfig holds the admin-tunable knobs, cached in memory and
// refreshed from system_settings (same pattern as relayState in
// admin_relay.go). Separate min/max per node type because controls and
// exits carry very different traffic profiles and may need independent
// tuning.
type loadFactorConfig struct {
	mu sync.RWMutex
	loadFactorValues
}

const (
	lfSettingEnabled    = "loadfactor_enabled"
	lfSettingControlMin = "loadfactor_control_min"
	lfSettingControlMax = "loadfactor_control_max"
	lfSettingExitMin    = "loadfactor_exit_min"
	lfSettingExitMax    = "loadfactor_exit_max"

	lfDefaultMin = 0.5
	lfDefaultMax = 2.0
)

// loadLoadFactorConfig refreshes the in-memory config from DB. Missing
// settings fall back to the defaults above (0.5..2.0, enabled).
func (h *handler) loadLoadFactorConfig() {
	get := func(key string, def float64) float64 {
		val, ok, err := h.db.getSetting(key)
		if !ok || err != nil {
			return def
		}
		f, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return def
		}
		return f
	}
	enabled := true
	if val, ok, err := h.db.getSetting(lfSettingEnabled); ok && err == nil {
		enabled = val != "0"
	}

	h.loadFactor.mu.Lock()
	h.loadFactor.Enabled = enabled
	h.loadFactor.ControlMin = get(lfSettingControlMin, lfDefaultMin)
	h.loadFactor.ControlMax = get(lfSettingControlMax, lfDefaultMax)
	h.loadFactor.ExitMin = get(lfSettingExitMin, lfDefaultMin)
	h.loadFactor.ExitMax = get(lfSettingExitMax, lfDefaultMax)
	h.loadFactor.mu.Unlock()
}

// loadFactorSnapshot returns a copy of the current config, safe for concurrent
// use (and safe to embed in template data -- no mutex).
func (h *handler) loadFactorSnapshot() loadFactorValues {
	h.loadFactor.mu.RLock()
	defer h.loadFactor.mu.RUnlock()
	return h.loadFactor.loadFactorValues
}

// StartLoadFactorTicker launches the periodic recomputation loop. Called once
// at startup. Runs immediately, then every interval.
func (h *handler) StartLoadFactorTicker(interval time.Duration) {
	h.loadLoadFactorConfig()
	go func() {
		h.recomputeLoadFactors()
		t := time.NewTicker(interval)
		defer t.Stop()
		for range t.C {
			h.recomputeLoadFactors()
		}
	}()
}

// recomputeLoadFactors is the actual computation: for each node type
// (control, exit) independently, group live nodes by effective region
// (override, else CIDR-detected -- see regionFnWithOverrides), compute each
// node's last-hour traffic share relative to its group's mean, clamp to the
// configured [min,max], and write it back via setNodeLoad. A group of size 1
// (or a group with zero total traffic) naturally scores 1.0 -- there's no
// competitor to be relatively over/under loaded against.
//
// Deliberately does NOT touch which nodes a client/control considers
// eligible or which region they're filtered to -- this only adjusts the
// signed "load" value nodes already carry, which downstream formulas
// multiply into their existing RTT-based score. If disabled, every node's
// load is reset to 0 (neutral -- see nodeScore/effectiveRTT on the
// client/control side, which already treat 0 as "no data, use RTT alone").
func (h *handler) recomputeLoadFactors() {
	cfg := h.loadFactorSnapshot()

	for _, nodeType := range []string{"control", "exit"} {
		nodes, err := h.db.liveNodes(nodeType)
		if err != nil {
			logWarnf("load-factor: list %s nodes: %v", nodeType, err)
			continue
		}
		if len(nodes) == 0 {
			continue
		}

		if !cfg.Enabled {
			for _, n := range nodes {
				if err := h.db.setNodeLoad(n.ID, 0); err != nil {
					logWarnf("load-factor: reset %s: %v", n.Addr, err)
				}
			}
			continue
		}

		regionOf := h.regionFnWithOverrides(nodes)

		type sample struct {
			id    int64
			addr  string
			bytes int64
		}
		groups := make(map[string][]sample)
		for _, n := range nodes {
			region := regionOf(n.Addr)
			b := h.db.nodeHourlyBytes(n.ID)
			groups[region] = append(groups[region], sample{id: n.ID, addr: n.Addr, bytes: b})
		}

		lo, hi := cfg.ExitMin, cfg.ExitMax
		if nodeType == "control" {
			lo, hi = cfg.ControlMin, cfg.ControlMax
		}

		for region, samples := range groups {
			var total int64
			for _, s := range samples {
				total += s.bytes
			}
			mean := float64(total) / float64(len(samples))

			for _, s := range samples {
				factor := 1.0
				if mean > 0 {
					factor = float64(s.bytes) / mean
					if factor < lo {
						factor = lo
					} else if factor > hi {
						factor = hi
					}
				}
				if err := h.db.setNodeLoad(s.id, factor); err != nil {
					logWarnf("load-factor: write %s: %v", s.addr, err)
				}
			}
			logDebugf("load-factor: %s/%s: %d node(s), mean=%.0f MB/h", nodeType, region, len(samples), mean/1e6)
		}
	}
}

// adminLoadFactorUpdate handles POST /admin/loadfactor/update -- the tuning
// form (enabled toggle + 4 min/max fields) for admin_dashboard.html's
// Network Stats tab.
func (h *handler) adminLoadFactorUpdate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	admin := h.currentUser(r)
	who := "admin"
	if admin != nil {
		who = admin.Username
	}

	parse := func(field string, def float64) (float64, error) {
		v := r.FormValue(field)
		if v == "" {
			return def, nil
		}
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || f <= 0 {
			return 0, fmt.Errorf("%s: invalid value %q", field, v)
		}
		return f, nil
	}

	controlMin, err := parse("control_min", lfDefaultMin)
	if err == nil {
		var controlMax, exitMin, exitMax float64
		controlMax, err = parse("control_max", lfDefaultMax)
		if err == nil {
			exitMin, err = parse("exit_min", lfDefaultMin)
		}
		if err == nil {
			exitMax, err = parse("exit_max", lfDefaultMax)
		}
		if err == nil && (controlMin >= controlMax || exitMin >= exitMax) {
			err = fmt.Errorf("min must be less than max")
		}
		if err == nil {
			enabled := "0"
			if r.FormValue("enabled") == "1" {
				enabled = "1"
			}
			h.db.setSetting(lfSettingEnabled, enabled, who)                                //nolint:errcheck
			h.db.setSetting(lfSettingControlMin, strconv.FormatFloat(controlMin, 'f', 2, 64), who) //nolint:errcheck
			h.db.setSetting(lfSettingControlMax, strconv.FormatFloat(controlMax, 'f', 2, 64), who) //nolint:errcheck
			h.db.setSetting(lfSettingExitMin, strconv.FormatFloat(exitMin, 'f', 2, 64), who)       //nolint:errcheck
			h.db.setSetting(lfSettingExitMax, strconv.FormatFloat(exitMax, 'f', 2, 64), who)       //nolint:errcheck
			h.loadLoadFactorConfig()
			go h.recomputeLoadFactors() // apply immediately, don't make the admin wait for the ticker
			logInfof("admin: load-factor settings updated by %s (enabled=%s control=%.2f-%.2f exit=%.2f-%.2f)",
				who, enabled, controlMin, controlMax, exitMin, exitMax)
		}
	}
	if err != nil {
		http.Redirect(w, r, "/admin?tab=netstats&flash=Load+factor+error:+"+err.Error(), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin?tab=netstats&flash=Load+factor+settings+saved", http.StatusSeeOther)
}
