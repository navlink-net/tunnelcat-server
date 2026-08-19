// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// exitBytesTotal is a monotonically increasing counter of all bytes proxied by
// this exit node (up + down combined). Read by the heartbeat to compute bw_mbps.
var exitBytesTotal atomic.Int64

// statsFlushInterval controls how often accumulated stats are sent to the arbiter.
const statsFlushInterval = 5 * time.Minute

// sessionIdleTimeout is how long a user can go without any traffic before
// their session is considered over. Needs to be long enough that an
// ordinary brief network hiccup or a reconnect within the same logical VPN
// session doesn't fragment it into two, but short enough that "session
// duration" means something -- 15 min splits the difference (longer than
// any normal control/exit failover, per router.go's dial budgets; shorter
// than someone plausibly stepping away and coming back to what they'd
// consider the "same" session).
const sessionIdleTimeout = 15 * time.Minute

// sessionSweepInterval controls how often idle sessions get closed out and
// queued for reporting. Independent of statsFlushInterval on purpose: a
// session in progress must survive across many flush cycles (flush() wipes
// sc.users every statsFlushInterval regardless of whether the user is still
// connected -- that map is a per-flush-window accumulator, not session
// state), so session tracking lives in its own map that only sweep()
// touches.
const sessionSweepInterval = 1 * time.Minute

// userAccum holds per-user aggregated stats between flushes.
type userAccum struct {
	country   string
	bytesUp   int64
	bytesDown int64
	conns     int64
	lastSeen  time.Time
}

// activeSession tracks one in-progress session for session-duration
// reporting. Separate from userAccum (see sessionSweepInterval's doc
// comment) -- this lives until sweep() decides the user has gone idle long
// enough that the session is over, not until the next stats flush.
type activeSession struct {
	start        time.Time
	lastActivity time.Time
}

// completedSession is a finished session queued for the next stats flush.
type completedSession struct {
	username string
	seconds  int64
	endedAt  time.Time
}

// StatsCollector accumulates per-user traffic stats, flushing them to the
// arbiter every statsFlushInterval.
type StatsCollector struct {
	mu    sync.Mutex
	users map[string]*userAccum

	sessions          map[string]*activeSession
	completedSessions []completedSession

	// rejectedSessions counts sessions THIS exit gave up on because it
	// couldn't deliver the user's data to the target or get a response back
	// -- see RecordRejectedSession's callers in handler.go. Deliberately the
	// only source of the admin dashboard's "rejected sessions" stat: this is
	// an exit-observable fact (it decided to tear the session down), not
	// something the client can infer reliably.
	rejectedSessions atomic.Int64

	arbiterURL string
	token      string
}

func newStatsCollector(arbiterURL, token string) *StatsCollector {
	sc := &StatsCollector{
		users:      make(map[string]*userAccum),
		sessions:   make(map[string]*activeSession),
		arbiterURL: strings.TrimRight(arbiterURL, "/"),
		token:      token,
	}
	go sc.loop()
	go sc.sweepLoop()
	return sc
}

// RecordBytes adds bytes transferred for a user, for the per-user stats
// this exit flushes to the arbiter (/api/node/stats) -- a separate feature
// from the node-wide exitBytesTotal counter (see ServeHTTP's wireBytesPaths
// handling, handler.go), which is tallied at the HTTP wire level instead so
// it's directly comparable to control's controlBytesTotal. Don't fold this
// back into exitBytesTotal: bytesUp/bytesDown here are post-frame-parse
// target-connection payload, a different (and, for /api/udp/relay traffic,
// incomplete) measurement than the wire-level one.
// country is the ISO-2 code from CIDR lookup (may be "").
func (sc *StatsCollector) RecordBytes(username, country string, bytesUp, bytesDown int64) {
	if username == "" {
		return
	}
	sc.mu.Lock()
	u := sc.users[username]
	if u == nil {
		u = &userAccum{}
		sc.users[username] = u
	}
	u.bytesUp += bytesUp
	u.bytesDown += bytesDown
	u.conns++
	u.lastSeen = time.Now()
	if country != "" {
		u.country = country
	}

	now := u.lastSeen
	s := sc.sessions[username]
	if s == nil {
		s = &activeSession{start: now}
		sc.sessions[username] = s
	}
	s.lastActivity = now

	sc.mu.Unlock()
}

// RecordRejectedSession counts one session this exit tore down because it
// couldn't deliver the user's data to the target or get a response back --
// see handler.go's three call sites (dial failure, mid-session write
// failure, and a target connection that closed having sent back nothing at
// all). Not tied to a specific user: this is a fleet-wide count for the
// admin dashboard's existing "rejected sessions" chart, same shape as
// exitBytesTotal.
func (sc *StatsCollector) RecordRejectedSession() {
	sc.rejectedSessions.Add(1)
}

// sweepLoop periodically closes out sessions that have gone idle past
// sessionIdleTimeout, queuing them for the next stats flush.
func (sc *StatsCollector) sweepLoop() {
	t := time.NewTicker(sessionSweepInterval)
	defer t.Stop()
	for range t.C {
		sc.sweep()
	}
}

func (sc *StatsCollector) sweep() {
	cutoff := time.Now().Add(-sessionIdleTimeout)
	sc.mu.Lock()
	for username, s := range sc.sessions {
		if s.lastActivity.Before(cutoff) {
			sc.completedSessions = append(sc.completedSessions, completedSession{
				username: username,
				seconds:  int64(s.lastActivity.Sub(s.start).Seconds()),
				endedAt:  s.lastActivity,
			})
			delete(sc.sessions, username)
		}
	}
	sc.mu.Unlock()
}

func (sc *StatsCollector) loop() {
	// Flush shortly after startup so admin reflects reconnecting users quickly
	// instead of waiting the full statsFlushInterval after every restart.
	time.Sleep(30 * time.Second)
	sc.flush()
	t := time.NewTicker(statsFlushInterval)
	defer t.Stop()
	for range t.C {
		sc.flush()
	}
}

type statsPayload struct {
	Users            []statsUserEntry    `json:"users"`
	Sessions         []statsSessionEntry `json:"sessions"`
	RejectedSessions int64               `json:"rejected_sessions"`
}

// statsSessionEntry is one completed session (see sweep()), reported once,
// after the fact -- not a live/in-progress figure.
type statsSessionEntry struct {
	Username string `json:"username"`
	Seconds  int64  `json:"seconds"`
	EndedAt  int64  `json:"ended_at"`
}

type statsUserEntry struct {
	Username  string `json:"username"`
	Country   string `json:"country"`
	BytesUp   int64  `json:"bytes_up"`
	BytesDown int64  `json:"bytes_down"`
	Conns     int64  `json:"conns"`
	LastSeen  int64  `json:"last_seen"`
}

func (sc *StatsCollector) flush() {
	rejected := sc.rejectedSessions.Swap(0)
	sc.mu.Lock()
	if len(sc.users) == 0 && len(sc.completedSessions) == 0 && rejected == 0 {
		sc.mu.Unlock()
		return
	}
	payload := statsPayload{RejectedSessions: rejected}
	for username, u := range sc.users {
		payload.Users = append(payload.Users, statsUserEntry{
			Username:  username,
			Country:   u.country,
			BytesUp:   u.bytesUp,
			BytesDown: u.bytesDown,
			Conns:     u.conns,
			LastSeen:  u.lastSeen.Unix(),
		})
	}
	for _, s := range sc.completedSessions {
		payload.Sessions = append(payload.Sessions, statsSessionEntry{
			Username: s.username,
			Seconds:  s.seconds,
			EndedAt:  s.endedAt.Unix(),
		})
	}
	sc.completedSessions = nil
	sc.users = make(map[string]*userAccum)
	sc.mu.Unlock()

	body, err := json.Marshal(payload)
	if err != nil {
		logWarnf("stats: marshal: %v", err)
		return
	}
	req, err := http.NewRequest("POST", sc.arbiterURL+"/api/node/stats", bytes.NewReader(body))
	if err != nil {
		logWarnf("stats: build request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Node-Token", sc.token)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logWarnf("stats: POST failed: %v", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logWarnf("stats: arbiter returned status=%d", resp.StatusCode)
		return
	}
	logDebugf("stats: flushed users=%d", len(payload.Users))
}
