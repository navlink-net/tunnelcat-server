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
	"unicode"
)

// Bulk email broadcast to every registered user, admin-triggered from
// /admin/notify (not a separate CLI subcommand -- an earlier one-off
// `snc-arbiter notify-users` tool required editing hardcoded Go constants,
// rebuilding and redeploying the arbiter binary, then SSHing in to run it
// by hand for every single campaign. Replaced entirely by this API + form.

const broadcastDelay = 2 * time.Second
const broadcastStateDir = "/var/lib/snc/notify_sent"

// broadcastJob tracks the one broadcast that may be running at a time --
// there's no real use case for two concurrent campaigns, so a single
// in-memory job (not a queue) keeps this simple. Guarded by its own mutex
// since it's read by status polls while a send goroutine writes to it.
type broadcastJob struct {
	mu        sync.Mutex
	running   bool
	done      bool
	campaign  string
	total     int
	sent      int
	failed    int
	skipped   int
	log       []string
	startedAt time.Time
}

var currentBroadcast broadcastJob

func (j *broadcastJob) snapshot() map[string]interface{} {
	j.mu.Lock()
	defer j.mu.Unlock()
	logTail := j.log
	if len(logTail) > 200 {
		logTail = logTail[len(logTail)-200:]
	}
	return map[string]interface{}{
		"running":  j.running,
		"done":     j.done,
		"campaign": j.campaign,
		"total":    j.total,
		"sent":     j.sent,
		"failed":   j.failed,
		"skipped":  j.skipped,
		"log":      strings.Join(logTail, "\n"),
	}
}

func (j *broadcastJob) logf(format string, a ...interface{}) {
	j.mu.Lock()
	j.log = append(j.log, fmt.Sprintf(format, a...))
	j.mu.Unlock()
}

// slugifyCampaign turns a subject line into a filesystem-safe, stable id.
// The dedupe/resume state is scoped per campaign (one state file per slug),
// not one file shared by every broadcast forever -- that was the original
// CLI tool's design, and it meant a second, unrelated campaign would
// silently skip everyone who'd already received the *first* one. A letter
// about Wildcat and, next month, a letter about a pricing change are
// different campaigns and must each reach every user once.
func slugifyCampaign(subject string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(subject) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			prevDash = false
			continue
		}
		if !prevDash && b.Len() > 0 {
			b.WriteByte('-')
			prevDash = true
		}
	}
	s := strings.Trim(b.String(), "-")
	if s == "" {
		s = "campaign"
	}
	if len(s) > 60 {
		s = s[:60]
	}
	return s
}

// loadSentState reads a campaign's state file into a set. A missing file
// just means nothing from this campaign has been sent yet.
func loadSentState(path string) map[string]bool {
	set := make(map[string]bool)
	f, err := os.Open(path)
	if err != nil {
		return set
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := sc.Text(); line != "" {
			set[line] = true
		}
	}
	return set
}

type broadcastRequest struct {
	Subject string `json:"subject"`
	Body    string `json:"body"`
	Test    string `json:"test"` // present only for the test-send endpoint
}

// ── GET /admin/api/broadcast/preview ────────────────────────────────────────

// apiAdminBroadcastPreview returns how many users a broadcast would reach,
// so the admin form can show a real number before the confirm dialog.
func (h *handler) apiAdminBroadcastPreview(w http.ResponseWriter, r *http.Request) {
	n, err := h.db.userCount()
	if err != nil {
		jsonErr(w, "database error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"count": n}) //nolint:errcheck
}

// ── POST /admin/api/broadcast/test ──────────────────────────────────────────

// apiAdminBroadcastTest sends the draft to a single address (typically the
// admin's own), synchronously, without touching campaign state -- lets the
// admin see the real rendered email before committing to the full send.
func (h *handler) apiAdminBroadcastTest(w http.ResponseWriter, r *http.Request) {
	var req broadcastRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	req.Subject = strings.TrimSpace(req.Subject)
	req.Body = strings.TrimSpace(req.Body)
	req.Test = strings.TrimSpace(req.Test)
	if req.Subject == "" || req.Body == "" || req.Test == "" {
		jsonErr(w, "subject, body and test address are required", http.StatusBadRequest)
		return
	}
	html := adminEmailHTML(req.Subject, req.Body)
	if err := h.auth.sendEmail(req.Test, req.Subject, html); err != nil {
		jsonErr(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"ok": true}) //nolint:errcheck
}

// ── POST /admin/api/broadcast/send ──────────────────────────────────────────

// apiAdminBroadcastSend starts a background send to every registered user
// and returns immediately; progress is polled via apiAdminBroadcastStatus.
func (h *handler) apiAdminBroadcastSend(w http.ResponseWriter, r *http.Request) {
	var req broadcastRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	req.Subject = strings.TrimSpace(req.Subject)
	req.Body = strings.TrimSpace(req.Body)
	if req.Subject == "" || req.Body == "" {
		jsonErr(w, "subject and body are required", http.StatusBadRequest)
		return
	}

	currentBroadcast.mu.Lock()
	if currentBroadcast.running {
		currentBroadcast.mu.Unlock()
		jsonErr(w, "a broadcast is already running", http.StatusConflict)
		return
	}
	campaign := slugifyCampaign(req.Subject)
	// Reset fields in place -- NOT `currentBroadcast = broadcastJob{...}`,
	// which replaces the struct (and its embedded sync.Mutex) with a fresh,
	// never-locked one; the Unlock() below would then panic with "sync:
	// unlock of unlocked mutex", taking down the whole arbiter process, not
	// just this request. Confirmed live 2026-08-10: every "Send to all"
	// click crashed the arbiter (4 times in an hour) before this fix.
	currentBroadcast.running = true
	currentBroadcast.done = false
	currentBroadcast.campaign = campaign
	currentBroadcast.total = 0
	currentBroadcast.sent = 0
	currentBroadcast.failed = 0
	currentBroadcast.skipped = 0
	currentBroadcast.log = nil
	currentBroadcast.startedAt = time.Now()
	currentBroadcast.mu.Unlock()

	admin := ""
	if u := h.currentUser(r); u != nil {
		admin = u.Username
	}
	logInfof("broadcast: admin=%s campaign=%s starting", admin, campaign)

	go h.runBroadcast(campaign, req.Subject, req.Body)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"campaign": campaign}) //nolint:errcheck
}

// runBroadcast is the background send loop. Resumable across interruptions
// the same way the original CLI tool was (each successful send is appended
// to the campaign's state file immediately, so a restart mid-campaign skips
// addresses already reached instead of re-sending) -- just scoped per
// campaign and driven by the running server instead of a manual SSH session.
func (h *handler) runBroadcast(campaign, subject, body string) {
	defer func() {
		currentBroadcast.mu.Lock()
		currentBroadcast.running = false
		currentBroadcast.done = true
		currentBroadcast.mu.Unlock()
	}()

	emails, err := h.db.allUsernames()
	if err != nil {
		currentBroadcast.logf("ERROR: query users: %v", err)
		return
	}
	currentBroadcast.mu.Lock()
	currentBroadcast.total = len(emails)
	currentBroadcast.mu.Unlock()

	if err := os.MkdirAll(broadcastStateDir, 0755); err != nil {
		currentBroadcast.logf("ERROR: create state dir %s: %v", broadcastStateDir, err)
		return
	}
	statePath := filepath.Join(broadcastStateDir, campaign+".log")
	alreadySent := loadSentState(statePath)
	stateFile, err := os.OpenFile(statePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		currentBroadcast.logf("ERROR: open state file %s: %v", statePath, err)
		return
	}
	defer stateFile.Close()

	html := adminEmailHTML(subject, body)

	for _, e := range emails {
		if alreadySent[e] {
			currentBroadcast.mu.Lock()
			currentBroadcast.skipped++
			currentBroadcast.mu.Unlock()
			continue
		}
		if err := h.auth.sendEmail(e, subject, html); err != nil {
			currentBroadcast.logf("FAILED %s: %v", e, err)
			currentBroadcast.mu.Lock()
			currentBroadcast.failed++
			currentBroadcast.mu.Unlock()
			time.Sleep(broadcastDelay)
			continue
		}
		fmt.Fprintln(stateFile, e) //nolint:errcheck
		currentBroadcast.mu.Lock()
		currentBroadcast.sent++
		currentBroadcast.mu.Unlock()
		time.Sleep(broadcastDelay)
	}
	logInfof("broadcast: campaign=%s done sent=%d failed=%d skipped=%d",
		campaign, currentBroadcast.sent, currentBroadcast.failed, currentBroadcast.skipped)
}

// ── GET /admin/api/broadcast/status ─────────────────────────────────────────

func (h *handler) apiAdminBroadcastStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(currentBroadcast.snapshot()) //nolint:errcheck
}
