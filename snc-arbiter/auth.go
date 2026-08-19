// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const sessionCacheTTL = 600 * time.Second

// camerlengoNamespace is the user account namespace on the Camerlengo instance.
const camerlengoNamespace = "users"

// authClient talks to Camerlengo's v2 API (2026-08-13 migration off the
// legacy ".command" API — see docs/camerlengo-v2-migration.md). Same POST /
// endpoint and response envelope ({".status"/".errcode"/".reason"/...}) as
// legacy; the only wire difference is the request discriminator field
// ("command" instead of ".command") and that every command now declares an
// explicit auth mode (scope key / session / public) instead of one shared
// unscoped key gating everything. apiKey here is a v2 scoped key — see that
// doc for exactly which scopes it must carry (user:verify, user:getSessionUser,
// user:forceChangePassword, email:send, misc:generateQr; user:add is public
// and needs no key at all).
type authClient struct {
	url    string
	apiKey string
	client *http.Client
	mu     sync.Mutex
	cache  map[string]*cacheEntry
}

type cacheEntry struct {
	username  string
	validated time.Time
}

func newAuthClient(rawURL, apiKey string) *authClient {
	return &authClient{
		url:    strings.TrimRight(rawURL, "/") + "/",
		apiKey: apiKey,
		client: &http.Client{Timeout: 10 * time.Second},
		cache:  make(map[string]*cacheEntry),
	}
}

// v2Envelope is the common response shape for every v2 command (identical to
// legacy's — see Api2Dispatcher.CommandProcessorV2.makeResponse/error).
type v2Envelope struct {
	Status  string `json:".status"`
	ErrCode string `json:".errcode"`
	Reason  string `json:".reason"`
}

// v2Call POSTs a v2 command (payload must not already contain "command") and
// decodes the response into out (which should embed v2Envelope). Returns an
// error for transport/parse failures only — callers check .Status themselves,
// since "explicit rejection" vs. "transient" is handled differently in each
// call site (see login's retry loop).
func (a *authClient) v2Call(command string, payload map[string]interface{}, out interface{}) error {
	payload["command"] = command
	body, _ := json.Marshal(payload)
	resp, err := a.client.Post(a.url, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("POST %s: %w", command, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	logDebugf("auth: v2 %s response status=%d body=%s", command, resp.StatusCode, string(raw))
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("parse %s response: %w", command, err)
	}
	return nil
}

// validateSession returns the username for a Camerlengo session token, or "".
// Uses a local TTL cache; falls back to stale on auth-server error.
func (a *authClient) validateSession(token string) string {
	if token == "" {
		return ""
	}
	now := time.Now()

	a.mu.Lock()
	if e := a.cache[token]; e != nil && now.Sub(e.validated) < sessionCacheTTL {
		a.mu.Unlock()
		return e.username
	}
	var stale *cacheEntry
	if e := a.cache[token]; e != nil {
		stale = e
	}
	a.mu.Unlock()

	username, err := a.querySession(token)
	if err != nil {
		logWarnf("auth: session query failed: %v", err)
		if stale != nil {
			logWarnf("auth: using stale cache token=%.8s user=%s", token, stale.username)
			return stale.username
		}
		return ""
	}

	a.mu.Lock()
	if username != "" {
		a.cache[token] = &cacheEntry{username: username, validated: now}
		cutoff := now.Add(-2 * sessionCacheTTL)
		for k, v := range a.cache {
			if v.validated.Before(cutoff) {
				delete(a.cache, k)
			}
		}
	} else {
		delete(a.cache, token)
	}
	a.mu.Unlock()

	return username
}

// querySession calls v2 user:getSessionUser (scope key).
func (a *authClient) querySession(token string) (string, error) {
	var result struct {
		v2Envelope
		User string `json:"user"`
	}
	err := a.v2Call("user:getSessionUser", map[string]interface{}{
		"session": token,
		"key":     a.apiKey,
	}, &result)
	if err != nil {
		return "", err
	}
	return result.User, nil
}

// addUser creates a new user account in Camerlengo via v2 user:add (public —
// self-signup needs no key at all; see Api2UserCommands.py's docstring).
func (a *authClient) addUser(email, password string) error {
	var result struct {
		v2Envelope
	}
	err := a.v2Call("user:add", map[string]interface{}{
		"path":     camerlengoNamespace,
		"user":     email,
		"password": password,
	}, &result)
	if err != nil {
		return err
	}
	if result.Status == "error" {
		if result.Reason != "" {
			return fmt.Errorf("%s", result.Reason)
		}
		return fmt.Errorf("addUser rejected (code %s)", result.ErrCode)
	}
	return nil
}

// forceChangePassword sets a user's password in Camerlengo without a session,
// via the v2 user:forceChangePassword scope command added specifically for
// this project (2026-08-13) — see that command's docstring in
// reforce/API/Api2UserCommands.py. Used only where we've already established
// account ownership through our own out-of-band mechanism (an emailed
// single-use reset token, or a brand-new account whose throwaway password we
// created seconds ago) and genuinely have no Camerlengo session to present —
// plain v2 user:changePassword requires one and would incorrectly reject
// both of these calls.
func (a *authClient) forceChangePassword(email, password string) error {
	var result struct {
		v2Envelope
	}
	err := a.v2Call("user:forceChangePassword", map[string]interface{}{
		"path":     camerlengoNamespace,
		"user":     email,
		"password": password,
		"key":      a.apiKey,
	}, &result)
	if err != nil {
		return err
	}
	if result.Status == "error" {
		if result.Reason != "" {
			return fmt.Errorf("%s", result.Reason)
		}
		return fmt.Errorf("forceChangePassword rejected (code %s)", result.ErrCode)
	}
	return nil
}

// sendEmail sends an HTML email via Camerlengo's v2 email:send command, from
// TunnelCat's own mailbox. Email.send (reforce/EmailBasics.py) recognizes
// "cat@navlink.net" in the From header and automatically authenticates SMTP
// as that mailbox (instead of the shared relay account) and saves a copy to
// its real IMAP Sent folder -- see EmailBasics.send's save_to_sent doc.
func (a *authClient) sendEmail(to, subject, htmlBody string) error {
	return a.sendEmailFrom(to, "The Tunnel Cat <cat@navlink.net>", subject, htmlBody)
}

// sendEmailFrom sends an HTML email with a custom From address via Camerlengo v2.
func (a *authClient) sendEmailFrom(to, from, subject, htmlBody string) error {
	var result struct {
		v2Envelope
	}
	err := a.v2Call("email:send", map[string]interface{}{
		"to":      to,
		"from":    from,
		"subject": subject,
		"text":    htmlBody,
		"html":    true,
		"key":     a.apiKey,
	}, &result)
	if err != nil {
		return err
	}
	if result.Status != "ok" && result.Reason != "" {
		return fmt.Errorf("sendEmail: %s", result.Reason)
	}
	return nil
}

// generateQRCodeBase64 calls Camerlengo v2 misc:generateQr and returns a
// base64-encoded PNG of the QR code for the given text. Returns "" on any error.
func (a *authClient) generateQRCodeBase64(text string) string {
	var result struct {
		v2Envelope
		Data string `json:"data"`
	}
	err := a.v2Call("misc:generateQr", map[string]interface{}{
		"key":        a.apiKey,
		"text":       text,
		"errorLevel": "M",
	}, &result)
	if err != nil || result.Status != "ok" {
		return ""
	}
	return result.Data
}

// login calls Camerlengo v2 user:verify and returns the session token.
//
// Explicit rejections (.status == "error") are returned immediately without
// retry.  Transient failures (network errors, non-JSON responses, or empty
// responses where Camerlengo returns {} during startup) are retried with
// exponential backoff for up to loginMaxRetryDuration.  Camerlengo can take
// several minutes to restart, so the retry window is intentionally generous.
const loginMaxRetryDuration = 5 * time.Minute

func (a *authClient) login(username, password string) (string, error) {
	payload := map[string]interface{}{
		"path":     camerlengoNamespace,
		"user":     username,
		"password": password,
		"key":      a.apiKey,
	}

	deadline := time.Now().Add(loginMaxRetryDuration)
	retryDelay := 5 * time.Second
	const maxRetryDelay = 30 * time.Second

	for attempt := 1; ; attempt++ {
		if attempt > 1 {
			logWarnf("auth: login retry %d for %s (wait %s)", attempt, username, retryDelay)
			time.Sleep(retryDelay)
			retryDelay *= 2
			if retryDelay > maxRetryDelay {
				retryDelay = maxRetryDelay
			}
		}

		// Camerlengo response fields.  Wrong password returns
		//   {".status":"error", ".errcode":"203", ".reason":"Invalid username or password"}
		// Success returns
		//   {".status":"ok", "session":"<token>", ...}
		// During restart Camerlengo may return {} or non-JSON (HTML error page).
		var result struct {
			v2Envelope
			Session string `json:"session"`
		}
		err := a.v2Call("user:verify", payload, &result)
		if err != nil {
			// Transport error or non-JSON (e.g. HTML error page from a proxy): transient.
			if time.Now().After(deadline) {
				return "", err
			}
			continue
		}

		// Explicit auth rejection — never retry.
		if result.Status == "error" {
			if result.Reason != "" {
				return "", fmt.Errorf("%s", result.Reason)
			}
			return "", fmt.Errorf("auth rejected (code %s)", result.ErrCode)
		}

		// Success.
		if result.Session != "" {
			return result.Session, nil
		}

		// Empty/partial response ({} or {".status":"ok"} without a session):
		// Camerlengo is likely still starting up.  Retry until the deadline.
		lastErr := fmt.Errorf("login: empty session in response")
		if time.Now().After(deadline) {
			return "", lastErr
		}
	}
}
