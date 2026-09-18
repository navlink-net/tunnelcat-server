// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

//go:build linux

package androidcore

import (
	"encoding/json"
	"net"
)

// Command is a JSON-framed IPC request from Kotlin.
type Command struct {
	Cmd  string          `json:"cmd"`
	Args json.RawMessage `json:"args,omitempty"`
}

// Response is a JSON-framed IPC reply to Kotlin.
type Response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// StatusResponse carries the current state of the core process.
type StatusResponse struct {
	Running   bool   `json:"running"`
	SocksAddr string `json:"socks_addr,omitempty"`
	NodeID    string `json:"node_id,omitempty"`
}

// TokenArgs carries a token update.
type TokenArgs struct {
	Token string `json:"token"`
}

// ClubStatusResponse carries the current Cat Club / Elite Cat Club
// membership state for the Kotlin UI: which theme to render (badge color +
// images), the permanent membership badge text, whether the logged-in
// account is an admin (gates the theme-preview switcher), and whether the
// account currently qualifies to recommend new Cat Club members.
type ClubStatusResponse struct {
	Theme        string `json:"theme"` // "", "catclub", or "elite" -- "" = regular, no club membership
	BadgeText    string `json:"badge_text,omitempty"`
	IsAdmin      bool   `json:"is_admin"`
	CanRecommend bool   `json:"can_recommend"`
}

// ClubPreviewArgs selects an admin-only theme preview override.
// Theme must be "", "catclub", or "elite" -- "" clears the override and
// reverts to the account's real discovered membership theme.
type ClubPreviewArgs struct {
	Theme string `json:"theme"`
}

// ClubRecommendArgs carries the target username for a Cat Club recommendation.
type ClubRecommendArgs struct {
	Username string `json:"username"`
}

// LogUploadPrefResponse mirrors tunnel_cat/snc/core.LogUploadPrefResponse --
// same field names, same meaning. See docs/LOG_UPLOAD_PRIVACY.md. Returned
// by the "log-upload-pref-get" and "log-upload-pref-set" IPC commands; a
// zero value (all false) is returned when there's no live tunnel to ask the
// arbiter over, same "empty on failure" convention as ClubStatusResponse.
type LogUploadPrefResponse struct {
	// OK is true only when the arbiter actually answered. An all-false reply
	// with OK=false means "couldn't reach the arbiter" (no live tunnel dialer
	// yet, or the request failed) -- deliberately explicit rather than
	// inferred from the other fields, because an all-false reply with
	// OK=true is also a real, legitimate state (global kill switch off AND
	// this user opted out), and the two must not be confused.
	OK            bool `json:"ok"`
	Enabled       bool `json:"enabled"`
	AdminDisabled bool `json:"admin_disabled"`
	GlobalEnabled bool `json:"global_enabled"`
	Effective     bool `json:"effective"`
}

// LogUploadPrefArgs carries the user's requested preference for the
// "log-upload-pref-set" IPC command.
type LogUploadPrefArgs struct {
	Enabled bool `json:"enabled"`
}

func WriteJSON(conn net.Conn, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = conn.Write(b)
	return err
}
