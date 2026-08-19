// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import "errors"

// ErrorKind is a coarse, user-facing classification of a connect/login
// failure. UIs use this (via FriendlyConnectError) to show a short message
// instead of the full technical error chain -- which routinely contains
// internal control-node IPs, ports, and Go's raw dial/transport error text.
// The full detail always stays available via the normal Log.Printf calls at
// each call site; this classification never replaces that, only what gets
// shown on screen.
type ErrorKind int

const (
	// ErrKindUnknown is the fallback when the error doesn't match any of the
	// sentinels below (e.g. a TUN/routing setup failure, a panic, or some
	// other non-auth error). Still shown as a short, non-technical message.
	ErrKindUnknown ErrorKind = iota
	// ErrKindNoConnection: transport-level failure -- dial timeout, connection
	// refused, DNS failure -- no control node actually responded. Covers the
	// case of a stale cached control address the client hasn't refreshed
	// away from yet, as well as genuine local network loss.
	ErrKindNoConnection
	// ErrKindAccessDenied: a control node responded but explicitly rejected
	// the credentials/key (ErrAuthRejected).
	ErrKindAccessDenied
	// ErrKindServerUnavailable: a control node responded but flagged the
	// arbiter itself as briefly unreachable (ErrAuthTransient) -- expected to
	// clear on retry, not a credential problem.
	ErrKindServerUnavailable
)

// ClassifyConnectError buckets any connect/login error into an ErrorKind
// using errors.Is against the sentinels this package already defines.
// Never returns an error itself -- nil input classifies as ErrKindUnknown,
// same as any error that doesn't match a known sentinel.
func ClassifyConnectError(err error) ErrorKind {
	switch {
	case err == nil:
		return ErrKindUnknown
	case errors.Is(err, ErrAuthRejected):
		return ErrKindAccessDenied
	case errors.Is(err, ErrAuthTransient):
		return ErrKindServerUnavailable
	case errors.Is(err, ErrNoConnection):
		return ErrKindNoConnection
	default:
		return ErrKindUnknown
	}
}

// friendlyConnectMessages holds the short, English, technical-detail-free
// text shown to the user for each ErrorKind. Keep these short -- tray
// tooltips and status bars have limited room -- and never interpolate the
// underlying error into them.
var friendlyConnectMessages = map[ErrorKind]string{
	ErrKindNoConnection:      "No connection",
	ErrKindAccessDenied:      "Access denied",
	ErrKindServerUnavailable: "Server temporarily unavailable",
	ErrKindUnknown:           "Unknown error",
}

// FriendlyConnectError returns the short, user-facing message for err.
// This is what UI code should show on screen (tray tooltip, status bar,
// etc.) -- log the full err separately via Log.Printf for diagnostics, as
// existing call sites already do.
func FriendlyConnectError(err error) string {
	return friendlyConnectMessages[ClassifyConnectError(err)]
}
