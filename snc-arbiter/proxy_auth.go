// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/json"
	"net/http"
)

// transientErrBody matches the {"error":"...","transient":true} convention
// used by snc-exit/auth.go's deferredOrTransient — classifyAuthError (see
// snc/core/tunnel.go) turns a 503 with transient:true into ErrAuthTransient
// rather than ErrAuthRejected, which is what makes the caller retry (re-login
// then retry the request) instead of treating this as a hard credential
// failure. See the caller-session-expiry comment below for why that
// distinction matters here specifically.
const transientErrBody = `{"error":"caller_session_expired","transient":true}`

// proxyAuthRequest is the body of POST /api/auth/proxy-validate.
type proxyAuthRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// proxyAuthResponse is the response of POST /api/auth/proxy-validate.
type proxyAuthResponse struct {
	Session string `json:"session"`
}

// apiProxyValidate handles POST /api/auth/proxy-validate.
//
// Called by BlackBadger proxy instances to validate a SOCKS5 user's SNC
// credentials and obtain a session token on their behalf.
//
// Authentication: the caller must supply a valid SNC session token via
// X-Session (proving it is itself a legitimate, tunnel-connected SNC client).
// The returned session token belongs to the validated user — all traffic
// authorised with it is attributed to that user's account.
func (h *handler) apiProxyValidate(w http.ResponseWriter, r *http.Request) {
	// Authenticate the calling BlackBadger instance via its own session token.
	callerToken := r.Header.Get("X-Session")
	if callerToken == "" {
		jsonErr(w, "X-Session required", http.StatusUnauthorized)
		return
	}
	callerUser, _, _, _ := h.sessions.Validate(callerToken)
	if callerUser == "" {
		// The CALLER's (BlackBadger's) own session is unknown/expired here —
		// not the SOCKS5 end-user's credentials, which haven't even been
		// looked at yet. BB authenticates itself via key-auth (see
		// blackbadger/cmd/blackbadger main_linux.go SetKeyAuth), and key-auth
		// sessions are explicitly excluded from the background refresher
		// (sessions.go refreshOne: "Key-auth sessions have no Camerlengo
		// session — let them expire naturally") — so BB's own caller session
		// reliably dies after sessionStaleTTL (3h) unless BB itself re-logs
		// in. If this returned a plain 401 here, classifyAuthError (see
		// snc/core/tunnel.go) would turn it into ErrAuthRejected, which
		// blackbadger/core/auth_cache.go's GetDialer treats as a hard
		// rejection of the *end user's* password and gives up immediately —
		// even though the user's credentials were never actually checked.
		// This caused a real outage (2026-08-06): every BB instance's own
		// caller session expired ~3h after its last login/restart, and every
		// SOCKS5 auth attempt after that failed with "wrong password" for
		// every user, indefinitely, until the BB process itself was
		// restarted. Returning transient:true here instead routes through
		// GetDialer's existing ErrAuthTransient path, which re-logs in
		// callerAuth and retries ProxyValidate once — recovering without
		// any user-visible failure or manual restart.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(transientErrBody)) //nolint:errcheck
		return
	}

	var req proxyAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
		jsonErr(w, "username and password required", http.StatusBadRequest)
		return
	}

	token, err := h.sessions.LoginAsProxy(req.Username, req.Password)
	if err != nil {
		logInfof("proxy-auth: denied user=%s caller=%s: %v", req.Username, callerUser, err)
		jsonErr(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	logInfof("proxy-auth: ok user=%s caller=%s token=%.8s…", req.Username, callerUser, token)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(proxyAuthResponse{Session: token}) //nolint:errcheck
}
