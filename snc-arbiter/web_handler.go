// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"net/http"
	"strings"
	"time"
)

// isGetOrHead reports whether r is a GET or HEAD request. Download routes
// match both: front-end pages (e.g. Web/navlink/download.html) HEAD-check
// each binary's availability before showing its button, and net/http's
// ServeContent (used by downloadFile) already answers HEAD correctly on its
// own -- responds with the same headers, no body. Before this, HEAD fell
// through every GET-only case to the default JSON-RPC handler, which
// returned 400 for a request with no JSON body -- every visitor's
// availability check failed and every download button showed "Coming soon"
// regardless of whether the file was actually there (confirmed live
// 2026-08-18: GET returned 200, HEAD returned 400 for the same URL).
func isGetOrHead(r *http.Request) bool {
	return r.Method == http.MethodGet || r.Method == http.MethodHead
}

// webPlane serves the public website and admin UI over the web-facing port
// (typically :8080, behind nginx). It is intentionally isolated from the
// network control plane so that web traffic cannot crash node heartbeats.
type webPlane struct{ h *handler }

func (p *webPlane) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	p.serveHTTP(rec, r)
	logInfof("web: %s %s %s status=%d dur=%s",
		r.Method, r.URL.Path, r.RemoteAddr, rec.status, time.Since(start).Round(time.Millisecond))
}

// devFrontendOrigins are the local dev ports for the new per-brand front-ends
// (tunnel_cat/Web/{navlink,tunnelcat,shortnerdcat,apps}/) that call this
// arbiter's JSON API cross-origin during local review. Extend with the real
// subdomain origins (https://navlink.net, https://shortnerdcat.navlink.net,
// etc.) once those are deployed — never use "*" here, credentialed CORS
// requires an explicit origin echo.
var devFrontendOrigins = map[string]bool{
	"http://localhost:8888":            true,
	"http://127.0.0.1:8888":            true,
	"https://navlink.net":              true,
	"https://www.navlink.net":          true,
	"https://shortnerdcat.navlink.net": true,
	"https://tunnelcat.navlink.net":    true,
	"https://apps.navlink.net":         true,
}

// applyCORS allows the JSON API (called via fetch() from the new front-ends,
// which live on a different origin/port than this arbiter) to be used with
// credentials. Only applied to /api/* and /my/api/* — never to /admin* or
// the control-plane, which don't need cross-origin access.
func applyCORS(w http.ResponseWriter, r *http.Request) (handled bool) {
	origin := r.Header.Get("Origin")
	if origin != "" && devFrontendOrigins[origin] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Vary", "Origin")
	}
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

// healthCheck reports whether this instance can actually serve traffic --
// used by the load balancer to decide whether to route to it. A process
// that's up but has lost its DB connection (network blip to the DB server,
// DB server itself down) must be pulled from rotation, not left serving
// errors to real clients, so this does a real query rather than just
// answering "process alive".
func (h *handler) healthCheck(w http.ResponseWriter, r *http.Request) {
	var one int
	if err := h.db.db.Get(&one, "SELECT 1"); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("db unreachable")) //nolint:errcheck
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok")) //nolint:errcheck
}

func (p *webPlane) serveHTTP(w http.ResponseWriter, r *http.Request) {
	h := p.h
	path := r.URL.Path

	if strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/my/api/") {
		if applyCORS(w, r) {
			return
		}
	}

	switch {
	// ── Health check (load balancer target) ───────────────────────────────
	// Unauthenticated on purpose -- reveals nothing beyond up/down, and a
	// load balancer's health checker has no way to hold admin credentials.
	// Checks real DB connectivity (not just "process is running"), so an
	// instance whose DB connection is broken gets pulled out of rotation
	// instead of serving errors to real traffic.
	case path == "/healthz":
		h.healthCheck(w, r)

	// ── Static assets (embedded) ──────────────────────────────────────────
	case strings.HasPrefix(path, "/static/"):
		h.serveStatic(w, r)

	// ── Partner pages ─────────────────────────────────────────────────────
	case path == "/partners" && r.Method == http.MethodGet:
		h.partnersPage(w, r)
	case path == "/partners/download/apk" && isGetOrHead(r):
		h.partnersDownloadApk(w, r)
	case path == "/partners/proekt" && r.Method == http.MethodGet:
		h.partnersProekt(w, r)
	case path == "/partners/lisinder" && r.Method == http.MethodGet:
		h.partnersLisinder(w, r)
	case path == "/partners/lisinder/download/apk" && isGetOrHead(r):
		h.partnersLisinderDownloadApk(w, r)

	// ── Public landing page (real navlink.net traffic never reaches "/" here
	// -- nginx's catch-all already sends it to the static site) ────────────
	case path == "/blackbadger" && r.Method == http.MethodGet:
		h.blackbadgerPage(w, r)
	case path == "/blackbadger-inquiry" && r.Method == http.MethodPost:
		h.blackbadgerInquiry(w, r)

	case path == "/api/key/free" && r.Method == http.MethodPost:
		h.apiKeyFree(w, r)
	case path == "/api/captcha" && r.Method == http.MethodGet:
		h.apiCaptcha(w, r)
	case path == "/api/account/start" && r.Method == http.MethodPost:
		h.apiAccountStart(w, r)
	case path == "/api/account/login" && r.Method == http.MethodPost:
		h.apiAccountLogin(w, r)
	case path == "/api/account/set-password" && r.Method == http.MethodPost:
		h.apiAccountSetPassword(w, r)
	case path == "/api/session/token" && r.Method == http.MethodGet:
		h.apiSessionToken(w, r)
	case path == "/api/session/verify" && r.Method == http.MethodPost:
		// Server-to-server only (see session_api.go) -- deliberately outside
		// the CORS allowlist below; a browser can't usefully call this anyway
		// since it needs the raw token, not cookie credentials.
		h.apiSessionVerify(w, r)
	case path == "/api/downloads/info" && r.Method == http.MethodGet:
		h.apiDownloadsInfo(w, r)

	// ── Apps showcase (apps.navlink.net storefront, public read-only) ──────
	case path == "/api/apps/meta" && r.Method == http.MethodGet:
		h.apiAppsMeta(w, r)
	case path == "/api/apps/list" && r.Method == http.MethodGet:
		h.apiAppsList(w, r)
	case strings.HasPrefix(path, "/api/apps/") && r.Method == http.MethodGet:
		h.apiAppGet(w, r)

	case path == "/support" && r.Method == http.MethodGet:
		h.supportPage(w, r)
	case path == "/support" && r.Method == http.MethodPost:
		h.supportSubmit(w, r)
	case path == "/download/zip" && isGetOrHead(r):
		h.downloadZip(w, r)
	case path == "/download/zip-installer" && isGetOrHead(r):
		h.downloadZipInstaller(w, r)
	case path == "/download/apk" && isGetOrHead(r):
		h.downloadApk(w, r)
	case path == "/download/dmg" && isGetOrHead(r):
		h.downloadDmg(w, r)
	case path == "/download/deb" && isGetOrHead(r):
		h.downloadDeb(w, r)
	case path == "/ratatosk" && r.Method == http.MethodGet:
		h.ratatoskPage(w, r)
	case path == "/ratatosk/privacy" && r.Method == http.MethodGet:
		h.ratatoskPrivacyPage(w, r)
	case path == "/ratatosk/support" && r.Method == http.MethodGet:
		h.ratatoskSupportPage(w, r)
	case path == "/ratatosk/support" && r.Method == http.MethodPost:
		h.ratatoskSupportSubmit(w, r)
	case path == "/ratatosk/download/apk" && isGetOrHead(r):
		h.ratatoskDownloadApk(w, r)
	case path == "/ratatosk/download/zip" && isGetOrHead(r):
		h.ratatoskDownloadZip(w, r)
	case path == "/ratatosk/download/dmg" && isGetOrHead(r):
		h.ratatoskDownloadDmg(w, r)

	// ── Auth API (JSON only -- see get_key.go/signup.go) ───────────────────
	case path == "/api/account/confirm-email" && r.Method == http.MethodPost:
		h.apiConfirmEmail(w, r)
	case path == "/api/account/resend-confirmation" && r.Method == http.MethodPost:
		h.apiResendConfirmation(w, r)
	case path == "/api/account/forgot-password" && r.Method == http.MethodPost:
		h.apiForgotPassword(w, r)
	case path == "/api/account/reset-password" && r.Method == http.MethodPost:
		h.apiResetPassword(w, r)
	case path == "/api/account/logout" && r.Method == http.MethodPost:
		h.apiAccountLogout(w, r)
	case path == "/logout":
		h.logout(w, r)
	case path == "/admin/logout":
		h.adminLogout(w, r)
	case path == "/admin/login" && r.Method == http.MethodGet:
		h.adminLoginPage(w, r)
	case path == "/admin/login" && r.Method == http.MethodPost:
		h.adminLoginSubmit(w, r)

	// ── Admin UI ──────────────────────────────────────────────────────────
	case path == "/admin" && r.Method == http.MethodGet:
		h.requireAdmin(h.adminDashboard)(w, r)
	case path == "/admin/pending" && r.Method == http.MethodGet:
		h.requireAdmin(h.adminPendingPage)(w, r)
	case path == "/admin/infra" && r.Method == http.MethodGet:
		h.requireAdmin(h.adminInfraPage)(w, r)
	case strings.HasPrefix(path, "/admin/nodes/") && r.Method == http.MethodPost:
		h.requireAdmin(h.adminNodeAction)(w, r)
	case path == "/admin/apps" && r.Method == http.MethodGet:
		h.requireAdmin(h.adminAppsPage)(w, r)
	case strings.HasPrefix(path, "/admin/apps/") && r.Method == http.MethodPost:
		h.requireAdmin(h.adminAppAction)(w, r)
	case path == "/admin/update" && r.Method == http.MethodGet:
		h.requireAdmin(h.adminUpdatePage)(w, r)
	case path == "/admin/update/upload" && r.Method == http.MethodPost:
		h.requireAdmin(h.adminUpdateUpload)(w, r)
	case path == "/admin/downloads" && r.Method == http.MethodGet:
		h.requireAdmin(h.adminDownloadsPage)(w, r)
	case path == "/admin/downloads/upload" && r.Method == http.MethodPost:
		// Allow either an admin session (browser) or Bearer upload-key (deploy scripts).
		if h.checkUploadKey(r) && r.Header.Get("Authorization") != "" {
			h.adminDownloadsUpload(w, r)
		} else {
			h.requireAdmin(h.adminDownloadsUpload)(w, r)
		}
	case path == "/admin/key" && r.Method == http.MethodGet:
		h.requireAdmin(h.adminKeygenPage)(w, r)
	case path == "/admin/key/generate-page" && r.Method == http.MethodPost:
		h.requireAdmin(h.adminKeygenPageSubmit)(w, r)
	case path == "/admin/key/generate" && r.Method == http.MethodPost:
		h.adminGenerateKey(w, r) // auth handled inside: admin session OR X-Admin-Token
	case path == "/admin/whitelist" && r.Method == http.MethodGet:
		h.requireAdmin(h.adminWhitelistPage)(w, r)
	case path == "/admin/whitelist/add" && r.Method == http.MethodPost:
		h.requireAdmin(h.adminWhitelistAdd)(w, r)
	case path == "/admin/whitelist/delete" && r.Method == http.MethodPost:
		h.requireAdmin(h.adminWhitelistDelete)(w, r)

	case path == "/admin/clubs" && r.Method == http.MethodGet:
		h.requireAdmin(h.adminClubsPage)(w, r)
	case path == "/admin/clubs/invite" && r.Method == http.MethodPost:
		h.requireAdmin(h.adminClubsInvite)(w, r)
	case path == "/admin/clubs/grant" && r.Method == http.MethodPost:
		h.requireAdmin(h.adminClubsGrant)(w, r)
	case path == "/admin/clubs/revoke" && r.Method == http.MethodPost:
		h.requireAdmin(h.adminClubsRevoke)(w, r)
	case path == "/admin/clubs/assign-node" && r.Method == http.MethodPost:
		h.requireAdmin(h.adminClubsAssignNode)(w, r)

	case path == "/admin/service-blocks" && r.Method == http.MethodGet:
		h.requireAdmin(h.adminServiceBlocksPage)(w, r)
	case path == "/admin/service-blocks/add" && r.Method == http.MethodPost:
		h.requireAdmin(h.adminServiceBlocksAdd)(w, r)
	case path == "/admin/service-blocks/delete" && r.Method == http.MethodPost:
		h.requireAdmin(h.adminServiceBlocksDelete)(w, r)

	case path == "/admin/anon-bootstrap" && r.Method == http.MethodGet:
		h.requireAdmin(h.adminAnonBootstrapPage)(w, r)
	case path == "/admin/anon-bootstrap/add" && r.Method == http.MethodPost:
		h.requireAdmin(h.adminAnonBootstrapAdd)(w, r)
	case path == "/admin/anon-bootstrap/delete" && r.Method == http.MethodPost:
		h.requireAdmin(h.adminAnonBootstrapDelete)(w, r)
	case path == "/admin/anon-bootstrap/regenerate" && r.Method == http.MethodPost:
		h.requireAdmin(h.adminAnonBootstrapRegenerate)(w, r)

	case path == "/admin/blacklist" && r.Method == http.MethodGet:
		h.requireAdmin(h.adminBlacklistPage)(w, r)
	case path == "/admin/blacklist/add" && r.Method == http.MethodPost:
		h.requireAdmin(h.adminBlacklistAdd)(w, r)
	case path == "/admin/blacklist/delete" && r.Method == http.MethodPost:
		h.requireAdmin(h.adminBlacklistDelete)(w, r)

	case path == "/admin/torrent-blocked/add" && r.Method == http.MethodPost:
		h.requireAdmin(h.adminTorrentBlockedAdd)(w, r)
	case path == "/admin/torrent-blocked/delete" && r.Method == http.MethodPost:
		h.requireAdmin(h.adminTorrentBlockedDelete)(w, r)

	case path == "/api/admin/excluded" && r.Method == http.MethodGet:
		h.requireAdmin(h.adminExcludedList)(w, r)
	case path == "/api/admin/excluded/add" && r.Method == http.MethodPost:
		h.requireAdmin(h.adminExcludedAdd)(w, r)
	case path == "/api/admin/excluded/delete" && r.Method == http.MethodPost:
		h.requireAdmin(h.adminExcludedDelete)(w, r)

	case path == "/admin/users" && r.Method == http.MethodGet:
		http.Redirect(w, r, "/admin?tab=users", http.StatusFound)
	case path == "/admin/api/dashboard/stats" && r.Method == http.MethodGet:
		h.requireAdmin(h.apiDashboardStats)(w, r)
	case path == "/admin/api/users/stats" && r.Method == http.MethodGet:
		h.requireAdmin(h.apiAdminUsersStats)(w, r)
	case path == "/admin/api/users/summary" && r.Method == http.MethodGet:
		h.requireAdmin(h.apiAdminUsersSummary)(w, r)
	case path == "/admin/api/users/export.csv" && r.Method == http.MethodGet:
		h.requireAdmin(h.apiAdminUsersCSV)(w, r)
	case path == "/admin/api/users/pending" && r.Method == http.MethodGet:
		h.requireAdmin(h.apiAdminPendingUsers)(w, r)
	case strings.HasPrefix(path, "/admin/api/users/") && strings.HasSuffix(path, "/confirm-email") && r.Method == http.MethodPost:
		h.requireAdmin(h.apiAdminConfirmEmail)(w, r)
	case strings.HasPrefix(path, "/admin/api/users/") && strings.HasSuffix(path, "/conn-stats") && r.Method == http.MethodGet:
		h.requireAdmin(h.apiAdminUserConnStats)(w, r)
	case strings.HasPrefix(path, "/admin/api/users/") && strings.HasSuffix(path, "/bananameter") && r.Method == http.MethodGet:
		h.requireAdmin(h.apiAdminUserBananameter)(w, r)

	// ── Admin key management API ──────────────────────────────────────────
	case strings.HasPrefix(path, "/admin/api/users/") && strings.HasSuffix(path, "/keys") && r.Method == http.MethodGet:
		h.requireAdmin(h.apiAdminUserKeys)(w, r)
	case strings.HasPrefix(path, "/admin/api/keys/") && strings.HasSuffix(path, "/enable") && r.Method == http.MethodPost:
		h.requireAdmin(h.apiAdminKeyEnable)(w, r)
	case strings.HasPrefix(path, "/admin/api/keys/") && strings.HasSuffix(path, "/disable") && r.Method == http.MethodPost:
		h.requireAdmin(h.apiAdminKeyDisable)(w, r)
	case strings.HasPrefix(path, "/admin/api/users/") && strings.HasSuffix(path, "/enable") && r.Method == http.MethodPost:
		h.requireAdmin(h.apiAdminUserEnable)(w, r)
	case strings.HasPrefix(path, "/admin/api/users/") && strings.HasSuffix(path, "/disable") && r.Method == http.MethodPost:
		h.requireAdmin(h.apiAdminUserDisable)(w, r)
	case strings.HasPrefix(path, "/admin/api/users/") && strings.HasSuffix(path, "/issue-key") && r.Method == http.MethodPost:
		h.requireAdmin(h.apiAdminIssueKey)(w, r)
	case strings.HasPrefix(path, "/admin/api/users/") && strings.HasSuffix(path, "/email") && r.Method == http.MethodPost:
		h.requireAdmin(h.apiAdminEmailUser)(w, r)
	case strings.HasPrefix(path, "/admin/api/keys/") && strings.HasSuffix(path, "/unbind") && r.Method == http.MethodPost:
		h.requireAdmin(h.apiAdminKeyUnbind)(w, r)
	case strings.HasPrefix(path, "/admin/api/keys/") && strings.HasSuffix(path, "/set-paid-until") && r.Method == http.MethodPost:
		h.requireAdmin(h.apiAdminKeySetPaidUntil)(w, r)
	case strings.HasPrefix(path, "/admin/api/keys/") && strings.HasSuffix(path, "/set-unlimited") && r.Method == http.MethodPost:
		h.requireAdmin(h.apiAdminKeySetUnlimited)(w, r)
	case path == "/api/admin/keys" && r.Method == http.MethodPost:
		h.apiRegisterKey(w, r)
	case path == "/api/admin/node" && r.Method == http.MethodPost:
		h.requireAdmin(h.apiAdminNodeRegister)(w, r)
	case strings.HasPrefix(path, "/api/admin/node/") && strings.HasSuffix(path, "/approve") && r.Method == http.MethodPost:
		h.requireAdmin(h.apiAdminNodeApprove)(w, r)

	// ── Node deploy status ────────────────────────────────────────────────────
	case strings.HasPrefix(path, "/api/nodes/") && strings.HasSuffix(path, "/deploy-status") && r.Method == http.MethodGet:
		h.requireUser(h.apiNodeDeployStatus)(w, r)
	case strings.HasPrefix(path, "/admin/api/nodes/") && strings.HasSuffix(path, "/deploy-status") && r.Method == http.MethodGet:
		h.requireAdmin(h.apiAdminNodeDeployStatus)(w, r)
	case strings.HasPrefix(path, "/admin/api/nodes/") && strings.HasSuffix(path, "/region") && r.Method == http.MethodPost:
		h.requireAdmin(h.adminNodeSetRegion)(w, r)
	case strings.HasPrefix(path, "/admin/api/nodes/") && strings.HasSuffix(path, "/pinned") && r.Method == http.MethodPost:
		h.requireAdmin(h.adminNodeSetPinned)(w, r)
	case strings.HasPrefix(path, "/admin/api/nodes/") && strings.HasSuffix(path, "/sni-list") && r.Method == http.MethodPost:
		h.requireAdmin(h.apiAdminNodeSetSNIList)(w, r)
	case strings.HasPrefix(path, "/admin/api/nodes/") && strings.HasSuffix(path, "/stats") && r.Method == http.MethodGet:
		h.requireAdmin(h.apiAdminNodeStats)(w, r)
	case strings.HasPrefix(path, "/admin/api/nodes/") && strings.HasSuffix(path, "/bananameter") && r.Method == http.MethodGet:
		h.requireAdmin(h.apiAdminNodeBananameter)(w, r)
	case path == "/admin/api/network/stats" && r.Method == http.MethodGet:
		h.requireAdmin(h.apiAdminNetworkStats)(w, r)
	case path == "/admin/api/network/usage" && r.Method == http.MethodGet:
		h.requireAdmin(h.apiAdminNetworkUsage)(w, r)
	case path == "/admin/api/network/peaks" && r.Method == http.MethodGet:
		h.requireAdmin(h.apiAdminNetworkPeaks)(w, r)
	case path == "/admin/api/network/conn-stats" && r.Method == http.MethodGet:
		h.requireAdmin(h.apiAdminNetworkConnStats)(w, r)
	case path == "/admin/api/network/bananameter" && r.Method == http.MethodGet:
		h.requireAdmin(h.apiAdminNetworkBananameter)(w, r)
	case path == "/admin/api/network/bananameter/by-type" && r.Method == http.MethodGet:
		h.requireAdmin(h.apiAdminTypeBananameter)(w, r)
	case path == "/admin/api/network/unreachable/by-type" && r.Method == http.MethodGet:
		h.requireAdmin(h.apiAdminTypeUnreachability)(w, r)

	// ── My-cabinet (self-service key portal) ──────────────────────────────
	// HTML rendering moved entirely to the static my.html/my-support.html/
	// my-club.html pages -- these old arbiter URLs are 301s for anyone with
	// a stale bookmark/link, everything else is JSON below.
	case (path == "/my" || path == "/my/subscription" || path == "/my/keys" ||
		path == "/my/support" || path == "/my/club") && r.Method == http.MethodGet:
		h.myCabinetRedirect(w, r)
	case path == "/my/api/support" && r.Method == http.MethodPost:
		h.apiMySupportSubmit(w, r)
	case path == "/my/api/club" && r.Method == http.MethodGet:
		h.apiMyClubStatus(w, r)
	case path == "/my/api/club/recommend" && r.Method == http.MethodPost:
		h.apiMyClubRecommend(w, r)
	case path == "/my/api/keys" && r.Method == http.MethodGet:
		// Not wrapped in requireMySession: this is called from a public static
		// page that needs a real 401 JSON response for logged-out visitors,
		// not an HTML redirect to /login.
		h.myApiKeysList(w, r)
	case strings.HasPrefix(path, "/my/api/keys/") && strings.HasSuffix(path, "/download") && r.Method == http.MethodGet:
		// Not requireMySession — same JSON-401-not-HTML-redirect reasoning as
		// /my/api/keys above; the handler already does its own session check.
		h.myDownloadKey(w, r)
	case strings.HasPrefix(path, "/my/api/keys/") && strings.HasSuffix(path, "/unbind") && r.Method == http.MethodPost:
		h.myUnbindKey(w, r)
	case path == "/my/api/keys/new" && r.Method == http.MethodPost:
		h.myNewKey(w, r)
	case path == "/logout-my":
		h.myLogout(w, r)

	// ── My-cabinet: app-store publisher profile + submissions ─────────────
	// Not wrapped in requireMySession — same JSON-401-not-HTML-redirect
	// reasoning as /my/api/keys above; each handler does its own session check.
	case path == "/my/api/profile" && r.Method == http.MethodGet:
		h.myApiProfileGet(w, r)
	case path == "/my/api/profile" && r.Method == http.MethodPost:
		h.myApiProfileSet(w, r)
	case path == "/my/api/apps" && (r.Method == http.MethodGet || r.Method == http.MethodPost):
		h.myApiAppsList(w, r) // dispatches to myApiAppsSubmit internally on POST
	case strings.HasPrefix(path, "/my/api/apps/") && r.Method == http.MethodPost:
		h.myApiAppEdit(w, r)

	case path == "/admin/notify" && r.Method == http.MethodGet:
		h.requireAdmin(h.adminNotifyPage)(w, r)
	case path == "/admin/notify/add" && r.Method == http.MethodPost:
		h.requireAdmin(h.adminNotifyAdd)(w, r)
	case path == "/admin/notify/delete" && r.Method == http.MethodPost:
		h.requireAdmin(h.adminNotifyDelete)(w, r)

	// ── Email broadcast (to every registered user, from /admin/notify) ────
	case path == "/admin/api/broadcast/preview" && r.Method == http.MethodGet:
		h.requireAdmin(h.apiAdminBroadcastPreview)(w, r)
	case path == "/admin/api/broadcast/test" && r.Method == http.MethodPost:
		h.requireAdmin(h.apiAdminBroadcastTest)(w, r)
	case path == "/admin/api/broadcast/send" && r.Method == http.MethodPost:
		h.requireAdmin(h.apiAdminBroadcastSend)(w, r)
	case path == "/admin/api/broadcast/status" && r.Method == http.MethodGet:
		h.requireAdmin(h.apiAdminBroadcastStatus)(w, r)

	case strings.HasPrefix(path, "/admin/egress/") && strings.HasSuffix(path, "/caps") && r.Method == http.MethodGet:
		h.requireAdmin(h.adminEgressCapsPage)(w, r)

	case strings.HasPrefix(path, "/admin/nodes/") && strings.HasSuffix(path, "/stats") && r.Method == http.MethodGet:
		h.requireAdmin(h.adminNodeStatsPage)(w, r)
	case strings.HasPrefix(path, "/admin/users/") && strings.HasSuffix(path, "/stats") && r.Method == http.MethodGet:
		h.requireAdmin(h.adminUserStatsPage)(w, r)

	case path == "/admin/relay/toggle" && r.Method == http.MethodPost:
		h.requireAdmin(h.adminRelayToggle)(w, r)

	case path == "/admin/ipv6/toggle" && r.Method == http.MethodPost:
		h.requireAdmin(h.adminIPv6Toggle)(w, r)

	case path == "/admin/loadfactor/update" && r.Method == http.MethodPost:
		h.requireAdmin(h.adminLoadFactorUpdate)(w, r)

	// ── BananaMeter client probe result ────────────────────────────────────
	// apiClientBananameterResult is also registered on the :443 node-facing
	// plane (serveNetworkHTTP in handler.go), which is correct for
	// control/exit nodes reporting their own probes directly against the
	// arbiter's IP with X-Node-Token auth. But end-user SNC clients never
	// reach :443 directly -- per the dual-listener split (see
	// shortnerdcat-deploy-arbiter skill: ":443 = tunnel protocol, :8080 =
	// web/admin plane, only reachable via navlink.net proxy"), a client's
	// only path to the arbiter is https://navlink.net/... which resolves
	// through the public proxy to this :8080 web plane. Without this case,
	// every client POST to /api/bananameter/client-result fell through to
	// the Camerlengo default below, which happily answered 200 with its own
	// generic "unrecognized command" body -- reportToArbiter (bananameter_
	// probe.go) only checks the transport-level error from client.Do(), never
	// the response status or body, so this looked like success on both ends
	// while silently inserting zero rows. Confirmed live 2026-08-10: control/
	// exit had thousands of bananameter_results rows (they use :443 directly)
	// while source_type='client' had exactly zero despite the arbiter log
	// showing a steady stream of "web: POST /api/bananameter/client-result
	// ... status=200" -- reproduced by curling 127.0.0.1:8080 directly, which
	// returned {"result": "error"} (Camerlengo's stub, not this handler's
	// {"ok":true}/jsonErr shapes) without touching the database.
	case path == "/api/bananameter/client-result" && r.Method == http.MethodPost:
		h.apiClientBananameterResult(w, r)

	// ── Device log upload (client, shared Bearer key) ──────────────────────
	// Same dual-listener trap as the BananaMeter case just above -- clients
	// only ever reach the arbiter via https://navlink.net/... (:8080), never
	// :443 directly, so this must live here, not (only) on the node-facing
	// plane. See log_upload_client_api.go and tunnel_cat/snc/core/log_upload.go.
	case path == "/api/log/client-upload" && r.Method == http.MethodPost:
		h.apiLogClientUpload(w, r)

	// ── Connection-stats upload (client, shared Bearer key) ────────────────
	// Same dual-listener trap as the two cases above -- clients only ever
	// reach the arbiter via https://navlink.net/... (:8080), never :443
	// directly. See conn_stats_client_api.go and
	// tunnel_cat/snc/core/conn_stats_upload.go.
	case path == "/api/conn-stats/client-upload" && r.Method == http.MethodPost:
		h.apiClientConnStatsUpload(w, r)

	// ── Manifest fetch (client, shared Bearer key) ──────────────────────────
	// Same dual-listener trap as the three cases above -- clients only ever
	// reach the arbiter via https://navlink.net/... (:8080), never :443
	// directly. Independent fallback path alongside the existing exit-relayed
	// /api/manifest (node-facing plane): doesn't depend on any particular
	// exit or control being reachable, only on navlink.net itself. See
	// manifest_client_api.go.
	case path == "/api/manifest/client" && r.Method == http.MethodGet:
		h.apiManifestClientFetch(w, r)

	// ── Live account-status check (client) ──────────────────────────────────
	// Same dual-listener trap as the cases above -- clients only ever reach
	// the arbiter via https://navlink.net/... (:8080), never :443 directly.
	// See club_manifest_api.go's apiWhoAmI.
	case path == "/api/whoami" && r.Method == http.MethodGet:
		h.apiWhoAmI(w, r)

	// ── Camerlengo proxy (client commands) ────────────────────────────────
	default:
		h.handleClientRequest(w, r)
	}
}
