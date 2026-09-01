// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const sessionCookieName = "snc_session"

// handler is the root http.Handler for snc-arbiter.
type handler struct {
	db            *DB
	auth          *authClient
	signer        *signingKey
	sessions      *SessionManager
	cidrSt        cidrState // thread-safe provider map; empty = bypass disabled
	pages         map[string]*template.Template
	publicPages   map[string]bool // templates that use base_public (not base)
	emailTmpls    map[string]*template.Template
	updateDir     string // directory with update binaries; empty = update serving disabled
	appsAssetsDir string // shared sshfs-mounted dir (icons/binaries) for the apps-store; empty = uploads disabled
	contentDir    string // directory mirrored to clients via the content-manifest (torrent-like); empty = disabled
	contentCache  contentManifestCache
	uploadKey     string // bearer key for /admin/downloads/upload; empty = admin session only

	// torrentSeedManifestURL/torrentSeedDataDir/torrentTrackersFile/
	// torrentMagnetsState -- see torrent_magnets.go. Distinct from
	// torrentFeature (torrent_enabled toggle, admin_torrent_enabled.go) and
	// from contentDir (unrelated content-manifest mirroring feature) --
	// this is specifically about surfacing the torrent-seed fleet's
	// client-software magnets and this arbiter's own signed-manifest magnet
	// in SignedList.
	torrentSeedManifestURL string
	torrentSeedDataDir     string
	torrentTrackersFile    string
	torrentMagnetsState    torrentMagnetsState

	// peerArbiters lists this node's fellow arbiter cluster members (base
	// URLs, e.g. "https://203.0.113.12") that a successful client-binary
	// upload should be replicated to. The two-node cluster (see
	// docs/ARBITER_FAILOVER.md) is fronted by a round-robin Load Balancer
	// with no shared filesystem for /var/lib/snc/updates -- without this, a
	// binary uploaded to whichever node deploy.sh happened to hit only ever
	// existed on that one node's disk, and ~half of real download/OTA
	// requests (whichever the LB routed to the other node) 404'd. Empty =
	// no replication (single-node deployments, or intentionally disabled).
	peerArbiters         []string
	appLogKey            string // bearer key embedded in client APKs for /api/log/app-upload; empty = disabled
	bananameterClientKey string // bearer key embedded in every client build for /api/bananameter/client-result; empty = disabled
	logUploadClientKey   string // legacy bearer key for /api/log/client-upload; kept for clients built before clientTelemetryKey existed -- see checkClientOrLegacyKey
	connStatsClientKey   string // legacy per-feature key, superseded by clientTelemetryKey before this feature ever shipped to a real client -- kept only for config-shape symmetry with the others; safe to leave unset
	// clientTelemetryKey is the ONE shared bearer key new client builds embed
	// for every client-facing telemetry endpoint (app-log, bananameter,
	// log-upload, conn-stats). Replaces the old one-key-per-endpoint scheme
	// (2026-08-13) -- those keys are all baked into the same binary any real
	// attacker already has, so per-endpoint separation added real operational
	// cost (a deploy step per new feature, missed twice already: the
	// log-upload-client-key incident, then conn-stats-client-key waiting on
	// the exact same fix) for essentially no blast-radius reduction. The
	// legacy per-endpoint fields above are kept and still checked (see
	// checkClientOrLegacyKey) so already-shipped client builds embedding the
	// old keys keep working -- only new builds get the new shared key.
	clientTelemetryKey   string
	notifMu              sync.RWMutex
	notifCache           []NotificationEntry // in-memory active notifications, refreshed after each admin add/delete
	notifier             *Notifier           // may be nil
	relay                relayState
	ipv6                 ipv6State
	torrentFeature       torrentState
	loadFactor           loadFactorConfig   // see load_factor.go
	logs                 *nodeLogStore      // device log storage; always set
	provisioner          *provisioner       // may be nil if setup-dir/node-bin-dir not configured
	forgotPwLimiter      *simpleRateLimiter // per-email/IP cooldown for /forgot-password
	bbInquiryLimiter     *simpleRateLimiter // per-email/IP cooldown for /blackbadger-inquiry
	resendConfirmLimiter *simpleRateLimiter // per-email/IP cooldown for /resend-confirmation

	// Flood/DoS hardening added 2026-08-08 -- see TODO.md's arbiter API audit.
	keyLimiter     *tieredWindowLimiter // per-account tiers for /api/key/free
	supportLimiter *tieredWindowLimiter // per-email/IP cooldown for /support, /ratatosk/support
	supportGlobal  *tokenBucket         // sitewide cap across all support submissions
	loginIPLimiter *tieredWindowLimiter // per-IP tiers for /api/account/login
	loginGlobal    *tokenBucket         // sitewide cap across all logins, with burst

	manifestClientLimiter *tieredWindowLimiter // per-IP tiers for /api/manifest/client
	manifestTopupLimiter  *tieredWindowLimiter // per-IP tiers for /api/manifest/topup
}

// loadNotificationsFromDB refreshes the in-memory notification cache from the DB.
// Called once at startup and after each admin add/delete.
func (h *handler) loadNotificationsFromDB() {
	entries, err := h.db.activeNotifications("")
	if err != nil {
		logWarnf("notifications: load from db: %v", err)
		return
	}
	h.notifMu.Lock()
	h.notifCache = entries
	h.notifMu.Unlock()
	logInfof("notifications: loaded %d active from db", len(entries))
}

// setCIDRs updates the CIDR provider map (called by the background refresher).
func (h *handler) setCIDRs(providers map[string]*cidrProvider) {
	h.cidrSt.set(providers)
}

// regionOf resolves addr (host or host:port) to an IP and returns the ISO-3166
// region code from the loaded CIDR buckets, or "" if no bucket matches or the
// CIDR data has not been loaded yet.
func (h *handler) regionOf(addr string) string {
	host := addr
	if h2, _, err := net.SplitHostPort(addr); err == nil {
		host = h2
	}
	ips, err := net.LookupHost(host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	ip := net.ParseIP(ips[0])
	if ip == nil {
		return ""
	}
	return h.cidrSt.lookupIP(ip)
}

func newHandler(db *DB, auth *authClient, signer *signingKey, sessions *SessionManager, authURL string) *handler {
	h := &handler{db: db, auth: auth, signer: signer, sessions: sessions,
		publicPages:           make(map[string]bool),
		emailTmpls:            make(map[string]*template.Template),
		forgotPwLimiter:       newSimpleRateLimiter(),
		bbInquiryLimiter:      newSimpleRateLimiter(),
		resendConfirmLimiter:  newSimpleRateLimiter(),
		keyLimiter:            newTieredWindowLimiter(),
		supportLimiter:        newTieredWindowLimiter(),
		supportGlobal:         newTokenBucket(1, 1.0/60),
		loginIPLimiter:        newTieredWindowLimiter(),
		loginGlobal:           newTokenBucket(20, 1),
		manifestClientLimiter: newTieredWindowLimiter(),
		manifestTopupLimiter:  newTieredWindowLimiter(),
	}

	funcs := template.FuncMap{
		"fmtTime": func(t time.Time) string { return t.Format("2006-01-02 15:04") },
		"fmtTimePtr": func(t *time.Time) string {
			if t == nil {
				return "â€”"
			}
			return t.Format("2006-01-02 15:04")
		},
		"derefBool": func(b *bool) bool {
			if b == nil {
				return false
			}
			return *b
		},
		// isKeyExpired reports whether a key's paid_until has passed. nil (perpetual) is
		// never expired. Used by my_keys.html/my_subscription.html so the status badge
		// reflects real auth-server behavior instead of only the enabled flag -- a key
		// can be enabled=true and still get rejected as expired if paid_until is past.
		"isKeyExpired": func(t *time.Time) bool {
			return t != nil && t.Before(time.Now())
		},
		"fmtBytes": func(n int64) string {
			const unit = 1024
			if n < unit {
				return fmt.Sprintf("%d B", n)
			}
			div, exp := int64(unit), 0
			for v := n / unit; v >= unit; v /= unit {
				div *= unit
				exp++
			}
			return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
		},
		"unixTime": func(ts int64) time.Time { return time.Unix(ts, 0) },
		"stripPort": func(addr string) string {
			return strings.TrimSuffix(addr, ":443")
		},
		"sub": func(a, b, c int) int { return a - b - c },
		"fmtCapabilities": func(caps map[string]bool) template.HTML {
			if len(caps) == 0 {
				return template.HTML("&mdash;")
			}
			var ok, fail []string
			for k, v := range caps {
				if v {
					ok = append(ok, k)
				} else {
					fail = append(fail, k)
				}
			}
			sort.Strings(ok)
			sort.Strings(fail)
			total := len(ok) + len(fail)
			color := "#22c55e"
			if len(fail) > 0 && len(ok) > 0 {
				color = "#eab308"
			} else if len(ok) == 0 {
				color = "#ef4444"
			}
			var tip strings.Builder
			for _, d := range ok {
				tip.WriteString("âœ“ " + d + "&#10;")
			}
			for _, d := range fail {
				tip.WriteString("âœ— " + d + "&#10;")
			}
			return template.HTML(fmt.Sprintf(
				`<span style="color:%s;font-weight:600;cursor:default" title="%s">%d/%d</span>`,
				color, tip.String(), len(ok), total,
			))
		},
	}

	// Each page is parsed together with base.html so that each set has exactly
	// one "content" definition.  Sharing a single template set caused the last
	// alphabetically-parsed definition of "content" to overwrite all others.
	// Admin/auth pages use base.html; public pages use base_public.html.
	// Public-facing HTML lives entirely on the static site now (see the
	// 2026-08-16 HTML-removal pass); the arbiter only still renders
	// support/ratatosk*/partners/blackbadger (not yet migrated) plus the
	// admin panel + admin login.
	adminPages := []string{"index.html", "admin_infra.html", "admin_pending.html", "admin_update.html", "admin_dashboard.html", "admin_keygen.html", "admin_blacklist.html", "admin_lists.html", "admin_downloads.html", "admin_users.html", "admin_notify.html", "admin_egress_caps.html", "admin_node_stats.html", "admin_user_stats.html", "admin_apps.html", "admin_service_blocks.html", "admin_anon_bootstrap.html", "admin_clubs.html", "admin_login.html"}
	publicPages := []string{
		"support.html",
		"ratatosk.html",
		"ratatosk_privacy.html",
		"ratatosk_support.html",
		"partners.html",
		"blackbadger.html",
	}

	h.pages = make(map[string]*template.Template, len(adminPages)+len(publicPages))
	for _, name := range adminPages {
		h.pages[name] = template.Must(
			template.New(name).Funcs(funcs).ParseFS(
				templateFS, "templates/base.html", "templates/"+name,
			),
		)
	}
	for _, name := range publicPages {
		h.publicPages[name] = true
		h.pages[name] = template.Must(
			template.New(name).Funcs(funcs).ParseFS(
				templateFS, "templates/base_public.html", "templates/"+name,
			),
		)
	}

	// Email templates are standalone â€” no base template, no page chrome.
	for _, name := range []string{"email_key_issued.html"} {
		h.emailTmpls[name] = template.Must(
			template.New(name).Funcs(funcs).ParseFS(templateFS, "templates/"+name),
		)
	}

	return h
}

// statusRecorder wraps ResponseWriter to capture the HTTP status code for logging.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

// ServeHTTP is the network control-plane handler (port :443).
// It only handles node/client API endpoints â€” no web UI, no admin pages.
// Web traffic goes through webPlane on the web-facing port.
func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	h.serveNetworkHTTP(rec, r)
	logInfof("net: %s %s %s status=%d dur=%s",
		r.Method, r.URL.Path, r.RemoteAddr, rec.status, time.Since(start).Round(time.Millisecond))
}

// serveNetworkHTTP routes the control-plane requests.
func (h *handler) serveNetworkHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	// â”€â”€ Node heartbeat & topology â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
	case path == "/api/heartbeat" && r.Method == http.MethodPost:
		h.apiHeartbeat(w, r)
	case path == "/api/exits" && r.Method == http.MethodGet:
		h.apiExits(w, r)
	case path == "/api/manifest" && r.Method == http.MethodGet:
		h.apiManifest(w, r)
	case path == "/api/club-manifest" && r.Method == http.MethodGet:
		h.apiClubManifest(w, r)
	case path == "/api/club-key" && r.Method == http.MethodGet:
		h.apiClubKey(w, r)
	case path == "/api/club-recommend" && r.Method == http.MethodPost:
		h.apiClubRecommend(w, r)
	case path == "/api/whoami" && r.Method == http.MethodGet:
		h.apiWhoAmI(w, r)
	case path == "/api/content-manifest" && r.Method == http.MethodGet:
		h.apiContentManifest(w, r)
	case path == "/api/content-chunk" && r.Method == http.MethodGet:
		h.apiContentChunk(w, r)
	case path == "/api/nodes" && r.Method == http.MethodGet:
		h.apiNodes(w, r)
	case path == "/api/app-log" && r.Method == http.MethodPost:
		h.apiAppLogUpload(w, r)
	// probe-sites is X-Node-Token authenticated, fetched by control nodes via
	// exit proxy (never direct arbiter contact -- see ProbeSiteRegistry.fetch
	// in snc-control) -- it belongs on this node-facing :443 switch with
	// every other node API, not on the :8080 admin/web plane switch in
	// web_handler.go. Registering it there (its previous home) made it
	// unreachable through the exit-proxied path controls actually use,
	// which is why control's data-plane probe always 404'd and silently
	// fell back to control<->exit-only RTT (see routing_rtt_ms fix, 2026-08-10).
	case path == "/api/probe-sites" && r.Method == http.MethodGet:
		h.apiProbeSites(w, r)

	// â”€â”€ Session & CIDR (used by exit nodes and SNC clients) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
	case path == "/api/session/validate" && r.Method == http.MethodPost:
		h.apiSessionValidate(w, r)
	case path == "/api/cidr/all" && r.Method == http.MethodGet:
		h.apiCIDRAll(w, r)

	// â”€â”€ User traffic stats (exit nodes) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
	case path == "/api/node/stats" && r.Method == http.MethodPost:
		h.apiNodeStats(w, r)
	case path == "/api/node/bananameter-result" && r.Method == http.MethodPost:
		h.apiNodeBananameterResult(w, r)
	case path == "/api/bananameter/client-result" && r.Method == http.MethodPost:
		h.apiClientBananameterResult(w, r)
	case path == "/api/node/validate" && r.Method == http.MethodPost:
		h.apiNodeValidate(w, r)
	case path == "/api/geoip" && r.Method == http.MethodGet:
		h.apiGeoIP(w, r)

	// â”€â”€ Traffic whitelist (exit nodes; drives exit-to-exit peer-routing fallback) â”€â”€
	case path == "/api/whitelist" && r.Method == http.MethodGet:
		h.apiWhitelist(w, r)

	// â”€â”€ Service region blocks (exit/control nodes) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
	case path == "/api/service-blocks" && r.Method == http.MethodGet:
		h.apiServiceRegionBlocks(w, r)

	// â”€â”€ Anonymous bootstrap manifest (exit/control nodes) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
	case path == "/api/anon-bootstrap" && r.Method == http.MethodGet:
		h.apiAnonBootstrap(w, r)

	// â”€â”€ Exit address blacklist (exit nodes) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
	case path == "/api/blacklist" && r.Method == http.MethodGet:
		h.apiBlacklist(w, r)
	case path == "/api/torrent-blocked" && r.Method == http.MethodGet:
		h.apiTorrentBlocked(w, r)

	// â”€â”€ OTA update binary serving (exit nodes) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
	case path == "/api/update/control-version" && r.Method == http.MethodGet:
		h.apiUpdateFile(w, r, "exit", "version")
	case path == "/api/update/control" && r.Method == http.MethodGet:
		h.apiUpdateFile(w, r, "exit", "snc-control")
	case path == "/api/update/control.sha256" && r.Method == http.MethodGet:
		h.apiUpdateFile(w, r, "exit", "snc-control.sha256")

	// â”€â”€ OTA client binary serving (control nodes) â”€â”€ generic, manifest-driven.
	// See otaSlugs (admin_downloads.go) and ota_manifest.go: control nodes
	// discover what's distributable at runtime instead of each type needing
	// its own hardcoded route here and in snc-control.
	case path == "/api/update/manifest" && r.Method == http.MethodGet:
		h.apiUpdateManifest(w, r)
	case strings.HasPrefix(path, "/api/update/dist/") && r.Method == http.MethodGet:
		h.apiUpdateDist(w, r)

	// â”€â”€ Admin node management JSON API (CLI/automation, not browser) â”€â”€â”€â”€â”€â”€
	case path == "/api/admin/node" && r.Method == http.MethodPost:
		h.requireAdmin(h.apiAdminNodeRegister)(w, r)
	case strings.HasPrefix(path, "/api/admin/node/") && strings.HasSuffix(path, "/approve") && r.Method == http.MethodPost:
		h.requireAdmin(h.apiAdminNodeApprove)(w, r)
	case strings.HasPrefix(path, "/api/admin/node/") && strings.HasSuffix(path, "/delete") && r.Method == http.MethodPost:
		h.requireAdmin(h.apiAdminNodeDelete)(w, r)
	case strings.HasPrefix(path, "/api/admin/node/") && strings.HasSuffix(path, "/decommission") && r.Method == http.MethodPost:
		h.requireAdmin(h.apiAdminNodeDecommission)(w, r)
	case strings.HasPrefix(path, "/api/admin/node/") && strings.HasSuffix(path, "/update") && r.Method == http.MethodPost:
		h.requireAdmin(h.apiAdminNodeUpdate)(w, r)
	case path == "/api/admin/nodes" && r.Method == http.MethodGet:
		h.requireAdmin(h.apiAdminNodeList)(w, r)

	// â”€â”€ Device log upload / retrieval (forwarded by control nodes) â”€â”€â”€â”€â”€â”€
	case path == "/api/log/upload" && r.Method == http.MethodPost:
		h.apiLogUpload(w, r)
	case path == "/api/log/get" && r.Method == http.MethodGet:
		h.apiLogGet(w, r)
	case path == "/api/log/app-upload" && r.Method == http.MethodPost:
		h.apiAppLogUpload(w, r)

	// â”€â”€ Client binary upload (deploy scripts use Bearer key over port 443) â”€
	case path == "/admin/downloads/upload" && r.Method == http.MethodPost:
		if h.checkUploadKey(r) && r.Header.Get("Authorization") != "" {
			h.adminDownloadsUpload(w, r)
		} else {
			h.requireAdmin(h.adminDownloadsUpload)(w, r)
		}

	// â”€â”€ Excluded control nodes (decommissioned nodes clients must skip) â”€â”€
	case path == "/api/admin/excluded" && r.Method == http.MethodGet:
		h.requireAdmin(h.adminExcludedList)(w, r)
	case path == "/api/admin/excluded/add" && r.Method == http.MethodPost:
		h.requireAdmin(h.adminExcludedAdd)(w, r)
	case path == "/api/admin/excluded/delete" && r.Method == http.MethodPost:
		h.requireAdmin(h.adminExcludedDelete)(w, r)

	// â”€â”€ BlackBadger proxy credential validation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
	case path == "/api/auth/proxy-validate" && r.Method == http.MethodPost:
		h.apiProxyValidate(w, r)

	// â”€â”€ SNC client Camerlengo proxy (login, commands) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
	default:
		h.handleClientRequest(w, r)
	}
}

// â”€â”€ session helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

func (h *handler) sessionToken(r *http.Request) string {
	if c, err := r.Cookie(sessionCookieName); err == nil {
		return c.Value
	}
	return r.Header.Get("X-Auth-Token")
}

func (h *handler) currentUser(r *http.Request) *User {
	token := h.sessionToken(r)
	if token == "" {
		return nil
	}
	// Arbiter sessions (web login, key-auth) are stored in the local DB.
	// Check there first so wallet operations work (session carries EncPassword + CamSession).
	if sess, err := h.db.getSession(token); err == nil && sess != nil {
		u, err := h.db.getOrCreateUser(sess.Username)
		if err != nil {
			logWarnf("handler: getOrCreateUser %s: %v", sess.Username, err)
			return nil
		}
		return u
	}
	// Fall back to direct Camerlengo token validation (legacy / external callers).
	username := h.auth.validateSession(token)
	if username == "" {
		return nil
	}
	u, err := h.db.getOrCreateUser(username)
	if err != nil {
		logWarnf("handler: getOrCreateUser %s: %v", username, err)
		return nil
	}
	return u
}

type handlerFunc func(http.ResponseWriter, *http.Request)

// requireUser is only used by apiNodeDeployStatus (an admin-UI-only JSON
// endpoint) -- redirects to the admin login on an expired session, same as
// requireAdmin.
func (h *handler) requireUser(next handlerFunc) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.currentUser(r) == nil {
			http.Redirect(w, r, "/admin/login?next="+r.URL.Path, http.StatusFound)
			return
		}
		next(w, r)
	}
}

func (h *handler) requireAdmin(next handlerFunc) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Allow X-Admin-Token header as an alternative to a browser session.
		// Used by deploy automation that fetches the token from the arbiter DB.
		if h.checkAdminAPIToken(r) {
			next(w, r)
			return
		}
		u := h.currentUser(r)
		if u == nil {
			http.Redirect(w, r, "/admin/login?next="+r.URL.Path, http.StatusFound)
			return
		}
		if u.Role != "admin" {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		// currentUser reads the session with a raw DB lookup and never touches
		// validated_at, so an admin actively working the dashboard could still
		// hit sessionStaleTTL (3h, see sessions.go) and get silently logged
		// out mid-session -- the dashboard's 10s poll loops swallow the
		// resulting redirect/parse failure (admin_dashboard.html's fetch
		// .catch is a no-op "stale values stay"), so nothing visibly signals
		// it happened; the numbers just freeze. Since every admin API/page
		// request already passes through here, touching the session on each
		// one keeps it alive for as long as the dashboard tab stays open and
		// polling, without needing a dedicated keep-alive endpoint.
		if token := h.sessionToken(r); token != "" {
			if err := h.db.touchSession(token, time.Now()); err != nil {
				logWarnf("requireAdmin: touchSession: %v", err)
			}
		}
		next(w, r)
	}
}

// â”€â”€ page data helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

type pageData struct {
	User    *User
	Data    interface{}
	Flash   string // error message (red)
	FlashOK string // success message (green)
	Lang    string
	Next    string // redirect target for login form
	Path    string // current URL path, used by lang switcher

	CaptchaQ     string // captcha question text, e.g. "3 + 5"
	CaptchaToken string // signed captcha token, see captcha.go
}

func (h *handler) renderPage(w http.ResponseWriter, name string, data pageData) {
	h.renderPageR(w, nil, name, data)
}

func (h *handler) renderPageR(w http.ResponseWriter, r *http.Request, name string, data pageData) {
	if r != nil && data.Path == "" {
		data.Path = r.URL.Path
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t, ok := h.pages[name]
	if !ok {
		http.Error(w, "page not found: "+name, http.StatusInternalServerError)
		return
	}
	baseTmpl := "base"
	if h.publicPages[name] {
		baseTmpl = "base_public"
	}
	if err := t.ExecuteTemplate(w, baseTmpl, data); err != nil {
		logWarnf("template %s: %v", name, err)
	}
}

func (h *handler) render(w http.ResponseWriter, r *http.Request, name string, data interface{}) {
	u := h.currentUser(r)
	h.renderPage(w, name, pageData{User: u, Data: data})
}

// â”€â”€ pages â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

// adminLoginPage/adminLoginSubmit are the ONLY login UI left on the arbiter
// -- scoped to admin sign-in specifically (requireAdmin redirects here).
// Regular user login lives entirely on the static site now, via the JSON
// POST /api/account/login (get_key.go:apiAccountLogin) that the static
// front-end's auth-modals.js already calls.
func (h *handler) adminLoginPage(w http.ResponseWriter, r *http.Request) {
	h.renderPage(w, "admin_login.html", pageData{Next: r.URL.Query().Get("next")})
}

func (h *handler) adminLoginSubmit(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")
	next := r.FormValue("next")
	if next == "" {
		next = "/admin"
	}

	bad := func(msg string) {
		h.renderPage(w, "admin_login.html", pageData{Flash: msg, Next: next})
	}

	if _, err := h.auth.login(username, password); err != nil {
		logInfof("admin login: failed for %s: %v", username, err)
		bad("Invalid email or password.")
		return
	}

	token, err := h.sessions.Login(username, password, nil)
	if err != nil {
		logWarnf("admin login: sessions.Login %s: %v", username, err)
		bad("Login failed. Please try again.")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400 * 7,
	})
	http.Redirect(w, r, next, http.StatusFound)
}

// logout clears the shared session cookie and sends the caller back to the
// public homepage. This is the endpoint the static personal-cabinet page
// (shortnerdcat/my.html) links to directly -- do not repoint it at the
// admin login, that page is used by ordinary customers, not admins.
func (h *handler) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   sessionCookieName,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

// adminLogout is the admin nav's "Logout" link (base.html) -- same cookie
// clear as logout, but returns to the admin login instead of the homepage.
func (h *handler) adminLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   sessionCookieName,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.Redirect(w, r, "/admin/login", http.StatusFound)
}

// â”€â”€ Landing page & static assets â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

const langCookieName = "snc_lang"

// setLangCookie writes the lang preference cookie and redirects to the clean path.
// Returns true if a redirect was issued (caller must return).
func setLangCookie(w http.ResponseWriter, r *http.Request) bool {
	q := r.URL.Query().Get("lang")
	if q != "ru" && q != "en" {
		return false
	}
	http.SetCookie(w, &http.Cookie{
		Name:     langCookieName,
		Value:    q,
		Path:     "/",
		MaxAge:   86400 * 365,
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, r.URL.Path, http.StatusFound)
	return true
}

// detectLang returns "ru" or "en": ?lang= param takes priority over cookie,
// then falls back to Accept-Language header.
func detectLang(r *http.Request) string {
	if q := r.URL.Query().Get("lang"); q == "ru" || q == "en" {
		return q
	}
	if c, err := r.Cookie(langCookieName); err == nil {
		if c.Value == "ru" || c.Value == "en" {
			return c.Value
		}
	}
	accept := r.Header.Get("Accept-Language")
	if strings.Contains(strings.ToLower(accept), "ru") {
		return "ru"
	}
	return "en"
}

func (h *handler) serveStatic(w http.ResponseWriter, r *http.Request) {
	// Strip leading slash; path is like "static/logo.png"
	name := strings.TrimPrefix(r.URL.Path, "/")
	data, err := staticFS.ReadFile(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case strings.HasSuffix(name, ".png"):
		w.Header().Set("Content-Type", "image/png")
	case strings.HasSuffix(name, ".jpg"), strings.HasSuffix(name, ".jpeg"):
		w.Header().Set("Content-Type", "image/jpeg")
	case strings.HasSuffix(name, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml")
	case strings.HasSuffix(name, ".ico"):
		w.Header().Set("Content-Type", "image/x-icon")
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(data) //nolint:errcheck
}

func (h *handler) indexPage(w http.ResponseWriter, r *http.Request) {
	exits, _ := h.db.liveNodes("exit")
	controls, _ := h.db.liveNodes("control")
	h.render(w, r, "index.html", map[string]interface{}{
		"LiveExits":    exits,
		"LiveControls": controls,
	})
}

// NodeView wraps Node with additional fields used only for template rendering.
type NodeView struct {
	Node
	SNIEditable bool // true for control nodes â€” shows SNI editor button in admin table
}

func toNodeViews(nodes []Node, sniEditable bool) []NodeView {
	out := make([]NodeView, len(nodes))
	for i, n := range nodes {
		out[i] = NodeView{Node: n, SNIEditable: sniEditable}
	}
	return out
}

type dashboardData struct {
	Controls         []NodeView
	Egresses         []NodeView
	ControlRotations []AddrRotation // address changes, last 24h
	EgressRotations  []AddrRotation // address changes, last 24h
	Tab              string
	Search           string
	OnlineCtrl       int
	OnlineEgress     int
	ActiveUsers      int              // users with a live SNC session (validated within sessionStaleTTL)
	TotalUsers       int              // all unique users ever seen via exit nodes
	AllAccounts      int              // every registered account, including ones that have never connected
	CatClubOnline    int              // directly-granted Cat Club members currently online (last_seen <= 5 min)
	EliteClubOnline  int              // directly-granted Elite Cat Club members currently online (last_seen <= 5 min)
	HealthStatus     string           // "green" | "yellow" | "red"
	RelayEnabled     bool             // current relay_enabled toggle value
	IPv6Enabled      bool             // current ipv6_enabled toggle value
	Flash            string           // one-shot success message
	LoadFactor       loadFactorValues // current tuning knobs, for the Network Stats form
}

func (h *handler) adminDashboard(w http.ResponseWriter, r *http.Request) {
	tab := r.URL.Query().Get("tab")
	if tab != "egresses" && tab != "users" && tab != "netstats" {
		tab = "controls"
	}
	search := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))

	controls, _ := h.db.listApprovedNodes("control")
	egresses, _ := h.db.listApprovedNodes("exit")

	filterNodes := func(nodes []Node) []Node {
		if search == "" {
			return nodes
		}
		var out []Node
		for _, n := range nodes {
			if strings.Contains(strings.ToLower(n.Addr), search) {
				out = append(out, n)
			}
		}
		return out
	}

	countOnline := func(nodes []Node) int {
		n := 0
		for i := range nodes {
			if nodes[i].IsOnline() {
				n++
			}
		}
		return n
	}
	// Suspended nodes are intentionally offline â€” exclude them from the
	// expected baseline so health stays green when only suspended nodes are missing.
	countExpected := func(nodes []Node) int {
		n := 0
		for i := range nodes {
			if nodes[i].Status != "suspended" {
				n++
			}
		}
		return n
	}
	// countDegraded counts nodes that are online but have data_plane_ok=false.
	countDegraded := func(nodes []Node) int {
		n := 0
		for i := range nodes {
			if nodes[i].IsOnline() && nodes[i].DataPlaneOK != nil && !*nodes[i].DataPlaneOK {
				n++
			}
		}
		return n
	}

	onlineCtrl := countOnline(controls)
	onlineEgress := countOnline(egresses)
	expectedCtrl := countExpected(controls)
	expectedEgress := countExpected(egresses)
	degradedEgress := countDegraded(egresses)
	degradedCtrl := countDegraded(controls)

	h.db.populateNodeTraffic(controls)
	h.db.populateNodeTraffic(egresses)

	// Populate CIDR-detected region for display (used by template to show Auto vs UNKNOWN).
	for i := range controls {
		controls[i].CIDRRegion = h.regionOf(controls[i].Addr)
	}
	for i := range egresses {
		egresses[i].CIDRRegion = h.regionOf(egresses[i].Addr)
	}

	activeUsers, _ := h.db.CountLiveActiveUsers()
	totalUsers, _ := h.db.CountTotalUsers()
	allAccounts, _ := h.db.CountAllAccounts()

	var catClubOnline, eliteClubOnline int
	if catClub, err := h.db.ClubBySlug("cat_club"); err == nil && catClub != nil {
		catClubOnline, _ = h.db.CountClubMembersOnlineLive(catClub.ID)
	}
	if eliteClub, err := h.db.ClubBySlug("elite_cat_club"); err == nil && eliteClub != nil {
		eliteClubOnline, _ = h.db.CountClubMembersOnlineLive(eliteClub.ID)
	}

	health := "green"
	if onlineEgress == 0 || onlineCtrl == 0 {
		health = "red"
	} else if onlineEgress < expectedEgress || onlineCtrl < expectedCtrl ||
		degradedEgress > 0 || degradedCtrl > 0 {
		health = "yellow"
	}

	h.loadRelayState()
	h.loadIPv6State()

	var controlRotations, egressRotations []AddrRotation
	if tab == "controls" {
		controlRotations, _ = h.db.recentAddrRotations("control", time.Now().Add(-24*time.Hour))
	} else if tab == "egresses" {
		egressRotations, _ = h.db.recentAddrRotations("exit", time.Now().Add(-24*time.Hour))
	}

	u := h.currentUser(r)
	h.renderPage(w, "admin_dashboard.html", pageData{
		User: u,
		Data: dashboardData{
			Controls:         toNodeViews(filterNodes(controls), true),
			Egresses:         toNodeViews(filterNodes(egresses), false),
			ControlRotations: controlRotations,
			EgressRotations:  egressRotations,
			Tab:              tab,
			Search:           r.URL.Query().Get("q"),
			OnlineCtrl:       onlineCtrl,
			OnlineEgress:     onlineEgress,
			ActiveUsers:      activeUsers,
			TotalUsers:       totalUsers,
			AllAccounts:      allAccounts,
			CatClubOnline:    catClubOnline,
			EliteClubOnline:  eliteClubOnline,
			HealthStatus:     health,
			RelayEnabled:     h.relayEnabled(),
			IPv6Enabled:      h.ipv6Enabled(),
			LoadFactor:       h.loadFactorSnapshot(),
			Flash:            r.URL.Query().Get("flash"),
		},
	})
}

// apiDashboardStats returns the summary stat cards as JSON for AJAX polling.
func (h *handler) apiDashboardStats(w http.ResponseWriter, r *http.Request) {
	controls, _ := h.db.listApprovedNodes("control")
	egresses, _ := h.db.listApprovedNodes("exit")

	countOnline := func(nodes []Node) int {
		n := 0
		for i := range nodes {
			if nodes[i].IsOnline() {
				n++
			}
		}
		return n
	}
	countExpected := func(nodes []Node) int {
		n := 0
		for i := range nodes {
			if nodes[i].Status != "suspended" {
				n++
			}
		}
		return n
	}
	countDegraded := func(nodes []Node) int {
		n := 0
		for i := range nodes {
			if nodes[i].IsOnline() && nodes[i].DataPlaneOK != nil && !*nodes[i].DataPlaneOK {
				n++
			}
		}
		return n
	}

	onlineCtrl := countOnline(controls)
	onlineEgress := countOnline(egresses)
	expectedCtrl := countExpected(controls)
	expectedEgress := countExpected(egresses)
	degradedEgress := countDegraded(egresses)
	degradedCtrl := countDegraded(controls)

	activeUsers, _ := h.db.CountLiveActiveUsers()
	totalUsers, _ := h.db.CountTotalUsers()
	allAccounts, _ := h.db.CountAllAccounts()

	var catClubOnline, eliteClubOnline int
	if catClub, err := h.db.ClubBySlug("cat_club"); err == nil && catClub != nil {
		catClubOnline, _ = h.db.CountClubMembersOnlineLive(catClub.ID)
	}
	if eliteClub, err := h.db.ClubBySlug("elite_cat_club"); err == nil && eliteClub != nil {
		eliteClubOnline, _ = h.db.CountClubMembersOnlineLive(eliteClub.ID)
	}

	health := "green"
	if onlineEgress == 0 || onlineCtrl == 0 {
		health = "red"
	} else if onlineEgress < expectedEgress || onlineCtrl < expectedCtrl ||
		degradedEgress > 0 || degradedCtrl > 0 {
		health = "yellow"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
		"online_ctrl":       onlineCtrl,
		"total_ctrl":        len(controls),
		"online_egress":     onlineEgress,
		"total_egress":      len(egresses),
		"active_users":      activeUsers,
		"total_users":       totalUsers,
		"all_accounts":      allAccounts,
		"cat_club_online":   catClubOnline,
		"elite_club_online": eliteClubOnline,
		"health":            health,
	})
}

func (h *handler) adminNodeAction(w http.ResponseWriter, r *http.Request) {
	// Path: /admin/nodes/{id}/suspend or /admin/nodes/{id}/unsuspend or /admin/nodes/{id}/delete
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// parts: ["admin","nodes","{id}","action"]
	if len(parts) != 4 {
		http.NotFound(w, r)
		return
	}
	nodeID, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	action := parts[3]
	switch action {
	case "suspend":
		h.db.setNodeStatus(nodeID, "suspended")
	case "unsuspend":
		h.db.setNodeStatus(nodeID, "approved")
	case "delete":
		if h.provisioner != nil {
			if info, infoErr := h.db.getNodeProvisionInfo(nodeID); infoErr == nil {
				h.provisioner.EnqueueTeardown(nodeID, info.SSHHost, info.SSHUser, info.Type)
			}
		}
		if err := h.db.deleteNode(nodeID); err != nil {
			logWarnf("adminNodeAction delete %d: %v", nodeID, err)
			http.Error(w, "error", http.StatusInternalServerError)
			return
		}
		logInfof("admin: deleted node %d", nodeID)
	default:
		http.NotFound(w, r)
		return
	}
	if h.notifier != nil {
		h.notifier.NotifyAll()
	}
	// Redirect back to wherever the request came from (dashboard or pending list).
	ref := r.Header.Get("Referer")
	if ref == "" {
		ref = "/admin"
	}
	http.Redirect(w, r, ref, http.StatusFound)
}

// â”€â”€ API â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

// probeSites is the per-region set of URLs that control nodes use to test exit
// data-plane connectivity. Fetched by controls via /api/probe-sites every 2 hours
// and cached locally; centralised here so it can be updated without redeploying controls.
var probeSites = map[string][]string{
	"RU": {"https://yandex.ru", "https://ok.ru", "https://mail.ru"},
	"EU": {"https://google.com", "https://cloudflare.com", "https://microsoft.com"},
	"US": {"https://google.com", "https://cloudflare.com", "https://amazon.com"},
	"CN": {"https://baidu.com", "https://qq.com", "https://163.com"},
	"TR": {"https://google.com", "https://cloudflare.com", "https://microsoft.com"},
	"":   {"https://google.com", "https://cloudflare.com", "https://microsoft.com"},
}

// apiProbeSites returns the per-region URL map used by controls to probe exit data-plane health.
// Authenticated by X-Node-Token (control or exit node).
func (h *handler) apiProbeSites(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Node-Token")
	if token == "" {
		jsonErr(w, "X-Node-Token required", http.StatusUnauthorized)
		return
	}
	node, err := h.db.nodeByToken(token)
	if err != nil || node == nil || (node.Type != "control" && node.Type != "exit") {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(probeSites) //nolint:errcheck
}

// apiLogUpload receives a gzip-compressed log bundle from a control or exit node.
// Authenticated by X-Node-Token. X-Node-ID identifies the source node.
// X-Node-Type (android|control|exit) determines the storage subdirectory;
// defaults to "android" for legacy uploads without the header.
func (h *handler) apiLogUpload(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Node-Token")
	if token == "" {
		jsonErr(w, "X-Node-Token required", http.StatusUnauthorized)
		return
	}
	node, err := h.db.nodeByToken(token)
	if err != nil || node == nil || (node.Type != "control" && node.Type != "exit") {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	nodeID := r.Header.Get("X-Node-ID")
	if nodeID == "" {
		jsonErr(w, "X-Node-ID required", http.StatusBadRequest)
		return
	}

	nodeType := r.Header.Get("X-Node-Type")
	if !validNodeType(nodeType) {
		nodeType = "android" // legacy: android client logs forwarded by control
	}

	data, err := io.ReadAll(io.LimitReader(r.Body, int64(nodeLogMaxLen)+1))
	if err != nil {
		jsonErr(w, "read error", http.StatusBadRequest)
		return
	}

	// Same best-effort username resolution as apiLogClientUpload; only
	// meaningful for "android" here (control/exit have no user concept),
	// but harmless to call unconditionally -- usernameForDeviceID just
	// returns "" on no match, which is exactly the right fallback for
	// control/exit's own nodeID anyway.
	username := h.db.usernameForDeviceID(nodeID)

	if err := h.logs.Store(nodeType, nodeID, username, data); err != nil {
		logWarnf("log-upload: store type=%s node=%.16sâ€¦: %v", nodeType, nodeID, err)
		jsonErr(w, "store error", http.StatusInternalServerError)
		return
	}

	logInfof("log-upload: stored type=%s node=%.16sâ€¦ user=%s size=%d from=%s", nodeType, nodeID, username, len(data), node.Addr)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`)) //nolint:errcheck
}

// apiLogGet returns the stored gzip log for a device node.
// Authenticated by X-Node-Token (control node token).
func (h *handler) apiLogGet(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Node-Token")
	if token == "" {
		jsonErr(w, "X-Node-Token required", http.StatusUnauthorized)
		return
	}
	node, err := h.db.nodeByToken(token)
	if err != nil || node == nil || node.Type != "control" {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	nodeID := r.URL.Query().Get("node")
	if nodeID == "" {
		jsonErr(w, "node query param required", http.StatusBadRequest)
		return
	}

	data, err := h.logs.Get(nodeID)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	logInfof("log-get: node=%.16sâ€¦ size=%d requested by control=%s", nodeID, len(data), node.Addr)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Encoding", "gzip")
	w.Write(data) //nolint:errcheck
}

func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	fmt.Fprintf(w, `{"error":%q}`, msg)
}

type heartbeatReq struct {
	ID           string          `json:"id"`
	Token        string          `json:"token"`
	RTTms        float64         `json:"rtt_ms"`
	RoutingRTTms float64         `json:"routing_rtt_ms,omitempty"`
	BWMbps       float64         `json:"bw_mbps"`
	BytesTotal   int64           `json:"bytes_total"`
	Fingerprint  string          `json:"fingerprint,omitempty"`
	DataPlaneOK  *bool           `json:"data_plane_ok,omitempty"`
	Capabilities map[string]bool `json:"capabilities,omitempty"`
	CPUPct       float64         `json:"cpu_pct,omitempty"`
	MemPct       float64         `json:"mem_pct,omitempty"`
	DiskPct      float64         `json:"disk_pct,omitempty"`
}

func (h *handler) apiHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req heartbeatReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	rows, err := h.db.updateHeartbeat(req.Token, req.RTTms, req.RoutingRTTms, req.BWMbps, req.BytesTotal, req.Fingerprint, req.DataPlaneOK, req.Capabilities, req.CPUPct, req.MemPct, req.DiskPct)
	if err != nil || rows == 0 {
		logWarnf("heartbeat: rejected token=%.8sâ€¦ id=%s err=%v rows=%d", req.Token, req.ID, err, rows)
		jsonErr(w, "unknown token or node not approved", http.StatusUnauthorized)
		return
	}
	logInfof("heartbeat: ok token=%.8sâ€¦ id=%s rtt=%.1fms bw=%.1fMbps bytes=%d",
		req.Token, req.ID, req.RTTms, req.BWMbps, req.BytesTotal)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

// regionFnWithOverrides returns a regionFn that respects per-node manual
// overrides. If a node has RegionOverride set, that value is returned
// verbatim -- including "OTHER", which is a real, explicit classification
// ("not RU, not CN, not IR, not EU, not US"), not a synonym for "unknown".
// It must survive being encoded in the signed exits/manifest list and read
// back by control/exit nodes exactly as "OTHER", or a node whose location
// CIDR-detects as e.g. "RU" but is manually corrected to "OTHER" ends up
// silently re-detecting itself as "RU" downstream (see the regionOther
// sentinel in snc-exit/peers.go, which needs that distinct value to avoid
// re-deriving the very region the override was meant to correct).
// A node with no override at all falls back to CIDR lookup via h.regionOf.
func (h *handler) regionFnWithOverrides(nodes []Node) func(string) string {
	overrides := make(map[string]string, len(nodes))
	for _, n := range nodes {
		if n.RegionOverride != "" {
			overrides[n.Addr] = n.RegionOverride
		}
	}
	return func(addr string) string {
		if v, ok := overrides[addr]; ok {
			return v
		}
		return h.regionOf(addr)
	}
}

// apiExits returns a signed list of live exit nodes.
// Control and exit nodes (identified by their token) may call this.
// Exit nodes use it to discover peers for geo-routing and fallback forwarding.
func (h *handler) apiExits(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Node-Token")
	if token == "" {
		jsonErr(w, "X-Node-Token required", http.StatusUnauthorized)
		return
	}
	node, err := h.db.nodeByToken(token)
	if err != nil || node == nil || (node.Type != "control" && node.Type != "exit") {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	exits, err := h.db.liveNodes("exit")
	if err != nil {
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	regionFn := h.regionFnWithOverrides(exits)
	regMap := make(map[string]string, len(exits))
	for _, e := range exits {
		if cc := regionFn(e.Addr); cc != "" {
			regMap[e.Addr] = cc
		}
	}
	h.loadRelayState()
	relayOn := h.relayEnabled()
	// Resolved server-side from the caller's own token, not from the exit
	// list by IP -- an exit behind cloud-provider NAT (e.g. Yandex Cloud)
	// can't reliably match its own outbound-detected IP against its public
	// Addr, which silently defeats RegionOverride. See SelfRegion doc comment.
	selfRegion := regionFn(node.Addr)
	logInfof("exits: serving token=%.8sâ€¦ node=%s count=%d regions=%v relay_enabled=%v self_region=%q", token, node.Addr, len(exits), regMap, relayOn, selfRegion)
	data, err := h.signer.signListWithConfig("exits", exits, regionFn, relayOn, selfRegion)
	if err != nil {
		jsonErr(w, "signing error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data) //nolint:errcheck
}

// maxManifestNodes is the maximum number of control nodes returned per manifest request.
// Partial-knowledge principle: no single exit learns the full topology.
const maxManifestNodes = 12

// apiManifest returns a signed list of â‰¤12 randomly-selected live control nodes.
// Only exit nodes (identified by their token) may call this.
// Clients fetch this through the exit to discover control nodes.
func (h *handler) apiManifest(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Node-Token")
	if token == "" {
		jsonErr(w, "X-Node-Token required", http.StatusUnauthorized)
		return
	}
	node, err := h.db.nodeByToken(token)
	if err != nil || node == nil || node.Type != "exit" {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	controls, err := h.db.liveNodes("control")
	if err != nil {
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	selected := selectManifestNodes(controls, maxManifestNodes)
	logInfof("manifest: serving token=%.8sâ€¦ node=%s total=%d selected=%d",
		token, node.Addr, len(controls), len(selected))

	data, err := h.signer.signList("manifest", selected, h.regionFnWithOverrides(controls))
	if err != nil {
		jsonErr(w, "signing error", http.StatusInternalServerError)
		return
	}
	// Broadcast notifications from the in-memory cache (broadcast-only, fast path).
	// If the client sends its session token we also append per-user notifications.
	h.notifMu.RLock()
	notifs := make([]NotificationEntry, len(h.notifCache))
	copy(notifs, h.notifCache)
	h.notifMu.RUnlock()
	if tok := r.Header.Get("X-Session"); tok != "" {
		if username, _, _, _ := h.sessions.Validate(tok); username != "" {
			if userNotifs, err := h.db.activeNotifications(username); err == nil {
				// userNotifs includes broadcast + per-user; replace the broadcast-only slice.
				notifs = userNotifs
			}
		}
	}
	// Build advisory SNI map: addr â†’ []string from each node's sni_list.
	var nodeSNIs map[string][]string
	for _, n := range selected {
		if n.SNIList == "" {
			continue
		}
		snis := splitSNIList(n.SNIList)
		if len(snis) == 0 {
			continue
		}
		if nodeSNIs == nil {
			nodeSNIs = make(map[string][]string)
		}
		nodeSNIs[n.Addr] = snis
	}

	var excludedAddrs []string
	if excl, err := h.db.listExcludedNodes(); err == nil && len(excl) > 0 {
		for _, e := range excl {
			excludedAddrs = append(excludedAddrs, e.Addr)
		}
	}

	// ipv6Enabled is always bolted on (unlike the others below, which are only
	// added when non-empty) -- clients need to distinguish "arbiter says off"
	// from "arbiter said nothing", so a nil/absent field must never happen.
	h.loadIPv6State()
	ipv6On := h.ipv6Enabled()
	{
		var m SignedList
		if err := json.Unmarshal(data, &m); err == nil {
			m.IPv6Enabled = &ipv6On
			if len(notifs) > 0 {
				m.Notifications = notifs
			}
			if len(nodeSNIs) > 0 {
				m.NodeSNIs = nodeSNIs
			}
			if len(excludedAddrs) > 0 {
				m.Excluded = excludedAddrs
			}
			if out, err := json.Marshal(m); err == nil {
				data = out
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data) //nolint:errcheck
}

// splitSNIList splits a comma-separated SNI list, trimming whitespace and
// dropping empty entries.
func splitSNIList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// sampleNodes returns a random sample of up to n nodes from nodes.
func sampleNodes(nodes []Node, n int) []Node {
	if len(nodes) <= n {
		return nodes
	}
	out := make([]Node, len(nodes))
	copy(out, nodes)
	rand.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out[:n]
}

// selectManifestNodes builds the manifest's control list: every live pinned
// (long-lived anchor) node unconditionally first, then a random sample of
// the rest filling up to n total. Pinned nodes exist so a client that's been
// offline long enough for every other control in its cached manifest to have
// IP-rotated away still has at least one address that's still alive -- so
// they must never be subject to the random cut the way ordinary nodes are.
// If pinned nodes alone already reach or exceed n, all of them are still
// returned (n is a target for the non-pinned fill, not a hard cap on pinned).
func selectManifestNodes(nodes []Node, n int) []Node {
	var pinned, rest []Node
	for _, node := range nodes {
		if node.Pinned {
			pinned = append(pinned, node)
		} else {
			rest = append(rest, node)
		}
	}
	remaining := n - len(pinned)
	if remaining <= 0 {
		return pinned
	}
	return append(pinned, sampleNodes(rest, remaining)...)
}

// apiUpdateFile serves a binary update file from updateDir to authenticated exit nodes.
// nodeType is the required node type ("exit"). filename is one of: version, snc-control, snc-control.sha256.
func (h *handler) apiUpdateFile(w http.ResponseWriter, r *http.Request, nodeType, filename string) {
	if h.updateDir == "" {
		http.Error(w, `{"error":"updates not configured"}`, http.StatusNotFound)
		return
	}
	token := r.Header.Get("X-Node-Token")
	if token == "" {
		jsonErr(w, "X-Node-Token required", http.StatusUnauthorized)
		return
	}
	node, err := h.db.nodeByToken(token)
	if err != nil || node == nil || node.Type != nodeType {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	data, err := os.ReadFile(filepath.Join(h.updateDir, filename))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if strings.HasSuffix(filename, ".sha256") || strings.HasSuffix(filename, ".version") || filename == "version" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	w.Write(data) //nolint:errcheck
	logInfof("update: served %s to %s token=%.8sâ€¦", filename, node.Addr, token)
}

// apiNodes returns a signed list of live control nodes (public endpoint for operators/keygen).
func (h *handler) apiNodes(w http.ResponseWriter, r *http.Request) {
	controls, err := h.db.liveNodes("control")
	if err != nil {
		jsonErr(w, "internal error", http.StatusInternalServerError)
		return
	}
	data, err := h.signer.signList("controls", controls, h.regionFnWithOverrides(controls))
	if err != nil {
		jsonErr(w, "signing error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// apiSessionValidate validates a VPN client SNC token.
// Called by exit nodes with their node token in X-Node-Token.
func (h *handler) apiSessionValidate(w http.ResponseWriter, r *http.Request) {
	nodeToken := r.Header.Get("X-Node-Token")
	node, err := h.db.nodeByToken(nodeToken)
	if err != nil || node == nil {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Session string `json:"session"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}

	username, clientID, deviceID, denied := h.sessions.Validate(req.Session)
	logInfof("session validate token=%.8sâ€¦ user=%q client_id=%s device_id=%s node=%s denied=%v",
		req.Session, username, clientID, deviceID, node.Addr, denied)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{ //nolint:errcheck
		"user":      username,
		"client_id": clientID,
		"denied":    denied,
	})
}

// apiCIDRAll returns all per-country signed CIDR bypass lists.
// Exit and control nodes (identified by their token) may call this.
func (h *handler) apiCIDRAll(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Node-Token")
	if token == "" {
		jsonErr(w, "X-Node-Token required", http.StatusUnauthorized)
		return
	}
	node, err := h.db.nodeByToken(token)
	if err != nil || node == nil || (node.Type != "exit" && node.Type != "control") {
		jsonErr(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	cidrs := h.cidrSt.get()
	if len(cidrs) == 0 {
		http.NotFound(w, r)
		return
	}
	data, err := h.signer.signAllCountries(cidrs)
	if err != nil {
		logWarnf("apiCIDRAll: sign: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data) //nolint:errcheck
}

// handleClientRequest handles requests that arrive via the clientâ†’controlâ†’exitâ†’arbiter
// chain. Only verifyPassword and authenticateKey are legitimate here -- every
// SNC client build only ever sends one of those two to this endpoint (see
// tunnel_cat/snc/core/tunnel.go). Anything else used to be blind-proxied
// straight through to Camerlengo using the arbiter's own key (2026-08-13:
// closed -- audited that no client, current or historical, relies on that
// fallback for anything; it was reachable by anyone who could route a
// request through client->control->exit, unscoped, with no client-side
// change needed to remove it).
func (h *handler) handleClientRequest(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	// Extract command without failing on non-string fields (e.g. arrays in authenticateKey).
	var meta struct {
		Command string `json:".command"`
	}
	json.Unmarshal(body, &meta) //nolint:errcheck
	switch meta.Command {
	case "verifyPassword":
		// verifyPassword has only string fields; re-parse as flat map for convenience.
		var cmd map[string]string
		json.Unmarshal(body, &cmd) //nolint:errcheck
		username := cmd["user"]
		password := cmd["password"]
		opts := &LoginOpts{
			KeyID:      cmd["key_id"],
			DeviceID:   cmd["device_id"],
			DeviceName: cmd["device_name"],
		}
		token, err := h.sessions.Login(username, password, opts)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			logInfof("sessions: login failed user=%s device=%q(%s): %v", username, opts.DeviceName, opts.DeviceID, err)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid credentials"}) //nolint:errcheck
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"session": token}) //nolint:errcheck
		return

	case "authenticateKey":
		h.handleKeyAuth(w, body)
		return

	default:
		logWarnf("handleClientRequest: unrecognized command %q from %s", meta.Command, clientIP(r))
		http.Error(w, "unknown command", http.StatusBadRequest)
	}
}

// adminNodeSetRegion sets or clears the manual region override for a node.
// POST /admin/api/nodes/{id}/region  body: {"region":"RU"} or {"region":""}
func (h *handler) adminNodeSetRegion(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// parts: ["admin","api","nodes","{id}","region"]
	if len(parts) != 5 {
		jsonErr(w, "bad path", http.StatusBadRequest)
		return
	}
	nodeID, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		jsonErr(w, "bad id", http.StatusBadRequest)
		return
	}
	var body struct {
		Region string `json:"region"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	allowed := map[string]bool{"": true, "RU": true, "EU": true, "US": true, "CN": true, "IR": true, "OTHER": true}
	if !allowed[body.Region] {
		jsonErr(w, "unknown region", http.StatusBadRequest)
		return
	}
	if err := h.db.setNodeRegionOverride(nodeID, body.Region); err != nil {
		logWarnf("adminNodeSetRegion %d: %v", nodeID, err)
		jsonErr(w, "db error", http.StatusInternalServerError)
		return
	}
	logInfof("admin: node %d region_override=%q", nodeID, body.Region)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`)) //nolint:errcheck
}

// adminNodeSetPinned sets or clears the pinned (long-lived anchor) flag for a
// control node -- see the Node.Pinned doc comment for what this controls.
// POST /admin/api/nodes/{id}/pinned  body: {"pinned":true}
func (h *handler) adminNodeSetPinned(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// parts: ["admin","api","nodes","{id}","pinned"]
	if len(parts) != 5 {
		jsonErr(w, "bad path", http.StatusBadRequest)
		return
	}
	nodeID, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		jsonErr(w, "bad id", http.StatusBadRequest)
		return
	}
	var body struct {
		Pinned bool `json:"pinned"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErr(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := h.db.setNodePinned(nodeID, body.Pinned); err != nil {
		logWarnf("adminNodeSetPinned %d: %v", nodeID, err)
		jsonErr(w, "db error", http.StatusInternalServerError)
		return
	}
	logInfof("admin: node %d pinned=%v", nodeID, body.Pinned)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`)) //nolint:errcheck
}

// handleKeyAuth handles the authenticateKey command: verifies the AuthSig embedded
// in the request against the arbiter's own Ed25519 public key, then issues an SNC
// session token without requiring a Camerlengo password check.
func (h *handler) handleKeyAuth(w http.ResponseWriter, body []byte) {
	var req struct {
		Username      string   `json:"username"`
		Servers       []string `json:"servers"`
		ControlNodes  []string `json:"control_nodes"`
		ArbiterPubkey string   `json:"arbiter_pubkey"`
		NodeID        string   `json:"node_id"`
		APIKey        string   `json:"api_key"`
		ClientID      string   `json:"client_id"`
		KeyID         string   `json:"key_id"`
		AuthSig       string   `json:"auth_sig"`
		DeviceID      string   `json:"device_id"`
		DeviceName    string   `json:"device_name"`
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.Unmarshal(body, &req); err != nil || req.Username == "" || req.AuthSig == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid request"}) //nolint:errcheck
		return
	}

	// Reconstruct the canonical payload and verify the signature.
	authCanon, err := json.Marshal(keyPayloadAuthCanonical{
		Username:      req.Username,
		Servers:       req.Servers,
		ControlNodes:  req.ControlNodes,
		ArbiterPubkey: req.ArbiterPubkey,
		NodeID:        req.NodeID,
		APIKey:        req.APIKey,
		ClientID:      req.ClientID,
		KeyID:         req.KeyID,
	})
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "internal error"}) //nolint:errcheck
		return
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(req.AuthSig)
	if err != nil || !ed25519.Verify(h.signer.pub, authCanon, sigBytes) {
		logInfof("sessions: key-auth failed user=%s device=%q(%s): invalid AuthSig", req.Username, req.DeviceName, req.DeviceID)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid key"}) //nolint:errcheck
		return
	}

	// Check per-key expiry (NULL paid_until = perpetual key, always allowed).
	if req.KeyID != "" {
		if k, kerr := h.db.GetKey(req.KeyID); kerr == nil && k != nil {
			if k.PaidUntil != nil && time.Now().After(*k.PaidUntil) {
				logInfof("sessions: key-auth rejected user=%s device=%q(%s) key=%.8s: expired %s",
					req.Username, req.DeviceName, req.DeviceID, req.KeyID, k.PaidUntil.Format("2006-01-02"))
				json.NewEncoder(w).Encode(map[string]string{"error": "key expired"}) //nolint:errcheck
				return
			}
		}
	}

	opts := &LoginOpts{KeyID: req.KeyID, DeviceID: req.DeviceID, DeviceName: req.DeviceName}
	token, err := h.sessions.LoginWithKey(req.Username, opts)
	if err != nil {
		logInfof("sessions: key-auth login failed user=%s device=%q(%s): %v", req.Username, req.DeviceName, req.DeviceID, err)
		json.NewEncoder(w).Encode(map[string]string{"error": "login failed"}) //nolint:errcheck
		return
	}
	resp := map[string]interface{}{"session": token}
	// Attach any pending per-user notifications so the client can show them immediately.
	if notifs, nerr := h.db.activeNotifications(req.Username); nerr == nil && len(notifs) > 0 {
		resp["notifications"] = notifs
	}
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}
