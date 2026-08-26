// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"net/http"
	"time"
)

// checkSupportRateLimit enforces the shared cooldown/global cap for every
// contact/support-form submission through POST /api/contact (see
// contact.go) -- one namespace across every context (support/blackbadger/
// ratatosk/partners) so splitting one endpoint into several forms doesn't
// multiply the effective rate. email is self-reported and unverified on
// these anonymous forms, so it alone is not a reliable key -- see
// TODO.md's arbiter API flood audit -- hence the IP check alongside it.
//
// GET/POST /support (the page + submit handler this limiter originally
// shipped with) were removed 2026-08-25, migrated to a static page +
// POST /api/contact -- this function is the one piece that survived that
// move.
func (h *handler) checkSupportRateLimit(r *http.Request, email string) bool {
	if !h.supportGlobal.Allow() {
		return false
	}
	if !h.supportLimiter.Allow("ip:"+clientIP(r), limitTier{Window: 5 * time.Second, Max: 1}) {
		return false
	}
	if email != "" && !h.supportLimiter.Allow("email:"+email, limitTier{Window: 6 * time.Hour, Max: 1}) {
		return false
	}
	return true
}
