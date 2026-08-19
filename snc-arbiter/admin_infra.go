// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import "net/http"

func (h *handler) adminInfraPage(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, "admin_infra.html", nil)
}
