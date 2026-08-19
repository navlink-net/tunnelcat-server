// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import "embed"

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS
