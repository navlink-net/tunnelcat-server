// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

//go:build !windows

package core

import "net"

// WrapWithTorrentFilter is a no-op on non-Windows platforms.
func WrapWithTorrentFilter(ln net.Listener) net.Listener { return ln }
