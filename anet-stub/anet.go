// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

// Package anet is a stub replacement for github.com/wlynxg/anet.
// The original package uses //go:linkname net.zoneCache which was removed in Go 1.22.
// We replace it with simple delegation to net.Interfaces() / iface.Addrs().
// On Android we never call these functions (androidNet handles interface enumeration),
// so correctness on Android is not required — only compilation.
package anet

import "net"

func Interfaces() ([]net.Interface, error) {
	return net.Interfaces()
}

func InterfaceAddrsByInterface(iface *net.Interface) ([]net.Addr, error) {
	return iface.Addrs()
}
