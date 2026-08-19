// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

//go:build windows

// Package wintun embeds the WinTun driver DLL and provides a helper to
// extract it to the directory of the running executable before use.
//
// The DLL file (internal/wintun/wintun.dll) must be present at compile time.
// Fetch it once with:
//
//	go run ./tools/fetch_wintun/
//
//go:generate go run ../../tools/fetch_wintun/
package wintun

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed wintun.dll
var dllBytes []byte

// Extract writes wintun.dll next to the running executable if it is not
// already present. wintun's LoadLibraryEx call searches APPLICATION_DIR first,
// so the DLL must live beside the .exe.
func Extract() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("wintun extract: executable path: %w", err)
	}
	dst := filepath.Join(filepath.Dir(exe), "wintun.dll")

	if _, err := os.Stat(dst); err == nil {
		return nil // already extracted
	}

	if err := os.WriteFile(dst, dllBytes, 0644); err != nil {
		return fmt.Errorf("wintun extract: write %s: %w", dst, err)
	}
	return nil
}
