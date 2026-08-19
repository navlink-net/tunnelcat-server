// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

//go:build !windows

package core

// On non-Windows platforms (Android, Linux) the private key is stored as
// plaintext in appDataDir — the OS sandbox (Android app isolation, Unix
// file permissions) provides the equivalent protection.

func nodeIDEncrypt(plain []byte) ([]byte, error) { return plain, nil }
func nodeIDDecrypt(enc []byte) ([]byte, error)   { return enc, nil }
