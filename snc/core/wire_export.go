// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

// External test/mock tooling (e.g. tunnelcat-sdk's mockserver, which stands
// in for a real exit so SDK adapters can be exercised without real
// credentials) needs to speak the same wire-frame format the real client
// and exit use, but has no reason to reach into unexported internals for
// it. These are thin exported wrappers around the same code paths the
// client/exit already share -- no new logic lives here, and internal
// callers should keep using the unexported sealFrame/openFrame/etc.
// directly rather than switching to these.

// SessionKey derives the ChaCha20-Poly1305 frame key from a session token,
// exactly as the real exit/control does.
func SessionKey(token string) []byte { return sessionKey(token) }

// SealFrame is the exported form of sealFrame.
func SealFrame(key, plaintext []byte) ([]byte, error) { return sealFrame(key, plaintext) }

// OpenFrame is the exported form of openFrame.
func OpenFrame(key, data []byte) ([]byte, error) { return openFrame(key, data) }

// FrameTypeUpload is the exported form of frameTypeUpload.
const FrameTypeUpload = frameTypeUpload

// ParseUploadFrame is the exported form of parseUploadFrame.
func ParseUploadFrame(plain []byte) (connID string, seq uint32, target string, payload []byte, err error) {
	return parseUploadFrame(plain)
}

// BuildUploadResponse is the exported form of buildUploadResponse.
func BuildUploadResponse(key, data []byte) ([]byte, error) { return buildUploadResponse(key, data) }
