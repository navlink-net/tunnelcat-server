// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"
)

// Self-hosted arithmetic quasi-CAPTCHA for public unauthenticated forms
// (currently /forgot-password). It needs no external service or API key:
// the challenge (two small numbers) and its expiry are embedded in a
// token signed with a key derived from the arbiter's own signing seed, so
// any arbiter instance holding that seed can verify a token it did not
// itself issue. This does not stop a targeted attacker who scripts the
// arithmetic, but combined with per-email/IP rate limiting (see
// forgotPasswordSubmit) it kills naive form-spam scripts, which is what
// was actually observed abusing this endpoint.
const captchaTTL = 10 * time.Minute

func deriveCaptchaKey(priv ed25519.PrivateKey) [32]byte {
	h, _ := blake2b.New256(nil)
	h.Write(priv.Seed())
	h.Write([]byte("snc-arbiter-captcha-hmac-v1"))
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key
}

// newCaptcha returns a human-readable question and a signed token encoding
// the expected answer and an expiry.
func (h *handler) newCaptcha() (question, token string) {
	a := rand.Intn(8) + 1
	b := rand.Intn(8) + 1
	exp := time.Now().Add(captchaTTL).Unix()

	payload := make([]byte, 10)
	payload[0] = byte(a)
	payload[1] = byte(b)
	binary.BigEndian.PutUint64(payload[2:], uint64(exp))

	key := deriveCaptchaKey(h.signer.priv)
	mac := hmac.New(sha256.New, key[:])
	mac.Write(payload)
	sig := mac.Sum(nil)

	token = base64.RawURLEncoding.EncodeToString(append(payload, sig...))
	question = fmt.Sprintf("%d + %d", a, b)
	return question, token
}

// verifyCaptcha checks a token+answer pair produced by newCaptcha.
func (h *handler) verifyCaptcha(token, answer string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 10+sha256.Size {
		return false
	}
	payload, sig := raw[:10], raw[10:]

	key := deriveCaptchaKey(h.signer.priv)
	mac := hmac.New(sha256.New, key[:])
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return false
	}

	exp := int64(binary.BigEndian.Uint64(payload[2:]))
	if time.Now().Unix() > exp {
		return false
	}

	ans, err := strconv.Atoi(strings.TrimSpace(answer))
	if err != nil {
		return false
	}
	return ans == int(payload[0])+int(payload[1])
}

// apiCaptcha handles GET /api/captcha -- issues a fresh challenge as JSON,
// for static-front-end (JS fetch) callers that have no server-rendered page
// to embed the {{.CaptchaQ}}/{{.CaptchaToken}} pageData fields into.
func (h *handler) apiCaptcha(w http.ResponseWriter, r *http.Request) {
	q, tok := h.newCaptcha()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"question": q, "token": tok}) //nolint:errcheck
}
