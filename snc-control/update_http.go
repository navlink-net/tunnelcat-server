// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// startUpdateHTTP serves cached client binaries over HTTPS on a dedicated
// port so clients can reach them without tunnelling. certFile and keyFile
// must be valid PEM paths (LE or self-signed); the client connects by IP so
// cert hostname validation is intentionally skipped on the client side.
//
// Routes are entirely generic: /client-<slug>[-version|.sha256] is parsed
// into a slug + kind and served straight from cacheDir/<slug>/{bin,version,
// sha256} (populated by clientCache from the arbiter's manifest). Adding a
// new distributable type needs no change here — see client_cache.go.
func startUpdateHTTP(addr, cacheDir, certFile, keyFile string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		slug, fileName, ct, ok := parseClientUpdatePath(r.URL.Path)
		if !ok {
			http.NotFound(w, r)
			return
		}
		data, err := os.ReadFile(filepath.Join(cacheDir, slug, fileName))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", ct)
		w.Write(data) //nolint:errcheck
	})
	srv := &http.Server{Addr: addr, Handler: mux}
	logInfof("update HTTPS server listening on %s", addr)
	if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil {
		logWarnf("update HTTPS server: %v", err)
	}
}

// parseClientUpdatePath parses "/client-<slug>", "/client-<slug>-version", or
// "/client-<slug>.sha256" into (slug, cache-filename, content-type, ok).
func parseClientUpdatePath(path string) (slug, fileName, contentType string, ok bool) {
	const prefix = "/client-"
	if !strings.HasPrefix(path, prefix) {
		return "", "", "", false
	}
	rest := path[len(prefix):]
	switch {
	case strings.HasSuffix(rest, "-version"):
		slug = strings.TrimSuffix(rest, "-version")
		fileName, contentType = "version", "text/plain; charset=utf-8"
	case strings.HasSuffix(rest, ".sha256"):
		slug = strings.TrimSuffix(rest, ".sha256")
		fileName, contentType = "sha256", "text/plain; charset=utf-8"
	default:
		slug = rest
		fileName, contentType = "bin", "application/octet-stream"
	}
	if slug == "" {
		return "", "", "", false
	}
	return slug, fileName, contentType, true
}
