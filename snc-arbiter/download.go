// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
)

type downloadInfoEntry struct {
	Available bool   `json:"available"`
	Version   string `json:"version,omitempty"`
	Hash      string `json:"hash,omitempty"`
}

// apiDownloadsInfo is a public, unauthenticated JSON endpoint exposing the
// same version/hash/availability data downloadPage renders server-side, for
// the static front-ends (apps.navlink.net, shortnerdcat/download.html) that
// can't run Go templates. Read-only, no side effects.
func (h *handler) apiDownloadsInfo(w http.ResponseWriter, r *http.Request) {
	win := h.readClientBinaryInfo("shortnerdcat.zip")
	winInstaller := h.readClientBinaryInfo("shortnerdcat-installer.zip")
	apk := h.readClientBinaryInfo("shortnerdcat.apk")
	dmg := h.readClientBinaryInfo("shortnerdcat.dmg")
	deb := h.readClientBinaryInfo("shortnerdcat.deb")
	proektApk := h.readClientBinaryInfo("proekt.apk")
	lisinderApk := h.readClientBinaryInfo("lisinder.apk")

	// windows-installer's own Version is deliberately NOT winInstaller.Version
	// here -- same single-source-of-truth reasoning as downloadPage below.
	// Static front-ends (shortnerdcat/download.html) read this exact key for
	// their Windows tile, so this is the one that actually needs to be right.
	resp := map[string]downloadInfoEntry{
		"windows":           {Available: win.Size > 0, Version: win.Version, Hash: win.Hash},
		"windows-installer": {Available: winInstaller.Size > 0, Version: win.Version, Hash: winInstaller.Hash},
		"android":           {Available: apk.Size > 0, Version: apk.Version, Hash: apk.Hash},
		"macos":             {Available: dmg.Size > 0, Version: dmg.Version, Hash: dmg.Hash},
		"linux":             {Available: deb.Size > 0, Version: deb.Version, Hash: deb.Hash},
		"proekt":            {Available: proektApk.Size > 0, Version: proektApk.Version, Hash: proektApk.Hash},
		"lisinder":          {Available: lisinderApk.Size > 0, Version: lisinderApk.Version, Hash: lisinderApk.Hash},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

// downloadFile serves storedName from updateDir with displayName in Content-Disposition.
func (h *handler) downloadFile(w http.ResponseWriter, r *http.Request, storedName, displayName string) {
	if h.updateDir == "" {
		http.Error(w, "not available", http.StatusNotFound)
		return
	}
	path := filepath.Join(h.updateDir, storedName)
	f, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Prevent browsers from serving a stale cached binary when a new version is uploaded.
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Disposition", `attachment; filename="`+displayName+`"`)
	switch filepath.Ext(storedName) {
	case ".apk":
		w.Header().Set("Content-Type", "application/vnd.android.package-archive")
	case ".dmg":
		w.Header().Set("Content-Type", "application/x-apple-diskimage")
	case ".deb":
		w.Header().Set("Content-Type", "application/vnd.debian.binary-package")
	}
	http.ServeContent(w, r, displayName, fi.ModTime(), f)
}

func (h *handler) downloadZip(w http.ResponseWriter, r *http.Request) {
	info := h.readClientBinaryInfo("shortnerdcat.zip")
	name := "shortnerdcat.zip"
	if info.Version != "" {
		name = "shortnerdcat-" + info.Version + ".zip"
	}
	h.downloadFile(w, r, "shortnerdcat.zip", name)
}

func (h *handler) downloadZipInstaller(w http.ResponseWriter, r *http.Request) {
	info := h.readClientBinaryInfo("shortnerdcat-installer.zip")
	name := "shortnerdcat-installer.zip"
	if info.Version != "" {
		name = "shortnerdcat-installer-" + info.Version + ".zip"
	}
	h.downloadFile(w, r, "shortnerdcat-installer.zip", name)
}

func (h *handler) downloadApk(w http.ResponseWriter, r *http.Request) {
	info := h.readClientBinaryInfo("shortnerdcat.apk")
	name := "shortnerdcat.apk"
	if info.Version != "" {
		name = "shortnerdcat-" + info.Version + ".apk"
	}
	h.downloadFile(w, r, "shortnerdcat.apk", name)
}

func (h *handler) downloadDmg(w http.ResponseWriter, r *http.Request) {
	info := h.readClientBinaryInfo("shortnerdcat.dmg")
	name := "shortnerdcat.dmg"
	if info.Version != "" {
		name = "shortnerdcat-" + info.Version + ".dmg"
	}
	h.downloadFile(w, r, "shortnerdcat.dmg", name)
}

func (h *handler) downloadDeb(w http.ResponseWriter, r *http.Request) {
	info := h.readClientBinaryInfo("shortnerdcat.deb")
	name := "shortnerdcat.deb"
	if info.Version != "" {
		name = "shortnerdcat-" + info.Version + ".deb"
	}
	h.downloadFile(w, r, "shortnerdcat.deb", name)
}

