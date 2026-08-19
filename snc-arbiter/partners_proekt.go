// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"net/http"
)

type partnersPageData struct {
	ApkAvailable bool
	ApkVersion   string

	LisinderApkAvailable bool
	LisinderApkVersion   string
}

func (h *handler) partnersPage(w http.ResponseWriter, r *http.Request) {
	if setLangCookie(w, r) {
		return
	}
	lang := detectLang(r)
	apk := h.readClientBinaryInfo("proekt.apk")
	lisinderApk := h.readClientBinaryInfo("lisinder.apk")
	data := partnersPageData{
		ApkAvailable: apk.Size > 0,
		ApkVersion:   apk.Version,

		LisinderApkAvailable: lisinderApk.Size > 0,
		LisinderApkVersion:   lisinderApk.Version,
	}
	h.renderPageR(w, r, "partners.html", pageData{User: h.currentUser(r), Lang: lang, Data: data})
}

func (h *handler) partnersDownloadApk(w http.ResponseWriter, r *http.Request) {
	info := h.readClientBinaryInfo("proekt.apk")
	name := "proekt.apk"
	if info.Version != "" {
		name = "proekt-" + info.Version + ".apk"
	}
	h.downloadFile(w, r, "proekt.apk", name)
}

// partnersProekt serves GET /partners/proekt — the hidden control page loaded
// by the Agents Media Android app in a non-visible WebView.
// It has access to the AppBridge JS interface (exposed as `Android`) and can:
//
//	Android.showOverlay(url)    — full-screen ad WebView
//	Android.hideOverlay()       — close overlay
//	Android.switchTab(index)    — 0=Proekt Media, 1=Agents Media
//	Android.loadInContent(url)  — navigate content WebView
//	Android.evalInContent(js)   — run JS in content WebView
//	Android.showToast(text)     — native Android toast
//	Android.isVpnRunning()      — bool
//	Android.getCurrentTab()     — 0 or 1
//	Android.log(message)        — logcat tag: ControlPage
func (h *handler) partnersProekt(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(partnersProektHTML)) //nolint:errcheck
}

const partnersProektHTML = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Control</title></head>
<body>
<script>
(function () {
    if (typeof Android === 'undefined') {
        console.log('Control page: no Android bridge (running outside app)');
        return;
    }

    Android.log('Control page loaded, tab=' + Android.getCurrentTab()
        + ' vpn=' + Android.isVpnRunning());

    // ── Place ad logic here ──────────────────────────────────────────────────
    //
    // Examples:
    //
    //   Show a full-screen overlay after 5 s:
    //     setTimeout(function() { Android.showOverlay('https://navlink.net/ad/test'); }, 5000);
    //
    //   Inject a banner into the content page:
    //     Android.evalInContent('document.body.insertAdjacentHTML("afterbegin","<div ...>");');
    //
    //   Switch to Agents Media tab:
    //     Android.switchTab(1);
    //
    // ────────────────────────────────────────────────────────────────────────

})();
</script>
</body>
</html>
`
