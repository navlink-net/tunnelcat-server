// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"net/http"
)

func (h *handler) partnersLisinderDownloadApk(w http.ResponseWriter, r *http.Request) {
	info := h.readClientBinaryInfo("lisinder.apk")
	name := "lisinder.apk"
	if info.Version != "" {
		name = "lisinder-" + info.Version + ".apk"
	}
	h.downloadFile(w, r, "lisinder.apk", name)
}

// partnersLisinder serves GET /partners/lisinder — the hidden control page loaded
// by the Lisinder Android app in a non-visible WebView.
// It has access to the AppBridge JS interface (exposed as `Android`) and can:
//
//	Android.showOverlay(url)    — full-screen ad WebView
//	Android.hideOverlay()       — close overlay
//	Android.loadInContent(url)  — navigate the content WebView
//	Android.evalInContent(js)   — run JS in the content WebView
//	Android.showToast(text)     — native Android toast
//	Android.isVpnRunning()      — bool
//	Android.log(message)        — logcat tag: ControlPage
func (h *handler) partnersLisinder(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(partnersLisinderHTML)) //nolint:errcheck
}

const partnersLisinderHTML = `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Control</title></head>
<body>
<script>
(function () {
    if (typeof Android === 'undefined') {
        console.log('Control page: no Android bridge (running outside app)');
        return;
    }

    Android.log('Control page loaded, vpn=' + Android.isVpnRunning());

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
    // ────────────────────────────────────────────────────────────────────────

})();
</script>
</body>
</html>
`
