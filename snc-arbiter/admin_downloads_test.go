// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestReplicateOneUpload_PushesFileAndSkipsSecondHop verifies replicateOneUpload
// actually delivers the binary_type/version/file fields a receiving node's own
// adminDownloadsUpload expects, and that the receiving node -- seeing
// X-No-Replicate -- does not itself try to replicate further (which would
// ping-pong forever between two real nodes).
func TestReplicateOneUpload_PushesFileAndSkipsSecondHop(t *testing.T) {
	// sourceDir simulates the node that received the original deploy.sh
	// upload; peerDir simulates the fellow cluster node's own updateDir --
	// deliberately separate directories so the test can't pass just because
	// replicateOneUpload happens to read from the same place the assertion
	// checks afterward.
	sourceDir := t.TempDir()
	peerDir := t.TempDir()
	sourceHandler := &handler{updateDir: sourceDir, uploadKey: "test-key"}
	peerHandler := &handler{updateDir: peerDir, uploadKey: "test-key"}

	var gotReplicateHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/downloads/upload" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		gotReplicateHeader = r.Header.Get("X-No-Replicate")
		peerHandler.adminDownloadsUpload(w, r)
	}))
	defer srv.Close()

	src := filepath.Join(sourceDir, "shortnerdcat.apk")
	if err := os.WriteFile(src, []byte("fake apk bytes"), 0644); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	if err := sourceHandler.replicateOneUpload(srv.URL, "android", "202608180000", src); err != nil {
		t.Fatalf("replicateOneUpload: %v", err)
	}

	if gotReplicateHeader != "1" {
		t.Fatalf("receiving handler saw X-No-Replicate=%q, want %q", gotReplicateHeader, "1")
	}

	// The receiving node's own adminDownloadsUpload installs asynchronously
	// (background goroutine) -- but replicateOneUpload only returns after
	// reading a full HTTP response, and adminDownloadsUpload writes that
	// response synchronously before launching the install goroutine, so
	// there's an inherent small race here in a unit test. Poll briefly.
	dst := filepath.Join(peerDir, "shortnerdcat.apk")
	var lastErr error
	ok := false
	for i := 0; i < 100; i++ {
		data, err := os.ReadFile(dst)
		if err == nil && string(data) == "fake apk bytes" {
			ok = true
			break
		}
		lastErr = err
		time.Sleep(10 * time.Millisecond)
	}
	if !ok {
		t.Fatalf("receiving node never installed the replicated file (last err=%v)", lastErr)
	}

	verData, err := os.ReadFile(dst + ".version")
	if err != nil {
		t.Fatalf("read version file: %v", err)
	}
	if got := string(verData); got != "202608180000\n" {
		t.Fatalf("version file = %q, want %q", got, "202608180000\n")
	}
}

// TestAdminDownloadsUpload_NoReplicateHeaderSkipsReplication verifies a
// request carrying X-No-Replicate never calls replicateToPeers (which would
// need h.peerArbiters and a real network round-trip) -- guards against the
// two-node cluster ping-ponging the same upload back and forth.
func TestAdminDownloadsUpload_NoReplicateHeaderSkipsReplication(t *testing.T) {
	dir := t.TempDir()
	// peerArbiters points at an address that would fail/hang if ever dialed,
	// so this test fails loudly if the isReplica guard is ever removed.
	h := &handler{updateDir: dir, peerArbiters: []string{"http://127.0.0.1:1"}}

	body, contentType := buildUploadBody(t, "android", "202608180000", "shortnerdcat.apk", []byte("x"))
	req := httptest.NewRequest(http.MethodPost, "/admin/downloads/upload", body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-No-Replicate", "1")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer ") // uploadKey empty -> checkUploadKey passes regardless
	rec := httptest.NewRecorder()

	h.adminDownloadsUpload(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// The response is sent before the background install goroutine finishes
	// writing .version/.sha256 -- wait for it so t.TempDir()'s own cleanup
	// (which runs as soon as this test function returns) doesn't race an
	// in-flight write to the directory it's about to remove. Nothing here
	// should ever touch peerArbiters (if it did, this would hang or error
	// dialing 127.0.0.1:1, not silently pass).
	verPath := filepath.Join(dir, "shortnerdcat.apk.version")
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(verPath); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("background install never finished (no %s)", verPath)
}

func buildUploadBody(t *testing.T, binaryType, version, filename string, content []byte) (io.Reader, string) {
	t.Helper()
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		defer pw.Close()
		defer mw.Close()
		mw.WriteField("binary_type", binaryType) //nolint:errcheck
		mw.WriteField("version", version)        //nolint:errcheck
		fw, err := mw.CreateFormFile("file", filename)
		if err != nil {
			return
		}
		fw.Write(content) //nolint:errcheck
	}()
	return pr, mw.FormDataContentType()
}
