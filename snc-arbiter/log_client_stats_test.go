// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"archive/zip"
	"bytes"
	"testing"

	"tunnel_cat/binlog"
)

func buildZip1(t *testing.T, logContent, statsContent []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if fw, err := zw.CreateHeader(&zip.FileHeader{Name: "log", Method: zip.Deflate}); err != nil {
		t.Fatalf("create log entry: %v", err)
	} else if _, err := fw.Write(logContent); err != nil {
		t.Fatalf("write log entry: %v", err)
	}
	if fw, err := zw.CreateHeader(&zip.FileHeader{Name: "stats", Method: zip.Deflate}); err != nil {
		t.Fatalf("create stats entry: %v", err)
	} else if _, err := fw.Write(statsContent); err != nil {
		t.Fatalf("write stats entry: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// TestControlDeadAddrsFromClientUpload confirms the "stats" member decodes
// to the right addrs without ever touching "log" -- log content here is
// deliberately not valid binlog at all (plain garbage bytes), proving the
// extraction never attempts to read it.
func TestControlDeadAddrsFromClientUpload(t *testing.T) {
	var stats []byte
	stats = binlog.AppendRecord(stats, binlog.TagControlDead, []byte("1.2.3.4:443"))
	stats = binlog.AppendRecord(stats, binlog.TagControlDead, []byte("5.6.7.8:443"))

	logContent := []byte("this is not binlog-framed at all, just plain text")
	data := buildZip1(t, logContent, stats)

	addrs := controlDeadAddrsFromClientUpload(data)
	if len(addrs) != 2 || addrs[0] != "1.2.3.4:443" || addrs[1] != "5.6.7.8:443" {
		t.Fatalf("controlDeadAddrsFromClientUpload = %v, want [1.2.3.4:443 5.6.7.8:443]", addrs)
	}
}

func TestControlDeadAddrsFromClientUpload_NoStatsEntry(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	fw, _ := zw.CreateHeader(&zip.FileHeader{Name: "log", Method: zip.Deflate})
	fw.Write([]byte("hello"))
	zw.Close()

	if addrs := controlDeadAddrsFromClientUpload(buf.Bytes()); addrs != nil {
		t.Fatalf("expected nil with no stats entry, got %v", addrs)
	}
}

func TestControlDeadAddrsFromClientUpload_NotZip(t *testing.T) {
	if addrs := controlDeadAddrsFromClientUpload([]byte("not a zip file")); addrs != nil {
		t.Fatalf("expected nil for non-zip input, got %v", addrs)
	}
}
