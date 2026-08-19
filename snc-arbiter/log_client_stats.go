// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

import (
	"archive/zip"
	"bytes"
	"io"

	"tunnel_cat/binlog"
)

// maxStatsEntryBytes bounds decompression of the "stats" zip member only --
// deliberately tiny, since it only ever holds small structured stat records
// (see binlog.TagControlDead). The "log" member, which can be arbitrarily
// large and is never treated as trusted, is never opened here at all: zip's
// central directory lets a single named entry be read without touching any
// other member's compressed bytes, which is the whole reason this upload is
// a zip archive instead of a bare gzip stream (see
// snc/core/log_upload.go's LogUploader.upload).
const maxStatsEntryBytes = 256 * 1024

// controlDeadAddrsFromClientUpload extracts TagControlDead payloads from the
// "stats" member of a zip1-formatted client log upload. Returns nil (never
// an error) for anything that doesn't look like a well-formed zip1 upload --
// absence of stats is not a failure, and this must never block storing the
// upload itself.
func controlDeadAddrsFromClientUpload(data []byte) []string {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil
	}
	for _, f := range zr.File {
		if f.Name != "stats" {
			continue
		}
		if f.UncompressedSize64 > maxStatsEntryBytes {
			return nil
		}
		rc, err := f.Open()
		if err != nil {
			return nil
		}
		raw, err := io.ReadAll(io.LimitReader(rc, maxStatsEntryBytes))
		rc.Close()
		if err != nil {
			return nil
		}
		records, _ := binlog.DecodeRecords(raw)
		var addrs []string
		for _, r := range records {
			if r.Tag == binlog.TagControlDead && len(r.Payload) > 0 {
				addrs = append(addrs, string(r.Payload))
			}
		}
		return addrs
	}
	return nil
}
