// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"tunnel_cat/binlog"
)

const (
	logUploadInterval   = 5 * time.Minute
	logUploadArbiterURL = "https://navlink.net"
	logUploadPath       = "/api/log/client-upload"

	// statsRingSize is deliberately tiny -- it only ever holds small,
	// structured stat records (e.g. TagControlDead's bare addr payloads),
	// not log text. Kept as its own ring, separate from the main disk log,
	// so it can ride as a small, independent member of the upload's zip
	// archive (see LogUploader.upload) -- the arbiter can then extract and
	// decode just this one small entry without ever touching the
	// (potentially large) main log content on its hot ingest path.
	statsRingSize = 32 * 1024

	// maxRawLogPerUpload caps how much raw (pre-compression) disk log text
	// a single upload tick reads. The arbiter caps the whole request body
	// at 4MB after zip compression (log_store.go's nodeLogMaxLen);
	// repetitive log text compresses well under Deflate, so this raw cap
	// leaves comfortable headroom even in a pathological low-compression
	// case. A backlog larger than this (catching up after being offline,
	// or a long-lived install's very first upload) is deliberately NOT
	// sent in one shot -- the cursor only advances past what was actually
	// included, so the remainder is picked up on the next tick(s),
	// continuing every logUploadInterval until fully caught up.
	maxRawLogPerUpload = 3 << 20 // 3 MB

	// logUploadCursorFile persists how far into the disk log LogUploader
	// has successfully uploaded, as "<filename>\n<byte offset>", inside
	// LogDir itself. Survives process restarts -- without this, every
	// restart would either re-upload everything from the start of
	// retention or (worse) silently skip ahead and never send the gap.
	logUploadCursorFile = ".log_upload_cursor"
)

// StatsRing collects structured stat records (see binlog.TagControlDead and
// friends) between uploads. Exported so callers elsewhere in this package
// (e.g. conn_stats.go's Snapshot) can record into it without a setter.
var StatsRing = newRingBuffer(statsRingSize)

// WriteRecord frames payload under tag and appends it directly -- for
// structured stat events that must decode on the receiving end without any
// text parsing. The only writer this ring buffer type has left; the old
// generic Write(io.Writer)/auto-tagging path was removed with LogRing (see
// LogUploader's doc comment) since nothing else used it once that ring
// buffer stopped being written to. WriteRecord itself, and Snapshot, are
// unchanged.
func (rb *ringBuffer) WriteRecord(tag binlog.Tag, payload []byte) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	framed := binlog.AppendRecord(nil, tag, payload)
	n := len(framed)
	cap := len(rb.buf)
	if n >= cap {
		copy(rb.buf, framed[n-cap:])
		rb.pos = 0
		rb.full = true
		return
	}
	end := rb.pos + n
	if end <= cap {
		copy(rb.buf[rb.pos:], framed)
	} else {
		first := cap - rb.pos
		copy(rb.buf[rb.pos:], framed[:first])
		copy(rb.buf, framed[first:])
		rb.full = true
	}
	rb.pos = end % cap
}

// Auth uses DefaultClientTelemetryKey, the one shared key across every
// client-facing telemetry endpoint (see client_telemetry_key.go).

// ringBuffer is a fixed-capacity circular byte buffer. Thread-safe;
// overwrites oldest data when full. Used only by StatsRing now -- the main
// client log is read directly from disk (see readUnuploadedLog below), not
// buffered in memory at all.
type ringBuffer struct {
	mu   sync.Mutex
	buf  []byte
	pos  int
	full bool
}

func newRingBuffer(size int) *ringBuffer {
	return &ringBuffer{buf: make([]byte, size)}
}

// Snapshot returns a linear copy of buffer contents in chronological order.
func (rb *ringBuffer) Snapshot() []byte {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	cap := len(rb.buf)
	if !rb.full {
		out := make([]byte, rb.pos)
		copy(out, rb.buf[:rb.pos])
		return out
	}
	out := make([]byte, cap)
	copy(out, rb.buf[rb.pos:])
	copy(out[cap-rb.pos:], rb.buf[:rb.pos])
	return out
}

// LogUploader periodically reads unsent content straight from the on-disk
// rotating log (LogDir, see log.go) and POSTs it to the arbiter (via
// navlink.net) over the client's own live tunnel dialer -- exactly the same
// path BananameterProber.reportToArbiter already uses.
//
// 2026-08-17: replaced the old approach of mirroring every log line into a
// separate 256KB in-memory ring buffer (LogRing) and uploading whatever
// snapshot of *that* happened to still be there every 5 minutes. Real-world
// diagnosis (a user's report, 2026-08-17) found the automatic upload
// consistently showed a much narrower, sometimes stale window than the same
// device's manually-exported "Share Logs" files covered for the exact same
// period -- the ring buffer got overwritten by ordinary chatter well before
// its 5-minute upload tick, and a missed tick (e.g. not connected) lost that
// window's content permanently since nothing tracked what had or hadn't
// been sent. Reading from disk with a persisted cursor (see
// readUnuploadedLog) fixes both: the full detail already being written to
// disk is what gets sent, and a missed or short tick just leaves the cursor
// where it is, so the backlog is picked up (and fully caught up on,
// deliberately over multiple ticks if needed -- see maxRawLogPerUpload) by
// subsequent ticks instead of being silently skipped.
//
// 2026-08-11: replaced the old path (client -> control's relay-API channel
// -> a randomly picked exit -> arbiter, see git history for logUpload in
// snc-control/relay_api.go). That path was hop-by-hop TLS only: both the
// control and the exit that happened to relay a given upload saw the full
// decompressed log content in plaintext in memory, not just the arbiter --
// found after a raw third-party OAuth token turned up in cleartext in a real user's
// uploaded logs. The fix is encrypting the *channel*, not redacting log
// content (content stays exactly as detailed as before, including for
// direct/manual log sharing, which is unaffected). Sending over the client's
// real tunnel dialer to navlink.net is indistinguishable from any other of
// the user's own tunneled HTTPS traffic -- no separate relay-API/uTLS
// fingerprint to single out, and it's genuinely end-to-end: the tunnel
// encrypts client->egress, TLS covers egress->navlink.net->arbiter, and
// neither control nor exit ever holds the plaintext.
type LogUploader struct {
	nodeID   string
	nodeType string
	stop     chan struct{}
}

// NewLogUploader creates a LogUploader for this device. nodeType is this
// client's platform ("windows"/"macos"/"linux"/"android"/"ios") -- the old
// code hardcoded "windows" here regardless of caller, silently mislabeling
// every non-Windows upload; now it's an explicit parameter.
func NewLogUploader(nodeID, nodeType string) *LogUploader {
	return &LogUploader{nodeID: nodeID, nodeType: nodeType, stop: make(chan struct{})}
}

// Start launches the background upload goroutine. Uploads once immediately,
// then every 5 minutes. Non-blocking.
//
// pickDialer returns the currently active TunnelDialer (e.g. pool.Pick()),
// or nil if not connected right now -- checked fresh on every tick, matching
// BananameterProber.Start. wildcatActive reports whether WildCat transport
// is the active mode; when true, the tick is skipped entirely and nothing is
// sent -- WildCat's bandwidth is deliberately constrained (third-party relay),
// and log uploads are not important enough to compete with it for bytes.
// Skipped ticks don't lose anything: the cursor doesn't move, so the next
// successful tick picks up exactly where the last one left off.
func (lu *LogUploader) Start(pickDialer func() *TunnelDialer, wildcatActive func() bool) {
	go func() {
		t := time.NewTicker(logUploadInterval)
		defer t.Stop()
		for {
			select {
			case <-lu.stop:
				return
			case <-t.C:
				if wildcatActive != nil && wildcatActive() {
					Log.Printf("log-upload: skipping tick, WildCat active")
					continue
				}
				dialer := pickDialer()
				if dialer == nil {
					Log.Printf("log-upload: skipping tick, not connected")
					continue
				}
				lu.upload(dialer)
			}
		}
	}()
}

// Stop shuts down the upload goroutine.
func (lu *LogUploader) Stop() { close(lu.stop) }

// UploadOnce performs a single log upload synchronously against the given
// dialer. Useful for testing.
func (lu *LogUploader) UploadOnce(dialer *TunnelDialer) { lu.upload(dialer) }

// readUnuploadedLog returns up to maxRawLogPerUpload bytes of log content
// that hasn't been uploaded yet, read directly from LogDir's rotating
// "snc_*.log" files (see log.go's InitLogging) -- not a separate in-memory
// buffer. Files are named with an embedded timestamp (mainLogPrefix +
// "2006-01-02_150405" + ".log"), so a lexical sort is a chronological sort.
//
// newFile/newOffset describe exactly how far this read reached; the caller
// must persist them via saveLogUploadCursor ONLY after a confirmed
// successful upload -- on any failure the cursor must stay where it was, so
// the same unsent content (plus whatever accumulated meanwhile) is retried
// on the next tick rather than being lost.
//
// If the persisted cursor's file no longer exists among LogDir's current
// files -- either this is the very first upload ever, or disk rotation
// already deleted the file the cursor pointed at -- this starts over from
// the oldest file still on disk. "All logs, unless disk rotation's quota
// already ate them" is exactly what that fallback gives: nothing is skipped
// that's still actually on disk.
// backlogBytes returns how many unread bytes remain across files[fromIdx:]
// starting at fromOffset within files[fromIdx] -- i.e. how far behind the
// cursor still is after this tick, in raw disk bytes. Diagnostic only (see
// upload's log line); a Stat() per remaining file is cheap next to the
// actual read/zip/POST work this function's caller already does per tick.
func backlogBytes(dir string, files []string, fromIdx int, fromOffset int64) int64 {
	var total int64
	for i := fromIdx; i < len(files); i++ {
		fi, err := os.Stat(filepath.Join(dir, files[i]))
		if err != nil {
			continue // vanished under us -- same "skip, not fatal" as the read loop
		}
		size := fi.Size()
		start := int64(0)
		if i == fromIdx {
			start = fromOffset
		}
		if start < size {
			total += size - start
		}
	}
	return total
}

func readUnuploadedLog() (data []byte, newFile string, newOffset int64, backlog int64, err error) {
	if LogDir == "" {
		return nil, "", 0, 0, nil // InitLogging never called (e.g. some test/tool binaries)
	}
	entries, err := os.ReadDir(LogDir)
	if err != nil {
		return nil, "", 0, 0, err
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, mainLogPrefix) || !strings.HasSuffix(name, ".log") {
			continue
		}
		// Exact-prefix guard: the character right after mainLogPrefix must be
		// a digit (start of the embedded timestamp), so "snc_" doesn't also
		// match the separate "snc_tun_*.log" TUN-traffic log set.
		if rest := name[len(mainLogPrefix):]; len(rest) == 0 || rest[0] < '0' || rest[0] > '9' {
			continue
		}
		files = append(files, name)
	}
	if len(files) == 0 {
		return nil, "", 0, 0, nil
	}
	sort.Strings(files)

	cursorFile, cursorOffset := loadLogUploadCursor()
	cursorFound := false
	startIdx, startOffset := 0, int64(0)
	for i, f := range files {
		if f == cursorFile {
			startIdx, startOffset, cursorFound = i, cursorOffset, true
			break
		}
	}
	Log.Printf("log-upload: cursor file=%q offset=%d found=%v (of %d files on disk, oldest=%q newest=%q)",
		cursorFile, cursorOffset, cursorFound, len(files), files[0], files[len(files)-1])

	var buf bytes.Buffer
	newFile, newOffset = cursorFile, cursorOffset
	filesTouched := 0
	for i := startIdx; i < len(files) && buf.Len() < maxRawLogPerUpload; i++ {
		offset := int64(0)
		if i == startIdx {
			offset = startOffset
		}
		f, ferr := os.Open(filepath.Join(LogDir, files[i]))
		if ferr != nil {
			continue // vanished under us (rotation/pruning) -- skip, not fatal
		}
		fi, serr := f.Stat()
		if serr != nil {
			f.Close()
			continue
		}
		size := fi.Size()
		if offset > size {
			offset = 0 // stale cursor somehow past EOF -- never read negative
		}
		if offset < size {
			if _, serr := f.Seek(offset, io.SeekStart); serr != nil {
				f.Close()
				continue
			}
			n, _ := io.CopyN(&buf, f, int64(maxRawLogPerUpload)-int64(buf.Len()))
			offset += n
			filesTouched++
		}
		f.Close()
		newFile, newOffset = files[i], offset
	}

	// newIdx: where newFile sits in files, for the backlog calc below --
	// distinct from startIdx since this tick may have advanced past it.
	newIdx := startIdx
	for i, f := range files {
		if f == newFile {
			newIdx = i
			break
		}
	}
	backlog = backlogBytes(LogDir, files, newIdx, newOffset)
	Log.Printf("log-upload: read %dB from %d file(s) this tick, cursor now file=%q offset=%d, backlog remaining=%dB across %d file(s)",
		buf.Len(), filesTouched, newFile, newOffset, backlog, len(files)-newIdx)

	return buf.Bytes(), newFile, newOffset, backlog, nil
}

func loadLogUploadCursor() (file string, offset int64) {
	raw, err := os.ReadFile(filepath.Join(LogDir, logUploadCursorFile))
	if err != nil {
		return "", 0
	}
	parts := strings.SplitN(strings.TrimSpace(string(raw)), "\n", 2)
	if len(parts) != 2 {
		return "", 0
	}
	off, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", 0
	}
	return parts[0], off
}

func saveLogUploadCursor(file string, offset int64) {
	if LogDir == "" || file == "" {
		return
	}
	content := file + "\n" + strconv.FormatInt(offset, 10)
	// Best-effort: a failed cursor save just means the next tick re-reads
	// (and re-uploads) a bit of already-sent content -- harmless duplicate
	// bytes on the server, never data loss -- so the error isn't propagated.
	_ = os.WriteFile(filepath.Join(LogDir, logUploadCursorFile), []byte(content), 0644)
}

// upload sends everything currently unsent, looping over as many chunks as
// needed within this single tick until the backlog is fully drained -- not
// one capped chunk per 5-minute tick. Per-request size is still bounded
// (see maxRawLogPerUpload) because the arbiter itself caps a request body
// at 4MB post-compression (log_store.go's nodeLogMaxLen) -- that's a real
// server-side constraint, not a pacing choice -- but nothing here paces how
// many such requests happen per tick. A backlog that took many ticks to
// build up used to take just as many ticks to drain even while connected
// and idle-quiet the whole time; sending "everything accumulated" every 5
// minutes means backlog only grows when a tick is actually skipped
// (disconnected, WildCat active), and drains in the very next tick that
// isn't, exactly as originally specified.
func (lu *LogUploader) upload(dialer *TunnelDialer) {
	for {
		sent, more := lu.uploadOneChunk(dialer)
		if !sent || !more {
			return
		}
	}
}

// uploadOneChunk sends one request's worth of unsent log (bounded by
// maxRawLogPerUpload) plus the current stats snapshot. Returns (sent, more):
// sent is true if the chunk was successfully delivered and the cursor
// advanced; more is true if there's still backlog left to send after this
// chunk, i.e. the caller should call again immediately.
func (lu *LogUploader) uploadOneChunk(dialer *TunnelDialer) (sent, more bool) {
	logData, newFile, newOffset, backlog, err := readUnuploadedLog()
	if err != nil {
		Log.Printf("log-upload: read disk log: %v", err)
		return false, false
	}
	statsSnap := StatsRing.Snapshot()
	if len(logData) == 0 && len(statsSnap) == 0 {
		return false, false
	}

	// zip, not a bare gzip stream: "log" now carries the raw disk log bytes
	// directly (no binlog framing -- the arbiter never decodes this member
	// either way, see apiLogClientUpload, and tools/decode_snc_log.py
	// already passes plain-text content through byte-for-byte when it finds
	// no framing, so this is fully compatible with existing tooling); "stats"
	// is its own small, independent member so the arbiter can extract and
	// decode just that one entry (see apiLogClientUpload) without ever
	// decompressing "log".
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	if fw, err := zw.CreateHeader(&zip.FileHeader{Name: "log", Method: zip.Deflate}); err != nil {
		Log.Printf("log-upload: zip log entry: %v", err)
		return false, false
	} else if _, err := fw.Write(logData); err != nil {
		Log.Printf("log-upload: zip log write: %v", err)
		return false, false
	}
	if fw, err := zw.CreateHeader(&zip.FileHeader{Name: "stats", Method: zip.Deflate}); err != nil {
		Log.Printf("log-upload: zip stats entry: %v", err)
		return false, false
	} else if _, err := fw.Write(statsSnap); err != nil {
		Log.Printf("log-upload: zip stats write: %v", err)
		return false, false
	}
	if err := zw.Close(); err != nil {
		Log.Printf("log-upload: zip close: %v", err)
		return false, false
	}

	// Dial through the real active tunnel, same as any of the user's own
	// traffic -- never a bypass. See BananameterProber.runOnce for the same
	// pattern and rationale.
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
				return dialer.Dial(addr)
			},
		},
	}

	req, err := http.NewRequest(http.MethodPost, logUploadArbiterURL+logUploadPath, &zipBuf)
	if err != nil {
		Log.Printf("log-upload: build request: %v", err)
		return false, false
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", "Bearer "+DefaultClientTelemetryKey)
	req.Header.Set("X-Node-ID", lu.nodeID)
	req.Header.Set("X-Node-Type", lu.nodeType)
	req.Header.Set("X-SNC-Version", Version)
	// zip1: two-member zip archive ("log" + "stats"), see above. Absence of
	// this header is how the server tells a legacy client (or bin1's bare
	// gzip stream) apart from this format; the receiving side must support
	// all of them indefinitely, since there's no way to force every
	// installed client to update at once.
	req.Header.Set("X-Log-Format", "zip1")

	resp, err := client.Do(req)
	if err != nil {
		Log.Printf("log-upload: post: %v", err)
		return false, false // cursor not advanced -- retried next tick
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		Log.Printf("log-upload: unexpected status=%d, not advancing cursor (will retry)", resp.StatusCode)
		return false, false
	}

	// Only now, with a confirmed 200, mark this content as sent. Advancing
	// the cursor before the request is known to have succeeded is exactly
	// how a transient network failure would turn into permanently lost log
	// content instead of a retry on the next tick.
	saveLogUploadCursor(newFile, newOffset)
	Log.Printf("log-upload: sent %d bytes (zip), raw_log=%dB status=%d, backlog remaining=%dB", zipBuf.Len(), len(logData), resp.StatusCode, backlog)
	return true, backlog > 0
}
