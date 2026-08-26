// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package core

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"tunnel_cat/binlog"
	"tunnel_cat/logevent"
)

// ChanDepth controls the depth of each TunnelConn's dataChan buffer.
// Android sets this proportionally to available RAM via SNC_DATACHAN_DEPTH.
var ChanDepth = 64

// chunkPool reuses 65536-byte backing arrays to reduce GC pressure on the
// stream-read hot path. Producer gets a buffer, slices to actual read length,
// sends the slice; consumer returns the full-capacity slice after draining.
var chunkPool = sync.Pool{New: func() any { return make([]byte, 65536) }}

// TunnelConn is a net.Conn whose Read/Write go through the HTTP tunnel.
// Callers use it like a regular TCP connection.
//
// Two read modes are supported:
//   - Streaming (streamFn != nil): a background goroutine holds an open HTTP
//     response and pushes received bytes into dataChan.  Read() blocks on the
//     channel — no polling, minimal latency.
//   - Polling (streamFn == nil): legacy mode; Read() sends empty POSTs to
//     fetch buffered data from the server.
type TunnelConn struct {
	connID  string
	seq     atomic.Int64
	readBuf []byte
	readMu  sync.Mutex

	// send(seq, payload) POSTs browser→target data and returns target→browser
	// bytes (empty in streaming mode; the response contains only padding).
	send func(seq int64, payload []byte) ([]byte, error)

	// streamFn opens a long-lived streaming POST and returns its response body.
	// Nil in legacy polling mode.  ctx is the TunnelConn's lifetime context;
	// canceling it (via Close) aborts the in-flight HTTP request immediately.
	streamFn func(context.Context) (io.ReadCloser, error)

	// dataChan carries target→browser chunks from the streaming goroutine.
	// Closed when the goroutine gives up permanently.
	dataChan chan []byte

	// onStreamDead, if non-nil, is called once when the stream loop gives up
	// permanently (consecutive open errors or repeated short-lived streams).
	// Used to escalate to the TunnelDialer's data-fail counter.
	onStreamDead func()

	// renewStream, if non-nil, is called when flaps or open errors exhaust their
	// retry budget.  It should return a replacement streamFn and true to continue,
	// or nil/false to give up permanently.  Each call counts as one renewal;
	// the implementation limits total renewals per connection.
	renewStream func() (func(context.Context) (io.ReadCloser, error), bool)

	onClose func() // called once on Close; used by TunnelDialer to track open conns

	once   sync.Once
	closed chan struct{}
	ctx    context.Context
	cancel context.CancelFunc

	localAddr  net.Addr
	remoteAddr net.Addr

	// Pipeline write: up to pipeSem capacity sends are in-flight simultaneously.
	// nil means sync mode (one send at a time, blocking).  Only valid in streaming
	// mode; polling mode sends carry inline response data so must stay sync.
	pipeSem chan struct{}
	pipeErr atomic.Pointer[error] // first error from any pipeline goroutine
}

// newConnID generates a random 16-byte conn-id encoded as a 32-char hex string.
func newConnID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// newTunnelConn constructs a TunnelConn.
//
// connID must be the same ID used in the send closure's HTTP headers.
// streamFn may be nil to use legacy polling mode.
// pipeWidth > 0 enables pipeline mode (that many concurrent in-flight sends).
// Pipeline must not be used in polling mode because poll sends carry inline response data.
func newTunnelConn(
	connID string,
	send func(seq int64, payload []byte) ([]byte, error),
	streamFn func(context.Context) (io.ReadCloser, error),
	pipeWidth int,
) *TunnelConn {
	ctx, cancel := context.WithCancel(context.Background())
	c := &TunnelConn{
		connID:     connID,
		send:       send,
		streamFn:   streamFn,
		closed:     make(chan struct{}),
		ctx:        ctx,
		cancel:     cancel,
		localAddr:  &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)},
		remoteAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)},
	}
	if streamFn != nil {
		c.dataChan = make(chan []byte, ChanDepth)
	}
	if pipeWidth > 0 && streamFn != nil {
		c.pipeSem = make(chan struct{}, pipeWidth)
	}
	return c
}

// ConnID returns the unique ID for this tunnel connection.
func (c *TunnelConn) ConnID() string { return c.connID }

// NextSeq atomically returns and increments the sequence counter.
func (c *TunnelConn) NextSeq() int64 { return c.seq.Add(1) - 1 }

// Write sends payload through the tunnel and buffers any returned data.
func (c *TunnelConn) Write(p []byte) (int, error) {
	if ep := c.pipeErr.Load(); ep != nil {
		return 0, *ep
	}
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}

	if c.pipeSem != nil {
		// Pipeline mode: acquire a send slot, copy payload, fire async send.
		// seq is assigned here (atomically) to preserve ordering before launch.
		select {
		case c.pipeSem <- struct{}{}:
		case <-c.closed:
			return 0, net.ErrClosed
		}
		if ep := c.pipeErr.Load(); ep != nil {
			<-c.pipeSem
			return 0, *ep
		}
		seq := c.NextSeq()
		data := make([]byte, len(p))
		copy(data, p)
		Log.Printf("tunnel-conn %s: Write seq=%d payload=%dB (pipeline)", c.connID, seq, len(data))
		go func() {
			defer func() { <-c.pipeSem }()
			_, err := c.send(seq, data)
			if err != nil {
				Log.Printf("tunnel-conn %s: pipeline send seq=%d error: %v", c.connID, seq, err)
				c.pipeErr.CompareAndSwap(nil, &err)
			}
		}()
		return len(p), nil
	}

	// Sync mode (polling, or streaming with pipeline disabled).
	seq := c.NextSeq()
	Log.Printf("tunnel-conn %s: Write seq=%d payload=%dB", c.connID, seq, len(p))
	resp, err := c.send(seq, p)
	if err != nil {
		Log.Printf("tunnel-conn %s: Write seq=%d error: %v", c.connID, seq, err)
		return 0, err
	}
	if len(resp) > 0 {
		Log.Printf("tunnel-conn %s: Write seq=%d got inline resp=%dB", c.connID, seq, len(resp))
		c.readMu.Lock()
		c.readBuf = append(c.readBuf, resp...)
		c.readMu.Unlock()
	}
	return len(p), nil
}

// Read returns data received from the tunnel target.
//
// In streaming mode the call blocks on dataChan, which is fed by the
// background goroutine; no polling requests are sent.
// In legacy polling mode it sends empty POSTs until data arrives.
// pollBackoffStart/pollBackoffMax bound the delay between consecutive empty
// polls in TunnelConn.Read's legacy polling mode (see the loop below). The
// endpoint polling hits replies instantly to an empty poll (a fixed-size
// padding ACK, no server-side long-poll -- unlike /api/udp/drain, which
// does long-poll server-side and needs no client-side pacing of its own),
// so without a client-side delay here nothing bounds the loop's rate.
// Confirmed in the wild, 2026-08-16: a client on a network that blocked UDP
// holepunch entirely (every hole-punch attempt to every control failed)
// fell back to this path for its UDP relay traffic and spun at ~190
// requests/sec sustained for 2+ hours. Exponential backoff keeps the common
// case (data arrives within the first poll or two) fast while capping the
// cost of a genuinely idle connection; resets to pollBackoffStart the
// moment any poll returns data.
const (
	pollBackoffStart = 20 * time.Millisecond
	pollBackoffMax   = 500 * time.Millisecond
)

func (c *TunnelConn) Read(p []byte) (int, error) {
	// Drain any locally buffered bytes first (both modes).
	c.readMu.Lock()
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		c.readMu.Unlock()
		return n, nil
	}
	c.readMu.Unlock()

	// ── Streaming mode ────────────────────────────────────────────────────────
	if c.dataChan != nil {
		select {
		case <-c.closed:
			return 0, net.ErrClosed
		case chunk, ok := <-c.dataChan:
			if !ok {
				return 0, net.ErrClosed // stream goroutine gave up
			}
			n := copy(p, chunk)
			if n < len(chunk) {
				c.readMu.Lock()
				c.readBuf = append(c.readBuf, chunk[n:]...)
				c.readMu.Unlock()
			}
			chunkPool.Put(chunk[:cap(chunk)])
			Log.Printf("tunnel-conn %s: Read streaming %dB", c.connID, n)
			return n, nil
		}
	}

	// ── Legacy polling mode ───────────────────────────────────────────────────
	pollCount := 0
	backoff := pollBackoffStart
	for {
		select {
		case <-c.closed:
			return 0, net.ErrClosed
		default:
		}

		seq := c.NextSeq()
		if pollCount == 0 {
			Log.Printf("tunnel-conn %s: Read buffer empty, polling (seq=%d)", c.connID, seq)
		}
		resp, err := c.send(seq, nil)
		if err != nil {
			Log.Printf("tunnel-conn %s: Read poll seq=%d error after %d polls: %v", c.connID, seq, pollCount, err)
			select {
			case <-c.closed:
				return 0, net.ErrClosed
			case <-time.After(2 * time.Second):
			}
			return 0, err
		}
		if len(resp) > 0 {
			Log.Printf("tunnel-conn %s: Read poll seq=%d got %dB after %d empty polls", c.connID, seq, len(resp), pollCount)
			n := copy(p, resp)
			if n < len(resp) {
				c.readMu.Lock()
				c.readBuf = append(c.readBuf, resp[n:]...)
				c.readMu.Unlock()
			}
			return n, nil
		}
		pollCount++
		select {
		case <-c.closed:
			return 0, net.ErrClosed
		case <-time.After(backoff):
		}
		if backoff < pollBackoffMax {
			backoff *= 2
			if backoff > pollBackoffMax {
				backoff = pollBackoffMax
			}
		}
	}
}

// startStreamLoop launches the background goroutine that continuously opens
// streaming POSTs and feeds received bytes into dataChan.
// Must be called once after the initial connection is established.
const (
	streamMinLifetime   = 1 * time.Second // streams shorter than this count as flaps
	streamMaxFlaps      = 5               // consecutive flaps before giving up
	streamMaxOpenErrors = 5               // consecutive open errors before giving up
)

// No-op when streamFn is nil (legacy polling mode).
func (c *TunnelConn) startStreamLoop() {
	if c.streamFn == nil {
		return
	}
	go func() {
		defer close(c.dataChan)

		openErrors := 0 // consecutive stream-open failures
		flaps := 0      // consecutive streams that lived < streamMinLifetime
		buf := make([]byte, 65536)
		streamFn := c.streamFn // local copy; replaced on successful renewal

		// tryRenew attempts to get a fresh streamFn from the renewal callback.
		// Returns true if the loop should continue with the new function.
		tryRenew := func(reason string) bool {
			if c.renewStream == nil {
				return false
			}
			newFn, ok := c.renewStream()
			if !ok || newFn == nil {
				return false
			}
			logevent.Emit(binlog.TagTunnel, logevent.EventSessionStreamRenewed,
				logevent.Str(logevent.AttrConnId, c.connID),
				logevent.Str(logevent.AttrReason, reason))
			streamFn = newFn
			openErrors = 0
			flaps = 0
			return true
		}

		// controlFailure distinguishes "the control/exit path is broken" (counts
		// toward the dialer's data-fail threshold, can evict a healthy control)
		// from "the remote target closed normally" (expected app-layer event,
		// must not be mistaken for a control failure).
		giveUp := func(reason string, controlFailure bool) {
			logevent.Emit(binlog.TagTunnel, logevent.EventSessionStreamGiveup,
				logevent.Str(logevent.AttrConnId, c.connID),
				logevent.Str(logevent.AttrReason, reason))
			if controlFailure && c.onStreamDead != nil {
				c.onStreamDead()
			}
		}

		for {
			select {
			case <-c.closed:
				return // clean shutdown — do NOT fire onStreamDead
			default:
			}

			body, err := streamFn(c.ctx)
			if err != nil {
				// 404 from the exit means the exit already closed the connection
				// (targetClosed=true in the exit pool).  Retrying 15 times over 30s
				// only delays teardown — give up immediately so the caller can open a
				// fresh upload and start a new connection.
				if he, ok := err.(*streamHTTPError); ok && he.status == 404 {
					logevent.Emit(binlog.TagTunnel, logevent.EventSessionStreamGiveup404,
						logevent.Str(logevent.AttrConnId, c.connID),
						logevent.Str(logevent.AttrCloseReason, he.closeReason))
					// The exit explicitly reported targetClosed or not-found —
					// this is an app-layer outcome, not evidence the control/exit
					// path is broken, so it must not count toward data-fail eviction.
					giveUp("exit returned 404 on stream open", false)
					return
				}
				openErrors++
				flaps = 0
				logevent.Emit(binlog.TagTunnel, logevent.EventSessionStreamOpenError,
					logevent.Str(logevent.AttrConnId, c.connID),
					logevent.Int(logevent.AttrAttempt, int64(openErrors)),
					logevent.Str("err", err.Error()))
				if openErrors >= streamMaxOpenErrors {
					if tryRenew(fmt.Sprintf("%d consecutive open errors", openErrors)) {
						continue
					}
					giveUp(fmt.Sprintf("%d consecutive open errors", openErrors), true)
					return
				}
				delay := time.Duration(openErrors) * 200 * time.Millisecond
				select {
				case <-c.closed:
					return
				case <-time.After(delay):
				}
				continue
			}
			openErrors = 0
			opened := time.Now()
			logevent.Emit(binlog.TagTunnel, logevent.EventSessionStreamOpened,
				logevent.Str(logevent.AttrConnId, c.connID))

			var readErr error
			for {
				n, err := body.Read(buf)
				if n > 0 {
					b := chunkPool.Get().([]byte)
					chunk := b[:n]
					copy(chunk, buf[:n])
					select {
					case c.dataChan <- chunk:
					case <-c.closed:
						chunkPool.Put(b[:cap(b)])
						body.Close()
						return // clean shutdown — do NOT fire onStreamDead
					}
				}
				if err != nil {
					readErr = err
					break
				}
			}
			body.Close()

			// A stream that died immediately is a flap — add backoff and count
			// toward give-up. But only when it actually died: io.EOF here means
			// the exit closed the body after cleanly delivering everything it
			// had (e.g. a fast request/response against a quick destination —
			// confirmed live 2026-08-21, sub-second io.EOF closes against
			// Google CDN IPs were being flap-counted identically to a real
			// broken connection, which cascaded into unwarranted control
			// eviction and reauth). A genuine failure (reset, timeout,
			// anything but a clean EOF) still counts exactly as before.
			if readErr != nil && readErr != io.EOF && time.Since(opened) < streamMinLifetime {
				flaps++
				logevent.Emit(binlog.TagTunnel, logevent.EventSessionStreamFlapped,
					logevent.Str(logevent.AttrConnId, c.connID),
					logevent.Int(logevent.AttrCount, int64(flaps)),
					logevent.Int(logevent.AttrMax, int64(streamMaxFlaps)))
				if flaps >= streamMaxFlaps {
					if tryRenew(fmt.Sprintf("%d consecutive flaps", flaps)) {
						continue
					}
					giveUp(fmt.Sprintf("%d consecutive flaps", flaps), true)
					return
				}
				delay := time.Duration(flaps) * 500 * time.Millisecond
				select {
				case <-c.closed:
					return
				case <-time.After(delay):
				}
			} else {
				flaps = 0
				logevent.Emit(binlog.TagTunnel, logevent.EventSessionStreamClosedReopening,
					logevent.Str(logevent.AttrConnId, c.connID))
			}
		}
	}()
}

// Close sends a final empty request to let the server know, then closes.
func (c *TunnelConn) Close() error {
	c.once.Do(func() {
		c.cancel() // abort any in-flight stream HTTP request immediately
		close(c.closed)
		// best-effort final notification to server
		_, _ = c.send(c.NextSeq(), nil)
		TunnelMonitor.Forget(c.connID) // stop influencing IsStuck once this connection is done
		if c.onClose != nil {
			c.onClose()
		}
	})
	return nil
}

func (c *TunnelConn) LocalAddr() net.Addr                { return c.localAddr }
func (c *TunnelConn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c *TunnelConn) SetDeadline(_ time.Time) error      { return nil }
func (c *TunnelConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *TunnelConn) SetWriteDeadline(_ time.Time) error { return nil }
