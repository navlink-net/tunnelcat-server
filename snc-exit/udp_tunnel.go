// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

package main

// udp_tunnel.go — UDP SNCU exit handler.
//
// Receives SNCU frames from snc-control nodes and handles frameTypeUpload
// exactly like the TCP handleTunnel path, except:
//
//   - Each request/response is one datagram (no long-lived streaming).
//   - After writing the upload payload, a short bounded read is done on the
//     target socket so that any immediately available data can be piggybacked
//     in the upload ACK.  The polling TunnelDialer (used by NewUDPRelayDialer)
//     sends empty-payload upload frames as Read polls; they are served the same
//     way — bounded read, data in ACK.
//
// Wire format is identical to snc-control/udp_tunnel.go and
// win-client/core/udp_relay.go (magic=0x534E4355, SNCU).

import (
	"encoding/binary"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	udpExitMagic        = uint32(0x534E4355) // 'SNCU'
	udpExitTypeRequest  = byte(0x01)
	udpExitTypeResponse = byte(0x02)
	udpExitMaxFrame     = 65536
	udpExitReadTimeout  = 50 * time.Millisecond
)

type udpExitHandler struct {
	conn    *net.UDPConn
	h       *handler
	readMus sync.Map // connID → *sync.Mutex; serialises concurrent sock.Read per conn
}

func newUDPExitHandler(conn *net.UDPConn, h *handler) *udpExitHandler {
	return &udpExitHandler{conn: conn, h: h}
}

func (u *udpExitHandler) serve() {
	buf := make([]byte, udpExitMaxFrame)
	for {
		n, src, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			logWarnf("udp-exit: read: %v", err)
			return
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		go u.handle(src, data)
	}
}

func (u *udpExitHandler) handle(src *net.UDPAddr, data []byte) {
	if len(data) < 9 || binary.BigEndian.Uint32(data) != udpExitMagic {
		return
	}
	if data[8] != udpExitTypeRequest {
		return
	}
	reqID := binary.BigEndian.Uint32(data[4:])
	path, token, body, ok := udpExitDecodeRequest(data)
	if !ok {
		logDebugf("udp-exit: malformed frame from %s", src)
		return
	}
	logDebugf("udp-exit: req from %s reqID=%d path=%s bodyLen=%d", src, reqID, path, len(body))

	if !tunnelPaths[path] {
		logWarnf("udp-exit: unknown path %q from %s", path, src)
		u.sendResponse(src, reqID, 404, nil)
		return
	}

	username, _, denied, transient := u.h.auth.validateSession(token)
	if denied {
		logWarnf("udp-exit: denied token=%.8s… from %s", token, src)
		u.sendResponse(src, reqID, 404, nil)
		return
	}
	if transient {
		u.sendResponse(src, reqID, 503, nil)
		return
	}
	key := sessionKey(token)
	plain, err := openTunnelFrame(key, body)
	if err != nil {
		logWarnf("udp-exit: decrypt fail user=%s: %v", username, err)
		u.sendResponse(src, reqID, 404, nil)
		return
	}

	// /api/udp/relay carries the SOCKS5 UDP-ASSOCIATE relay frame format
	// (parseUDPRelayFrame: connID+family+ip+port+payload), not the generic
	// upload-frame format (parseUploadFrame: connID+seq+target-string+payload)
	// the rest of this handler uses for the main tunnel channel. Parsing a
	// udp-relay frame as a generic upload frame fails essentially every time,
	// so every /api/udp/relay request that ever took this SNCU/UDP fallback
	// transport (used when TCP is DPI-blocked) 404'd regardless of session
	// validity -- confirmed 2026-08-17 on a real control node. The TCP/HTTP
	// path (handler.serveUDPRelay) was never affected; this mirrors its logic.
	if path == "/api/udp/relay" {
		u.handleUDPRelay(src, reqID, key, plain, username)
		return
	}

	if len(plain) < 1 {
		u.sendResponse(src, reqID, 404, nil)
		return
	}
	if plain[0] != frameTypeUpload {
		// frameTypeStreamOpen is not used in polling mode (NewUDPRelayDialer).
		logWarnf("udp-exit: unexpected frame type 0x%02x from %s", plain[0], src)
		u.sendResponse(src, reqID, 404, nil)
		return
	}

	connID, seq, target, payload, err := parseUploadFrame(plain)
	if err != nil {
		logWarnf("udp-exit: bad upload frame from %s: %v", src, err)
		u.sendResponse(src, reqID, 404, nil)
		return
	}
	logDebugf("udp-exit: upload conn=%.8s seq=%d user=%s payload=%d", connID, seq, username, len(payload))

	var sock net.Conn
	if seq == 0 {
		targetHost, portStr, err := net.SplitHostPort(target)
		if err != nil {
			u.sendResponse(src, reqID, 404, nil)
			return
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			u.sendResponse(src, reqID, 404, nil)
			return
		}
		if u.h.selfIPs[targetHost] {
			logWarnf("udp-exit: routing loop target=%s — rejecting", target)
			u.sendResponse(src, reqID, 404, nil)
			return
		}
		if ip := net.ParseIP(targetHost); ip != nil && (ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
			logWarnf("udp-exit: non-routable target=%s — rejecting", target)
			u.sendResponse(src, reqID, 404, nil)
			return
		}
		if u.h.bl != nil && u.h.bl.IsBlacklisted(targetHost) {
			logInfof("udp-exit: blacklist blocked user=%s target=%s", username, target)
			u.sendResponse(src, reqID, 404, nil)
			return
		}
		conn, err := u.h.pool.getOrCreate(connID, targetHost, port, username)
		if err != nil {
			logErrorf("udp-exit: connect failed user=%s target=%s: %v", username, target, err)
			u.sendResponse(src, reqID, 404, nil)
			return
		}
		logInfof("udp-exit: connect user=%s conn=%.8s target=%s", username, connID, target)
		sock = conn
	} else {
		sock = u.h.pool.get(connID)
		if sock == nil {
			u.sendResponse(src, reqID, 404, nil)
			return
		}
	}

	if len(payload) > 0 {
		if _, err := sock.Write(payload); err != nil {
			logWarnf("udp-exit: send failed conn=%.8s user=%s: %v", connID, username, err)
			u.h.pool.close(connID)
			u.sendResponse(src, reqID, 404, nil)
			return
		}
		u.h.pool.addBytesUp(connID, int64(len(payload)))
	}
	u.h.pool.recordActivity(connID)

	// For write frames (payload present), return an empty ACK immediately.
	// Data flows back exclusively via poll frames (empty payload, seq > 0) so
	// that the client's concurrent Read goroutine always picks it up — avoiding
	// a race where inline data lands in readBuf but the polling loop never rechecks it.
	var readData []byte
	if len(payload) == 0 && seq > 0 {
		// Poll frame: do a bounded read and return whatever is available.
		// Only one goroutine reads from sock at a time.
		actual, _ := u.readMus.LoadOrStore(connID, &sync.Mutex{})
		readMu := actual.(*sync.Mutex)
		if readMu.TryLock() {
			var rbuf [32 * 1024]byte
			sock.SetReadDeadline(time.Now().Add(udpExitReadTimeout)) //nolint:errcheck
			n, _ := sock.Read(rbuf[:])
			sock.SetReadDeadline(time.Time{}) //nolint:errcheck
			readMu.Unlock()
			if n > 0 {
				readData = make([]byte, n)
				copy(readData, rbuf[:n])
				u.h.pool.recordActivity(connID)
			}
		}
	}

	resp, err := buildUploadResponse(key, readData)
	if err != nil {
		u.sendResponse(src, reqID, 500, nil)
		return
	}
	u.sendResponse(src, reqID, 200, resp)
}

// handleUDPRelay is the SNCU/UDP fallback-transport counterpart to
// handler.serveUDPRelay's TCP/HTTP implementation -- same frame format
// (parseUDPRelayFrame), same session pool (h.udpPool), same response
// encoding, just carried over one-datagram-per-request/response instead of
// a persistent HTTP connection. See the comment at its call site in handle
// for why this needed its own path instead of falling through to the
// generic upload-frame branch.
func (u *udpExitHandler) handleUDPRelay(src *net.UDPAddr, reqID uint32, key, plain []byte, username string) {
	connID, dst, payload, err := parseUDPRelayFrame(plain)
	if err != nil {
		logWarnf("udp-exit: bad udp-relay frame user=%s: %v", username, err)
		u.sendResponse(src, reqID, 404, nil)
		return
	}
	if u.h.selfIPs[dst.IP.String()] {
		logWarnf("udp-exit: udp-relay routing loop dst=%s user=%s", dst, username)
		u.sendResponse(src, reqID, 404, nil)
		return
	}

	poolKey := udpSessionKey{connID: connID, dst: dst.String()}
	sess, err := u.h.udpPool.getOrCreate(poolKey, dst, username)
	if err != nil {
		logWarnf("udp-exit: udp-relay dial failed user=%s dst=%s: %v", username, dst, err)
		u.sendResponse(src, reqID, 404, nil)
		return
	}

	if len(payload) > 0 {
		sess.conn.SetWriteDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
		if _, err := sess.conn.Write(payload); err != nil {
			logWarnf("udp-exit: udp-relay write failed user=%s dst=%s: %v", username, dst, err)
			u.h.udpPool.close(poolKey)
			u.sendResponse(src, reqID, 404, nil)
			return
		}
	}

	frames := sess.DrainRecv(100*time.Millisecond, 32)
	u.h.udpPool.recordActivity(poolKey)

	batch := encodeDatagramBatch(frames)
	resp, err := buildUploadResponse(key, batch)
	if err != nil {
		u.sendResponse(src, reqID, 500, nil)
		return
	}
	logDebugf("udp-exit: udp-relay user=%s conn=%.8s dst=%s payload=%d frames=%d", username, connID, dst, len(payload), len(frames))
	u.sendResponse(src, reqID, 200, resp)
}

func (u *udpExitHandler) sendResponse(dst *net.UDPAddr, reqID uint32, status int, body []byte) {
	frame := udpExitEncodeResponse(reqID, status, body)
	if _, err := u.conn.WriteToUDP(frame, dst); err != nil {
		logDebugf("udp-exit: write to %s: %v", dst, err)
	}
}

// ── Frame codec (wire format shared with snc-control/udp_tunnel.go) ────────────

func udpExitDecodeRequest(data []byte) (path, token string, body []byte, ok bool) {
	if len(data) < 9+2+2+4 {
		return
	}
	o := 9
	pLen := int(binary.BigEndian.Uint16(data[o:]))
	o += 2
	if o+pLen+2 > len(data) {
		return
	}
	path = string(data[o : o+pLen])
	o += pLen
	tLen := int(binary.BigEndian.Uint16(data[o:]))
	o += 2
	if o+tLen+4 > len(data) {
		return
	}
	token = string(data[o : o+tLen])
	o += tLen
	bLen := int(binary.BigEndian.Uint32(data[o:]))
	o += 4
	if o+bLen > len(data) {
		return
	}
	body = data[o : o+bLen]
	ok = true
	return
}

func udpExitEncodeResponse(reqID uint32, status int, body []byte) []byte {
	buf := make([]byte, 4+4+1+2+4+len(body))
	o := 0
	binary.BigEndian.PutUint32(buf[o:], udpExitMagic)
	o += 4
	binary.BigEndian.PutUint32(buf[o:], reqID)
	o += 4
	buf[o] = udpExitTypeResponse
	o++
	binary.BigEndian.PutUint16(buf[o:], uint16(status))
	o += 2
	binary.BigEndian.PutUint32(buf[o:], uint32(len(body)))
	o += 4
	copy(buf[o:], body)
	return buf
}
