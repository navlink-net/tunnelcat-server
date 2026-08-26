<!--
The Tunnel Cat Project
Copyright (C) NavLink, 2026
Лицензировано под лицензией Apache 2.0
-->

# tunneld IPC protocol

`cmd/tunneld` is the subprocess every non-iOS SDK adapter (Python, Kotlin,
C#, Swift-on-macOS) drives. It wraps `tunnelcat-server`'s
`Authenticator`/`TunnelDialer`/`SOCKS5Server` behind a duplex,
newline-delimited JSON protocol on a local Unix domain socket. This
document is the contract — enough to write a 5th-language adapter without
reading `cmd/tunneld/main.go`.

## Transport

- Unix domain socket at a path you choose, passed via `tunneld -socket <path>`.
- Works identically on Linux, macOS, and Windows — Go's `net.Listen("unix",
  ...)` is natively supported on Windows 10 1803+ via `AF_UNIX`, so no
  separate named-pipe implementation exists or is needed.
- One `tunneld` process serves one tunnel session. Spawn a new process
  (with a new socket path) per session.
- Framing: one JSON object per line (`\n`-terminated), both directions.

## Requests

```json
{"id": <int>, "method": "<name>", "params": {...}}
```

`id` must be a positive integer you choose (increment per request); it's
echoed back in the matching response so you can correlate replies even if
multiple requests are in flight. `params` is omitted for methods that take
none.

## Responses

```json
{"id": <int>, "result": {...}}
{"id": <int>, "error": "<message>"}
```

Exactly one of `result`/`error` is present.

## Methods

### `connect`

```json
{"server": "https://control:443", "apikey": "", "username": "", "password": "", "socksAddr": "127.0.0.1:0", "pollingOnly": false}
```

Logs in (`Authenticator.Login()`) and starts a local SOCKS5 listener.
`socksAddr` may be `"127.0.0.1:0"` (or omitted) to let the OS pick a port —
read the actual bound address back from the result. `pollingOnly: true`
selects `NewTunnelDialerPolling` instead of the default streaming
`NewTunnelDialer` — required against `cmd/mockserver`, since it only
implements the polling side of the wire protocol (see `docs/PROTOCOL.md`).

Result: `{"connected": true, "socksAddr": "127.0.0.1:54321", "state": "connected"}`

### `disconnect`

No params. Tears down the SOCKS5 listener. Result: `{"ok": true}`.

### `status`

No params. Result: `{"connected": bool, "socksAddr": "...", "uptimeSec": int, "state": "..."}`.

### `reconnect`

No params. Re-runs `Login()` against the same credentials passed to the
last `connect`. Errors if not currently connected.

## Events (unsolicited, pushed on every open connection)

```json
{"event": "state", "state": "connecting"|"connected"|"disconnected"|"error", "error": "<message, only when state is error>"}
```

Pushed immediately when state changes, rather than requiring the client to
poll a status endpoint. A client that only cares about request/response
semantics can safely ignore lines containing an `"event"` key.

## Example session (see `cmd/tunneld`'s own test client pattern)

```
→ {"id":1,"method":"connect","params":{"server":"http://127.0.0.1:8443","apikey":"x","username":"u","password":"p","socksAddr":"127.0.0.1:1080","pollingOnly":true}}
← {"event":"state","state":"connecting"}
← {"event":"state","state":"connected"}
← {"id":1,"result":{"connected":true,"socksAddr":"127.0.0.1:1080","state":"connected"}}
→ {"id":2,"method":"status"}
← {"id":2,"result":{"connected":true,"socksAddr":"127.0.0.1:1080","state":"connected"}}
→ {"id":3,"method":"disconnect"}
← {"event":"state","state":"disconnected"}
← {"id":3,"result":{"ok":true}}
```
