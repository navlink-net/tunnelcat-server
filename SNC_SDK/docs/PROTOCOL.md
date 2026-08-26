<!--
The Tunnel Cat Project
Copyright (C) NavLink, 2026
Лицензировано под лицензией Apache 2.0
-->

# tunnelcat-server wire protocol

This document describes the HTTP wire protocol `Authenticator`/`TunnelDialer`
in [tunnelcat-server](https://github.com/navlink-net/tunnelcat-server) speak,
so a third party can implement a compatible control/exit server (or a
client in a language with no SDK adapter) without reading Go source.
[`cmd/mockserver`](../cmd/mockserver) is a minimal reference implementation
of everything described here.

## Login

`POST <server>/` with `Content-Type: application/json`.

**Password auth** (`Authenticator.Login()` when constructed with a
username/password):

```json
{".command": "verifyPassword", "path": "users", "user": "<username>", "password": "<password>", "key": "<apikey>"}
```

Optional fields (all omitted if empty): `key_id`, `device_id`, `device_name`.

**Key auth** (`SetKeyAuthParams` + non-empty `AuthSig`):

```json
{".command": "authenticateKey", "username": "...", "node_id": "...", "auth_sig": "...", "servers": [...], "control_nodes": [...], "arbiter_pubkey": "...", "api_key": "...", "client_id": "...", "key_id": "...", "device_id": "...", "device_name": "..."}
```

Login tries both methods in parallel if both are configured; whichever
succeeds first wins.

**Response** (either method), HTTP 200:

```json
{"session": "<opaque session token>"}
```

Any other status code, or a 200 with no `session` field, is treated as a
rejected login (`core.ErrAuthRejected`).

## Data plane

Every subsequent request carries the session token in an `X-Session` header
and POSTs to one of two decoy paths, chosen at random per request to vary
the apparent endpoint:

- `/api/media/upload`
- `/api/content/submit`

The request/response body is an encrypted **frame**:

```
[12B nonce][ChaCha20-Poly1305(plaintext) + 16B tag]
```

keyed by `BLAKE2b-256(session token)` — see the exported
`core.SessionKey`/`core.SealFrame`/`core.OpenFrame` helpers.

### Upload frame (polling mode — `NewTunnelDialerPolling`)

Plaintext request body, tag byte `0x00`:

```
[1B 0x00][16B conn_id][4B seq_be][2B target_len_be][target][payload]
```

- `conn_id`: 16 raw bytes (client-generated, hex-encoded when passed to
  `ParseUploadFrame`), identifies one logical connection across requests.
- `seq`: 0 on the first request for a `conn_id` (server should dial `target`
  fresh), non-zero on subsequent requests for the same connection.
- `target`: `host:port` to dial (only meaningful when `seq == 0`).
- `payload`: bytes to write to the connection (may be empty, e.g. a
  keep-alive poll).

Response plaintext (still frame-encrypted the same way), padded to at least
512 bytes:

```
[4B data_len_be][data][random padding]
```

`data` is whatever bytes the target connection produced since the last poll
(server-side, a short read window — `core.BuildUploadResponse` in the mock
implementation uses ~200ms).

### Stream-open frame (default streaming mode — `NewTunnelDialer`)

Plaintext, tag byte `0x01`: `[1B 0x01][16B conn_id]`. The server should
respond with a persistent chunked/streamed body carrying frame-encrypted
data as it arrives (`core`'s client-side reader is `newFramedDecryptReader`).
**`cmd/mockserver` does not implement this mode** — it returns 404 for
stream-open frames, which is why the mock server and SDK examples all pass
`pollingOnly: true`. A production control/exit server should implement
streaming for efficiency; polling is the simpler/legacy fallback.

## Manifest/discovery signing

Separately from the login/data-plane protocol above, `discovery.go`/
`bypass.go`/`mirror.go` verify arbiter-signed manifest data using
`core.VerifySignedPayload(payload, pubkeyHex, sigB64)` — plain Ed25519
verification, no fixed canonical payload shape is mandated by `core` itself
(callers define their own signed structure).
