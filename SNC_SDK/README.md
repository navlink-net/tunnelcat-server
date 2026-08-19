<!--
Copyright (C) Konstantin Khait & Claude Code
For IT Partners Solutions and Freedom and Rights
2026
-->

# tunnelcat-sdk

Build your own client on top of
[tunnelcat-core](https://github.com/kostiakhait/tunnelcat-core): language
adapters (Python, Kotlin, C#, Swift) that spawn a small local daemon and
drive it over JSON-RPC, plus a mock control/exit server so you can develop
and test without any real credentials or network access.

## Try it in 30 seconds

```sh
go build -o tunneld ./cmd/tunneld
go run ./cmd/mockserver &

cd sdk/csharp/examples/Basic && dotnet run
```

This logs in (against the mock — no real credentials needed), opens a local
SOCKS5 proxy, checks its status, and disconnects — the same
connect→status→disconnect flow every adapter follows. Swap `sdk/csharp` for
`sdk/python` or `sdk/kotlin`'s example once you have the matching toolchain
(see `docs/sdk/<language>.md`).

## Layout

- **`cmd/tunneld`** — the subprocess every non-iOS adapter drives: wraps
  tunnelcat-core's `Authenticator`/`TunnelDialer`/`SOCKS5Server` behind a
  duplex JSON-RPC protocol over a local Unix domain socket. See
  [`docs/IPC.md`](docs/IPC.md).
- **`cmd/mockserver`** — a local mock control/exit implementing just enough
  of tunnelcat-core's wire protocol (see [`docs/PROTOCOL.md`](docs/PROTOCOL.md))
  to test connect/disconnect/data-relay with zero real credentials.
- **`cmd/lib-ios`** — iOS-only cgo `c-archive` export (iOS forbids
  subprocesses, so this is linked directly into an app/extension instead of
  spawned).
- **`sdk/python`**, **`sdk/kotlin`**, **`sdk/csharp`** — thin `tunneld`
  clients (subprocess + Unix socket JSON-RPC).
- **`sdk/swift/macOS`** — same shape as the above three.
  **`sdk/swift/ios`** — links `cmd/lib-ios` directly instead.
- **`docs/`** — [`PROTOCOL.md`](docs/PROTOCOL.md) (the wire format, for
  anyone building a compatible server or a client in an unlisted language),
  [`IPC.md`](docs/IPC.md) (`tunneld`'s own contract), and one quickstart per
  language under `docs/sdk/`.

## Status

Connect/status/disconnect/reconnect verified end-to-end through
`cmd/tunneld` + `cmd/mockserver` for the Go test client and the C# adapter
(the example above). Python, Kotlin, and Swift adapters are implemented
against the same protocol but were not live-tested on this development
machine (no working `AF_UNIX` in the available Python builds; no
Kotlin/Swift toolchain installed) — see each `docs/sdk/*.md` for specifics.

## License

MIT, matching tunnelcat-core — see [LICENSE](LICENSE).
