<!--
The Tunnel Cat Project
Copyright (C) NavLink, 2026
Лицензировано под лицензией Apache 2.0
-->

# Swift SDK quickstart

Two different mechanisms, since iOS and macOS have fundamentally different
constraints (not a single shared design — see `sdk/swift/macOS/` and
`sdk/swift/ios/` for why):

## macOS — `sdk/swift/macOS` (Swift Package)

Same shape as the Python/Kotlin/C# adapters: spawns
[`cmd/tunneld`](../../cmd/tunneld) via `Foundation.Process` and talks to it
over a Unix domain socket (raw POSIX `socket(AF_UNIX, ...)`, wrapped in
`FileHandle`).

```sh
cd sdk/swift/macOS
swift build
```

You need a built `tunneld` binary on your `PATH`:

```sh
go build -o tunneld ./cmd/tunneld   # from the repo root
```

Usage:

```swift
import TunnelCatSDK

let client = TunnelClient()
try client.start()
let result = try client.connect(ConnectParams(
    server: "https://your-control-server:443", username: "you", password: "secret"))
print(result?["socksAddr"] ?? "")
try client.disconnect()
client.close()
```

Try it with zero real credentials: `go run ./cmd/mockserver &` then
`swift run Basic` (see `sdk/swift/macOS/Examples/Basic/main.swift`).

## iOS — `sdk/swift/ios` (linked static archive, not a subprocess)

iOS sandboxing forbids spawning subprocesses, so this is a completely
different mechanism: `cmd/lib-ios` is built as a cgo `c-archive` and linked
directly into your app or extension target (see
[`docs/PROTOCOL.md`](../PROTOCOL.md) and `cmd/lib-ios/lib_ios.go`'s header
comment for the exact exported C functions).

1. Build the archive (needs a Mac with Xcode's iOS SDK; `CC` must point at
   the iOS-targeted clang):

   ```sh
   GOOS=ios GOARCH=arm64 CGO_ENABLED=1 CC=<clang> \
     go build -buildmode=c-archive -o libtunnelcat_core_arm64.a ./cmd/lib-ios
   ```

2. Add `libtunnelcat_core_arm64.a` to your Xcode target's
   `LIBRARY_SEARCH_PATHS`/`OTHER_LDFLAGS` (`-ltunnelcat_core_arm64`).
3. Set [`Bridging-Header.h`](../../sdk/swift/ios/Bridging-Header.h) as the
   target's `SWIFT_OBJC_BRIDGING_HEADER`.
4. Add [`GoCore.swift`](../../sdk/swift/ios/GoCore.swift) to the target.

Usage — note this is synchronous call-and-poll, not event-driven (there's
no separate process boundary once linked in, so there's nothing to push
events across):

```swift
let ok = GoCore.start(server: "https://your-control-server:443", apiKey: "",
                       username: "you", password: "secret",
                       logDir: logDirPath, dataDir: dataDirPath)
let port = GoCore.socksPort()
// point a WKWebView (WKWebsiteDataStore.proxyConfigurations, iOS 17+) or
// any other SOCKS5-consuming component at 127.0.0.1:<port>
GoCore.stop()
```

This is unverified on this development machine (no Apple toolchain
available) — build and device/simulator testing needs to happen on a Mac.
