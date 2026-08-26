<!--
The Tunnel Cat Project
Copyright (C) NavLink, 2026
Лицензировано под лицензией Apache 2.0
-->

# Kotlin SDK quickstart

`sdk/kotlin` is a thin client for [`cmd/tunneld`](../../cmd/tunneld)'s
JSON-RPC protocol (see [`docs/IPC.md`](../IPC.md)). It spawns `tunneld` via
`ProcessBuilder` and talks to it over a Unix domain socket via
`java.nio.channels.SocketChannel` + `UnixDomainSocketAddress` (JDK 16+).

This is a JVM/desktop adapter, not an Android one. An Android target would
need an Android-sandbox-specific JNI fork/exec workaround (`ProcessBuilder`
alone can't keep a TUN file descriptor open across `exec` on Android) that
this adapter deliberately does not implement, since it's irrelevant off
Android.

## Build

```sh
cd sdk/kotlin
./gradlew build
```

You also need a built `tunneld` binary on your `PATH`:

```sh
go build -o tunneld ./cmd/tunneld   # from the repo root
```

## Usage

```kotlin
import com.tunnelcat.sdk.TunnelClient
import com.tunnelcat.sdk.ConnectParams

val client = TunnelClient()
client.start()
val result = client.connect(ConnectParams(server = "https://your-control-server:443", username = "you", password = "secret"))
println(result?.getString("socksAddr"))
client.disconnect()
client.close()
```

## Try it with zero real credentials

```sh
go run ./cmd/mockserver &
```

Then run [`src/main/examples/Basic.kt`](../../sdk/kotlin/src/main/examples/Basic.kt)
from your IDE (or wire it into a Gradle `application`/exec task) — it connects
through the mock server and prints the resulting SOCKS5 address.
`ConnectParams(pollingOnly = true)` is required against `cmd/mockserver`,
which only implements the polling side of the wire protocol.
