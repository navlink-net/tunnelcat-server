<!--
Copyright (C) Konstantin Khait & Claude Code
For IT Partners Solutions and Freedom and Rights
2026
-->

# C# SDK quickstart

`sdk/csharp` is a thin client for [`cmd/tunneld`](../../cmd/tunneld)'s
JSON-RPC protocol (see [`docs/IPC.md`](../IPC.md)). It spawns `tunneld` via
`System.Diagnostics.Process` and talks to it over a Unix domain socket via
`System.Net.Sockets.Socket` with `AddressFamily.Unix` (supported on Windows
since .NET Core 3.0+, and always on Linux/macOS).

## Build

```sh
cd sdk/csharp/TunnelCat.Sdk
dotnet build
```

You also need a built `tunneld` binary on your `PATH`:

```sh
go build -o tunneld ./cmd/tunneld   # from the repo root (add .exe on Windows)
```

## Usage

```csharp
using TunnelCat.Sdk;

using var client = new TunnelClient();
client.Start();
var result = client.Connect(new ConnectParams(
    Server: "https://your-control-server:443", Username: "you", Password: "secret"));
Console.WriteLine(result?["socksAddr"]);
client.Disconnect();
```

## Try it with zero real credentials

```sh
go run ./cmd/mockserver &
cd sdk/csharp/examples/Basic
dotnet run
```

This example (`examples/Basic`) is verified end-to-end against
`cmd/tunneld` + `cmd/mockserver` as part of this SDK's own development —
connect, status, and disconnect all round-trip correctly.
