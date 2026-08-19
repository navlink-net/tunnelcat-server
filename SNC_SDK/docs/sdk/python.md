<!--
Copyright (C) Konstantin Khait & Claude Code
For IT Partners Solutions and Freedom and Rights
2026
-->

# Python SDK quickstart

`sdk/python` is a thin client for [`cmd/tunneld`](../../cmd/tunneld)'s
JSON-RPC protocol (see [`docs/IPC.md`](../IPC.md)). It spawns `tunneld` as a
subprocess and talks to it over a Unix domain socket via the standard
library `socket` module.

> **Windows note**: `socket.AF_UNIX` support on Windows depends on your
> Python build (added for Windows in CPython 3.9, but not present in every
> official python.org Windows installer). Linux and macOS Python always
> have it.

## Install

```sh
cd sdk/python
pip install -e .
```

You also need a built `tunneld` binary on your `PATH` (or pass
`tunneld_path=` explicitly):

```sh
go build -o tunneld ./cmd/tunneld
```

## Usage

```python
from tunnelcat_sdk import TunnelClient

with TunnelClient() as tc:
    result = tc.connect(
        server="https://your-control-server:443",
        username="you",
        password="secret",
    )
    print(result["socksAddr"])  # point any SOCKS5 client at this
    tc.disconnect()
```

## Try it with zero real credentials

```sh
go run ./cmd/mockserver &
python examples/basic.py
```
