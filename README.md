# tunnelcat-server

Server components of the NavLink / Tunnel Cat secure tunneling network.

This repository contains:

- **`snc-arbiter/`** — the coordination/admin service. Issues and validates
  client activation keys, tracks node health and metrics, signs the node
  list clients bootstrap from, and serves the admin dashboard.
- **`snc-control/`** — control-plane nodes. The first hop a client connects
  to; brokers the client to an exit node and relays traffic.
- **`snc-exit/`** — exit nodes. Terminate the tunnel and forward traffic to
  the public internet.
- **`snc/core`** — the shared Go library used by both the server pieces
  above and by the client (see `tunnelcat-client`): the wire protocol,
  connection pooling, and transport plumbing.
- **`android-core/`**, **`anet-stub/`**, **`binlog/`**, **`dht/`**,
  **`SNC_SDK/`** — supporting libraries. `SNC_SDK` in particular is a
  documented, independently licensed SDK for talking to `snc-control` from
  third-party code.
- **`tools/decode_snc_log.py`** — decodes the binary log format emitted by
  clients (see `binlog/`) back to plain text.

## What's not here

This is the open-source edition of a larger private codebase. Removed
before publication:

- **Wildcat**, a covert transport that disguised tunnel traffic as a VK
  video call. It was woven throughout the control/arbiter/exit code as an
  alternate transport path; that path has been fully removed, not just
  disabled. The direct-TCP transport is unaffected.
- Marketing site (`Web/`), infrastructure deployment scripts (`deploy/`),
  internal operations tooling (node provisioning, IP rotation, key issuance
  against the production arbiter), and internal planning/business
  documents.
- Real infrastructure hostnames/IPs that appeared in code comments and
  examples have been replaced with [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737)
  documentation-range addresses (`203.0.113.0/24`).

## Building

```
go build ./...
```

Requires Go 1.26+. Depends on a small fork of
[`sagernet/sing-box`](https://github.com/sagernet/sing-box) — see the
`replace` directive in `go.mod` — which carries exactly one patch (making a
non-fatal network-monitor start failure not abort startup, needed when
running as an Android subprocess without `CAP_NET_ADMIN`); see
[NavLinkNet/sing-box](https://github.com/NavLinkNet/sing-box), branch
`navlink-patch`, for that diff.

The companion client lives in a separate repository:
[`tunnelcat-client`](https://github.com/navlink-net/tunnelcat-client). Its
`go.mod` expects this repository to be checked out as a sibling directory
named `tunnel_cat`.

## License

Apache License 2.0 — see [LICENSE](LICENSE). `SNC_SDK/` carries its own
copy of the same license plus a note on one third-party dependency's
license.
