// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

// Minimal example: connect through cmd/mockserver (no real credentials
// needed) and confirm the SOCKS5 proxy comes up.
//
// Run cmd/mockserver first: go run ./cmd/mockserver
// Then:                     swift run Basic

import TunnelCatSDK

let client = TunnelClient()
try client.start()

let result = try client.connect(ConnectParams(
    server: "http://127.0.0.1:8443",
    apiKey: "x",
    username: "u",
    password: "p",
    socksAddr: "127.0.0.1:1082",
    pollingOnly: true // cmd/mockserver only implements polling mode
))
print("connected:", result ?? [:])
print("status:", try client.status() ?? [:])
try client.disconnect()
client.close()
