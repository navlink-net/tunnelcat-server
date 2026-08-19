// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

// Minimal example: connect through cmd/mockserver (no real credentials
// needed) and confirm the SOCKS5 proxy comes up.
//
// Run cmd/mockserver first: go run ./cmd/mockserver
package examples

import com.tunnelcat.sdk.ConnectParams
import com.tunnelcat.sdk.TunnelClient

fun main() {
    val client = TunnelClient()
    client.start()
    val result = client.connect(
        ConnectParams(
            server = "http://127.0.0.1:8443",
            apiKey = "x",
            username = "u",
            password = "p",
            socksAddr = "127.0.0.1:1083",
            pollingOnly = true, // cmd/mockserver only implements polling mode
        ),
    )
    println("connected: $result")
    println("status: ${client.status()}")
    client.disconnect()
    client.close()
}
