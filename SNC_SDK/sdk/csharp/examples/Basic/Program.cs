// The Tunnel Cat Project
// Copyright (C) NavLink, 2026
// Лицензировано под лицензией Apache 2.0

// Minimal example: connect through cmd/mockserver (no real credentials
// needed) and confirm the SOCKS5 proxy comes up.
//
// Run cmd/mockserver first: go run ./cmd/mockserver
// Then:                     dotnet run

using TunnelCat.Sdk;

using var client = new TunnelClient();
client.Start();

var result = client.Connect(new ConnectParams(
    Server: "http://127.0.0.1:8443",
    ApiKey: "x",
    Username: "u",
    Password: "p",
    SocksAddr: "127.0.0.1:1081",
    PollingOnly: true)); // cmd/mockserver only implements polling mode

Console.WriteLine($"connected: {result}");
Console.WriteLine($"status: {client.Status()}");
client.Disconnect();
