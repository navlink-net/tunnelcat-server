# The Tunnel Cat Project
# Copyright (C) NavLink, 2026
# Лицензировано под лицензией Apache 2.0

"""Minimal example: connect through cmd/mockserver (no real credentials
needed) and confirm the SOCKS5 proxy comes up.

Run cmd/mockserver first:  go run ./cmd/mockserver
Then:                      python examples/basic.py
"""

from tunnelcat_sdk import TunnelClient

with TunnelClient() as tc:
    result = tc.connect(
        server="http://127.0.0.1:8443",
        apikey="x",
        username="u",
        password="p",
        socks_addr="127.0.0.1:1080",
        polling_only=True,  # cmd/mockserver only implements polling mode
    )
    print("connected:", result)
    print("status:", tc.status())
    tc.disconnect()
