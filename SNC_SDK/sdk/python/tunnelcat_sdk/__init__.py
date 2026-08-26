# The Tunnel Cat Project
# Copyright (C) NavLink, 2026
# Лицензировано под лицензией Apache 2.0

"""Python SDK for tunnelcat-server: a thin client for the tunneld JSON-RPC
protocol (see docs/IPC.md). Spawns tunneld as a subprocess and talks to it
over a local Unix domain socket.

No tunnel logic lives here — this is purely a process-and-socket wrapper.
"""

from .client import TunnelClient, TunnelError

__all__ = ["TunnelClient", "TunnelError"]
