# The Tunnel Cat Project
# Copyright (C) NavLink, 2026
# Лицензировано под лицензией Apache 2.0

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from typing import Any, Callable, Optional


class TunnelError(Exception):
    """Raised when tunneld returns an {"error": ...} response."""


class TunnelClient:
    """Spawns tunneld and drives it over its Unix-socket JSON-RPC protocol.

    Usage:
        with TunnelClient() as tc:
            tc.connect(server="https://your-control-server:443", username="u", password="p")
            # ... use tc.status()["socksAddr"] as a SOCKS5 proxy ...
            tc.disconnect()
    """

    def __init__(
        self,
        tunneld_path: Optional[str] = None,
        socket_path: Optional[str] = None,
        on_event: Optional[Callable[[dict], None]] = None,
        connect_timeout: float = 5.0,
    ):
        self._tunneld_path = tunneld_path or _find_tunneld()
        self._socket_path = socket_path or os.path.join(
            tempfile.gettempdir(), f"tunneld-{uuid.uuid4().hex}.sock"
        )
        self._on_event = on_event
        self._connect_timeout = connect_timeout

        self._proc: Optional[subprocess.Popen] = None
        self._sock: Optional[socket.socket] = None
        self._sock_file = None
        self._next_id = 1
        self._lock = threading.Lock()
        self._pending: dict[int, "queue.Queue"] = {}
        self._reader_thread: Optional[threading.Thread] = None
        self._closed = False

    def __enter__(self) -> "TunnelClient":
        self.start()
        return self

    def __exit__(self, *exc):
        self.close()

    def start(self) -> None:
        if not self._tunneld_path:
            raise TunnelError(
                "tunneld binary not found; pass tunneld_path= explicitly or "
                "put a built tunneld/tunneld.exe on PATH"
            )
        if os.path.exists(self._socket_path):
            os.remove(self._socket_path)

        self._proc = subprocess.Popen(
            [self._tunneld_path, "-socket", self._socket_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        deadline = time.time() + self._connect_timeout
        while time.time() < deadline:
            if os.path.exists(self._socket_path):
                break
            if self._proc.poll() is not None:
                raise TunnelError("tunneld exited before creating its socket")
            time.sleep(0.05)
        else:
            raise TunnelError("timed out waiting for tunneld socket")

        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.connect(self._socket_path)
        self._sock_file = self._sock.makefile("rwb")

        import queue  # local import: only needed once start() runs

        self._pending = {}
        self._queue_cls = queue.Queue
        self._reader_thread = threading.Thread(target=self._read_loop, daemon=True)
        self._reader_thread.start()

    def _read_loop(self) -> None:
        try:
            for line in self._sock_file:
                if not line.strip():
                    continue
                msg = json.loads(line)
                if "event" in msg:
                    if self._on_event:
                        self._on_event(msg)
                    continue
                mid = msg.get("id")
                with self._lock:
                    q = self._pending.pop(mid, None)
                if q is not None:
                    q.put(msg)
        except (OSError, ValueError):
            pass  # socket closed

    def _call(self, method: str, params: Optional[dict] = None, timeout: float = 15.0) -> Any:
        if self._sock is None:
            raise TunnelError("not started; call start() or use as a context manager")
        with self._lock:
            mid = self._next_id
            self._next_id += 1
            q = self._queue_cls()
            self._pending[mid] = q

        req = {"id": mid, "method": method}
        if params is not None:
            req["params"] = params
        self._sock_file.write((json.dumps(req) + "\n").encode())
        self._sock_file.flush()

        try:
            resp = q.get(timeout=timeout)
        except Exception:
            with self._lock:
                self._pending.pop(mid, None)
            raise TunnelError(f"timed out waiting for {method} response")

        if "error" in resp and resp["error"]:
            raise TunnelError(resp["error"])
        return resp.get("result")

    def connect(
        self,
        server: str,
        apikey: str = "",
        username: str = "",
        password: str = "",
        socks_addr: str = "",
        polling_only: bool = False,
    ) -> dict:
        return self._call(
            "connect",
            {
                "server": server,
                "apikey": apikey,
                "username": username,
                "password": password,
                "socksAddr": socks_addr,
                "pollingOnly": polling_only,
            },
        )

    def disconnect(self) -> dict:
        return self._call("disconnect")

    def status(self) -> dict:
        return self._call("status")

    def reconnect(self) -> dict:
        return self._call("reconnect")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        if os.path.exists(self._socket_path):
            try:
                os.remove(self._socket_path)
            except OSError:
                pass


def _find_tunneld() -> Optional[str]:
    name = "tunneld.exe" if os.name == "nt" else "tunneld"
    return shutil.which(name)
