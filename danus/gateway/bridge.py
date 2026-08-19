"""Credential-free stdio bridge to one host-owned Worker gateway socket.

The provider mount namespace exposes exactly one per-round random socket path.
Codex's enforced inner permission profile denies that path to model-created
commands, while this absolute trusted MCP command connects once.  The host
broker validates this process's executable, argv, cgroup, and ancestry before
consuming the one-shot listener.
"""

from __future__ import annotations

import os
import socket
import sys
import threading
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parents[1]))

from danus.host_isolation import (  # noqa: E402
    HostIsolationError,
    allow_host_process_inspection,
)


def _copy_stdin(conn: socket.socket) -> None:
    try:
        while True:
            chunk = os.read(sys.stdin.fileno(), 65536)
            if not chunk:
                break
            conn.sendall(chunk)
    except (BrokenPipeError, ConnectionError, OSError):
        pass
    finally:
        try:
            conn.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def main(socket_text: str) -> int:
    path = Path(socket_text)
    if not path.is_absolute() or "\0" in socket_text:
        print("Danus host gateway locator is invalid", file=sys.stderr)
        return 1
    try:
        # This process receives no credential or capability.  Explicitly make
        # only this exact bridge inspectable so the host broker can validate
        # its executable, argv and namespaces after provider exec.
        allow_host_process_inspection()
    except HostIsolationError:
        print("Danus gateway bridge identity cannot be inspected", file=sys.stderr)
        return 1
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        conn.connect(socket_text)
    except OSError:
        conn.close()
        print("Danus one-shot host gateway is unavailable", file=sys.stderr)
        return 1

    sender = threading.Thread(target=_copy_stdin, args=(conn,), daemon=True)
    sender.start()
    try:
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            os.write(sys.stdout.fileno(), chunk)
    except (BrokenPipeError, ConnectionError, OSError):
        return 1
    finally:
        conn.close()
        sender.join(timeout=1)
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--socket":
        print("usage: Danus gateway bridge requires one socket locator", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[2]))
