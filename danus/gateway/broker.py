"""Host-owned, identity-bound, one-shot Worker MCP broker.

The broker owns the verifier signing capability and a random pathname socket in
a 0700 host control directory.  The provider service sees only that exact socket
as a read-only bind mount.  Before a connection can consume the listener, the
trusted Worker host sends the pinned provider InvocationID/MainPID/cgroup over
stdin; the broker then verifies the peer's uid, executable, exact bridge argv,
cgroup, and ancestry.  Invalid peers are closed without consuming the one-shot
listener.  The path is unlinked immediately after the first valid bridge.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import BinaryIO, Optional

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parents[1]))

from danus.host_isolation import protect_host_process_secrets  # noqa: E402
from danus.gateway.fd_protocol import (  # noqa: E402
    BROKER_AUTHORIZED_MARKER,
    BROKER_READY_MARKER,
    PROVIDER_SOCKET_PATH,
)

_REQUIRED_ENV = (
    "DANUS_PROJECT_DIR", "DANUS_AUTHOR", "DANUS_VERIFY_URL",
    "DANUS_VERIFY_PROJECT", "DANUS_VERIFY_WORKER",
)
_GATEWAY_ENTRY = (_HERE / "trusted_entry.py").resolve()
_BRIDGE_ENTRY = (_HERE / "bridge.py").resolve()
_GATEWAY_PYTHON = Path(sys.executable).absolute()
_BRIDGE_PYTHON = Path(sys.executable).resolve()
_INVOCATION_RE = re.compile(r"^[0-9a-f]{32}$")
_SO_PEERPIDFD = 77
_NAMESPACE_NAMES = ("pid", "mnt", "user", "cgroup")
_GATEWAY: Optional[subprocess.Popen] = None
_LISTENER: Optional[socket.socket] = None


def _copy_socket_to_file(conn: socket.socket, target: BinaryIO) -> None:
    try:
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            target.write(chunk)
            target.flush()
    except (BrokenPipeError, ConnectionError, OSError):
        pass
    finally:
        try:
            target.close()
        except OSError:
            pass


def _gateway_env() -> dict[str, str]:
    if any(not os.environ.get(name) for name in _REQUIRED_ENV):
        raise RuntimeError("host gateway configuration is incomplete")
    env = {name: os.environ[name] for name in _REQUIRED_ENV}
    secret_file = os.environ.get("DANUS_VERIFY_CAPABILITY_SECRET_FILE")
    if secret_file:
        env["DANUS_VERIFY_CAPABILITY_SECRET_FILE"] = secret_file
    runtime = os.environ.get("DANUS_RUNTIME")
    if runtime:
        env["DANUS_RUNTIME"] = runtime
    env.update({
        "DANUS_ROLE": "worker", "PATH": os.defpath,
        "PYTHONDONTWRITEBYTECODE": "1", "PYTHONSAFEPATH": "1",
    })
    timeout = os.environ.get("DANUS_VERIFY_TIMEOUT")
    if timeout:
        env["DANUS_VERIFY_TIMEOUT"] = timeout
    return env


def _read_exact(fd: int, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(fd, remaining)
        if not chunk:
            raise RuntimeError("provider authorization channel closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_authorization(fd: int, socket_path: Path) -> dict[str, object]:
    (size,) = struct.unpack("!I", _read_exact(fd, 4))
    if size < 2 or size > 16384:
        raise RuntimeError("provider authorization frame has an unsafe size")
    value = json.loads(_read_exact(fd, size))
    expected_argv = [
        str(_BRIDGE_PYTHON), "-I", str(_BRIDGE_ENTRY),
        "--socket", PROVIDER_SOCKET_PATH,
    ]
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise RuntimeError("provider authorization frame is invalid")
    pid = value.get("main_pid")
    cgroup = value.get("cgroup")
    invocation = value.get("invocation_id")
    argv = value.get("bridge_argv")
    launcher_argv = value.get("launcher_argv")
    provider_argv = value.get("provider_argv")
    raw_namespaces = value.get("namespaces")
    if (
        not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1
        or not isinstance(cgroup, str) or not cgroup.startswith("/") or ".." in Path(cgroup).parts
        or not isinstance(invocation, str) or not _INVOCATION_RE.fullmatch(invocation)
        or argv != expected_argv
        or not isinstance(launcher_argv, list) or not launcher_argv
        or not isinstance(provider_argv, list) or not provider_argv
        or any(not isinstance(item, str) or not item or "\0" in item for item in launcher_argv)
        or any(not isinstance(item, str) or not item or "\0" in item for item in provider_argv)
        or not Path(launcher_argv[0]).is_absolute()
        or not Path(provider_argv[0]).is_absolute()
        or not isinstance(raw_namespaces, dict)
        or set(raw_namespaces) != set(_NAMESPACE_NAMES)
    ):
        raise RuntimeError("provider authorization identity is invalid")
    namespaces: dict[str, tuple[int, int]] = {}
    for name in _NAMESPACE_NAMES:
        identity = raw_namespaces[name]
        if (
            not isinstance(identity, list) or len(identity) != 2
            or any(
                not isinstance(item, int) or isinstance(item, bool)
                or item <= 0 or item >= 1 << 64
                for item in identity
            )
        ):
            raise RuntimeError("provider authorization namespace is invalid")
        namespaces[name] = (identity[0], identity[1])
    value["namespaces"] = namespaces
    if _proc_cgroup(pid) != cgroup:
        raise RuntimeError("authorized provider MainPID is outside its cgroup")
    return value


def _proc_cgroup(pid: int) -> str:
    text = (Path("/proc") / str(pid) / "cgroup").read_text(encoding="ascii")
    rows = [line[3:] for line in text.splitlines() if line.startswith("0::")]
    if len(rows) != 1:
        raise RuntimeError("provider peer lacks one unified cgroup")
    return rows[0]


def _proc_argv(pid: int) -> list[str]:
    raw = (Path("/proc") / str(pid) / "cmdline").read_bytes()
    return [
        item.decode("utf-8", errors="surrogateescape")
        for item in raw.split(b"\0") if item
    ]


def _proc_ppid(pid: int) -> int:
    text = (Path("/proc") / str(pid) / "status").read_text(encoding="ascii")
    for line in text.splitlines():
        if line.startswith("PPid:"):
            return int(line.split(":", 1)[1].strip())
    raise RuntimeError("provider peer parent identity is unavailable")


def _proc_starttime(pid: int) -> int:
    # comm may contain spaces and ')'; split only after its final closing paren.
    text = (Path("/proc") / str(pid) / "stat").read_text(encoding="ascii")
    tail = text[text.rfind(")") + 2:].split()
    return int(tail[19])  # field 22 overall; tail begins at field 3


def _namespace_inode(pid: int, name: str) -> tuple[int, int]:
    info = (Path("/proc") / str(pid) / "ns" / name).stat()
    return info.st_dev, info.st_ino


def _validate_pidfd(pidfd: int, expected_pid: int) -> int:
    if pidfd < 3:
        raise RuntimeError("kernel returned an invalid peer pidfd")
    os.set_inheritable(pidfd, False)
    fdinfo = (Path("/proc/self/fdinfo") / str(pidfd)).read_text(encoding="ascii")
    values = dict(
        line.split(":", 1) for line in fdinfo.splitlines() if ":" in line
    )
    if int(values.get("Pid", "-1").strip()) != expected_pid:
        raise RuntimeError("peer pidfd identity does not match SO_PEERCRED")
    return pidfd


def _peer_pidfd(conn: socket.socket, expected_pid: int) -> int:
    raw = conn.getsockopt(socket.SOL_SOCKET, _SO_PEERPIDFD, struct.calcsize("i"))
    (pidfd,) = struct.unpack("i", raw)
    try:
        return _validate_pidfd(pidfd, expected_pid)
    except BaseException:
        if pidfd >= 0:
            try:
                os.close(pidfd)
            except OSError:
                pass
        raise


def _open_pidfd(pid: int) -> int:
    try:
        pidfd = os.pidfd_open(pid, 0)
    except (AttributeError, OSError) as exc:
        raise RuntimeError("provider pidfd identity is unavailable") from exc
    try:
        return _validate_pidfd(pidfd, pid)
    except BaseException:
        try:
            os.close(pidfd)
        except OSError:
            pass
        raise


def _pidfd_alive(pidfd: int) -> bool:
    readable, _, _ = select.select([pidfd], [], [], 0)
    return not readable


def _pin_provider(authorization: dict[str, object]) -> tuple[int, int]:
    pid = int(authorization["main_pid"])
    expected_cgroup = str(authorization["cgroup"])
    starttime = _proc_starttime(pid)
    pidfd = _open_pidfd(pid)
    try:
        if (
            not _pidfd_alive(pidfd)
            or _proc_starttime(pid) != starttime
            or _proc_cgroup(pid) != expected_cgroup
            or _proc_argv(pid) != authorization["launcher_argv"]
        ):
            raise RuntimeError("provider launcher identity changed before authorization")
        return pidfd, starttime
    except BaseException:
        os.close(pidfd)
        raise


def _process_identity_matches(
    pid: int, *, starttime: int, cgroup: str,
    namespaces: dict[str, tuple[int, int]], executable: Path,
    argv: object,
) -> bool:
    try:
        return (
            _proc_starttime(pid) == starttime
            and _proc_cgroup(pid) == cgroup
            and _proc_argv(pid) == argv
            and (Path("/proc") / str(pid) / "exe").resolve(strict=True)
                == executable.resolve(strict=True)
            and all(
                _namespace_inode(pid, namespace) == namespaces[namespace]
                for namespace in _NAMESPACE_NAMES
            )
        )
    except (OSError, RuntimeError, ValueError):
        return False


def _peer_is_authorized(
    conn: socket.socket, authorization: dict[str, object], *,
    provider_pidfd: int, provider_starttime: int,
) -> int | None:
    pidfd = -1
    try:
        raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, _gid = struct.unpack("3i", raw)
        expected_main = int(authorization["main_pid"])
        expected_cgroup = str(authorization["cgroup"])
        expected_namespaces = dict(authorization["namespaces"])
        provider_executable = Path(str(authorization["provider_argv"][0]))
        if uid != os.getuid() or pid <= 1:
            return None
        pidfd = _peer_pidfd(conn, pid)
        starttime = _proc_starttime(pid)
        if not _pidfd_alive(provider_pidfd) or not _process_identity_matches(
            expected_main, starttime=provider_starttime, cgroup=expected_cgroup,
            namespaces=expected_namespaces, executable=provider_executable,
            argv=authorization["provider_argv"],
        ):
            return None
        if not _process_identity_matches(
            pid, starttime=starttime, cgroup=expected_cgroup,
            namespaces=expected_namespaces, executable=_BRIDGE_PYTHON,
            argv=authorization["bridge_argv"],
        ):
            return None
        # Every intermediate process must remain in the pinned provider cgroup,
        # and the chain must terminate at the exact service MainPID.
        current = pid
        seen: set[int] = set()
        for _ in range(32):
            if current == expected_main:
                if (
                    not _pidfd_alive(provider_pidfd)
                    or not _pidfd_alive(pidfd)
                    or not _process_identity_matches(
                        expected_main, starttime=provider_starttime,
                        cgroup=expected_cgroup, namespaces=expected_namespaces,
                        executable=provider_executable,
                        argv=authorization["provider_argv"],
                    )
                    or not _process_identity_matches(
                        pid, starttime=starttime, cgroup=expected_cgroup,
                        namespaces=expected_namespaces, executable=_BRIDGE_PYTHON,
                        argv=authorization["bridge_argv"],
                    )
                ):
                    return None
                result, pidfd = pidfd, -1
                return result
            if (
                current <= 1 or current in seen
                or _proc_cgroup(current) != expected_cgroup
                or any(
                    _namespace_inode(current, namespace) != expected_namespaces[namespace]
                    for namespace in _NAMESPACE_NAMES
                )
            ):
                return None
            seen.add(current)
            current = _proc_ppid(current)
        return None
    except (OSError, RuntimeError, ValueError):
        return None
    finally:
        if pidfd >= 0:
            try:
                os.close(pidfd)
            except OSError:
                pass


def _unlink_socket(path: Path, *, missing_ok: bool = False) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        if missing_ok:
            return
        raise
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
        raise RuntimeError("gateway locator changed type or owner")
    path.unlink()


def _accept_authorized(
    listener: socket.socket, authorization: dict[str, object], socket_path: Path,
    *, provider_pidfd: int, provider_starttime: int,
) -> tuple[socket.socket, int]:
    listener.settimeout(1.0)
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        try:
            conn, _address = listener.accept()
        except TimeoutError:
            continue
        pidfd = _peer_is_authorized(
            conn, authorization, provider_pidfd=provider_pidfd,
            provider_starttime=provider_starttime,
        )
        if pidfd is not None:
            _unlink_socket(socket_path)
            listener.close()
            return conn, pidfd
        conn.close()
    raise RuntimeError("authorized provider bridge did not connect")


def _serve_connection(
    conn: socket.socket, peer_pidfd: int, provider_pidfd: int,
) -> int:
    global _GATEWAY
    _GATEWAY = subprocess.Popen(
        [str(_GATEWAY_PYTHON), "-I", str(_GATEWAY_ENTRY)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=_gateway_env(), cwd="/", start_new_session=True,
    )
    assert _GATEWAY.stdin is not None and _GATEWAY.stdout is not None
    incoming = threading.Thread(
        target=_copy_socket_to_file, args=(conn, _GATEWAY.stdin), daemon=True,
    )
    incoming.start()
    try:
        while True:
            chunk = os.read(_GATEWAY.stdout.fileno(), 65536)
            if not chunk:
                break
            conn.sendall(chunk)
    except (BrokenPipeError, ConnectionError, OSError):
        pass
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        conn.close()
        os.close(peer_pidfd)
        os.close(provider_pidfd)
        incoming.join(timeout=1)
        if _GATEWAY.poll() is None:
            os.killpg(_GATEWAY.pid, signal.SIGTERM)
            try:
                _GATEWAY.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(_GATEWAY.pid, signal.SIGKILL)
        rc = _GATEWAY.wait()
        _GATEWAY = None
    return rc


def _on_term(_signum, _frame) -> None:
    if _GATEWAY is not None and _GATEWAY.poll() is None:
        os.killpg(_GATEWAY.pid, signal.SIGTERM)
    if _LISTENER is not None:
        _LISTENER.close()
    raise SystemExit(0)


def main(argv: list[str]) -> int:
    global _LISTENER
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--socket")
    parser.add_argument("--control-fd", type=int)
    args = parser.parse_args(argv)
    socket_path = Path(args.socket).absolute()
    provider_pidfd = -1
    try:
        protect_host_process_secrets()
        parent = socket_path.parent
        parent_info = parent.lstat()
        if (
            not socket_path.is_absolute() or socket_path.exists() or socket_path.is_symlink()
            or not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.getuid()
            or stat.S_IMODE(parent_info.st_mode) != 0o700
            or args.control_fd < 3 or not stat.S_ISFIFO(os.fstat(args.control_fd).st_mode)
        ):
            raise RuntimeError("unsafe gateway listener path")
        signal.signal(signal.SIGTERM, _on_term)
        _LISTENER = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        _LISTENER.bind(str(socket_path))
        os.chmod(socket_path, 0o600)
        _LISTENER.listen(8)
        os.write(args.control_fd, BROKER_READY_MARKER)
        authorization = _read_authorization(0, socket_path)
        provider_pidfd, provider_starttime = _pin_provider(authorization)
        os.write(args.control_fd, BROKER_AUTHORIZED_MARKER)
        os.close(args.control_fd)
        args.control_fd = -1
        conn, peer_pidfd = _accept_authorized(
            _LISTENER, authorization, socket_path,
            provider_pidfd=provider_pidfd, provider_starttime=provider_starttime,
        )
        _LISTENER = None
        pinned, provider_pidfd = provider_pidfd, -1
        return _serve_connection(conn, peer_pidfd, pinned)
    except Exception:
        print("Danus host gateway broker failed closed", file=sys.stderr)
        return 1
    finally:
        if args.control_fd >= 0:
            try:
                os.close(args.control_fd)
            except OSError:
                pass
        if provider_pidfd >= 0:
            try:
                os.close(provider_pidfd)
            except OSError:
                pass
        if _LISTENER is not None:
            try:
                _LISTENER.close()
            except OSError:
                pass
            _LISTENER = None
        try:
            _unlink_socket(socket_path, missing_ok=True)
        except (OSError, RuntimeError):
            pass


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
