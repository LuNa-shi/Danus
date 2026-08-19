"""Trusted PID-namespace entry for one Codex provider service.

The systemd service passes three capabilities as standard descriptors:

* fd 0: host-to-provider framed control stream;
* fd 1/2: provider diagnostics/output returned to the Worker host.

It consumes an allowlisted environment frame, closes every non-stdio descriptor,
enters the scoped Landlock/seccomp domain, and sends an exact READY preface over
stdout.  Only after the host validates that preface and the transient unit does
it send the prompt frame.  The prompt is exposed to ``codex exec -`` through a
sealed anonymous memfd: it never enters argv, a unit property, the environment,
the journal, or a pathname-backed file.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import resource
import stat
import struct
import sys
from pathlib import Path

_TRUSTED_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_TRUSTED_ROOT))

from danus.gateway.fd_protocol import (  # noqa: E402
    PROVIDER_SOCKET_PATH,
    provider_ready_attestation,
)
from danus.host_isolation import (  # noqa: E402
    HostIsolationError,
    host_process_is_dumpable,
    protect_host_process_secrets,
    restrict_current_process_scope,
    restrict_unix_socket_creation,
)

_ENV_FRAME_MAX = 65536
_PROMPT_FRAME_MAX = 8 * 1024 * 1024
_F_ADD_SEALS = getattr(fcntl, "F_ADD_SEALS", 1033)
_F_SEAL_SEAL = getattr(fcntl, "F_SEAL_SEAL", 0x0001)
_F_SEAL_SHRINK = getattr(fcntl, "F_SEAL_SHRINK", 0x0002)
_F_SEAL_GROW = getattr(fcntl, "F_SEAL_GROW", 0x0004)
_F_SEAL_WRITE = getattr(fcntl, "F_SEAL_WRITE", 0x0008)
_FORBIDDEN_ENV_MARKERS = (
    "DANUS_WEB_", "ARTIFACT", "LIFECYCLE", "VERIFY_CAPABILITY",
    "GITHUB", "GH_TOKEN", "CLOUDFLARE", "TUNNEL_TOKEN", "COOKIE", "PASSWORD",
)


def _read_exact(fd: int, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(fd, remaining)
        if not chunk:
            raise ValueError("truncated provider control frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_frame(fd: int, *, minimum: int, maximum: int) -> bytes:
    (size,) = struct.unpack("!I", _read_exact(fd, 4))
    if size < minimum or size > maximum:
        raise ValueError("provider control frame has an unsafe size")
    return _read_exact(fd, size)


def _load_environment(raw: bytes) -> dict[str, str]:
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("invalid provider environment")
    result: dict[str, str] = {}
    for key, item in value.items():
        if (
            not isinstance(key, str) or not key or "=" in key or "\0" in key
            or not isinstance(item, str) or "\0" in item
            or any(marker in key.upper() for marker in _FORBIDDEN_ENV_MARKERS)
        ):
            raise ValueError("unsafe provider environment")
        result[key] = item
    return result


def _open_fds() -> list[int]:
    try:
        return [
            int(entry.name) for entry in Path("/proc/self/fd").iterdir()
            if entry.name.isdigit()
        ]
    except OSError:
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        return list(range(3, min(1_048_576, int(soft))))


def _live_open_fds() -> set[int]:
    result: set[int] = set()
    for fd in _open_fds():
        try:
            fcntl.fcntl(fd, fcntl.F_GETFD)
        except OSError:
            continue
        result.add(fd)
    return result


def _close_unlisted_fds(keep: set[int]) -> None:
    for fd in _open_fds():
        if fd in keep:
            continue
        try:
            os.close(fd)
        except OSError:
            pass


def _namespace_inventory() -> dict[str, tuple[int, int]]:
    result: dict[str, tuple[int, int]] = {}
    for name in ("pid", "mnt", "user", "cgroup"):
        info = (Path("/proc/self/ns") / name).stat()
        result[name] = (info.st_dev, info.st_ino)
    return result


def _require_run_inventory() -> None:
    expected = {
        Path("/run"): (stat.S_IFDIR, 0o755),
        Path("/run/systemd"): (stat.S_IFDIR, 0o755),
        Path("/run/systemd/resolve"): (stat.S_IFDIR, 0o755),
        Path("/run/systemd/resolve/stub-resolv.conf"): (stat.S_IFREG, 0o644),
        Path("/run/user"): (stat.S_IFDIR, 0o755),
    }
    actual = {Path("/run"), *Path("/run").rglob("*")}
    if actual != set(expected):
        raise ValueError("provider service /run inventory is not minimal")
    for path, (kind, mode) in expected.items():
        info = path.lstat()
        if stat.S_IFMT(info.st_mode) != kind or stat.S_IMODE(info.st_mode) != mode:
            raise ValueError("provider service /run entry has an unsafe type or mode")


def _require_service_namespace(
    *, socket_dev: int, socket_ino: int,
) -> dict[str, tuple[int, int]]:
    if os.getpid() != 1:
        raise ValueError("provider launcher is not PID 1 in a private namespace")
    try:
        os.listdir("/sys/fs/cgroup")
    except OSError:
        pass
    else:
        raise ValueError("provider service exposes the host cgroup filesystem")
    _require_run_inventory()
    for endpoint in (
        Path(f"/run/user/{os.getuid()}/bus"),
        Path("/run/dbus/system_bus_socket"),
        Path("/run/systemd/private"),
    ):
        if endpoint.exists():
            raise ValueError("provider service exposes a host control socket")
    resolver = Path("/run/systemd/resolve/stub-resolv.conf")
    if not resolver.is_file():
        raise ValueError("provider service cannot resolve DNS safely")
    socket_info = Path(PROVIDER_SOCKET_PATH).stat()
    if socket_info.st_dev != socket_dev or socket_info.st_ino != socket_ino:
        raise ValueError("provider service gateway bind has the wrong inode")
    return _namespace_inventory()


def _require_irreversible_restrictions() -> None:
    status = Path("/proc/self/status").read_text(encoding="ascii")
    fields = dict(
        line.split(":", 1) for line in status.splitlines() if ":" in line
    )
    if fields.get("NoNewPrivs", "").strip() != "1":
        raise ValueError("provider launcher lacks no-new-privileges")
    if fields.get("Seccomp", "").strip() != "2":
        raise ValueError("provider launcher lacks its seccomp filter")


def _write_all(fd: int, value: bytes) -> None:
    view = memoryview(value)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("provider readiness channel closed")
        view = view[written:]


def _prompt_memfd(prompt: bytes) -> None:
    flags = os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING
    fd = os.memfd_create("danus-worker-prompt", flags)
    try:
        _write_all(fd, prompt)
        os.lseek(fd, 0, os.SEEK_SET)
        seals = _F_SEAL_SEAL | _F_SEAL_SHRINK | _F_SEAL_GROW | _F_SEAL_WRITE
        fcntl.fcntl(fd, _F_ADD_SEALS, seals)
        os.dup2(fd, 0, inheritable=True)
    finally:
        if fd != 0:
            os.close(fd)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--ready-challenge", required=True)
    parser.add_argument("--socket-dev", required=True, type=int)
    parser.add_argument("--socket-ino", required=True, type=int)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command or not Path(command[0]).is_absolute():
        print("provider launcher requires an absolute trusted command", file=sys.stderr)
        return 126
    try:
        try:
            challenge = bytes.fromhex(args.ready_challenge)
        except ValueError as exc:
            raise ValueError("invalid provider READY challenge") from exc
        if len(challenge) != 16 or args.socket_dev < 0 or args.socket_ino <= 0:
            raise ValueError("invalid provider READY identity")
        protect_host_process_secrets()
        if host_process_is_dumpable():
            raise ValueError("provider launcher credentials remain dumpable")
        namespaces = _require_service_namespace(
            socket_dev=args.socket_dev, socket_ino=args.socket_ino,
        )
        _close_unlisted_fds({0, 1, 2})
        if _live_open_fds() != {0, 1, 2}:
            raise ValueError("provider launcher retained an unexpected descriptor")
        provider_env = _load_environment(
            _read_frame(0, minimum=2, maximum=_ENV_FRAME_MAX),
        )
        os.environ.clear()
        os.environ.update(provider_env)
        restrict_unix_socket_creation(allow_pathname_unix=True)
        restrict_current_process_scope()
        _require_irreversible_restrictions()
        if host_process_is_dumpable():
            raise ValueError("provider launcher credentials became dumpable")
        _write_all(1, provider_ready_attestation(
            challenge, socket_dev=args.socket_dev, socket_ino=args.socket_ino,
            namespaces=namespaces,
        ))
        prompt = _read_frame(0, minimum=1, maximum=_PROMPT_FRAME_MAX)
        _prompt_memfd(prompt)
        os.execvpe(command[0], command, os.environ)
    except (
        HostIsolationError, OSError, ValueError, UnicodeDecodeError,
        json.JSONDecodeError,
    ):
        print("Danus provider isolation failed closed", file=sys.stderr)
        return 126


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
