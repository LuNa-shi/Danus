"""Production transient-service boundary for verifier provider runs.

The request body never enters a unit property, argv, environment assignment, or
the journal.  A fresh user service starts only the fixed trusted Python entry and
blocks on a non-secret startup challenge.  The controller pins the service,
process, executable, namespaces, and cgroup before releasing the framed request.
It returns only after the pinned cgroup proves ``populated 0``.
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
import os
from pathlib import Path
import pwd
import re
import secrets
import select
import shutil
import stat
import subprocess
import time
from typing import Iterable

from danus.execution import security as execution_security
from . import wire
from .runner import (
    TrustedVerifierTimeout,
    TrustedVerifierUnavailable,
    VerifierRunRequest,
    VerifierRunResult,
    trusted_entry_argv,
)


_UNIT_RE = re.compile(r"^danus-verifier-[0-9a-f]{32}\.service$")
_INVOCATION_RE = re.compile(r"^[0-9a-f]{32}$")
_MAX_CAPTURE_BYTES = 128 << 10
_START_TIMEOUT = 10.0
_READY_TIMEOUT = 10.0
_STOP_TIMEOUT = 15.0
_MANAGER_TIMEOUT = 15.0
_KERNEL_MOUNT_SOURCES = {Path("/proc"), Path("/sys")}
_SYSTEM_RESOLVER = Path("/run/systemd/resolve/stub-resolv.conf")
_TIMESPAN_PART_RE = re.compile(r"(?P<value>[0-9]+)(?P<unit>us|ms|s|min|h|d|w)")
_TIMESPAN_MULTIPLIER = {
    "us": 1,
    "ms": 1_000,
    "s": 1_000_000,
    "min": 60_000_000,
    "h": 3_600_000_000,
    "d": 86_400_000_000,
    "w": 604_800_000_000,
}

_SHOW_PROPERTIES = (
    "MainPID", "InvocationID", "ControlGroup", "ActiveState", "SubState",
    "Transient", "Type", "ExitType", "Restart", "KillMode", "SendSIGKILL",
    "CollectMode", "ExecStart", "PrivatePIDs", "ProtectProc", "ProcSubset",
    "ProtectSystem", "ProtectHome", "PrivateTmp", "PrivateDevices",
    "ProtectControlGroups", "NoNewPrivileges", "ProtectKernelTunables",
    "ProtectKernelModules", "ProtectKernelLogs", "ProtectClock",
    "LockPersonality", "RestrictRealtime", "RestrictSUIDSGID",
    "RestrictAddressFamilies", "UMask", "InaccessiblePaths", "ReadOnlyPaths",
    "BindPaths", "BindReadOnlyPaths", "TemporaryFileSystem", "RuntimeMaxUSec",
)


class _BoundaryError(RuntimeError):
    """Internal redacted failure; never returned directly to HTTP callers."""


@dataclass(frozen=True)
class _MountPolicy:
    read_only: frozenset[str]
    read_write: frozenset[str]


@dataclass
class _PinnedService:
    unit: str
    invocation_id: str
    main_pid: int
    cgroup: str
    starttime: str
    pidfd: int
    events_fd: int


def _safe_binary(name: str) -> str:
    value = shutil.which(name, path="/usr/bin:/bin")
    if not value:
        raise _BoundaryError("required service-manager binary is unavailable")
    path = Path(value).resolve(strict=True)
    info = path.stat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid not in {0, os.getuid()}
        or info.st_mode & 0o002
    ):
        raise _BoundaryError("service-manager binary is unsafe")
    return str(path)


def _manager_env() -> dict[str, str]:
    uid = os.getuid()
    runtime = Path("/run/user") / str(uid)
    bus = runtime / "bus"
    try:
        runtime_info = runtime.lstat()
        bus_info = bus.lstat()
    except OSError as exc:
        raise _BoundaryError("user service manager is unavailable") from exc
    if (
        not stat.S_ISDIR(runtime_info.st_mode)
        or runtime_info.st_uid != uid
        or not stat.S_ISSOCK(bus_info.st_mode)
        or bus_info.st_uid != uid
    ):
        raise _BoundaryError("user service manager endpoint is unsafe")
    return {
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={bus}",
        "XDG_RUNTIME_DIR": str(runtime),
        "HOME": pwd.getpwuid(uid).pw_dir,
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
    }


def _run_manager(
    argv: Iterable[str], *, timeout: float = _MANAGER_TIMEOUT, check: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            list(argv), cwd="/", env=_manager_env(), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise _BoundaryError("user service-manager request failed") from exc
    if check and completed.returncode != 0:
        raise _BoundaryError("user service-manager request was rejected")
    return completed


def _show(unit: str, properties: Iterable[str] = _SHOW_PROPERTIES) -> dict[str, str]:
    if not _UNIT_RE.fullmatch(unit):
        raise _BoundaryError("invalid verifier transient-unit identity")
    command = [_safe_binary("systemctl"), "--user", "show", unit, "--no-pager"]
    for name in properties:
        command.extend(("--property", name))
    completed = _run_manager(command, check=False)
    if completed.returncode != 0:
        raise _BoundaryError("verifier transient unit is unavailable")
    return dict(
        line.split("=", 1)
        for line in completed.stdout.splitlines()
        if "=" in line
    )


def _validated_manager_cgroup() -> str:
    completed = _run_manager([
        _safe_binary("systemctl"), "--user", "show", "--no-pager",
        "--property", "ControlGroup", "--property", "Version",
    ])
    values = dict(
        line.split("=", 1)
        for line in completed.stdout.splitlines()
        if "=" in line
    )
    expected = f"/user.slice/user-{os.getuid()}.slice/user@{os.getuid()}.service"
    if values.get("ControlGroup") != expected or not values.get("Version"):
        raise _BoundaryError("user service-manager identity is unsafe")
    try:
        own_cgroup = Path("/proc/self/cgroup").read_text(encoding="ascii")
        manager_path = Path("/sys/fs/cgroup" + expected)
        if "0::" not in own_cgroup or not manager_path.is_dir():
            raise _BoundaryError("unified cgroup boundary is unavailable")
    except OSError as exc:
        raise _BoundaryError("unified cgroup boundary is unavailable") from exc
    return expected


def _safe_mount_path(value: str, *, writable: bool) -> str:
    path = Path(value)
    if (
        not value
        or not path.is_absolute()
        or path != Path(os.path.abspath(path))
        or "\0" in value
        or any(char.isspace() or ord(char) < 0x20 or char in ":\\" for char in value)
    ):
        raise _BoundaryError("verifier mount policy is unsafe")
    try:
        info = path.stat()
    except OSError as exc:
        raise _BoundaryError("verifier mount source is unavailable") from exc
    system_owned_source = path in _KERNEL_MOUNT_SOURCES or path == _SYSTEM_RESOLVER
    if (
        not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode))
        or (not system_owned_source and info.st_uid not in {0, os.getuid()})
        or info.st_mode & 0o002
        or (writable and (info.st_uid != os.getuid() or info.st_mode & 0o077))
    ):
        raise _BoundaryError("verifier mount source is unsafe")
    return value


def _mount_policy(request: VerifierRunRequest) -> _MountPolicy:
    read_only = frozenset(
        _safe_mount_path(value, writable=False) for value in request.read_only_paths
    )
    read_write = frozenset(
        _safe_mount_path(value, writable=True) for value in request.read_write_paths
    )
    if (
        not read_only
        or not read_write
        or len(read_only) != len(request.read_only_paths)
        or len(read_write) != len(request.read_write_paths)
        or read_only & read_write
    ):
        raise _BoundaryError("verifier mount policy is unsafe")
    # A read-only child inside a writable source would silently widen the
    # writable view around trusted material.  The inverse is intentional: the
    # private run directory is a more-specific writable bind beneath read-only
    # Danus code in source checkouts.
    for writable in map(Path, read_write):
        for readonly in map(Path, read_only):
            if readonly != writable and readonly.is_relative_to(writable):
                raise _BoundaryError("verifier mount policy is unsafe")
    return _MountPolicy(read_only=read_only, read_write=read_write)


def _service_properties(policy: _MountPolicy, runtime_seconds: int) -> list[str]:
    values = [
        "KillMode=control-group", "SendSIGKILL=yes", "TimeoutStopSec=5s",
        f"RuntimeMaxSec={runtime_seconds}", "ExitType=main", "Restart=no",
        "PrivatePIDs=yes", "ProtectProc=ptraceable", "ProcSubset=all",
        "ProtectSystem=strict", "ProtectHome=tmpfs", "PrivateTmp=yes",
        "PrivateDevices=yes", "ProtectControlGroups=strict",
        "NoNewPrivileges=yes", "ProtectKernelTunables=yes",
        "ProtectKernelModules=yes", "ProtectKernelLogs=yes", "ProtectClock=yes",
        "LockPersonality=yes", "RestrictRealtime=yes", "RestrictSUIDSGID=yes",
        "UMask=0077",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
        "TemporaryFileSystem=/run:ro",
        "InaccessiblePaths=/sys/fs/cgroup",
        "ReadOnlyPaths=/tmp /var/tmp",
        "StandardError=null", "SyslogLevel=notice",
    ]
    values.extend(f"BindReadOnlyPaths={item}" for item in sorted(policy.read_only))
    values.extend(f"BindPaths={item}" for item in sorted(policy.read_write))
    return values


def _read_proc_cgroup(pid: int) -> str:
    try:
        rows = [
            line.removeprefix("0::")
            for line in (Path("/proc") / str(pid) / "cgroup")
            .read_text(encoding="ascii").splitlines()
            if line.startswith("0::")
        ]
    except OSError as exc:
        raise _BoundaryError("verifier process cgroup is unavailable") from exc
    if len(rows) != 1:
        raise _BoundaryError("verifier process cgroup is unsafe")
    return rows[0]


def _read_proc_argv(pid: int) -> tuple[str, ...]:
    try:
        raw = (Path("/proc") / str(pid) / "cmdline").read_bytes()
    except OSError as exc:
        raise _BoundaryError("verifier process argv is unavailable") from exc
    return tuple(
        item.decode("utf-8", errors="surrogateescape")
        for item in raw.split(b"\0") if item
    )


def _read_starttime(pid: int) -> str:
    try:
        raw = (Path("/proc") / str(pid) / "stat").read_text(encoding="ascii")
        closing = raw.rfind(")")
        fields = raw[closing + 2:].split()
        value = fields[19]
    except (OSError, IndexError) as exc:
        raise _BoundaryError("verifier process start identity is unavailable") from exc
    if not value.isdigit():
        raise _BoundaryError("verifier process start identity is unsafe")
    return value


def _expected_bind_values(paths: frozenset[str], *, writable: bool) -> set[str]:
    suffix = "rbind" if writable else "rbind"
    return {f"{item}:{item}:{suffix}" for item in paths}


def _split_property(value: str) -> set[str]:
    return {item for item in value.split() if item}


def _timespan_usec(value: str) -> int:
    parts = value.split()
    if not parts:
        raise _BoundaryError("verifier runtime limit is malformed")
    total = 0
    for part in parts:
        matched = _TIMESPAN_PART_RE.fullmatch(part)
        if matched is None:
            raise _BoundaryError("verifier runtime limit is malformed")
        total += int(matched.group("value")) * _TIMESPAN_MULTIPLIER[matched.group("unit")]
    return total


def _validate_properties(
    values: dict[str, str], *, policy: _MountPolicy, runtime_seconds: int,
) -> tuple[str, int, str]:
    invocation = values.get("InvocationID", "")
    cgroup = values.get("ControlGroup", "")
    try:
        pid = int(values.get("MainPID", "0"))
    except ValueError as exc:
        raise _BoundaryError("verifier transient-unit identity is malformed") from exc
    runtime_usec = _timespan_usec(values.get("RuntimeMaxUSec", ""))
    flags = (
        values.get("ActiveState") == "active"
        and values.get("Transient") == "yes"
        and values.get("Type") == "exec"
        and values.get("ExitType") == "main"
        and values.get("Restart") == "no"
        and values.get("KillMode") == "control-group"
        and values.get("SendSIGKILL") == "yes"
        and values.get("CollectMode") == "inactive-or-failed"
        and bool(values.get("ExecStart", "").strip())
        and values.get("PrivatePIDs") == "yes"
        and values.get("ProtectProc") == "ptraceable"
        and values.get("ProcSubset") == "all"
        and values.get("ProtectSystem") == "strict"
        and values.get("ProtectHome") == "tmpfs"
        and values.get("PrivateTmp") == "yes"
        and values.get("PrivateDevices") == "yes"
        and values.get("ProtectControlGroups") == "yes"
        and values.get("NoNewPrivileges") == "yes"
        and values.get("ProtectKernelTunables") == "yes"
        and values.get("ProtectKernelModules") == "yes"
        and values.get("ProtectKernelLogs") == "yes"
        and values.get("ProtectClock") == "yes"
        and values.get("LockPersonality") == "yes"
        and values.get("RestrictRealtime") == "yes"
        and values.get("RestrictSUIDSGID") == "yes"
        and values.get("UMask") == "0077"
        and _split_property(values.get("RestrictAddressFamilies", ""))
            == {"AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK"}
        and _split_property(values.get("InaccessiblePaths", ""))
            == {"/sys/fs/cgroup"}
        and _split_property(values.get("ReadOnlyPaths", ""))
            == {"/tmp", "/var/tmp"}
        and _split_property(values.get("TemporaryFileSystem", "")) == {"/run:ro"}
        and _split_property(values.get("BindReadOnlyPaths", ""))
            == _expected_bind_values(policy.read_only, writable=False)
        and _split_property(values.get("BindPaths", ""))
            == _expected_bind_values(policy.read_write, writable=True)
        and runtime_usec == runtime_seconds * 1_000_000
    )
    if (
        not flags
        or pid <= 1
        or not _INVOCATION_RE.fullmatch(invocation)
        or not cgroup
    ):
        raise _BoundaryError("verifier transient-unit properties are incomplete")
    return invocation, pid, cgroup


def _open_cgroup_events(cgroup: str, manager_cgroup: str, unit: str) -> int:
    if (
        not cgroup.startswith(manager_cgroup.rstrip("/") + "/")
        or Path(cgroup).name != unit
        or ".." in Path(cgroup).parts
    ):
        raise _BoundaryError("verifier cgroup identity is unsafe")
    path = Path("/sys/fs/cgroup" + cgroup) / "cgroup.events"
    try:
        return os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise _BoundaryError("verifier cgroup identity could not be pinned") from exc


def _pin_for_cleanup(unit: str, manager_cgroup: str) -> _PinnedService:
    """Pin a partially-started unit strongly enough to stop only that identity."""

    values = _show(
        unit, ("MainPID", "InvocationID", "ControlGroup", "ActiveState"),
    )
    invocation = values.get("InvocationID", "")
    cgroup = values.get("ControlGroup", "")
    try:
        pid = int(values.get("MainPID", "0"))
    except ValueError as exc:
        raise _BoundaryError("partial verifier identity is malformed") from exc
    if pid < 0 or not _INVOCATION_RE.fullmatch(invocation) or not cgroup:
        raise _BoundaryError("partial verifier identity is incomplete")
    events_fd = _open_cgroup_events(cgroup, manager_cgroup, unit)
    pidfd = -1
    try:
        # A service can finish between the property-failure observation and
        # cleanup.  InvocationID + cgroup.events still pins the exact transient
        # unit; there is simply no live PID to attach a pidfd to.
        if pid == 0:
            again = _show(
                unit, ("MainPID", "InvocationID", "ControlGroup", "ActiveState"),
            )
            if (
                again.get("MainPID") != "0"
                or again.get("InvocationID") != invocation
                or again.get("ControlGroup") != cgroup
            ):
                raise _BoundaryError("partial verifier identity changed during pinning")
            return _PinnedService(
                unit=unit, invocation_id=invocation, main_pid=0, cgroup=cgroup,
                starttime="", pidfd=-1, events_fd=events_fd,
            )
        pidfd = os.pidfd_open(pid, 0)
        starttime = _read_starttime(pid)
        if _read_proc_cgroup(pid) != cgroup or _pidfd_exited(pidfd):
            raise _BoundaryError("partial verifier process identity is unsafe")
        again = _show(
            unit, ("MainPID", "InvocationID", "ControlGroup", "ActiveState"),
        )
        if (
            again.get("MainPID") != str(pid)
            or again.get("InvocationID") != invocation
            or again.get("ControlGroup") != cgroup
            or _read_starttime(pid) != starttime
        ):
            raise _BoundaryError("partial verifier identity changed during pinning")
        return _PinnedService(
            unit=unit, invocation_id=invocation, main_pid=pid, cgroup=cgroup,
            starttime=starttime, pidfd=pidfd, events_fd=events_fd,
        )
    except BaseException:
        if pidfd >= 0:
            os.close(pidfd)
        os.close(events_fd)
        raise


def _pidfd_exited(pidfd: int) -> bool:
    readable, _, _ = select.select([pidfd], [], [], 0)
    return bool(readable)


def _pin_service(
    unit: str, *, policy: _MountPolicy, runtime_seconds: int,
    manager_cgroup: str, expected_argv: tuple[str, ...],
) -> _PinnedService:
    values = _show(unit)
    invocation, pid, cgroup = _validate_properties(
        values, policy=policy, runtime_seconds=runtime_seconds,
    )
    events_fd = _open_cgroup_events(cgroup, manager_cgroup, unit)
    pidfd = -1
    try:
        pidfd = os.pidfd_open(pid, 0)
        starttime = _read_starttime(pid)
        expected_executable = Path(expected_argv[0]).resolve(strict=True).stat()
        actual_executable = (Path("/proc") / str(pid) / "exe").stat()
        if (
            _read_proc_cgroup(pid) != cgroup
            or _read_proc_argv(pid) != expected_argv
            or (actual_executable.st_dev, actual_executable.st_ino)
                != (expected_executable.st_dev, expected_executable.st_ino)
            or _pidfd_exited(pidfd)
        ):
            raise _BoundaryError("verifier process identity is unsafe")
        again = _show(unit, ("MainPID", "InvocationID", "ControlGroup", "ActiveState"))
        if (
            again.get("MainPID") != str(pid)
            or again.get("InvocationID") != invocation
            or again.get("ControlGroup") != cgroup
            or again.get("ActiveState") != "active"
            or _read_starttime(pid) != starttime
        ):
            raise _BoundaryError("verifier process identity changed during pinning")
        return _PinnedService(
            unit=unit, invocation_id=invocation, main_pid=pid, cgroup=cgroup,
            starttime=starttime, pidfd=pidfd, events_fd=events_fd,
        )
    except BaseException:
        if pidfd >= 0:
            os.close(pidfd)
        os.close(events_fd)
        raise


def _events(fd: int, cgroup: str) -> dict[str, str]:
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        raw = os.read(fd, 4096).decode("ascii")
    except OSError as exc:
        if (
            exc.errno in {errno.ENXIO, errno.ENODEV}
            and not Path("/sys/fs/cgroup" + cgroup).exists()
        ):
            return {"populated": "0", "removed": "1"}
        raise _BoundaryError("pinned verifier cgroup proof is unavailable") from exc
    values = dict(
        line.split(maxsplit=1) for line in raw.splitlines() if " " in line
    )
    if values.get("populated") not in {"0", "1"}:
        raise _BoundaryError("pinned verifier cgroup proof is malformed")
    return values


def _identity_still_matches(pinned: _PinnedService) -> bool:
    try:
        values = _show(
            pinned.unit, ("MainPID", "InvocationID", "ControlGroup", "ActiveState"),
        )
    except _BoundaryError:
        return False
    return (
        values.get("MainPID") == str(pinned.main_pid)
        and values.get("InvocationID") == pinned.invocation_id
        and values.get("ControlGroup") == pinned.cgroup
    )


def _stop_and_prove_empty(pinned: _PinnedService) -> None:
    if _events(pinned.events_fd, pinned.cgroup)["populated"] != "0":
        if not _identity_still_matches(pinned):
            raise _BoundaryError("refusing to stop an unpinned verifier service")
        completed = _run_manager(
            [_safe_binary("systemctl"), "--user", "stop", pinned.unit],
            timeout=_STOP_TIMEOUT, check=False,
        )
        if (
            completed.returncode != 0
            and _events(pinned.events_fd, pinned.cgroup)["populated"] != "0"
        ):
            raise _BoundaryError("verifier cgroup cleanup was rejected")
    deadline = time.monotonic() + _STOP_TIMEOUT
    while time.monotonic() < deadline:
        if _events(pinned.events_fd, pinned.cgroup)["populated"] == "0":
            return
        time.sleep(0.02)
    raise _BoundaryError("verifier cgroup remained populated after cleanup")


def _read_ready(process: subprocess.Popen[bytes], challenge: bytes) -> dict[str, object]:
    if process.stdout is None:
        raise _BoundaryError("verifier startup channel is unavailable")
    data = bytearray()
    deadline = time.monotonic() + _READY_TIMEOUT
    fd = process.stdout.fileno()
    while len(data) < wire.READY_FRAME_SIZE and time.monotonic() < deadline:
        remaining = max(0.0, deadline - time.monotonic())
        readable, _, _ = select.select([fd], [], [], min(0.1, remaining))
        if not readable:
            if process.poll() is not None:
                break
            continue
        chunk = os.read(fd, wire.READY_FRAME_SIZE - len(data))
        if not chunk:
            break
        data.extend(chunk)
    try:
        return wire.decode_ready(bytes(data), challenge=challenge)
    except wire.VerifierFrameError as exc:
        raise _BoundaryError("verifier startup attestation is invalid") from exc


def _validate_ready(pinned: _PinnedService, ready: dict[str, object]) -> None:
    expected_executable = Path(trusted_entry_argv()[0]).resolve(strict=True).stat()
    namespaces = ready.get("namespaces")
    if (
        ready.get("entry_pid") != 1
        or
        ready.get("executable")
            != (expected_executable.st_dev, expected_executable.st_ino)
        or not isinstance(namespaces, dict)
    ):
        raise _BoundaryError("verifier startup attestation is unsafe")
    for name in ("pid", "mnt", "user", "cgroup"):
        identity = namespaces.get(name)
        if (
            not isinstance(identity, tuple)
            or len(identity) != 2
            or not all(isinstance(item, int) for item in identity)
        ):
            raise _BoundaryError("verifier namespace attestation is malformed")
        try:
            observed = (Path("/proc") / str(pinned.main_pid) / "ns" / name).stat()
        except (OSError, PermissionError):
            observed = None
        if observed is not None and identity != (observed.st_dev, observed.st_ino):
            raise _BoundaryError("verifier namespace identity does not match")
    for name in ("pid", "mnt"):
        own = (Path("/proc/self/ns") / name).stat()
        if namespaces[name] == (own.st_dev, own.st_ino):
            raise _BoundaryError("verifier service lacks a private namespace")
    if (
        _pidfd_exited(pinned.pidfd)
        or _read_starttime(pinned.main_pid) != pinned.starttime
        or not _identity_still_matches(pinned)
    ):
        raise _BoundaryError("verifier identity changed before request release")


def _capture_to_eof(process: subprocess.Popen[bytes], timeout: float) -> bytes:
    if process.stdout is None:
        raise _BoundaryError("verifier result channel is unavailable")
    data = bytearray()
    deadline = time.monotonic() + timeout
    fd = process.stdout.fileno()
    while time.monotonic() < deadline:
        readable, _, _ = select.select([fd], [], [], min(0.1, deadline - time.monotonic()))
        if not readable:
            continue
        chunk = os.read(fd, 65536)
        if not chunk:
            remaining = max(0.0, deadline - time.monotonic())
            process.wait(timeout=remaining)
            return bytes(data)
        data.extend(chunk)
        if len(data) > _MAX_CAPTURE_BYTES:
            raise _BoundaryError("verifier result frame exceeded its limit")
    raise subprocess.TimeoutExpired(process.args, timeout)


def _close_process(process: subprocess.Popen[bytes]) -> None:
    if process.stdin is not None and not process.stdin.closed:
        try:
            process.stdin.close()
        except OSError:
            pass
    if process.poll() is None:
        try:
            process.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2.0)


class SystemdTrustedVerifierRunner:
    """Host-owned production adapter for :class:`VerifierRunRequest`."""

    def run(self, request: VerifierRunRequest) -> VerifierRunResult:
        try:
            return self._run(request)
        except TrustedVerifierTimeout:
            raise
        except BaseException as exc:
            raise TrustedVerifierUnavailable(
                "verifier security boundary unavailable"
            ) from exc

    def _run(self, request: VerifierRunRequest) -> VerifierRunResult:
        fixed_argv = trusted_entry_argv()
        if request.entry_argv != fixed_argv or request.cwd != "/":
            raise _BoundaryError("verifier trusted entry does not match")
        # Revalidate the provider at the privileged sink.  The launcher is not
        # a trust boundary: callers can construct VerifierRunRequest directly,
        # and a fake/metadata-lookalike executable must never reach
        # systemd-run (which would place provider credentials in its frame).
        if not request.provider_argv:
            raise _BoundaryError("verifier provider command is empty")
        try:
            expected_provider = Path(
                execution_security.resolve_trusted_codex_bin(request.provider_argv[0])
            )
        except execution_security.WorkerSecurityError as exc:
            raise _BoundaryError("verifier provider executable is unsafe") from exc
        if request.provider_argv[0] != str(expected_provider):
            raise _BoundaryError("verifier provider executable is not the official native CLI")
        policy = _mount_policy(request)
        provider_limit = request.timeout_seconds or 900
        if (
            isinstance(provider_limit, bool)
            or not isinstance(provider_limit, int)
            or provider_limit <= 0
        ):
            raise _BoundaryError("verifier timeout policy is unsafe")
        runtime_seconds = min(provider_limit + 30, 7 * 24 * 3600)
        frame = wire.encode_request(
            run_id=request.run_id,
            provider_argv=request.provider_argv,
            provider_environment=request.provider_environment,
            timeout_seconds=request.timeout_seconds,
            prompt=request.prompt,
        )
        manager_cgroup = _validated_manager_cgroup()
        unit = f"danus-verifier-{secrets.token_hex(16)}.service"
        command = [
            _safe_binary("systemd-run"), "--user", "--quiet", "--wait", "--pipe",
            "--collect", "--service-type=exec", f"--unit={unit}",
            "--working-directory=/",
        ]
        command.extend(
            f"--property={value}"
            for value in _service_properties(policy, runtime_seconds)
        )
        command.extend(("--", *fixed_argv))

        process: subprocess.Popen[bytes] | None = None
        pinned: _PinnedService | None = None
        timed_out = False
        output = b""
        try:
            process = subprocess.Popen(
                command, cwd="/", env=_manager_env(), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
            if process.stdin is None:
                raise _BoundaryError("verifier request channel is unavailable")
            deadline = time.monotonic() + _START_TIMEOUT
            last_error: BaseException | None = None
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    pinned = _pin_service(
                        unit, policy=policy, runtime_seconds=runtime_seconds,
                        manager_cgroup=manager_cgroup, expected_argv=fixed_argv,
                    )
                    break
                except (OSError, _BoundaryError) as exc:
                    last_error = exc
                    time.sleep(0.02)
            if pinned is None:
                raise _BoundaryError("verifier service identity could not be pinned") from last_error

            challenge = secrets.token_bytes(32)
            process.stdin.write(wire.encode_challenge(challenge))
            process.stdin.flush()
            ready = _read_ready(process, challenge)
            _validate_ready(pinned, ready)

            process.stdin.write(frame)
            process.stdin.close()
            process.stdin = None
            try:
                output = _capture_to_eof(process, provider_limit + 45.0)
            except subprocess.TimeoutExpired:
                timed_out = True
            _stop_and_prove_empty(pinned)
            if timed_out:
                raise TrustedVerifierTimeout("verifier provider timed out")
            if process.returncode != 0:
                raise _BoundaryError("verifier trusted entry exited unsuccessfully")
            try:
                metadata = wire.read_result(output)
            except wire.VerifierFrameError as exc:
                raise _BoundaryError("verifier trusted result is invalid") from exc
            if metadata.get("timed_out") is True:
                raise TrustedVerifierTimeout("verifier provider timed out")
            return VerifierRunResult(
                returncode=int(metadata["returncode"]),
                duration_seconds=float(metadata["duration_seconds"]),
                stdout_sha256=str(metadata["stdout_sha256"]),
                stdout_bytes=int(metadata["stdout_bytes"]),
                descendants_empty=True,
            )
        finally:
            cleanup_error: BaseException | None = None
            if pinned is None and process is not None:
                # Killing the systemd-run client is not cleanup: its service can
                # survive.  During any startup failure, make a bounded attempt
                # to pin the created unit's exact identity before touching it.
                cleanup_deadline = time.monotonic() + 3.0
                while time.monotonic() < cleanup_deadline:
                    try:
                        pinned = _pin_for_cleanup(unit, manager_cgroup)
                        break
                    except (OSError, _BoundaryError) as exc:
                        cleanup_error = exc
                        if process.poll() is not None:
                            try:
                                _show(unit, ("InvocationID",))
                            except _BoundaryError:
                                # The unique unit never appeared or has already
                                # been collected; there is no service to stop.
                                cleanup_error = None
                                break
                        time.sleep(0.02)
            if pinned is not None:
                try:
                    _stop_and_prove_empty(pinned)
                except BaseException as exc:
                    cleanup_error = exc
                if pinned.pidfd >= 0:
                    os.close(pinned.pidfd)
                os.close(pinned.events_fd)
            if process is not None:
                _close_process(process)
            if cleanup_error is not None:
                raise _BoundaryError("verifier cgroup cleanup proof failed") from cleanup_error


DEFAULT_SYSTEMD_RUNNER = SystemdTrustedVerifierRunner()


__all__ = ["DEFAULT_SYSTEMD_RUNNER", "SystemdTrustedVerifierRunner"]
