"""Host-owned systemd/cgroup-v2 supervisor for Worker process trees.

Process groups are not a security boundary: a model-created child can call
``setsid()``, close every inherited descriptor, and outlive its leader.  A
systemd user service and dedicated slice provide kernel-enforced membership
which those descendants cannot leave.  The durable ledger is Project-external
and binds the canonical Worker path to the unit's systemd ``InvocationID``.

There is intentionally no direct-process production fallback.  Tests which do
not exercise the real manager inject/mask these functions at their call seam.
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import select
import shutil
import stat
import struct
import subprocess
import time
from typing import Iterable

from danus.secure_io import (
    SecureIOError,
    atomic_write_text,
    ensure_private_dir,
    read_private_bytes,
    secure_unlink,
)

from . import layout as L


class SystemdBoundaryError(RuntimeError):
    """The host cgroup supervisor is absent, stale, or unsafe."""


_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKER_ENTRY = (_REPO_ROOT / "danus" / "execution" / "worker_entry.py").resolve()
_UNIT_RE = re.compile(
    r"^(?:danus-worker-[0-9a-f]{20}\.(?:service|slice)|"
    r"danus-provider-[0-9a-f]{20}-[0-9a-f]{16}\.service)$"
)
_INVOCATION_RE = re.compile(r"^[0-9a-f]{32}$")
_ENV_FILE = "worker-environment.json"
_LEDGER_FILE = "unit.json"
_EXIT_FILE = "exit-proof.json"
_SCHEMA = 2
_RESOLVER_PATH = Path("/run/systemd/resolve/stub-resolv.conf")

_WORKER_UNIT_PROPERTIES = (
    "LoadState", "MainPID", "InvocationID", "ControlGroup", "ActiveState",
    "SubState", "Transient", "CollectMode", "Type", "ExitType", "Restart",
    "TimeoutStopUSec", "KillMode", "SendSIGKILL", "Slice", "ExecStart",
    "WorkingDirectory", "StandardOutput", "StandardError", "SyslogLevel",
)
_WORKER_SLICE_PROPERTIES = (
    "LoadState", "ControlGroup", "ActiveState", "InvocationID", "Transient",
    "CollectMode",
)

# Exact host variables the trusted loop may need.  In particular no Web
# lifecycle/artifact capability, cookie/password, GitHub, or tunnel variable is
# admitted.  The provider receives a smaller whitelist again in security.py.
_WORKER_HOST_ENV = {
    "DANUS_RUNTIME", "DANUS_AGENTS_ROOT", "DANUS_WORKER_CONTRACT",
    "DANUS_WORKER_SKILLS", "DANUS_CODEX_BIN", "CODEX_BIN",
    "DANUS_CODEX_MODEL", "DANUS_CODEX_EFFORT", "DANUS_NODE",
    "DANUS_CODEX_JS", "CODEX_HOME", "OPENAI_API_KEY",
    "DANUS_CODEX_API_KEY", "OPENAI_BASE_URL", "CODEX_API_BASE_URL",
    "OPENAI_CHATGPT_BASE_URL", "CODEX_CHATGPT_BASE_URL", "SSL_CERT_FILE",
    "SSL_CERT_DIR", "DANUS_VERIFY_URL", "DANUS_VERIFY_TIMEOUT",
    "DANUS_VERIFY_CAPABILITY_SECRET_FILE", "DANUS_ROUND_HARD_TIMEOUT",
    "DANUS_ROUND_BEAT", "DANUS_MAX_CONSEC_FAILURES",
    "DANUS_MAX_ROUNDS", "DANUS_RUN_DEADLINE",
}


def _safe_binary(name: str) -> str:
    value = shutil.which(name, path="/usr/bin:/bin")
    if not value:
        raise SystemdBoundaryError("required systemd supervisor binary is unavailable")
    path = Path(value).resolve()
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.getuid()} or info.st_mode & 0o002:
        raise SystemdBoundaryError("systemd supervisor binary has unsafe ownership or mode")
    return str(path)


def _manager_env() -> dict[str, str]:
    """Derive the user-bus locator from uid; never inherit it from a Worker."""

    uid = os.getuid()
    runtime = Path("/run/user") / str(uid)
    bus = runtime / "bus"
    try:
        info = runtime.lstat()
        bus_info = bus.lstat()
    except OSError as exc:
        raise SystemdBoundaryError("systemd user manager endpoint is unavailable") from exc
    if (
        not stat.S_ISDIR(info.st_mode) or info.st_uid != uid
        or not stat.S_ISSOCK(bus_info.st_mode) or bus_info.st_uid != uid
    ):
        raise SystemdBoundaryError("systemd user manager endpoint is unsafe")
    home = pwd.getpwuid(uid).pw_dir
    return {
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={bus}",
        "XDG_RUNTIME_DIR": str(runtime),
        "HOME": home,
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
    }


def manager_env() -> dict[str, str]:
    """Public copy for the trusted systemd-run controller only."""
    return dict(_manager_env())


def _run_manager(
    argv: Iterable[str], *, timeout: float = 15.0, check: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            list(argv), cwd="/", env=_manager_env(), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemdBoundaryError("systemd user manager request failed") from exc
    if check and completed.returncode != 0:
        raise SystemdBoundaryError("systemd user manager rejected a boundary request")
    return completed


def _show(unit: str, properties: Iterable[str]) -> dict[str, str]:
    if not _UNIT_RE.fullmatch(unit):
        raise SystemdBoundaryError("invalid Danus transient unit name")
    args = [_safe_binary("systemctl"), "--user", "show", unit, "--no-pager"]
    for prop in properties:
        args.extend(["--property", prop])
    completed = _run_manager(args, check=False)
    if completed.returncode != 0:
        raise SystemdBoundaryError("Danus transient unit is unavailable")
    result: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key] = value
    return result


def validate_user_manager() -> str:
    """Return the exact trusted user-manager cgroup after validating uid."""

    systemctl = _safe_binary("systemctl")
    completed = _run_manager([
        systemctl, "--user", "show", "--property", "ControlGroup",
        "--property", "Version", "--no-pager",
    ])
    values = dict(
        line.split("=", 1) for line in completed.stdout.splitlines() if "=" in line
    )
    expected = f"/user.slice/user-{os.getuid()}.slice/user@{os.getuid()}.service"
    if values.get("ControlGroup") != expected or not values.get("Version"):
        raise SystemdBoundaryError("systemd user manager identity does not match this uid")
    cgroup = Path("/sys/fs/cgroup" + expected)
    try:
        if "0::" not in Path("/proc/self/cgroup").read_text(encoding="ascii"):
            raise SystemdBoundaryError("unified cgroup v2 is required")
        if not cgroup.is_dir():
            raise SystemdBoundaryError("systemd user manager cgroup is unavailable")
    except OSError as exc:
        raise SystemdBoundaryError("cannot validate the systemd user manager cgroup") from exc
    return expected


def _run_system_manager(
    argv: Iterable[str], *, timeout: float = 15.0,
) -> subprocess.CompletedProcess[str]:
    """Run a read-only query against the system manager with a fixed env."""

    try:
        completed = subprocess.run(
            list(argv), cwd="/", env={
                "HOME": pwd.getpwuid(os.getuid()).pw_dir,
                "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
            }, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemdBoundaryError("system manager identity query failed") from exc
    if completed.returncode != 0:
        raise SystemdBoundaryError("system manager rejected the identity query")
    return completed


def _manager_identity() -> dict[str, object]:
    """Pin the durable identity of this uid's ``user@.service`` manager."""

    manager_cgroup = validate_user_manager()
    unit = f"user@{os.getuid()}.service"
    completed = _run_system_manager([
        _safe_binary("systemctl"), "show", unit, "--no-pager",
        "--property", "ActiveState", "--property", "InvocationID",
        "--property", "MainPID", "--property", "ControlGroup",
    ])
    values = dict(
        line.split("=", 1) for line in completed.stdout.splitlines() if "=" in line
    )
    invocation = values.get("InvocationID", "")
    try:
        main_pid = int(values.get("MainPID", "0"))
    except ValueError as exc:
        raise SystemdBoundaryError("user manager MainPID is invalid") from exc
    if (
        values.get("ActiveState") != "active"
        or values.get("ControlGroup") != manager_cgroup
        or not _INVOCATION_RE.fullmatch(invocation)
        or main_pid <= 1
    ):
        raise SystemdBoundaryError("user manager durable identity is incomplete")
    pin = _open_cgroup_pin(manager_cgroup)
    assert pin is not None
    try:
        return {
            "manager_unit": unit,
            "manager_invocation_id": invocation,
            "manager_main_pid": main_pid,
            "manager_cgroup": manager_cgroup,
            "manager_cgroup_dev": pin.dir_dev,
            "manager_cgroup_ino": pin.dir_ino,
            "manager_events_dev": pin.events_dev,
            "manager_events_ino": pin.events_ino,
        }
    finally:
        pin.close()


@dataclass
class _CgroupPin:
    """Open descriptors for one exact cgroup directory and events inode."""

    cgroup: str
    dir_fd: int
    events_fd: int
    dir_dev: int
    dir_ino: int
    events_dev: int
    events_ino: int

    def close(self) -> None:
        # Clear ownership before closing so repeated cleanup cannot close an
        # unrelated descriptor which later reused either fd number.
        events_fd, dir_fd = self.events_fd, self.dir_fd
        self.events_fd = -1
        self.dir_fd = -1
        for fd in (events_fd, dir_fd):
            if fd < 0:
                continue
            try:
                os.close(fd)
            except OSError:
                pass

    def populated(self) -> bool | None:
        """Read through the pinned inode; ``None`` means it was unlinked."""

        if not self.path_matches():
            return None
        try:
            raw = os.pread(self.events_fd, 4096, 0).decode("ascii")
        except OSError as exc:
            if exc.errno in {errno.ENXIO, errno.ENODEV, errno.ENOENT}:
                # ENODEV/ENXIO is only an empty proof when the exact cgroup
                # directory and events inode are now gone.  A path which was
                # replaced (or a still-present path with a transient read
                # error) is ambiguous and must fail closed.
                if not self.path_matches():
                    return None
                raise SystemdBoundaryError(
                    "pinned cgroup.events became unavailable while its path remained"
                ) from exc
            raise SystemdBoundaryError("cannot read pinned cgroup.events") from exc
        try:
            values = dict(
                line.split(maxsplit=1) for line in raw.splitlines() if " " in line
            )
        except ValueError as exc:
            raise SystemdBoundaryError("pinned cgroup.events is malformed") from exc
        if values.get("populated") not in {"0", "1"}:
            raise SystemdBoundaryError("pinned cgroup.events lacks populated state")
        # The cgroup may have been removed/recreated after the first path
        # check but while its old events fd remained readable.  Re-attest the
        # directory and pseudo-file so a same-name replacement never inherits
        # this pin's authority.
        if not self.path_matches():
            return None
        return values["populated"] == "1"

    def path_matches(self) -> bool:
        try:
            path = _cgroup_fs_path(self.cgroup)
            info = os.stat(path, follow_symlinks=False)
            events = os.stat(path / "cgroup.events", follow_symlinks=False)
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise SystemdBoundaryError("cannot restat the pinned cgroup") from exc
        if (info.st_dev, info.st_ino) != (self.dir_dev, self.dir_ino):
            raise SystemdBoundaryError("recorded cgroup path was replaced")
        if (events.st_dev, events.st_ino) != (self.events_dev, self.events_ino):
            raise SystemdBoundaryError("recorded cgroup.events was replaced")
        return True


def _cgroup_fs_path(cgroup: str) -> Path:
    path = Path(cgroup)
    if not cgroup.startswith("/") or ".." in path.parts or "\0" in cgroup:
        raise SystemdBoundaryError("invalid cgroup identity path")
    return Path("/sys/fs/cgroup" + cgroup)


def _open_cgroup_pin(
    cgroup: str, *, expected: tuple[int, int, int, int] | None = None,
    allow_missing: bool = False,
) -> _CgroupPin | None:
    """Open one cgroup without following links and optionally match its ledger."""

    path = _cgroup_fs_path(cgroup)
    dir_fd = -1
    events_fd = -1
    try:
        dir_fd = os.open(
            path,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        dir_info = os.fstat(dir_fd)
        events_fd = os.open(
            "cgroup.events", os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=dir_fd,
        )
        events_info = os.fstat(events_fd)
        observed = (
            dir_info.st_dev, dir_info.st_ino,
            events_info.st_dev, events_info.st_ino,
        )
        if expected is not None and observed != expected:
            raise SystemdBoundaryError("recorded cgroup inode identity does not match")
        pin = _CgroupPin(
            cgroup=cgroup, dir_fd=dir_fd, events_fd=events_fd,
            dir_dev=dir_info.st_dev, dir_ino=dir_info.st_ino,
            events_dev=events_info.st_dev, events_ino=events_info.st_ino,
        )
        dir_fd = -1
        events_fd = -1
        return pin
    except FileNotFoundError:
        if allow_missing:
            return None
        raise SystemdBoundaryError("recorded cgroup is unavailable")
    except OSError as exc:
        raise SystemdBoundaryError("cannot pin the recorded cgroup") from exc
    finally:
        if events_fd >= 0:
            try:
                os.close(events_fd)
            except OSError:
                pass
        if dir_fd >= 0:
            try:
                os.close(dir_fd)
            except OSError:
                pass


def _ledger_cgroup_identity(
    record: dict[str, object], prefix: str,
) -> tuple[int, int, int, int]:
    try:
        values = tuple(
            int(record[f"{prefix}_{suffix}"])
            for suffix in ("cgroup_dev", "cgroup_ino", "events_dev", "events_ino")
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise SystemdBoundaryError("Worker ledger cgroup identity is malformed") from exc
    if any(value <= 0 for value in values):
        raise SystemdBoundaryError("Worker ledger cgroup identity is invalid")
    return values  # type: ignore[return-value]


def _show_optional(unit: str, properties: Iterable[str]) -> dict[str, str] | None:
    values = _show(unit, tuple(dict.fromkeys(("LoadState", *properties))))
    if values.get("LoadState") == "not-found":
        return None
    return values


def _key(wl: L.WorkerLayout) -> str:
    canonical = str(wl.dir.resolve(strict=False)).encode("utf-8", errors="strict")
    return hashlib.sha256(canonical).hexdigest()[:20]


def worker_unit(wl: L.WorkerLayout) -> str:
    return f"danus-worker-{_key(wl)}.service"


def worker_slice(wl: L.WorkerLayout) -> str:
    return f"danus-worker-{_key(wl)}.slice"


def _control_dir(wl: L.WorkerLayout) -> Path:
    # Lazy import avoids security -> systemd_scope import cycles.
    from .security import control_dir
    return ensure_private_dir(control_dir(wl))


def ledger_path(wl: L.WorkerLayout) -> Path:
    return _control_dir(wl) / _LEDGER_FILE


def exit_proof_path(wl: L.WorkerLayout) -> Path:
    return _control_dir(wl) / _EXIT_FILE


def environment_path(wl: L.WorkerLayout) -> Path:
    return _control_dir(wl) / _ENV_FILE


def worker_environment(wl: L.WorkerLayout) -> dict[str, str]:
    env = {
        name: value for name in _WORKER_HOST_ENV
        if (value := os.environ.get(name))
    }
    env.update({
        "PATH": os.defpath,
        "HOME": pwd.getpwuid(os.getuid()).pw_dir,
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "PYTHONSAFEPATH": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "DANUS_BOUNDARY_LEDGER": str(ledger_path(wl)),
    })
    return env


def expected_worker_argv(wl: L.WorkerLayout) -> tuple[str, ...]:
    return (
        str(Path(os.sys.executable).absolute()), "-I", str(_WORKER_ENTRY),
        "--environment-file", str(environment_path(wl)), str(wl.dir.resolve()),
    )


def _read_boot_id() -> str:
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    except OSError as exc:
        raise SystemdBoundaryError("kernel boot identity is unavailable") from exc
    if not value:
        raise SystemdBoundaryError("kernel boot identity is invalid")
    return value


def _read_proc_cgroup(pid: int) -> str:
    try:
        text = (Path("/proc") / str(pid) / "cgroup").read_text(encoding="ascii")
    except OSError as exc:
        raise SystemdBoundaryError("Worker process cgroup identity is unavailable") from exc
    rows = [line.removeprefix("0::") for line in text.splitlines() if line.startswith("0::")]
    if len(rows) != 1:
        raise SystemdBoundaryError("Worker process is not in one unified cgroup")
    return rows[0]


def _read_proc_argv(pid: int) -> tuple[str, ...]:
    try:
        raw = (Path("/proc") / str(pid) / "cmdline").read_bytes()
    except OSError as exc:
        raise SystemdBoundaryError("Worker process argv identity is unavailable") from exc
    return tuple(
        item.decode("utf-8", errors="surrogateescape")
        for item in raw.split(b"\0") if item
    )


def _read_proc_start_time(pid: int) -> str:
    try:
        parts = (Path("/proc") / str(pid) / "stat").read_text(
            encoding="ascii"
        ).rsplit(")", 1)[1].split()
        value = parts[19]
    except (OSError, IndexError) as exc:
        raise SystemdBoundaryError("Worker process start identity is unavailable") from exc
    if not value:
        raise SystemdBoundaryError("Worker process start identity is invalid")
    return value


def _attest_worker_main_pid(
    wl: L.WorkerLayout, *, pid: int, unit: str, invocation: str,
    cgroup: str,
) -> tuple[tuple[str, ...], str]:
    """Pin MainPID while checking argv/cgroup/start identity on both sides."""

    opener = getattr(os, "pidfd_open", None)
    if opener is None:
        raise SystemdBoundaryError("pidfd support is required for Worker identity")
    try:
        pidfd = opener(pid, 0)
    except OSError as exc:
        raise SystemdBoundaryError("Worker MainPID could not be pinned") from exc
    try:
        if select.select([pidfd], [], [], 0)[0]:
            raise SystemdBoundaryError("Worker MainPID exited during identity capture")
        argv = _read_proc_argv(pid)
        observed_cgroup = _read_proc_cgroup(pid)
        start_time = _read_proc_start_time(pid)
        if argv != expected_worker_argv(wl) or observed_cgroup != cgroup:
            raise SystemdBoundaryError("Worker MainPID does not match its trusted entry")
        confirmed = _show(unit, ("LoadState", "MainPID", "InvocationID", "ControlGroup", "ActiveState"))
        if (
            confirmed.get("LoadState") != "loaded"
            or confirmed.get("MainPID") != str(pid)
            or confirmed.get("InvocationID") != invocation
            or confirmed.get("ControlGroup") != cgroup
            or confirmed.get("ActiveState") != "active"
            or _read_proc_argv(pid) != argv
            or _read_proc_cgroup(pid) != cgroup
            or _read_proc_start_time(pid) != start_time
            or select.select([pidfd], [], [], 0)[0]
        ):
            raise SystemdBoundaryError("Worker MainPID changed during identity capture")
        return argv, start_time
    except (OSError, ValueError) as exc:
        if isinstance(exc, SystemdBoundaryError):
            raise
        raise SystemdBoundaryError("Worker pidfd identity check failed") from exc
    finally:
        os.close(pidfd)


def _validate_live_properties(
    wl: L.WorkerLayout, unit_values: dict[str, str], slice_values: dict[str, str],
    *, expected_manager: dict[str, object] | None = None,
) -> dict[str, object]:
    unit = worker_unit(wl)
    slice_name = worker_slice(wl)
    try:
        pid = int(unit_values.get("MainPID", "0"))
    except ValueError as exc:
        raise SystemdBoundaryError("Worker transient unit has an invalid MainPID") from exc
    invocation = unit_values.get("InvocationID", "")
    slice_invocation = slice_values.get("InvocationID", "")
    unit_cgroup = unit_values.get("ControlGroup", "")
    slice_cgroup = slice_values.get("ControlGroup", "")
    if pid <= 1 or not _INVOCATION_RE.fullmatch(invocation) or not _INVOCATION_RE.fullmatch(slice_invocation):
        raise SystemdBoundaryError("Worker transient unit identity is incomplete")
    if (
        not unit_cgroup or not slice_cgroup
        or not unit_cgroup.startswith(slice_cgroup.rstrip("/") + "/")
        or not unit_cgroup.endswith("/" + unit)
        or not slice_cgroup.endswith("/" + slice_name)
    ):
        raise SystemdBoundaryError("Worker transient unit escaped its dedicated slice")
    manager = _manager_identity()
    if expected_manager is not None and any(
        manager.get(key) != expected_manager.get(key)
        for key in (
            "manager_unit", "manager_invocation_id", "manager_main_pid",
            "manager_cgroup", "manager_cgroup_dev", "manager_cgroup_ino",
            "manager_events_dev", "manager_events_ino",
        )
    ):
        raise SystemdBoundaryError("user manager changed during Worker start")
    if not slice_cgroup.startswith(str(manager["manager_cgroup"]).rstrip("/") + "/"):
        raise SystemdBoundaryError("Worker slice is outside the validated user manager")
    expected_unit = {
        "LoadState": "loaded", "ActiveState": "active", "SubState": "running",
        "Transient": "yes", "CollectMode": "inactive-or-failed", "Type": "exec",
        "ExitType": "main", "Restart": "no", "TimeoutStopUSec": "5s",
        "KillMode": "control-group", "SendSIGKILL": "yes", "Slice": slice_name,
        "WorkingDirectory": "/", "StandardOutput": "null", "StandardError": "null",
        "SyslogLevel": "5",
    }
    expected_slice = {
        "LoadState": "loaded", "ActiveState": "active", "Transient": "no",
        "CollectMode": "inactive",
    }
    if any(unit_values.get(key) != value for key, value in expected_unit.items()) or any(
        slice_values.get(key) != value for key, value in expected_slice.items()
    ) or not unit_values.get("ExecStart", "").strip():
        raise SystemdBoundaryError("Worker transient unit security properties are incomplete")
    argv, start_time = _attest_worker_main_pid(
        wl, pid=pid, unit=unit, invocation=invocation, cgroup=unit_cgroup,
    )
    unit_pin = _open_cgroup_pin(unit_cgroup)
    slice_pin = _open_cgroup_pin(slice_cgroup)
    assert unit_pin is not None and slice_pin is not None
    try:
        if not unit_pin.path_matches() or not slice_pin.path_matches():
            raise SystemdBoundaryError("Worker cgroup disappeared during identity capture")
        if unit_pin.populated() is not True or slice_pin.populated() is not True:
            raise SystemdBoundaryError("Worker exited before its durable identity was published")
        record: dict[str, object] = {
            "schema": _SCHEMA,
            "worker_dir": str(wl.dir.resolve()),
            "unit": unit,
            "slice": slice_name,
            "main_pid": pid,
            "main_pid_start_time": start_time,
            "worker_argv": list(argv),
            "invocation_id": invocation,
            "slice_invocation_id": slice_invocation,
            "unit_cgroup": unit_cgroup,
            "slice_cgroup": slice_cgroup,
            "unit_cgroup_dev": unit_pin.dir_dev,
            "unit_cgroup_ino": unit_pin.dir_ino,
            "unit_events_dev": unit_pin.events_dev,
            "unit_events_ino": unit_pin.events_ino,
            "slice_cgroup_dev": slice_pin.dir_dev,
            "slice_cgroup_ino": slice_pin.dir_ino,
            "slice_events_dev": slice_pin.events_dev,
            "slice_events_ino": slice_pin.events_ino,
            "boot_id": _read_boot_id(),
            "started_at": time.time(),
            "service_properties": {
                key: unit_values.get(key, "") for key in _WORKER_UNIT_PROPERTIES
            },
            "slice_properties": {
                key: slice_values.get(key, "") for key in _WORKER_SLICE_PROPERTIES
            },
            # Preserve the narrow flat interface consumed by provider startup.
            "exec_start": unit_values.get("ExecStart", ""),
            "type": unit_values.get("Type", ""),
            "exit_type": unit_values.get("ExitType", ""),
            "restart": unit_values.get("Restart", ""),
            "kill_mode": unit_values.get("KillMode", ""),
            "send_sigkill": unit_values.get("SendSIGKILL", ""),
            "transient": unit_values.get("Transient", ""),
        }
        record.update(manager)
        return record
    finally:
        unit_pin.close()
        slice_pin.close()


def read_ledger(wl: L.WorkerLayout) -> dict[str, object] | None:
    path = ledger_path(wl)
    try:
        raw = read_private_bytes(path, minimum=2, maximum=16384)
    except FileNotFoundError:
        return None
    except (OSError, SecureIOError) as exc:
        raise SystemdBoundaryError("Worker boundary ledger is unavailable or unsafe") from exc
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemdBoundaryError("Worker boundary ledger is malformed") from exc
    if not isinstance(value, dict) or value.get("schema") != _SCHEMA:
        raise SystemdBoundaryError("Worker boundary ledger has an unsupported schema")
    expected: dict[str, object] = {
        "worker_dir": str(wl.dir.resolve()),
        "unit": worker_unit(wl),
        "slice": worker_slice(wl),
        "manager_unit": f"user@{os.getuid()}.service",
        "manager_cgroup": f"/user.slice/user-{os.getuid()}.slice/user@{os.getuid()}.service",
        "worker_argv": list(expected_worker_argv(wl)),
    }
    if any(value.get(key) != item for key, item in expected.items()):
        raise SystemdBoundaryError("Worker boundary ledger identity does not match")
    if any(
        not _INVOCATION_RE.fullmatch(str(value.get(key, "")))
        for key in ("invocation_id", "slice_invocation_id", "manager_invocation_id")
    ):
        raise SystemdBoundaryError("Worker boundary ledger invocation is invalid")
    try:
        main_pid = int(value.get("main_pid", 0))
        manager_main_pid = int(value.get("manager_main_pid", 0))
    except (TypeError, ValueError) as exc:
        raise SystemdBoundaryError("Worker boundary ledger PID identity is malformed") from exc
    if (
        main_pid <= 1 or manager_main_pid <= 1
        or not isinstance(value.get("main_pid_start_time"), str)
        or not value.get("main_pid_start_time")
        or not isinstance(value.get("boot_id"), str) or not value.get("boot_id")
        or not isinstance(value.get("service_properties"), dict)
        or not isinstance(value.get("slice_properties"), dict)
    ):
        raise SystemdBoundaryError("Worker boundary ledger process identity is invalid")
    manager_cgroup = str(value["manager_cgroup"])
    slice_cgroup = str(value.get("slice_cgroup", ""))
    unit_cgroup = str(value.get("unit_cgroup", ""))
    if (
        not slice_cgroup.startswith(manager_cgroup.rstrip("/") + "/")
        or not unit_cgroup.startswith(slice_cgroup.rstrip("/") + "/")
        or not unit_cgroup.endswith("/" + worker_unit(wl))
        or not slice_cgroup.endswith("/" + worker_slice(wl))
    ):
        raise SystemdBoundaryError("Worker boundary ledger cgroup hierarchy is invalid")
    for prefix in ("manager", "unit", "slice"):
        _ledger_cgroup_identity(value, prefix)
    return value


@dataclass(frozen=True)
class WorkerBoundaryStatus:
    """Caller-facing lifecycle state with no PID/PGID authority leakage."""

    state: str
    pid: int | None
    populated: bool
    unit: str
    slice: str
    invocation_id: str | None = None
    reason: str | None = None

    @property
    def alive(self) -> bool:
        return self.state == "active"

    @property
    def reclaimable(self) -> bool:
        return self.state == "orphaned"


@dataclass
class ManagedWorker:
    """Minimal Popen-like handle returned to existing orchestration code."""

    pid: int
    unit: str
    slice: str
    invocation_id: str
    worker_dir: str

    def poll(self) -> int | None:
        try:
            status = inspect_worker_boundary(L.WorkerLayout(Path(self.worker_dir)))
        except SystemdBoundaryError:
            return 1
        if status.invocation_id not in {None, self.invocation_id}:
            return 1
        if status.state in {"active", "stopping"}:
            return None
        return 1

    def terminate(self) -> None:
        stop_worker_boundary(
            L.WorkerLayout(Path(self.worker_dir)), force=True,
        )

    def kill(self) -> None:
        self.terminate()

    def wait(self, timeout: float | None = None) -> int:
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            result = self.poll()
            if result is not None:
                return result
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(self.unit, timeout)
            time.sleep(0.02)


def _events_from_fd(
    fd: int, cgroup: str, *, expected: tuple[int, int, int, int] | None = None,
) -> dict[str, str]:
    """Read a cgroup.events fd, accepting removal only for its exact inode.

    ``expected`` is the directory/events ``(dev, ino)`` tuple captured by
    ``_open_cgroup_pin``.  The optional argument keeps this low-level helper
    useful to focused tests while production uses ``_events_from_pin``.
    """

    cgroup_path = _cgroup_fs_path(cgroup)
    if expected is not None:
        try:
            fd_info = os.fstat(fd)
            path_info = os.stat(cgroup_path, follow_symlinks=False)
            events_info = os.stat(cgroup_path / "cgroup.events", follow_symlinks=False)
        except FileNotFoundError:
            path_info = events_info = None
            fd_info = os.fstat(fd)
        except OSError as exc:
            raise SystemdBoundaryError("cannot validate provider cgroup identity") from exc
        if fd_info is not None and (
            (fd_info.st_dev, fd_info.st_ino) != expected[2:]
            or (path_info is not None and (path_info.st_dev, path_info.st_ino) != expected[:2])
            or (events_info is not None and (events_info.st_dev, events_info.st_ino) != expected[2:])
        ):
            raise SystemdBoundaryError("provider cgroup identity was replaced")
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        raw = os.read(fd, 4096).decode("ascii")
    except OSError as exc:
        # Kernels return ENXIO or ENODEV from an fd whose cgroup was removed.
        # This is a kernel-empty proof only for the exact cgroup path validated
        # and pinned at scope creation, and only when that path is now absent.
        # Any error while a path of that identity still exists remains fatal.
        if (
            exc.errno in {errno.ENXIO, errno.ENODEV}
            and not cgroup_path.exists()
        ):
            return {"populated": "0", "removed": "1"}
        raise SystemdBoundaryError("cannot read the pinned provider cgroup proof") from exc
    values = dict(
        line.split(maxsplit=1) for line in raw.splitlines() if " " in line
    )
    if values.get("populated") not in {"0", "1"}:
        raise SystemdBoundaryError("provider cgroup proof is malformed")
    return values


def _events_from_pin(pin: _CgroupPin) -> dict[str, str]:
    """Read one provider cgroup proof while checking its pinned identity."""

    # Validate the path/inode before reading.  This turns a same-name cgroup
    # replacement into a hard boundary error instead of allowing a stale fd to
    # be interpreted as proof for a new provider service.
    if not pin.path_matches():
        return {"populated": "0", "removed": "1"}
    try:
        raw = os.pread(pin.events_fd, 4096, 0).decode("ascii")
    except OSError as exc:
        if exc.errno in {errno.ENXIO, errno.ENODEV, errno.ENOENT}:
            if not pin.path_matches():
                return {"populated": "0", "removed": "1"}
        raise SystemdBoundaryError(
            "cannot read the pinned provider cgroup proof"
        ) from exc
    values = dict(
        line.split(maxsplit=1) for line in raw.splitlines() if " " in line
    )
    if values.get("populated") not in {"0", "1"}:
        raise SystemdBoundaryError("provider cgroup proof is malformed")
    if not pin.path_matches():
        return {"populated": "0", "removed": "1"}
    return values


@dataclass
class ManagedProvider:
    """Provider service whose complete cgroup is pinned by an fd."""

    process: subprocess.Popen
    unit: str
    invocation_id: str
    cgroup: str
    cgroup_pin: _CgroupPin
    main_pid: int
    prompt_sent: bool = False

    @property
    def pid(self) -> int:
        return self.main_pid

    @property
    def stdout(self):
        return self.process.stdout

    @property
    def events_fd(self) -> int:
        """Compatibility view for diagnostics; ownership stays with cgroup_pin."""

        return self.cgroup_pin.events_fd

    def send_prompt(self, prompt: str) -> None:
        if self.prompt_sent or self.process.stdin is None:
            raise SystemdBoundaryError("provider prompt channel was already consumed")
        payload = prompt.encode("utf-8")
        if not payload or len(payload) > 8 * 1024 * 1024:
            raise SystemdBoundaryError("provider prompt has an unsafe size")
        try:
            self.process.stdin.write(struct.pack("!I", len(payload)) + payload)
            self.process.stdin.close()
        except (BrokenPipeError, OSError, ValueError) as exc:
            raise SystemdBoundaryError("provider prompt channel failed") from exc
        self.prompt_sent = True

    def poll(self):
        return self.process.poll()

    def _empty(self) -> bool:
        return _events_from_pin(self.cgroup_pin)["populated"] == "0"

    def _stop_scope(self, timeout: float = 10.0) -> None:
        if not self._empty():
            current = _show(self.unit, (
                "InvocationID", "ActiveState", "ControlGroup", "MainPID",
            ))
            if (
                current.get("InvocationID") != self.invocation_id
                or current.get("ControlGroup") != self.cgroup
                or current.get("MainPID") != str(self.main_pid)
            ):
                raise SystemdBoundaryError("provider service identity changed before stop")
            completed = _run_manager(
                [_safe_binary("systemctl"), "--user", "stop", self.unit],
                timeout=timeout, check=False,
            )
            if completed.returncode != 0 and not self._empty():
                raise SystemdBoundaryError("systemd rejected provider service cleanup")
        deadline = time.monotonic() + timeout
        while not self._empty() and time.monotonic() < deadline:
            time.sleep(0.02)
        if not self._empty():
            raise SystemdBoundaryError("provider service remained populated after stop")

    def wait(self, timeout: float | None = None) -> int:
        try:
            rc = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            raise
        # Even a clean leader exit must not leave a double-fork/setsid child.
        self._stop_scope()
        return rc

    def terminate(self) -> None:
        self._stop_scope()

    def kill(self) -> None:
        self._stop_scope()

    def close(self) -> None:
        self.cgroup_pin.close()
        if self.process.stdin is not None and not self.process.stdin.closed:
            try:
                self.process.stdin.close()
            except (OSError, ValueError):
                pass


def _safe_unit_path(path: Path) -> str:
    value = str(path)
    if (
        not path.is_absolute() or "\0" in value
        or any(char.isspace() or ord(char) < 0x20 or char in ":\\" for char in value)
    ):
        raise SystemdBoundaryError("provider mount path cannot be represented safely")
    return value


def _provider_service_properties(
    wl: L.WorkerLayout, codex_bin: str, gateway, runtime_limit: int,
) -> tuple[list[str], set[str], set[str]]:
    from . import security

    read_only = security.provider_read_only_paths(wl, codex_bin)
    writable = security.provider_writable_paths(wl)
    ro_specs = {_safe_unit_path(path) for path in read_only}
    resolver = _safe_unit_path(_RESOLVER_PATH)
    try:
        resolver_info = _RESOLVER_PATH.stat()
    except OSError as exc:
        raise SystemdBoundaryError("host DNS resolver is unavailable") from exc
    if not stat.S_ISREG(resolver_info.st_mode) or resolver_info.st_mode & 0o002:
        raise SystemdBoundaryError("host DNS resolver has unsafe identity")
    ro_specs.add(resolver)
    socket_source = _safe_unit_path(gateway.socket_path)
    socket_destination = _safe_unit_path(gateway.provider_socket_path)
    ro_specs.add(f"{socket_source}:{socket_destination}")
    rw_specs = {_safe_unit_path(path) for path in writable}
    seconds = _provider_runtime_seconds(runtime_limit)
    properties = [
        "KillMode=control-group", "SendSIGKILL=yes", "TimeoutStopSec=5s",
        f"RuntimeMaxSec={seconds}", "ExitType=main", "Restart=no",
        "PrivatePIDs=yes", "ProtectProc=ptraceable", "ProcSubset=all",
        "ProtectSystem=strict", "ProtectHome=tmpfs", "PrivateTmp=yes",
        "PrivateDevices=yes", "ProtectControlGroups=strict", "NoNewPrivileges=yes",
        "ProtectKernelTunables=yes", "ProtectKernelModules=yes",
        "ProtectKernelLogs=yes", "ProtectClock=yes", "LockPersonality=yes",
        "RestrictRealtime=yes", "RestrictSUIDSGID=yes", "UMask=0077",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
        "TemporaryFileSystem=/run:ro", "InaccessiblePaths=/sys/fs/cgroup",
    ]
    properties.extend(f"BindReadOnlyPaths={value}" for value in sorted(ro_specs))
    properties.extend(f"BindPaths={value}" for value in sorted(rw_specs))
    return properties, ro_specs, rw_specs


def _provider_runtime_seconds(runtime_limit: int) -> int:
    seconds = runtime_limit if runtime_limit > 0 else 14400
    return max(30, min(seconds + 30, 7 * 24 * 3600))


def _systemd_timespan_usec(value: str) -> int | None:
    factors = {
        "us": 1, "ms": 1_000, "s": 1_000_000, "min": 60_000_000,
        "h": 3_600_000_000, "d": 86_400_000_000, "w": 604_800_000_000,
    }
    total = 0
    tokens = value.split()
    if not tokens:
        return None
    for token in tokens:
        match = re.fullmatch(r"([0-9]+)(us|ms|s|min|h|d|w)", token)
        if match is None:
            return None
        total += int(match.group(1)) * factors[match.group(2)]
    return total


_PROVIDER_SHOW_PROPERTIES = (
    "MainPID", "InvocationID", "ControlGroup", "ActiveState", "SubState",
    "Transient", "Type", "ExitType", "Restart", "KillMode", "SendSIGKILL",
    "Slice", "BindsTo", "PartOf", "After", "CollectMode", "ExecStart",
    "PrivatePIDs", "ProtectProc", "ProcSubset", "ProtectSystem", "ProtectHome",
    "PrivateTmp", "PrivateDevices", "ProtectControlGroups", "NoNewPrivileges",
    "ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs",
    "ProtectClock", "LockPersonality", "RestrictRealtime", "RestrictSUIDSGID",
    "RestrictAddressFamilies", "UMask", "InaccessiblePaths", "BindPaths",
    "BindReadOnlyPaths", "TemporaryFileSystem", "RuntimeMaxUSec",
    "TimeoutStopUSec", "WorkingDirectory",
)


def _bind_show_values(value: str) -> set[str]:
    return {item for item in value.split() if item}


def _validate_provider_service(
    *, unit: str, record: dict[str, object], values: dict[str, str],
    expected_argv: tuple[str, ...], ro_specs: set[str], rw_specs: set[str],
    gateway, expected_runtime_seconds: int, expected_invocation: str = "",
    expected_cgroup: str = "", expected_main_pid: int = 0,
) -> tuple[str, str, int]:
    invocation = values.get("InvocationID", "")
    cgroup = values.get("ControlGroup", "")
    try:
        main_pid = int(values.get("MainPID", "0"))
    except ValueError as exc:
        raise SystemdBoundaryError("provider service MainPID is invalid") from exc
    expected_ro = {
        f"{item}:{item}:rbind" if ":" not in item else f"{item}:rbind"
        for item in ro_specs
    }
    expected_rw = {f"{item}:{item}:rbind" for item in rw_specs}
    flags = (
        values.get("ActiveState") == "active"
        and values.get("Transient") == "yes"
        and values.get("Type") == "exec"
        and values.get("ExitType") == "main"
        and values.get("Restart") == "no"
        and values.get("KillMode") == "control-group"
        and values.get("SendSIGKILL") == "yes"
        and values.get("Slice") == record.get("slice")
        and values.get("CollectMode") == "inactive-or-failed"
        and bool(values.get("ExecStart", "").strip())
        and values.get("WorkingDirectory") == "/"
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
        and set(values.get("RestrictAddressFamilies", "").split())
            == {"AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK"}
        and set(values.get("InaccessiblePaths", "").split())
            == {"/sys/fs/cgroup"}
        and set(values.get("TemporaryFileSystem", "").split()) == {"/run:ro"}
        and _bind_show_values(values.get("BindReadOnlyPaths", "")) == expected_ro
        and _bind_show_values(values.get("BindPaths", "")) == expected_rw
        and values.get("TimeoutStopUSec") == "5s"
        and _systemd_timespan_usec(values.get("RuntimeMaxUSec", ""))
            == expected_runtime_seconds * 1_000_000
        and str(record["unit"]) in values.get("BindsTo", "").split()
        and str(record["unit"]) in values.get("PartOf", "").split()
        and str(record["unit"]) in values.get("After", "").split()
    )
    if (
        not flags or not _INVOCATION_RE.fullmatch(invocation) or not cgroup
        or main_pid <= 1
        or (expected_invocation and invocation != expected_invocation)
        or (expected_cgroup and cgroup != expected_cgroup)
        or (expected_main_pid and main_pid != expected_main_pid)
        or not cgroup.startswith("/")
        or not cgroup.startswith(str(record["slice_cgroup"]).rstrip("/") + "/")
        or ".." in Path(cgroup).parts
        or "\0" in cgroup
        or _read_proc_cgroup(main_pid) != cgroup
        or _read_proc_argv(main_pid) != expected_argv
    ):
        raise SystemdBoundaryError("provider transient service properties are incomplete")
    return invocation, cgroup, main_pid


def _read_ready(
    stream, timeout: float, *, challenge: bytes, socket_dev: int, socket_ino: int,
) -> dict[str, tuple[int, int]]:
    from danus.gateway.fd_protocol import (
        PROVIDER_READY_SIZE,
        parse_provider_ready_attestation,
    )

    fd = stream.fileno()
    data = bytearray()
    deadline = time.monotonic() + timeout
    while len(data) < PROVIDER_READY_SIZE and time.monotonic() < deadline:
        remaining = max(0.0, deadline - time.monotonic())
        readable, _, _ = select.select([fd], [], [], min(0.1, remaining))
        if not readable:
            continue
        chunk = os.read(fd, PROVIDER_READY_SIZE - len(data))
        if not chunk:
            break
        data.extend(chunk)
    try:
        namespaces = parse_provider_ready_attestation(
            bytes(data), challenge=challenge, socket_dev=socket_dev,
            socket_ino=socket_ino,
        )
    except ValueError as exc:
        raise SystemdBoundaryError(
            "provider service emitted an invalid readiness attestation"
        ) from exc
    for namespace in ("pid", "mnt", "cgroup"):
        own = (Path("/proc/self/ns") / namespace).stat()
        if namespaces[namespace] == (own.st_dev, own.st_ino):
            raise SystemdBoundaryError("provider service did not receive private namespaces")
    return namespaces


def _cleanup_failed_provider(
    *, unit: str, record: dict[str, object], process: subprocess.Popen | None,
    created_invocation: str, created_cgroup: str, created_pin: _CgroupPin | None,
) -> None:
    """Stop the exact transient unit and prove its cgroup empty on every failure."""

    proof_pin = created_pin
    owns_proof_pin = False
    identity_error: SystemdBoundaryError | None = None
    values: dict[str, str] = {}
    try:
        try:
            values = _show(unit, ("InvocationID", "ControlGroup", "MainPID"))
        except SystemdBoundaryError:
            values = {}
        if values:
            invocation = values.get("InvocationID", "")
            cgroup = values.get("ControlGroup", "")
            try:
                main_pid = int(values.get("MainPID", "0"))
            except ValueError:
                main_pid = 0
            main_matches = True
            if main_pid > 1:
                try:
                    main_matches = _read_proc_cgroup(main_pid) == cgroup
                except SystemdBoundaryError:
                    main_matches = False
            if (
                not _INVOCATION_RE.fullmatch(invocation)
                or not cgroup.startswith(str(record["slice_cgroup"]).rstrip("/") + "/")
                or (created_invocation and invocation != created_invocation)
                or (created_cgroup and cgroup != created_cgroup)
                or not main_matches
            ):
                identity_error = SystemdBoundaryError(
                    "failed provider service identity could not be proven"
                )
            elif proof_pin is None:
                try:
                    proof_pin = _open_cgroup_pin(cgroup)
                    if proof_pin is None:
                        raise SystemdBoundaryError("provider cgroup disappeared")
                    owns_proof_pin = True
                except (OSError, SystemdBoundaryError):
                    identity_error = SystemdBoundaryError(
                        "failed provider cgroup could not be pinned for cleanup"
                    )

        stopped = _run_manager(
            [_safe_binary("systemctl"), "--user", "stop", unit],
            timeout=10.0, check=False,
        )
        if proof_pin is not None:
            proof_cgroup = created_cgroup or values.get("ControlGroup", "")
            if not proof_cgroup:
                raise SystemdBoundaryError("failed provider cgroup proof lost its identity")
            deadline = time.monotonic() + 10.0
            while (
                _events_from_pin(proof_pin)["populated"] != "0"
                and time.monotonic() < deadline
            ):
                time.sleep(0.02)
            if _events_from_pin(proof_pin)["populated"] != "0":
                raise SystemdBoundaryError("failed provider service remained populated")
        elif values and stopped.returncode != 0:
            raise SystemdBoundaryError("systemd rejected failed provider cleanup")
        elif not values and stopped.returncode == 0:
            raise SystemdBoundaryError(
                "failed provider service was stopped without a pinned empty proof"
            )
        if identity_error is not None:
            raise identity_error
    finally:
        if process is not None:
            if process.stdin is not None and not process.stdin.closed:
                try:
                    process.stdin.close()
                except (OSError, ValueError):
                    pass
            try:
                process.wait(timeout=7)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
        if owns_proof_pin and proof_pin is not None:
            proof_pin.close()


def start_provider_scope(
    wl: L.WorkerLayout, *, codex_bin: str, provider_command: list[str],
    provider_environment: dict[str, str], gateway, runtime_limit: int,
) -> ManagedProvider:
    """Launch one provider transient service and validate its READY barrier."""

    # Do not make the loop's earlier selector check the only guard.  This
    # function is the direct sink for a provider executable and must fail
    # closed even when called by a new production caller or an untrusted seam.
    from . import security
    codex_bin = security.validated_worker_codex_bin(codex_bin)
    record = read_ledger(wl)
    if record is None or int(record.get("main_pid", 0)) != os.getpid():
        raise SystemdBoundaryError("provider launch is outside its managed Worker unit")
    live_unit = _show(str(record["unit"]), (
        "InvocationID", "ControlGroup", "ActiveState", "Transient", "KillMode",
        "SendSIGKILL", "Slice",
    ))
    if (
        live_unit.get("InvocationID") != record.get("invocation_id")
        or live_unit.get("ControlGroup") != record.get("unit_cgroup")
        or live_unit.get("ActiveState") != "active"
        or live_unit.get("Transient") != "yes"
        or live_unit.get("KillMode") != "control-group"
        or live_unit.get("SendSIGKILL") != "yes"
        or live_unit.get("Slice") != record.get("slice")
        or _read_proc_cgroup(os.getpid()) != record.get("unit_cgroup")
    ):
        raise SystemdBoundaryError("managed Worker unit properties do not match its ledger")

    nonce = secrets.token_hex(8)
    ready_challenge = secrets.token_bytes(16)
    unit = f"danus-provider-{_key(wl)}-{nonce}.service"
    launcher = security.outer_sandbox_command(
        wl, codex_bin, provider_command, ready_challenge=ready_challenge,
        socket_dev=gateway.socket_dev, socket_ino=gateway.socket_ino,
    )
    properties, ro_specs, rw_specs = _provider_service_properties(
        wl, codex_bin, gateway, runtime_limit,
    )
    expected_runtime_seconds = _provider_runtime_seconds(runtime_limit)
    args = [
        _safe_binary("systemd-run"), "--user", "--quiet", "--wait", "--pipe",
        "--collect", "--service-type=exec",
        f"--unit={unit}", f"--slice={record['slice']}",
        "--property=WorkingDirectory=/",
        f"--property=BindsTo={record['unit']}",
        f"--property=PartOf={record['unit']}",
        f"--property=After={record['unit']}",
    ]
    args.extend(f"--property={value}" for value in properties)
    args.extend(["--", *launcher])
    process: subprocess.Popen | None = None
    created_invocation = ""
    created_cgroup = ""
    created_pin: _CgroupPin | None = None
    main_pid = 0
    proof_transferred = False
    try:
        process = subprocess.Popen(
            args, cwd="/", env=_manager_env(), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        assert process.stdin is not None and process.stdout is not None
        identity_deadline = time.monotonic() + 5.0
        values: dict[str, str] = {}
        while time.monotonic() < identity_deadline and process.poll() is None:
            try:
                values = _show(unit, _PROVIDER_SHOW_PROPERTIES)
                created_invocation, created_cgroup, main_pid = _validate_provider_service(
                    unit=unit, record=record, values=values,
                    expected_argv=tuple(launcher), ro_specs=ro_specs, rw_specs=rw_specs,
                    gateway=gateway, expected_runtime_seconds=expected_runtime_seconds,
                )
                # Pin both the cgroup directory and cgroup.events inode with
                # O_NOFOLLOW; a bare events fd plus a path string is not enough
                # to detect same-name cgroup replacement.
                created_pin = _open_cgroup_pin(created_cgroup)
                if created_pin is None:
                    raise SystemdBoundaryError("provider cgroup disappeared")
                break
            except (OSError, SystemdBoundaryError):
                pass
            time.sleep(0.01)
        if created_pin is None:
            raise SystemdBoundaryError("provider service identity could not be pinned")
        environment = json.dumps(
            provider_environment, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        if len(environment) < 2 or len(environment) > 65536:
            raise SystemdBoundaryError("provider environment frame has an unsafe size")
        process.stdin.write(struct.pack("!I", len(environment)) + environment)
        process.stdin.flush()
        namespaces = _read_ready(
            process.stdout, 10.0, challenge=ready_challenge,
            socket_dev=gateway.socket_dev, socket_ino=gateway.socket_ino,
        )
        values = _show(unit, _PROVIDER_SHOW_PROPERTIES)
        invocation, cgroup, main_pid = _validate_provider_service(
            unit=unit, record=record, values=values, expected_argv=tuple(launcher),
            ro_specs=ro_specs, rw_specs=rw_specs, gateway=gateway,
            expected_runtime_seconds=expected_runtime_seconds,
            expected_invocation=created_invocation, expected_cgroup=created_cgroup,
            expected_main_pid=main_pid,
        )
        gateway.authorize_provider(
            main_pid=main_pid, cgroup=cgroup, invocation_id=invocation,
            namespaces=namespaces,
            launcher_argv=launcher, provider_argv=provider_command,
        )
        managed = ManagedProvider(
            process=process, unit=unit, invocation_id=invocation,
            cgroup=cgroup, cgroup_pin=created_pin, main_pid=main_pid,
        )
        proof_transferred = True
        return managed
    except BaseException:
        try:
            _cleanup_failed_provider(
                unit=unit, record=record, process=process,
                created_invocation=created_invocation,
                created_cgroup=created_cgroup,
                created_pin=created_pin,
            )
        except BaseException as cleanup_error:
            raise SystemdBoundaryError(
                "provider launch failed and its cgroup cleanup could not be proven"
            ) from cleanup_error
        raise
    finally:
        if created_pin is not None and not proof_transferred:
            created_pin.close()


def start_worker(wl: L.WorkerLayout) -> ManagedWorker:
    """Start one Worker in a new validated transient service/slice."""

    manager_before = _manager_identity()
    existing = inspect_worker_boundary(wl)
    if existing.state == "active":
        raise SystemdBoundaryError("existing Worker boundary is already active")
    if existing.state == "orphaned":
        raise SystemdBoundaryError("existing Worker boundary is orphaned; reclaim is required")
    env_path = environment_path(wl)
    atomic_write_text(
        env_path, json.dumps(worker_environment(wl), sort_keys=True, separators=(",", ":")),
        mode=0o600,
    )
    unit = worker_unit(wl)
    slice_name = worker_slice(wl)
    systemd_run = _safe_binary("systemd-run")
    args = [
        systemd_run, "--user", "--quiet", "--collect", "--service-type=exec",
        f"--unit={unit}", f"--slice={slice_name}",
        "--property=WorkingDirectory=/",
        "--property=KillMode=control-group", "--property=SendSIGKILL=yes",
        "--property=TimeoutStopSec=5s", "--property=StandardOutput=null",
        "--property=StandardError=null", "--property=SyslogLevel=notice",
        "--", *expected_worker_argv(wl),
    ]
    created_invocation = ""
    published = False
    record: dict[str, object] | None = None
    cleanup_record: dict[str, object] | None = None
    last_error: Exception | None = None
    try:
        _run_manager(args, timeout=20.0)
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                unit_values = _show(unit, _WORKER_UNIT_PROPERTIES)
                created_invocation = unit_values.get("InvocationID", "")
                slice_values = _show(slice_name, _WORKER_SLICE_PROPERTIES)
                created_slice_invocation = slice_values.get("InvocationID", "")
                created_slice_cgroup = slice_values.get("ControlGroup", "")
                created_unit_cgroup = unit_values.get("ControlGroup", "")
                if (
                    _INVOCATION_RE.fullmatch(created_invocation)
                    and _INVOCATION_RE.fullmatch(created_slice_invocation)
                    and created_unit_cgroup.startswith(created_slice_cgroup.rstrip("/") + "/")
                    and created_slice_cgroup.endswith("/" + slice_name)
                ):
                    cleanup_pin = _open_cgroup_pin(created_slice_cgroup)
                    assert cleanup_pin is not None
                    try:
                        cleanup_record = {
                            "unit": unit, "slice": slice_name,
                            "invocation_id": created_invocation,
                            "slice_invocation_id": created_slice_invocation,
                            "unit_cgroup": created_unit_cgroup,
                            "slice_cgroup": created_slice_cgroup,
                            "slice_cgroup_dev": cleanup_pin.dir_dev,
                            "slice_cgroup_ino": cleanup_pin.dir_ino,
                            "slice_events_dev": cleanup_pin.events_dev,
                            "slice_events_ino": cleanup_pin.events_ino,
                        }
                    finally:
                        cleanup_pin.close()
                # The entry removes this file only after it has loaded the
                # trusted environment.  Do not publish the ledger earlier: an
                # eager parent cleanup could race the child's first open.
                if env_path.exists():
                    raise SystemdBoundaryError("Worker has not acknowledged its environment")
                record = _validate_live_properties(
                    wl, unit_values, slice_values, expected_manager=manager_before,
                )
                cleanup_record = record
                atomic_write_text(
                    ledger_path(wl), json.dumps(record, sort_keys=True, separators=(",", ":")),
                    mode=0o600,
                )
                try:
                    secure_unlink(exit_proof_path(wl))
                except FileNotFoundError:
                    pass
                published = True
                return ManagedWorker(
                    pid=int(record["main_pid"]), unit=unit, slice=slice_name,
                    invocation_id=str(record["invocation_id"]), worker_dir=str(wl.dir.resolve()),
                )
            except SystemdBoundaryError as exc:
                last_error = exc
                time.sleep(0.02)
        raise SystemdBoundaryError("Worker transient unit did not publish a stable identity") from last_error
    except BaseException:
        cleanup_error: BaseException | None = None
        if _INVOCATION_RE.fullmatch(created_invocation):
            try:
                _cleanup_started_worker(
                    wl, unit, slice_name, created_invocation, cleanup_record,
                )
            except BaseException as exc:
                cleanup_error = exc
        try:
            secure_unlink(env_path)
        except FileNotFoundError:
            pass
        if cleanup_error is not None:
            raise SystemdBoundaryError(
                "Worker launch failed and its cgroup cleanup could not be proven"
            ) from cleanup_error
        raise
    finally:
        if not published:
            try:
                secure_unlink(env_path)
            except FileNotFoundError:
                pass


def _cleanup_started_worker(
    wl: L.WorkerLayout, unit: str, slice_name: str, invocation: str,
    record: dict[str, object] | None,
) -> None:
    """Stop only the invocation created by this start and prove slice empty."""

    current = _show_optional(
        unit, ("InvocationID", "ControlGroup", "ActiveState", "Slice"),
    )
    if record is None and current is not None:
        current_slice = _show_optional(
            slice_name, ("InvocationID", "ControlGroup", "ActiveState"),
        )
        current_unit_cgroup = current.get("ControlGroup", "")
        current_slice_cgroup = (
            current_slice.get("ControlGroup", "") if current_slice is not None else ""
        )
        if (
            current.get("InvocationID") == invocation
            and current.get("Slice") == slice_name
            and current_slice is not None
            and _INVOCATION_RE.fullmatch(current_slice.get("InvocationID", ""))
            and current_unit_cgroup.startswith(current_slice_cgroup.rstrip("/") + "/")
            and current_slice_cgroup.endswith("/" + slice_name)
        ):
            recovered_pin = _open_cgroup_pin(current_slice_cgroup)
            assert recovered_pin is not None
            try:
                record = {
                    "slice_invocation_id": current_slice["InvocationID"],
                    "unit_cgroup": current_unit_cgroup,
                    "slice_cgroup": current_slice_cgroup,
                    "slice_cgroup_dev": recovered_pin.dir_dev,
                    "slice_cgroup_ino": recovered_pin.dir_ino,
                    "slice_events_dev": recovered_pin.events_dev,
                    "slice_events_ino": recovered_pin.events_ino,
                }
            finally:
                recovered_pin.close()
    if current is None:
        # A collected unit may already be gone.  If the exact recorded slice is
        # also gone, there is no residual boundary to clean.
        slice_values = _show_optional(slice_name, ("InvocationID", "ControlGroup", "ActiveState"))
        if slice_values is None or not slice_values.get("InvocationID"):
            return
        if slice_values.get("InvocationID") != (record or {}).get("slice_invocation_id"):
            raise SystemdBoundaryError("Worker cleanup found a reused slice")
        current = {"InvocationID": invocation, "ControlGroup": str((record or {}).get("unit_cgroup", ""))}
    if current.get("InvocationID") != invocation:
        raise SystemdBoundaryError("Worker cleanup refused a reused unit")
    if record is None or current.get("ControlGroup") != record.get("unit_cgroup"):
        raise SystemdBoundaryError("Worker cleanup could not bind the created unit cgroup")
    current_slice = _show_optional(slice_name, ("InvocationID", "ControlGroup", "ActiveState"))
    if current_slice is None or current_slice.get("InvocationID") != (record or {}).get("slice_invocation_id"):
        raise SystemdBoundaryError("Worker cleanup refused a reused slice")
    cgroup = str(current_slice.get("ControlGroup", ""))
    expected = None
    if record is not None:
        expected = _ledger_cgroup_identity(record, "slice")
    pin = _open_cgroup_pin(cgroup, expected=expected)
    if pin is None:
        return
    try:
        _run_manager([_safe_binary("systemctl"), "--user", "stop", slice_name], timeout=15.0)
        _wait_for_pinned_slice_empty(pin, timeout=15.0)
    finally:
        pin.close()


def stop_worker_boundary_by_identity(unit: str, slice_name: str, invocation: str) -> None:
    values = _show_optional(unit, ("InvocationID", "ActiveState", "ControlGroup"))
    if values is None or values.get("InvocationID") != invocation:
        raise SystemdBoundaryError("refusing to stop a reused Worker unit name")
    _run_manager([_safe_binary("systemctl"), "--user", "stop", slice_name], timeout=15.0)


def _wait_for_pinned_slice_empty(pin: _CgroupPin, *, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        populated = pin.populated()
        if populated is False:
            return
        if populated is None and not pin.path_matches():
            return
        if populated is None:
            raise SystemdBoundaryError("pinned Worker cgroup disappeared ambiguously")
        time.sleep(0.05)
    raise SystemdBoundaryError("Worker slice did not become empty after stop")


def _write_exit_proof(wl: L.WorkerLayout, record: dict[str, object], *, reason: str) -> None:
    proof = {
        "schema": _SCHEMA,
        "worker_dir": str(wl.dir.resolve()),
        "unit": str(record["unit"]),
        "slice": str(record["slice"]),
        "invocation_id": str(record["invocation_id"]),
        "slice_invocation_id": str(record["slice_invocation_id"]),
        "boot_id": str(record["boot_id"]),
        "reason": reason,
        "populated": False,
        "observed_at": time.time(),
    }
    atomic_write_text(
        exit_proof_path(wl), json.dumps(proof, sort_keys=True, separators=(",", ":")),
        mode=0o600,
    )


def _clear_reconciled_worker(wl: L.WorkerLayout, record: dict[str, object], *, reason: str) -> WorkerBoundaryStatus:
    # An implicit slice otherwise stays active forever after its transient
    # service is collected. The caller has already pinned/proven the exact old
    # cgroup empty (or removed); retire only the matching recorded invocation.
    slice_values = _show_optional(
        str(record["slice"]), ("InvocationID", "ControlGroup", "ActiveState"),
    )
    if slice_values is not None and slice_values.get("InvocationID"):
        if (
            slice_values.get("InvocationID") != record.get("slice_invocation_id")
            or slice_values.get("ControlGroup") != record.get("slice_cgroup")
        ):
            raise SystemdBoundaryError("refusing to retire a reused Worker slice")
        if slice_values.get("ActiveState") == "active":
            _run_manager([
                _safe_binary("systemctl"), "--user", "stop", str(record["slice"]),
            ])
    _write_exit_proof(wl, record, reason=reason)
    for path in (ledger_path(wl), environment_path(wl), wl.pid, wl.process_identity):
        try:
            secure_unlink(path)
        except FileNotFoundError:
            pass
    return WorkerBoundaryStatus(
        state="absent", pid=None, populated=False,
        unit=str(record["unit"]), slice=str(record["slice"]),
        invocation_id=str(record["invocation_id"]), reason=reason,
    )


def _check_named_identity(
    values: dict[str, str] | None, *, invocation: str, cgroup: str, label: str,
) -> None:
    if values is None:
        return
    observed_invocation = values.get("InvocationID", "")
    if observed_invocation and observed_invocation != invocation:
        raise SystemdBoundaryError(f"recorded Worker {label} unit name was reused")
    observed_cgroup = values.get("ControlGroup", "")
    if observed_invocation and observed_cgroup and observed_cgroup != cgroup:
        raise SystemdBoundaryError(f"recorded Worker {label} cgroup was replaced")


def inspect_worker_boundary(wl: L.WorkerLayout) -> WorkerBoundaryStatus:
    """Reconcile one Worker from durable cgroup/unit identity.

    The result is intentionally typed and small so CLI/Web code cannot make a
    lifecycle decision from a stale PID, process group, or command line.
    """

    record = read_ledger(wl)
    unit = worker_unit(wl)
    slice_name = worker_slice(wl)
    if record is None:
        # A deterministic unit with no ledger is unmanaged.  Never silently
        # adopt it after a caller/Web restart.
        unit_values = _show_optional(unit, ("InvocationID", "ControlGroup", "ActiveState"))
        slice_values = _show_optional(slice_name, ("InvocationID", "ControlGroup", "ActiveState"))
        if unit_values is not None and (
            unit_values.get("InvocationID")
            or unit_values.get("ActiveState") == "active"
        ):
            raise SystemdBoundaryError("live Worker boundary has no durable ledger")
        if slice_values is not None and (
            slice_values.get("InvocationID")
            or slice_values.get("ActiveState") == "active"
        ):
            # systemd keeps an implicit named slice active after its last
            # collected service. With no ledger it grants no identity authority,
            # but populated=0 is sufficient to classify it as non-live without
            # issuing any destructive manager call.
            slice_cgroup = slice_values.get("ControlGroup", "")
            if not slice_cgroup.endswith("/" + slice_name):
                raise SystemdBoundaryError("unmanaged Worker slice path is invalid")
            pin = _open_cgroup_pin(slice_cgroup, allow_missing=True)
            if pin is not None:
                try:
                    if pin.populated() is True:
                        raise SystemdBoundaryError(
                            "populated Worker slice has no durable ledger"
                        )
                finally:
                    pin.close()
        return WorkerBoundaryStatus("absent", None, False, unit, slice_name, reason="no-ledger")

    invocation = str(record["invocation_id"])
    slice_invocation = str(record["slice_invocation_id"])
    unit_cgroup = str(record["unit_cgroup"])
    slice_cgroup = str(record["slice_cgroup"])
    unit_values = _show_optional(unit, _WORKER_UNIT_PROPERTIES)
    slice_values = _show_optional(slice_name, _WORKER_SLICE_PROPERTIES)
    _check_named_identity(unit_values, invocation=invocation, cgroup=unit_cgroup, label="service")
    _check_named_identity(slice_values, invocation=slice_invocation, cgroup=slice_cgroup, label="slice")

    slice_pin = _open_cgroup_pin(
        slice_cgroup, expected=_ledger_cgroup_identity(record, "slice"), allow_missing=True,
    )
    if slice_pin is None:
        # The exact old cgroup is gone.  A same-name active/invocation-bearing
        # unit would have been rejected above as a reuse.
        return _clear_reconciled_worker(wl, record, reason="cgroup-removed")
    try:
        if not slice_pin.path_matches():
            raise SystemdBoundaryError("recorded Worker slice path was replaced")
        populated = slice_pin.populated()
        if populated is None:
            if not slice_pin.path_matches():
                return _clear_reconciled_worker(wl, record, reason="cgroup-removed")
            raise SystemdBoundaryError("recorded Worker slice events became unavailable")
        if not populated:
            return _clear_reconciled_worker(wl, record, reason="cgroup-empty")

        # A populated old cgroup is never silently discarded.  If boot/manager
        # identity changed, report it as an orphan; explicit reclaim is the only
        # caller allowed to attempt an exact stop.
        current_boot = _read_boot_id()
        try:
            manager = _manager_identity()
        except SystemdBoundaryError:
            return WorkerBoundaryStatus(
                "orphaned", None, True, unit, slice_name, invocation,
                reason="manager-unavailable",
            )
        manager_same = all(
            manager.get(key) == record.get(key)
            for key in (
                "manager_unit", "manager_invocation_id", "manager_main_pid",
                "manager_cgroup", "manager_cgroup_dev", "manager_cgroup_ino",
                "manager_events_dev", "manager_events_ino",
            )
        )
        if current_boot != record.get("boot_id") or not manager_same:
            return WorkerBoundaryStatus(
                "orphaned", None, True, unit, slice_name, invocation,
                reason="host-identity-changed",
            )
        if slice_values is None:
            return WorkerBoundaryStatus(
                "orphaned", None, True, unit, slice_name, invocation,
                reason="slice-unit-gone",
            )
        if slice_values.get("InvocationID") != slice_invocation:
            raise SystemdBoundaryError("recorded Worker slice invocation changed")
        if unit_values is None:
            return WorkerBoundaryStatus(
                "orphaned", None, True, unit, slice_name, invocation,
                reason="service-unit-gone",
            )
        if unit_values.get("InvocationID") != invocation:
            raise SystemdBoundaryError("recorded Worker service invocation changed")
        if unit_values.get("ActiveState") != "active":
            return WorkerBoundaryStatus(
                "orphaned", None, True, unit, slice_name, invocation,
                reason=f"service-{unit_values.get('ActiveState', 'unknown')}",
            )
        try:
            observed = _validate_live_properties(
                wl, unit_values, slice_values, expected_manager=manager,
            )
        except SystemdBoundaryError:
            # MainPID may exit between ``show`` and pidfd_open.  The exact
            # slice inode is already pinned, so a subsequent populated=0 is a
            # stronger terminal proof than any cached unit MainPID.  Bound the
            # convergence wait; a still-populated mismatch remains fail-closed.
            settle_deadline = time.monotonic() + 0.25
            while True:
                settled = slice_pin.populated()
                if settled is False:
                    return _clear_reconciled_worker(
                        wl, record, reason="service-exited",
                    )
                if settled is None and not slice_pin.path_matches():
                    return _clear_reconciled_worker(
                        wl, record, reason="cgroup-removed",
                    )
                if time.monotonic() >= settle_deadline:
                    raise
                time.sleep(0.01)
        for key in (
            "boot_id", "manager_invocation_id", "manager_cgroup", "manager_cgroup_dev",
            "manager_cgroup_ino", "manager_events_dev", "manager_events_ino",
            "main_pid", "main_pid_start_time", "worker_argv", "invocation_id",
            "slice_invocation_id", "unit_cgroup", "slice_cgroup", "unit_cgroup_dev",
            "unit_cgroup_ino", "unit_events_dev", "unit_events_ino", "slice_cgroup_dev",
            "slice_cgroup_ino", "slice_events_dev", "slice_events_ino", "service_properties",
            "slice_properties",
        ):
            if observed.get(key) != record.get(key):
                raise SystemdBoundaryError(f"Worker boundary identity changed: {key}")
        return WorkerBoundaryStatus(
            "active", int(record["main_pid"]), True, unit, slice_name, invocation,
        )
    finally:
        slice_pin.close()


def stop_worker_boundary(
    wl: L.WorkerLayout, *, timeout: float = 15.0, force: bool = True,
) -> str:
    """Stop the exact recorded slice and prove its cgroup has no descendants."""

    record = read_ledger(wl)
    if record is None:
        return "not-managed"
    status = inspect_worker_boundary(wl)
    if status.state == "absent":
        return "not-managed"
    if status.state == "orphaned" and not force:
        raise SystemdBoundaryError("Worker boundary is orphaned; explicit force/reclaim is required")
    if status.state not in {"active", "orphaned", "stopping"}:
        raise SystemdBoundaryError(f"Worker boundary cannot be stopped from state {status.state}")
    # Reopen and pin after inspection; never rely on the descriptors or state
    # from a previous operation.
    pin = _open_cgroup_pin(
        str(record["slice_cgroup"]), expected=_ledger_cgroup_identity(record, "slice"),
    )
    assert pin is not None
    try:
        manager = _manager_identity()
        if any(
            manager.get(key) != record.get(key)
            for key in (
                "manager_unit", "manager_invocation_id", "manager_cgroup",
                "manager_cgroup_dev", "manager_cgroup_ino", "manager_events_dev",
                "manager_events_ino",
            )
        ) or _read_boot_id() != record.get("boot_id"):
            raise SystemdBoundaryError("refusing to stop a Worker after host identity changed")
        slice_values = _show_optional(
            str(record["slice"]), ("InvocationID", "ControlGroup", "ActiveState"),
        )
        if slice_values is None or slice_values.get("InvocationID") != record.get("slice_invocation_id"):
            raise SystemdBoundaryError("refusing to stop a reused or unloaded Worker slice")
        if slice_values.get("ControlGroup") != record.get("slice_cgroup"):
            raise SystemdBoundaryError("refusing to stop a replaced Worker slice cgroup")
        unit_values = _show_optional(
            str(record["unit"]), ("InvocationID", "ControlGroup", "ActiveState"),
        )
        if unit_values is not None:
            if unit_values.get("InvocationID") != record.get("invocation_id"):
                raise SystemdBoundaryError("refusing to stop a reused Worker service")
            if unit_values.get("ControlGroup") != record.get("unit_cgroup"):
                raise SystemdBoundaryError("refusing to stop a replaced Worker service cgroup")
        _run_manager(
            [_safe_binary("systemctl"), "--user", "stop", str(record["slice"])],
            timeout=timeout,
        )
        _wait_for_pinned_slice_empty(pin, timeout=timeout)
        _write_exit_proof(wl, record, reason="forced-stop" if force else "stop")
        for path in (ledger_path(wl), environment_path(wl), wl.pid, wl.process_identity):
            try:
                secure_unlink(path)
            except FileNotFoundError:
                pass
        return "stopped"
    finally:
        pin.close()


def boundary_populated(wl: L.WorkerLayout) -> bool:
    return inspect_worker_boundary(wl).populated


__all__ = [
    "ManagedWorker", "SystemdBoundaryError", "WorkerBoundaryStatus",
    "boundary_populated", "inspect_worker_boundary",
    "environment_path", "exit_proof_path", "expected_worker_argv",
    "ledger_path", "read_ledger", "start_worker", "stop_worker_boundary",
    "validate_user_manager", "worker_environment", "worker_slice", "worker_unit",
]
