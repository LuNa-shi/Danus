"""Linux Worker process identity and exact process-group lifecycle helpers.

The orchestration CLI owns verbs and presentation; this module owns execution
process identity, procfs reads, stable pidfd acquisition, and signal sequencing.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time
from typing import Any, Callable, Mapping, Protocol

from . import layout as L


@dataclass(frozen=True)
class WorkerProcessIdentity:
    """Host identity for one exact Worker loop process."""

    pid: int
    boot_id: str
    start_time: str
    cmdline: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "boot_id": self.boot_id,
            "start_time": self.start_time,
            "cmdline": list(self.cmdline),
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> WorkerProcessIdentity | None:
        if not isinstance(value, Mapping):
            return None
        pid = value.get("pid")
        boot_id = value.get("boot_id")
        start_time = value.get("start_time")
        cmdline = value.get("cmdline")
        if (
            not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0
            or not isinstance(boot_id, str) or not boot_id
            or not isinstance(start_time, str) or not start_time
            or not isinstance(cmdline, (list, tuple)) or not cmdline
            or not all(isinstance(part, str) and part for part in cmdline)
        ):
            return None
        return cls(pid=pid, boot_id=boot_id, start_time=start_time, cmdline=tuple(cmdline))


@dataclass(frozen=True)
class LinuxProcFS:
    """Configurable Linux procfs reader used by identity-sensitive code."""

    root: Path = Path("/proc")

    def process_state(self, pid: int) -> str:
        text = (self.root / str(pid) / "stat").read_text(encoding="utf-8")
        return text.rsplit(")", 1)[1].split()[0]

    def cmdline(self, pid: int) -> tuple[str, ...]:
        raw = (self.root / str(pid) / "cmdline").read_bytes()
        return tuple(
            part.decode("utf-8", errors="surrogateescape")
            for part in raw.split(b"\0") if part
        )

    def start_time(self, pid: int) -> str:
        parts = (self.root / str(pid) / "stat").read_text(
            encoding="utf-8"
        ).rsplit(")", 1)[1].split()
        # /proc/<pid>/stat field 22; ``parts`` begins at field 3 (state).
        return parts[19]

    def boot_id(self) -> str:
        return (self.root / "sys/kernel/random/boot_id").read_text(
            encoding="utf-8"
        ).strip()

    def process_record(self, pid: int) -> dict[str, Any]:
        parts = (self.root / str(pid) / "stat").read_text(
            encoding="utf-8"
        ).rsplit(")", 1)[1].split()
        return {
            "pid": pid, "state": parts[0], "ppid": int(parts[1]),
            "pgid": int(parts[2]), "start_time": parts[19],
            "cmdline": list(self.cmdline(pid)),
        }

    def process_ids(self) -> list[int]:
        try:
            return [int(path.name) for path in self.root.iterdir() if path.name.isdigit()]
        except OSError:
            return []

    def process_group_alive(self, pgid: int) -> bool:
        """Return whether procfs contains a non-zombie member of *pgid*."""
        for entry in self.root.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                parts = (entry / "stat").read_text(encoding="utf-8").rsplit(")", 1)[1].split()
                state = parts[0]
                process_group = int(parts[2])  # stat field 5; parts begins at field 3
            except (OSError, IndexError, ValueError):
                continue
            if process_group == pgid and state != "Z":
                return True
        return False

    def capture_worker_identity(
        self, wl: L.WorkerLayout, pid: int,
    ) -> WorkerProcessIdentity | None:
        try:
            cmdline = self.cmdline(pid)
            if cmdline != expected_worker_cmdline(wl):
                return None
            start_time = self.start_time(pid)
            boot_id = self.boot_id()
        except (OSError, IndexError, UnicodeError):
            return None
        if not start_time or not boot_id:
            return None
        return WorkerProcessIdentity(
            pid=pid, boot_id=boot_id, start_time=start_time, cmdline=cmdline,
        )


class ProcessOps(Protocol):
    def pid_exists(self, pid: int) -> bool: ...
    def open_pidfd(self, pid: int) -> int | None: ...
    def close_pidfd(self, fd: int) -> None: ...
    def pidfd_exited(self, fd: int) -> bool: ...
    def signal_pidfd(self, fd: int, sig: int) -> None: ...
    def getpgid(self, pid: int) -> int: ...
    def signal_group(self, pgid: int, sig: int) -> None: ...
    def group_exists(self, pgid: int) -> bool: ...
    def sleep(self, seconds: float) -> None: ...
    def monotonic(self) -> float: ...


class SystemProcessOps:
    """Narrow OS seam for lifecycle tests and fail-closed pidfd handling."""

    def pid_exists(self, pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    def open_pidfd(self, pid: int) -> int | None:
        opener = getattr(os, "pidfd_open", None)
        if opener is None:
            return None
        try:
            return opener(pid, 0)
        except (OSError, ProcessLookupError, PermissionError):
            return None

    def close_pidfd(self, fd: int) -> None:
        os.close(fd)

    def pidfd_exited(self, fd: int) -> bool:
        try:
            readable, _, _ = select.select([fd], [], [], 0)
        except (OSError, ValueError):
            return True
        return bool(readable)

    def signal_pidfd(self, fd: int, sig: int) -> None:
        sender = getattr(signal, "pidfd_send_signal", None)
        if sender is None:
            raise OSError("pidfd_send_signal unavailable")
        sender(fd, sig)

    def getpgid(self, pid: int) -> int:
        return os.getpgid(pid)

    def signal_group(self, pgid: int, sig: int) -> None:
        os.killpg(pgid, sig)

    def group_exists(self, pgid: int) -> bool:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)

    def monotonic(self) -> float:
        return time.monotonic()


DEFAULT_PROCFS = LinuxProcFS()
SYSTEM_PROCESS_OPS = SystemProcessOps()


def expected_worker_cmdline(wl: L.WorkerLayout) -> tuple[str, ...]:
    return (sys.executable, "-m", "danus.execution", str(wl.dir.resolve()))


def read_pid(wl: L.WorkerLayout) -> int | None:
    try:
        return int(wl.pid.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def read_worker_identity(wl: L.WorkerLayout) -> WorkerProcessIdentity | None:
    try:
        value = json.loads(wl.process_identity.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return WorkerProcessIdentity.from_mapping(value)


def write_worker_identity(wl: L.WorkerLayout, identity: WorkerProcessIdentity) -> None:
    from .scaffold import atomic_write
    atomic_write(wl.process_identity, json.dumps(identity.as_dict(), sort_keys=True))


def clear_worker_process_metadata(wl: L.WorkerLayout) -> None:
    wl.pid.unlink(missing_ok=True)
    wl.process_identity.unlink(missing_ok=True)


def process_alive(
    pid: int | None,
    *,
    procfs: LinuxProcFS = DEFAULT_PROCFS,
    ops: ProcessOps = SYSTEM_PROCESS_OPS,
) -> bool:
    if not pid or not ops.pid_exists(pid):
        return False
    try:
        return procfs.process_state(pid) != "Z"
    except (OSError, IndexError):
        # Portable fallback for development hosts without mounted procfs. If ps
        # itself cannot provide a state, retain the conservative "exists" result.
        try:
            result = subprocess.run(
                ["ps", "-o", "stat=", "-p", str(pid)],
                capture_output=True, text=True, timeout=1, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return True
        state = result.stdout.strip().split(maxsplit=1)[0] if result.stdout.strip() else ""
        return not state.startswith("Z")


def capture_worker_identity(
    wl: L.WorkerLayout,
    pid: int,
    *,
    procfs: LinuxProcFS = DEFAULT_PROCFS,
    ops: ProcessOps = SYSTEM_PROCESS_OPS,
) -> WorkerProcessIdentity | None:
    if not process_alive(pid, procfs=procfs, ops=ops):
        return None
    return procfs.capture_worker_identity(wl, pid)


def worker_process_alive(
    wl: L.WorkerLayout,
    *,
    procfs: LinuxProcFS = DEFAULT_PROCFS,
    ops: ProcessOps = SYSTEM_PROCESS_OPS,
) -> bool:
    pid = read_pid(wl)
    if not process_alive(pid, procfs=procfs, ops=ops) or pid is None:
        return False
    current = capture_worker_identity(wl, pid, procfs=procfs, ops=ops)
    if current is None:
        return False
    persisted = read_worker_identity(wl)
    # Adopt pre-identity projects only when the live command exactly matches.
    return persisted is None or persisted == current


def _stable_group_alive(
    pgid: int,
    pidfd: int,
    *,
    procfs: LinuxProcFS,
    ops: ProcessOps,
) -> bool:
    try:
        leader_exited = ops.pidfd_exited(pidfd)
    except (AttributeError, OSError):
        return ops.group_exists(pgid)
    if not leader_exited:
        return True
    # A dead but unreaped leader remains visible to killpg. Procfs distinguishes
    # that harmless zombie from a still-live descendant in the exact group.
    try:
        return procfs.process_group_alive(pgid)
    except OSError:
        return ops.group_exists(pgid)


def process_group_members(
    pgid: int, *, procfs: LinuxProcFS = DEFAULT_PROCFS,
) -> list[dict[str, Any]]:
    members: list[dict[str, Any]] = []
    for pid in procfs.process_ids():
        try:
            record = procfs.process_record(pid)
        except (OSError, ValueError, IndexError, UnicodeError):
            continue
        if record["pgid"] == pgid and record["state"] != "Z":
            members.append(record)
    return sorted(members, key=lambda row: int(row["pid"]))


def _freeze_process_group(
    pgid: int, *, required_leader: WorkerProcessIdentity | None = None,
    procfs: LinuxProcFS, ops: ProcessOps,
) -> dict[int, tuple[int, str]]:
    """Pin and SIGSTOP every member until the group membership is stable."""
    handles: dict[int, tuple[int, str]] = {}
    try:
        for _ in range(8):
            records = process_group_members(pgid, procfs=procfs)
            for record in records:
                pid = int(record["pid"])
                if pid in handles:
                    continue
                fd = ops.open_pidfd(pid)
                if fd is None:
                    raise RuntimeError(f"stable handle unavailable for pid {pid}")
                try:
                    current = procfs.process_record(pid)
                except (OSError, ValueError, IndexError) as exc:
                    ops.close_pidfd(fd)
                    raise RuntimeError(f"process identity unavailable for pid {pid}") from exc
                if current["pgid"] != pgid or current["start_time"] != record["start_time"]:
                    ops.close_pidfd(fd)
                    raise RuntimeError(f"process identity changed for pid {pid}")
                if required_leader is not None and pid == required_leader.pid and (
                    str(current["start_time"]) != required_leader.start_time
                    or tuple(current["cmdline"]) != required_leader.cmdline
                ):
                    ops.close_pidfd(fd)
                    raise RuntimeError("Worker leader identity changed")
                handles[pid] = (fd, str(current["start_time"]))
                ops.signal_pidfd(fd, signal.SIGSTOP)
            stop_deadline = ops.monotonic() + 1.0
            while True:
                stopped = True
                for pid, (fd, start_time) in handles.items():
                    if ops.pidfd_exited(fd):
                        continue
                    try:
                        current = procfs.process_record(pid)
                    except (OSError, ValueError, IndexError):
                        stopped = False
                        break
                    if str(current["start_time"]) != start_time or current["state"] not in {"T", "t"}:
                        stopped = False
                        break
                if stopped:
                    break
                if ops.monotonic() >= stop_deadline:
                    raise RuntimeError("process group did not reach the SIGSTOP barrier")
                ops.sleep(0.01)
            current_pids = {int(row["pid"]) for row in process_group_members(pgid, procfs=procfs)}
            if current_pids.issubset(handles):
                return handles
        raise RuntimeError("process group membership did not stabilize")
    except Exception:
        for fd, _start in handles.values():
            try:
                ops.signal_pidfd(fd, signal.SIGCONT)
            except (OSError, ProcessLookupError):
                pass
            try:
                ops.close_pidfd(fd)
            except OSError:
                pass
        raise


def _terminate_frozen_handles(
    handles: dict[int, tuple[int, str]], *, ops: ProcessOps,
    term_timeout: float, kill_timeout: float, poll_interval: float,
    on_signal: Callable[[str], None] | None = None,
) -> bool:
    try:
        for fd, _start in handles.values():
            if not ops.pidfd_exited(fd):
                ops.signal_pidfd(fd, signal.SIGTERM)
        if on_signal is not None:
            on_signal("SIGTERM")
        # SIGTERM is pending while stopped; SIGCONT lets handlers run without a
        # window for new work before the pending termination is delivered.
        for fd, _start in handles.values():
            if not ops.pidfd_exited(fd):
                ops.signal_pidfd(fd, signal.SIGCONT)
        deadline = ops.monotonic() + max(0.0, term_timeout)
        while any(not ops.pidfd_exited(fd) for fd, _ in handles.values()) and ops.monotonic() < deadline:
            ops.sleep(max(0.001, poll_interval))
        remaining = [(fd, start) for fd, start in handles.values() if not ops.pidfd_exited(fd)]
        if remaining:
            for fd, _start in remaining:
                ops.signal_pidfd(fd, signal.SIGKILL)
            if on_signal is not None:
                on_signal("SIGKILL")
            deadline = ops.monotonic() + max(0.0, kill_timeout)
            while any(not ops.pidfd_exited(fd) for fd, _ in remaining) and ops.monotonic() < deadline:
                ops.sleep(max(0.001, poll_interval))
        return all(ops.pidfd_exited(fd) for fd, _ in handles.values())
    finally:
        for fd, _start in handles.values():
            try:
                ops.close_pidfd(fd)
            except OSError:
                pass


def force_stop_worker(
    wl: L.WorkerLayout, *, procfs: LinuxProcFS = DEFAULT_PROCFS,
    ops: ProcessOps = SYSTEM_PROCESS_OPS, term_timeout: float = 5.0,
    kill_timeout: float = 5.0, poll_interval: float = 0.1,
    on_signal: Callable[[str], None] | None = None,
) -> str:
    """Stop a verified Worker subtree exclusively through stable pidfds."""
    pid = read_pid(wl)
    if not process_alive(pid, procfs=procfs, ops=ops) or pid is None:
        clear_worker_process_metadata(wl)
        return "not-running"
    current = capture_worker_identity(wl, pid, procfs=procfs, ops=ops)
    persisted = read_worker_identity(wl)
    if current is None or persisted is None or persisted != current:
        return "identity-mismatch"
    try:
        pgid = ops.getpgid(pid)
    except (ProcessLookupError, PermissionError, OSError):
        return "not-running" if not process_alive(pid, procfs=procfs, ops=ops) else "unsafe-process-group"
    if pgid != pid:
        return "unsafe-process-group"
    try:
        handles = _freeze_process_group(
            pgid, required_leader=current, procfs=procfs, ops=ops,
        )
        exited = _terminate_frozen_handles(
            handles, ops=ops, term_timeout=term_timeout,
            kill_timeout=kill_timeout, poll_interval=poll_interval,
            on_signal=on_signal,
        )
    except (RuntimeError, OSError, ProcessLookupError, PermissionError):
        return "stable-handle-unavailable"
    if not exited or process_group_members(pgid, procfs=procfs):
        return "kill-failed"
    clear_worker_process_metadata(wl)
    return "killed"


def _wait_and_reap(process: subprocess.Popen, timeout: float) -> bool:
    try:
        process.wait(timeout=max(0.0, timeout))
    except subprocess.TimeoutExpired:
        return False
    return process.poll() is not None


def terminate_spawned_worker(
    process: subprocess.Popen, *, procfs: LinuxProcFS = DEFAULT_PROCFS,
    ops: ProcessOps = SYSTEM_PROCESS_OPS, term_timeout: float = 5.0,
    kill_timeout: float = 5.0, poll_interval: float = 0.05,
) -> bool:
    """Terminate/reap a newly spawned Worker without numeric group signals."""
    pid = int(process.pid)
    try:
        pgid = ops.getpgid(pid)
        if pgid != pid:
            return False
        handles = _freeze_process_group(pgid, procfs=procfs, ops=ops)
        exited = _terminate_frozen_handles(
            handles, ops=ops, term_timeout=term_timeout,
            kill_timeout=kill_timeout, poll_interval=poll_interval,
        )
    except (RuntimeError, OSError, ProcessLookupError, PermissionError):
        return False
    reaped = _wait_and_reap(process, kill_timeout)
    return exited and reaped and not process_group_members(pgid, procfs=procfs)
