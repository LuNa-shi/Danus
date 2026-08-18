"""Worker process identity and lifecycle safety regressions."""
from __future__ import annotations

import json
import signal
import sys
from pathlib import Path

from danus.execution import layout as L
from danus.execution.processes import (
    LinuxProcFS,
    WorkerProcessIdentity,
    force_stop_worker,
)


class FakeProcessOps:
    def __init__(self, *, pidfd: int | None = 77, pgid: int | None = None):
        self.pidfd = pidfd
        self.pgid = pgid
        self.events: list[tuple | str] = []
        self.now = 0.0
        self.group_running = True

    def pid_exists(self, pid: int) -> bool:
        self.events.append(("pid_exists", pid))
        return True

    def open_pidfd(self, pid: int) -> int | None:
        self.events.append(("open_pidfd", pid))
        return self.pidfd

    def close_pidfd(self, fd: int) -> None:
        self.events.append(("close_pidfd", fd))

    def getpgid(self, pid: int) -> int:
        self.events.append(("getpgid", pid))
        return pid if self.pgid is None else self.pgid

    def signal_group(self, pgid: int, sig: int) -> None:
        self.events.append(("signal_group", pgid, sig))
        if sig == signal.SIGKILL:
            self.group_running = False

    def group_exists(self, pgid: int) -> bool:
        self.events.append(("group_exists", pgid))
        return self.group_running

    def sleep(self, seconds: float) -> None:
        self.events.append(("sleep", seconds))
        self.now += seconds

    def monotonic(self) -> float:
        return self.now


class RecordingProcFS(LinuxProcFS):
    def __init__(self, root: Path, events: list[tuple | str]):
        super().__init__(root)
        self.events = events

    def cmdline(self, pid: int) -> tuple[str, ...]:
        self.events.append(("procfs_cmdline", pid))
        return super().cmdline(pid)


def _worker_with_procfs(tmp_path: Path, pid: int = 4321):
    worker_dir = tmp_path / "project" / "workers" / "high"
    worker_dir.mkdir(parents=True)
    wl = L.WorkerLayout(worker_dir)
    proc_root = tmp_path / "proc"
    process_dir = proc_root / str(pid)
    process_dir.mkdir(parents=True)
    (proc_root / "sys/kernel/random").mkdir(parents=True)
    cmdline = (sys.executable, "-m", "danus.execution", str(worker_dir.resolve()))
    (process_dir / "cmdline").write_bytes(b"\0".join(part.encode() for part in cmdline) + b"\0")
    stat_fields = ["S", *(["0"] * 18), "4242"]
    (process_dir / "stat").write_text(f"{pid} (worker loop) " + " ".join(stat_fields), encoding="utf-8")
    (proc_root / "sys/kernel/random/boot_id").write_text("boot-test\n", encoding="utf-8")
    identity = WorkerProcessIdentity(
        pid=pid, boot_id="boot-test", start_time="4242", cmdline=cmdline,
    )
    wl.pid.write_text(str(pid), encoding="utf-8")
    wl.process_identity.write_text(json.dumps(identity.as_dict()), encoding="utf-8")
    return wl, proc_root, identity


def test_worker_process_identity_is_a_round_trippable_value_type(tmp_path: Path):
    wl, proc_root, identity = _worker_with_procfs(tmp_path)

    assert WorkerProcessIdentity.from_mapping(identity.as_dict()) == identity
    assert LinuxProcFS(proc_root).capture_worker_identity(wl, identity.pid) == identity


def test_force_stop_opens_pidfd_before_identity_revalidation_and_keeps_it_through_kill(
    tmp_path: Path,
):
    wl, proc_root, _identity = _worker_with_procfs(tmp_path)
    ops = FakeProcessOps()
    procfs = RecordingProcFS(proc_root, ops.events)

    result = force_stop_worker(
        wl, procfs=procfs, ops=ops, term_timeout=0.2, kill_timeout=0.2,
        poll_interval=0.1,
    )

    assert result == "killed"
    assert ops.events.index(("open_pidfd", 4321)) < ops.events.index(("procfs_cmdline", 4321))
    term_index = ops.events.index(("signal_group", 4321, signal.SIGTERM))
    kill_index = ops.events.index(("signal_group", 4321, signal.SIGKILL))
    close_index = ops.events.index(("close_pidfd", 77))
    assert term_index < kill_index < close_index
    assert not wl.pid.exists()
    assert not wl.process_identity.exists()


def test_force_stop_fails_closed_without_pidfd_and_keeps_recoverable_metadata(tmp_path: Path):
    wl, proc_root, _identity = _worker_with_procfs(tmp_path)
    ops = FakeProcessOps(pidfd=None)

    result = force_stop_worker(wl, procfs=LinuxProcFS(proc_root), ops=ops)

    assert result == "stable-handle-unavailable"
    assert not any(event[0] == "signal_group" for event in ops.events if isinstance(event, tuple))
    assert wl.pid.exists()
    assert wl.process_identity.exists()


def test_force_stop_requires_worker_to_lead_its_exact_process_group(tmp_path: Path):
    wl, proc_root, _identity = _worker_with_procfs(tmp_path)
    ops = FakeProcessOps(pgid=9999)

    result = force_stop_worker(wl, procfs=LinuxProcFS(proc_root), ops=ops)

    assert result == "unsafe-process-group"
    assert not any(event[0] == "signal_group" for event in ops.events if isinstance(event, tuple))
    assert ops.events[-1] == ("close_pidfd", 77)
    assert wl.pid.exists()
    assert wl.process_identity.exists()
