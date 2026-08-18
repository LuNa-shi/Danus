"""Public backend seams for issue #8 observability and safety controls."""
from __future__ import annotations

import os
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from danus.execution import layout as L
from danus.execution import processes as P
from danus.web_console.runtime import DanusRuntimeAdapter, RuntimeOperationError, RuntimeSafetyError


def test_runtime_worker_projection_exposes_stop_request_and_rejects_unrelated_live_pid(tmp_path: Path):
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    adapter.create_project("A", "alpha", "high:1", max_parallel_workers=1)
    worker_dir = tmp_path / "agents" / "A" / "workers" / "high"
    (worker_dir / ".pid").write_text(str(os.getpid()), encoding="utf-8")
    (worker_dir / ".stop").touch()

    worker = adapter.status_project("A")["workers"][0]

    assert worker["pid"] == os.getpid()
    assert worker["process_identity"] == "mismatch"
    assert worker["alive"] is False
    assert worker["stop_requested"] is True


def test_runtime_log_projection_is_bounded_sanitized_and_metadata_rich(tmp_path: Path):
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    adapter.create_project("A", "alpha", "high:1", max_parallel_workers=1)
    logs = tmp_path / "agents" / "A" / "workers" / "high" / "logs"
    loop = logs / "loop.log"
    loop.write_text(
        ("discard-me\n" * 100)
        + "\x1b[31mworker started\x1b[0m\n"
        + "Authorization: Bearer bearer-secret\n"
        + "OPENAI_API_KEY=sk-secret-value\n",
        encoding="utf-8",
    )
    (logs / "round_3.log").write_text(
        '{"api_key":"json-secret","message":"round output"}\n'
        "COOKIE=session-secret\n"
        "https://alice:password@example.test/path\n"
        "AKIAIOSFODNN7EXAMPLE\n"
        "eyJabcdefgh.abcdefgh.abcdefghi\n"
        "-----BEGIN PRIVATE KEY-----\nsecret-material\n-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    outside = tmp_path / "outside.log"
    outside.write_text("must not leak\n", encoding="utf-8")
    (logs / "escape.log").symlink_to(outside)

    projection = adapter.logs_projection("A", worker="high", tail=10, max_bytes=256)
    by_name = {entry["name"]: entry for entry in projection["entries"]}

    assert set(by_name) == {"loop.log", "round_3.log"}
    assert projection["worker"] == "high"
    assert projection["tail"] == 10
    assert projection["max_bytes"] == 256
    assert projection["fetched_at"] > 0
    assert by_name["loop.log"]["kind"] == "loop"
    assert by_name["round_3.log"]["kind"] == "round"
    assert by_name["round_3.log"]["round"] == 3
    assert by_name["loop.log"]["size"] == loop.stat().st_size
    assert by_name["loop.log"]["modified_at"] == loop.stat().st_mtime
    assert by_name["loop.log"]["truncated"] is True
    rendered = "\n".join(line for entry in by_name.values() for line in entry["lines"])
    assert "\x1b" not in rendered
    assert "bearer-secret" not in rendered
    assert "sk-secret-value" not in rendered
    assert "json-secret" not in rendered
    assert "session-secret" not in rendered
    assert "alice:password" not in rendered
    assert "AKIAIOSFODNN7EXAMPLE" not in rendered
    assert "eyJabcdefgh" not in rendered
    assert "secret-material" not in rendered
    assert "[REDACTED]" in rendered


def test_runtime_pause_and_resume_use_a_distinct_desired_state(tmp_path: Path, monkeypatch):
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    adapter.create_project("A", "alpha", "high:1", max_parallel_workers=1)
    worker_dir = tmp_path / "agents" / "A" / "workers" / "high"
    original_task = (worker_dir / "TASK.md").read_text(encoding="utf-8")

    paused = adapter.pause_project("A", worker="high")

    assert paused["status"] == "pause_requested"
    assert (worker_dir / ".pause").is_file()
    worker = adapter.status_project("A")["workers"][0]
    assert worker["pause_requested"] is True
    assert worker["desired_state"] == "paused"

    starts = []
    monkeypatch.setattr(
        "danus.web_console.runtime.cli.do_start",
        lambda target, *, root: starts.append((target, root)) or [
            {"worker": "high", "result": "started"}
        ],
    )
    resumed = adapter.resume_project("A", worker="high")

    assert resumed == {
        "status": "resume_requested",
        "workers": [{"worker": "high", "result": "started"}],
    }
    assert starts == [("A/high", adapter.agents_root)]
    assert not (worker_dir / ".pause").exists()
    assert (worker_dir / "TASK.md").read_text(encoding="utf-8") == original_task


def test_runtime_force_stop_refuses_a_live_identity_mismatch(tmp_path: Path):
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    adapter.create_project("A", "alpha", "high:1", max_parallel_workers=1)
    worker_dir = tmp_path / "agents" / "A" / "workers" / "high"
    (worker_dir / ".pid").write_text(str(os.getpid()), encoding="utf-8")

    with pytest.raises(RuntimeSafetyError, match="identity"):
        adapter.force_stop_project("A", worker="high", term_timeout=0.01)

    assert os.getpid() > 0
    assert (worker_dir / ".pid").exists()


def test_runtime_force_stop_fails_closed_on_unidentified_project_processes(
    tmp_path: Path, monkeypatch,
):
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    adapter.create_project("A", "alpha", "high:1", max_parallel_workers=1)
    monkeypatch.setattr(P, "processes_with_argv_path", lambda root: [{"pid": 4321}])

    with pytest.raises(RuntimeSafetyError, match="reclaim required"):
        adapter.force_stop_project("A", worker="high", term_timeout=0.01)


def test_runtime_force_stop_terminates_only_an_exact_worker_process_group(tmp_path: Path):
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    adapter.create_project("A", "alpha", "high:1", max_parallel_workers=1)
    worker_dir = tmp_path / "agents" / "A" / "workers" / "high"
    fake_codex = tmp_path / "fake_codex.sh"
    fake_codex.write_text("#!/bin/sh\nsleep 30\n", encoding="utf-8")
    fake_codex.chmod(0o755)
    env = os.environ.copy()
    env.update({"DANUS_CODEX_BIN": str(fake_codex), "DANUS_ROUND_BEAT": "0"})
    process = subprocess.Popen(
        [sys.executable, "-m", "danus.execution", str(worker_dir.resolve())],
        cwd=str(Path(__file__).resolve().parents[3]),
        env=env,
        start_new_session=True,
    )
    (worker_dir / ".pid").write_text(str(process.pid), encoding="utf-8")
    try:
        deadline = time.time() + 5
        identity = None
        wl = L.WorkerLayout(worker_dir)
        while time.time() < deadline:
            identity = P.capture_worker_identity(wl, process.pid)
            if identity is not None:
                break
            time.sleep(0.05)
        assert identity is not None
        P.write_worker_identity(wl, identity)
        assert adapter.status_project("A")["workers"][0]["process_identity"] == "matched"
        # Retained stable identity remains authoritative when the convenience
        # .pid file is missing.
        (worker_dir / ".pid").unlink()
        result = adapter.force_stop_project("A", worker="high", term_timeout=1.0)

        row = result["workers"][0]
        assert row["worker"] == "high"
        assert row["verified_identity"]["pid"] == process.pid
        assert row["signals_sent"][0] == "SIGTERM"
        assert row["outcome"] == "terminated"
        process.wait(timeout=3)
        assert not (worker_dir / ".pid").exists()
        status = json.loads((worker_dir / ".status.json").read_text(encoding="utf-8"))
        assert status["control_outcome"] == "emergency_force_stop"
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=3)


def test_runtime_reclaim_is_a_stale_plan_that_never_signals_a_mismatched_pid(tmp_path: Path):
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    adapter.create_project("A", "alpha", "high:1", max_parallel_workers=1)
    worker_dir = tmp_path / "agents" / "A" / "workers" / "high"
    (worker_dir / ".pid").write_text(str(os.getpid()), encoding="utf-8")
    (worker_dir / ".process.json").write_text(json.dumps({
        "pid": os.getpid(), "boot_id": "stale-boot", "start_time": "stale-start",
        "cmdline": ["python", "-m", "danus.execution", str(worker_dir.resolve())],
    }), encoding="utf-8")
    (worker_dir / ".stop").touch()
    (worker_dir / ".pause").touch()
    status_path = worker_dir / ".status.json"
    status = json.loads(status_path.read_text(encoding="utf-8"))
    status["state"] = "retrying"
    status_path.write_text(json.dumps(status), encoding="utf-8")

    plan = adapter.reclaim_project("A", worker="high")

    assert plan["dry_run"] is True
    assert plan["safe_to_execute"] is True
    assert plan["workers"][0]["process_identity"] == "mismatch"
    assert plan["workers"][0]["orphan_processes"] == []
    assert set(plan["workers"][0]["stale_artifacts"]) >= {".pid", ".stop", ".pause"}

    result = adapter.reclaim_project(
        "A", worker="high", execute=True,
        confirmation_token=plan["confirmation_token"],
    )

    assert result["status"] == "reclaimed"
    assert result["remaining_project_processes"] == []
    assert os.getpid() > 0
    assert not (worker_dir / ".pid").exists()
    assert not (worker_dir / ".stop").exists()
    assert not (worker_dir / ".pause").exists()
    reclaimed = json.loads(status_path.read_text(encoding="utf-8"))
    assert reclaimed["state"] == "reclaimed"


def test_runtime_reclaim_terminates_exact_orphan_group_and_clears_locks(tmp_path: Path):
    if not hasattr(os, "pidfd_open") or not hasattr(__import__("signal"), "pidfd_send_signal"):
        pytest.skip("Linux pidfd support required")
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    adapter.create_project("A", "alpha", "high:1", max_parallel_workers=1)
    worker_dir = tmp_path / "agents" / "A" / "workers" / "high"
    child_pid_path = tmp_path / "orphan-child.pid"
    script = (
        "import pathlib, subprocess, time; "
        "child=subprocess.Popen(['sleep','30']); "
        f"pathlib.Path({str(child_pid_path)!r}).write_text(str(child.pid)); "
        "time.sleep(0.5)"
    )
    leader = subprocess.Popen([sys.executable, "-c", script], start_new_session=True)
    try:
        deadline = time.time() + 3
        while time.time() < deadline and not child_pid_path.exists():
            time.sleep(0.02)
        assert child_pid_path.exists()
        record = P.DEFAULT_PROCFS.process_record(leader.pid)
        identity = P.WorkerProcessIdentity(
            pid=leader.pid,
            boot_id=P.DEFAULT_PROCFS.boot_id(),
            start_time=str(record["start_time"]),
            cmdline=tuple(record["cmdline"]),
        )
        wl = L.WorkerLayout(worker_dir)
        (worker_dir / ".pid").write_text(str(leader.pid), encoding="utf-8")
        P.write_worker_identity(wl, identity)
        leader.wait(timeout=3)
        child_pid = int(child_pid_path.read_text())
        (tmp_path / "agents" / "A" / ".worker-provider.lock").touch()

        plan = adapter.reclaim_project("A", worker="high")
        assert plan["safe_to_execute"] is True
        assert plan["workers"][0]["process_identity"] == "dead"
        assert [row["pid"] for row in plan["workers"][0]["orphan_processes"]] == [child_pid]

        result = adapter.reclaim_project(
            "A", worker="high", execute=True,
            confirmation_token=plan["confirmation_token"],
        )
        assert result["status"] == "reclaimed"
        assert result["workers"][0]["orphan_termination"]["outcome"] == "terminated"
        assert result["remaining_project_processes"] == []
        assert ".worker-provider.lock" in result["cleared_lock_artifacts"]
        with pytest.raises(ProcessLookupError):
            os.kill(child_pid, 0)
    finally:
        if leader.poll() is None:
            leader.kill()
        try:
            leader.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        if child_pid_path.exists():
            child_pid = int(child_pid_path.read_text())
            try:
                os.kill(child_pid, 9)
            except ProcessLookupError:
                pass


def test_project_resume_restarts_only_pause_marked_workers(tmp_path: Path, monkeypatch):
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    adapter.create_project("A", "alpha", "high:1,xhigh:1", max_parallel_workers=2)
    adapter.pause_project("A", worker="high")
    starts = []
    monkeypatch.setattr(
        "danus.web_console.runtime.cli.do_start",
        lambda target, *, root: starts.append(target) or [{"worker": target.split("/")[-1], "result": "started"}],
    )

    result = adapter.resume_project("A")

    assert starts == ["A/high"]
    assert result["workers"] == [{"worker": "high", "result": "started"}]
    assert not (tmp_path / "agents/A/workers/high/.pause").exists()
    assert not (tmp_path / "agents/A/workers/xhigh/.pause").exists()


def test_graceful_stop_supersedes_pause_marker(tmp_path: Path, monkeypatch):
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    adapter.create_project("A", "alpha", "high:1", max_parallel_workers=1)
    adapter.pause_project("A", worker="high")
    monkeypatch.setattr(
        "danus.web_console.runtime.cli.do_stop",
        lambda target, *, force, root: [{"worker": "high", "result": "stopping (graceful)"}],
    )

    adapter.stop_project("A")

    assert not (tmp_path / "agents/A/workers/high/.pause").exists()


def test_process_inspection_failure_is_unknown_not_mismatch(tmp_path: Path, monkeypatch):
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    adapter.create_project("A", "alpha", "high:1", max_parallel_workers=1)
    worker_dir = tmp_path / "agents/A/workers/high"
    (worker_dir / ".pid").write_text(str(os.getpid()), encoding="utf-8")
    monkeypatch.setattr(P.LinuxProcFS, "process_record", lambda self, pid: (_ for _ in ()).throw(PermissionError()))

    worker = adapter.status_project("A")["workers"][0]

    assert worker["process_identity"] == "unknown"
    assert worker["alive"] is False


def test_reclaim_retains_artifacts_when_selected_processes_remain(tmp_path: Path, monkeypatch):
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    adapter.create_project("A", "alpha", "high:1", max_parallel_workers=1)
    worker_dir = tmp_path / "agents/A/workers/high"
    (worker_dir / ".pid").write_text("999999999", encoding="utf-8")
    (worker_dir / ".stop").touch()
    plan = adapter.reclaim_project("A", worker="high")
    monkeypatch.setattr(adapter, "_project_processes", lambda root: [{"pid": 4242}])

    with pytest.raises(RuntimeSafetyError, match="left selected Worker processes"):
        adapter.reclaim_project(
            "A", worker="high", execute=True,
            confirmation_token=plan["confirmation_token"],
        )

    assert (worker_dir / ".pid").exists()
    assert (worker_dir / ".stop").exists()
    status = json.loads((worker_dir / ".status.json").read_text())
    assert status["state"] != "reclaimed"


def test_log_projection_rejects_symlink_swap_at_open_time(tmp_path: Path, monkeypatch):
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    adapter.create_project("A", "alpha", "high:1", max_parallel_workers=1)
    logs = tmp_path / "agents/A/workers/high/logs"
    raced = logs / "race.log"
    raced.write_text("safe before swap\n", encoding="utf-8")
    outside = tmp_path / "outside-secret.log"
    outside.write_text("must-not-leak\n", encoding="utf-8")
    real_open = os.open
    swapped = False

    def swap_then_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if path == "race.log" and dir_fd is not None and not swapped:
            swapped = True
            raced.unlink()
            raced.symlink_to(outside)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", swap_then_open)
    with pytest.raises(RuntimeOperationError, match="log file unavailable"):
        adapter.logs_projection("A", worker="high")

    assert swapped is True


def test_log_projection_rejects_log_directory_symlink_swap(tmp_path: Path, monkeypatch):
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    adapter.create_project("A", "alpha", "high:1", max_parallel_workers=1)
    logs = tmp_path / "agents/A/workers/high/logs"
    (logs / "loop.log").write_text("safe\n", encoding="utf-8")
    outside = tmp_path / "outside-logs"
    outside.mkdir()
    (outside / "secret.log").write_text("must-not-leak\n", encoding="utf-8")
    original_logs = logs.with_name("logs.original")
    real_open = os.open
    swapped = False

    def swap_directory_then_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal swapped
        if Path(path) == logs.resolve() and dir_fd is None and not swapped:
            swapped = True
            logs.rename(original_logs)
            logs.symlink_to(outside, target_is_directory=True)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", swap_directory_then_open)
    with pytest.raises(RuntimeOperationError, match="log directory unavailable"):
        adapter.logs_projection("A", worker="high")

    assert swapped is True


def test_reclaim_candidate_survives_missing_pid_when_identity_record_remains(tmp_path: Path):
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    adapter.create_project("A", "alpha", "high:1", max_parallel_workers=1)
    worker_dir = tmp_path / "agents/A/workers/high"
    (worker_dir / ".process.json").write_text(json.dumps({
        "pid": 999999999, "boot_id": "old-boot", "start_time": "42",
        "cmdline": [sys.executable, "-m", "danus.execution", str(worker_dir.resolve())],
    }), encoding="utf-8")

    worker = adapter.status_project("A")["workers"][0]

    assert worker["pid"] is None
    assert worker["process_identity"] == "dead"
    assert worker["reclaim_candidate"] is True


def test_truncated_log_tail_fails_closed_when_it_starts_inside_pem(tmp_path: Path):
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    adapter.create_project("A", "alpha", "high:1", max_parallel_workers=1)
    log = tmp_path / "agents/A/workers/high/logs/loop.log"
    key_line = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0123456789abcdef"
    log.write_text(
        "before\n-----BEGIN PRIVATE KEY-----\n"
        + (key_line + "\n") * 200
        + "-----END PRIVATE KEY-----\nafter\n",
        encoding="utf-8",
    )

    projection = adapter.logs_projection("A", worker="high", tail=200, max_bytes=1024)
    rendered = "\n".join(projection["entries"][0]["lines"])

    assert key_line not in rendered
    assert "END PRIVATE KEY" not in rendered
    assert "[REDACTED]" in rendered
