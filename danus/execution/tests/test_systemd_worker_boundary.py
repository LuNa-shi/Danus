"""Real integration gates for the host-owned Worker lifecycle seam."""

from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import signal
import time

import pytest

from danus.execution import layout as L
from danus.execution import scaffold, systemd_scope
from danus.orchestration import cli
from danus.secure_io import atomic_write_text
from danus.web_console.runtime import DanusRuntimeAdapter


def test_worker_host_environment_keeps_failure_budget_but_drops_web_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = L.WorkerLayout(
        tmp_path / "projects" / "Project-A" / "workers" / "high",
    )
    monkeypatch.setenv("DANUS_RUNTIME", str(tmp_path / "runtime"))
    monkeypatch.setenv("DANUS_MAX_CONSEC_FAILURES", "9")
    monkeypatch.setenv("DANUS_ROUND_MAX_CONSECUTIVE_FAILURES", "unsafe-alias")
    monkeypatch.setenv("DANUS_WEB_LIFECYCLE_CAPABILITY", "must-not-cross")
    monkeypatch.setenv("GH_TOKEN", "must-not-cross-either")

    environment = systemd_scope.worker_environment(worker)

    assert environment["DANUS_MAX_CONSEC_FAILURES"] == "9"
    assert "DANUS_ROUND_MAX_CONSECUTIVE_FAILURES" not in environment
    assert "DANUS_WEB_LIFECYCLE_CAPABILITY" not in environment
    assert "GH_TOKEN" not in environment


def _require_user_manager() -> None:
    try:
        systemd_scope.validate_user_manager()
    except systemd_scope.SystemdBoundaryError as exc:
        pytest.skip(f"systemd user manager unavailable: {exc}")


def _paused_worker(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> L.WorkerLayout:
    agents_root = tmp_path / "projects"
    runtime = tmp_path / "runtime"
    monkeypatch.setenv("DANUS_AGENTS_ROOT", str(agents_root))
    monkeypatch.setenv("DANUS_RUNTIME", str(runtime))
    created = scaffold.do_new("Project-A", roles="high:1", root=agents_root)
    worker = L.WorkerLayout(
        agents_root / "Project-A" / "workers" / created["workers"][0]
    )
    worker.pause.touch()
    return worker


def test_worker_waits_for_durable_identity_and_force_stop_proves_slice_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The public seam survives caller loss without PID/PGID authority."""

    _require_user_manager()
    worker = _paused_worker(tmp_path, monkeypatch)
    try:
        managed = systemd_scope.start_worker(worker)
        status = systemd_scope.inspect_worker_boundary(worker)

        assert status.state == "active"
        assert status.pid == managed.pid
        assert systemd_scope.environment_path(worker).exists() is False
        assert systemd_scope.ledger_path(worker).is_file()
        assert not worker.pid.exists()
        assert not worker.process_identity.exists()

        assert systemd_scope.stop_worker_boundary(worker, force=True) == "stopped"
        stopped = systemd_scope.inspect_worker_boundary(worker)
        assert stopped.state == "absent"
        assert stopped.populated is False
        assert not systemd_scope.ledger_path(worker).exists()
    finally:
        try:
            systemd_scope.stop_worker_boundary(worker, force=True)
        except systemd_scope.SystemdBoundaryError:
            pass
        for path in (systemd_scope.environment_path(worker), systemd_scope.ledger_path(worker)):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass


def test_cgroup_pin_owns_live_descriptors_after_helper_returns() -> None:
    """The cgroup proof must remain readable after the pin helper returns."""

    _require_user_manager()
    cgroup = systemd_scope.validate_user_manager()
    pin = systemd_scope._open_cgroup_pin(cgroup)  # type: ignore[attr-defined]
    assert pin is not None
    try:
        assert pin.dir_fd >= 0 and pin.events_fd >= 0
        assert pin.populated() is True
        assert pin.path_matches()
    finally:
        pin.close()


def test_cli_and_web_reconnect_and_force_stop_through_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Web adapter restart reconnects without PID/PGID metadata authority."""

    _require_user_manager()
    worker = _paused_worker(tmp_path, monkeypatch)
    agents_root = worker.project_dir.parent
    adapter = DanusRuntimeAdapter(agents_root)
    try:
        started = cli.do_start(
            f"{worker.project}/{worker.name}", root=agents_root,
        )
        assert started == [{"worker": worker.name, "result": "started"}]
        assert not worker.pid.exists() and not worker.process_identity.exists()

        cli_status = cli.worker_status(worker)
        assert cli_status["alive"] is True
        assert cli_status["process_identity"] == "matched"
        assert cli_status["identity_verified"] is True

        web = adapter.status_project(worker.project)["workers"][0]
        assert web["alive"] is True
        assert web["boundary_state"] == "active"
        assert web["process_identity"] == "matched"

        forced = adapter.force_stop_project(
            worker.project, worker=worker.name, term_timeout=5.0,
        )
        assert forced["status"] == "force_stopped"
        assert forced["workers"][0]["descendants_verified"] is True
        assert forced["workers"][0]["outcome"] == "terminated"
        assert systemd_scope.inspect_worker_boundary(worker).state == "absent"
    finally:
        try:
            systemd_scope.stop_worker_boundary(worker, force=True)
        except systemd_scope.SystemdBoundaryError:
            pass


def test_force_stop_slice_contains_setsid_double_fork_descendant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A model-style daemonization cannot escape the Worker cgroup boundary."""

    _require_user_manager()
    worker = _paused_worker(tmp_path, monkeypatch)
    escaped_pid_file = tmp_path / "escaped.pid"
    rogue_unit = f"danus-test-escape-{secrets.token_hex(8)}.service"
    escaped_pid: int | None = None
    try:
        systemd_scope.start_worker(worker)
        record = systemd_scope.read_ledger(worker)
        assert record is not None
        program = (
            "import os,time\n"
            "first=os.fork()\n"
            "if first==0:\n"
            " os.setsid()\n"
            " second=os.fork()\n"
            " if second>0: os._exit(0)\n"
            " os.setpgid(0,0)\n"
            f" open({str(escaped_pid_file)!r},'w').write(str(os.getpid()))\n"
            " time.sleep(300)\n"
            "os.waitpid(first,0)\n"
            "time.sleep(300)\n"
        )
        systemd_scope._run_manager([  # type: ignore[attr-defined]
            systemd_scope._safe_binary("systemd-run"),  # type: ignore[attr-defined]
            "--user", "--quiet", "--collect", "--service-type=exec",
            f"--unit={rogue_unit}", f"--slice={record['slice']}",
            "--property=WorkingDirectory=/",
            "--property=KillMode=control-group", "--property=SendSIGKILL=yes",
            "--", str(Path(os.sys.executable).absolute()), "-I", "-c", program,
        ])
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and not escaped_pid_file.is_file():
            time.sleep(0.01)
        assert escaped_pid_file.is_file()
        escaped_pid = int(escaped_pid_file.read_text(encoding="ascii"))
        assert os.getpgid(escaped_pid) == escaped_pid
        assert os.getsid(escaped_pid) != os.getsid(int(record["main_pid"]))
        assert systemd_scope._read_proc_cgroup(escaped_pid).startswith(  # type: ignore[attr-defined]
            str(record["slice_cgroup"]).rstrip("/") + "/"
        )

        assert systemd_scope.stop_worker_boundary(worker, force=True) == "stopped"
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and Path(f"/proc/{escaped_pid}").exists():
            time.sleep(0.01)
        assert not Path(f"/proc/{escaped_pid}").exists()
        assert systemd_scope.inspect_worker_boundary(worker).populated is False
    finally:
        systemd_scope._run_manager(  # type: ignore[attr-defined]
            [
                systemd_scope._safe_binary("systemctl"),  # type: ignore[attr-defined]
                "--user", "stop", rogue_unit,
            ],
            check=False,
        )
        try:
            systemd_scope.stop_worker_boundary(worker, force=True)
        except systemd_scope.SystemdBoundaryError:
            pass
        if escaped_pid is not None and Path(f"/proc/{escaped_pid}").exists():
            try:
                os.kill(escaped_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def test_reused_unit_name_is_never_stopped_from_stale_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A same-name, new invocation is rejected before any destructive call."""

    _require_user_manager()
    worker = _paused_worker(tmp_path, monkeypatch)
    unit = systemd_scope.worker_unit(worker)
    slice_name = systemd_scope.worker_slice(worker)
    try:
        systemd_scope.start_worker(worker)
        old = systemd_scope.read_ledger(worker)
        assert old is not None
        systemd_scope._run_manager(  # type: ignore[attr-defined]
            [
                systemd_scope._safe_binary("systemctl"),  # type: ignore[attr-defined]
                "--user", "stop", slice_name,
            ]
        )
        systemd_scope._run_manager([  # type: ignore[attr-defined]
            systemd_scope._safe_binary("systemd-run"),  # type: ignore[attr-defined]
            "--user", "--quiet", "--collect", "--service-type=exec",
            f"--unit={unit}", f"--slice={slice_name}",
            "--property=WorkingDirectory=/",
            "--property=KillMode=control-group", "--property=SendSIGKILL=yes",
            "--", "/usr/bin/sleep", "300",
        ])
        replacement = systemd_scope._show(  # type: ignore[attr-defined]
            unit, ("InvocationID", "ActiveState"),
        )
        assert replacement["InvocationID"] != old["invocation_id"]
        assert replacement["ActiveState"] == "active"

        with pytest.raises(systemd_scope.SystemdBoundaryError, match="reused"):
            systemd_scope.inspect_worker_boundary(worker)
        with pytest.raises(systemd_scope.SystemdBoundaryError, match="reused"):
            systemd_scope.stop_worker_boundary(worker, force=True)
        assert systemd_scope._show(  # type: ignore[attr-defined]
            unit, ("ActiveState",),
        )["ActiveState"] == "active"
    finally:
        systemd_scope._run_manager(  # type: ignore[attr-defined]
            [
                systemd_scope._safe_binary("systemctl"),  # type: ignore[attr-defined]
                "--user", "stop", slice_name,
            ],
            check=False,
        )
        systemd_scope.ledger_path(worker).unlink(missing_ok=True)
        systemd_scope.environment_path(worker).unlink(missing_ok=True)


def test_host_identity_change_marks_populated_boundary_orphaned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A reboot/manager mismatch cannot silently adopt a populated cgroup."""

    _require_user_manager()
    worker = _paused_worker(tmp_path, monkeypatch)
    original: dict[str, object] | None = None
    try:
        systemd_scope.start_worker(worker)
        original = systemd_scope.read_ledger(worker)
        assert original is not None
        stale = dict(original)
        stale["boot_id"] = "00000000-0000-0000-0000-000000000000"
        atomic_write_text(
            systemd_scope.ledger_path(worker),
            json.dumps(stale, sort_keys=True, separators=(",", ":")),
            mode=0o600,
        )
        status = systemd_scope.inspect_worker_boundary(worker)
        assert status.state == "orphaned"
        assert status.populated is True
        assert status.reason == "host-identity-changed"
    finally:
        if original is not None:
            atomic_write_text(
                systemd_scope.ledger_path(worker),
                json.dumps(original, sort_keys=True, separators=(",", ":")),
                mode=0o600,
            )
        try:
            systemd_scope.stop_worker_boundary(worker, force=True)
        except systemd_scope.SystemdBoundaryError:
            pass


def test_stale_host_ledger_clears_only_after_old_cgroup_is_gone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A reboot-style stale ledger is recoverable once its exact inode vanished."""

    _require_user_manager()
    worker = _paused_worker(tmp_path, monkeypatch)
    systemd_scope.start_worker(worker)
    record = systemd_scope.read_ledger(worker)
    assert record is not None
    systemd_scope._run_manager(  # type: ignore[attr-defined]
        [
            systemd_scope._safe_binary("systemctl"),  # type: ignore[attr-defined]
            "--user", "stop", str(record["slice"]),
        ]
    )
    stale = dict(record)
    stale["boot_id"] = "00000000-0000-0000-0000-000000000000"
    stale["manager_invocation_id"] = "0" * 32
    atomic_write_text(
        systemd_scope.ledger_path(worker),
        json.dumps(stale, sort_keys=True, separators=(",", ":")),
        mode=0o600,
    )
    status = systemd_scope.inspect_worker_boundary(worker)
    assert status.state == "absent"
    assert status.populated is False
    assert not systemd_scope.ledger_path(worker).exists()
