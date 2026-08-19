"""Regression tests for the Issue #32 destructive Replace Worker gate."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import sqlite3
import stat as stat_module
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable

import pytest
from starlette.requests import Request as StarletteRequest
from starlette.testclient import TestClient

from danus.execution import layout as L
from danus.execution import processes as P
from danus.web_console import runtime as runtime_module
from danus.web_console.app import AppSettings, create_app
from danus.web_console.runtime import (
    DanusRuntimeAdapter, RuntimeOperationError, RuntimeSafetyError,
)
from danus.web_console.security import hash_password
from danus.web_console.tests.test_http import FakeMemoryRuntime


_ORIGIN = "https://testserver"
_PASSWORD = "correct horse battery staple"


class GateRuntime(FakeMemoryRuntime):
    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.status_calls = 0
        self.status_projection: Any = None
        self.status_failure: Exception | None = None
        self.inspect_status: Callable[[], None] | None = None
        self.block_status = False
        self.status_entered = threading.Event()
        self.release_status = threading.Event()

    def status_project(self, runtime_name: str) -> dict[str, Any]:
        self.status_calls += 1
        if self.inspect_status is not None:
            self.inspect_status()
        if self.block_status:
            self.status_entered.set()
            if not self.release_status.wait(timeout=5):
                raise TimeoutError("test did not release status projection")
        if self.status_failure is not None:
            raise self.status_failure
        if self.status_projection is not None:
            return copy.deepcopy(self.status_projection)
        return super().status_project(runtime_name)


def _make_app(tmp_path: Path) -> tuple[Any, GateRuntime, AppSettings]:
    runtime = GateRuntime(tmp_path / "projects")
    settings = AppSettings(
        database_path=tmp_path / "console.sqlite3",
        password_hash=hash_password(_PASSWORD),
        cookie_secure=True,
        allowed_origins={_ORIGIN},
        lifecycle_hmac_secret=b"issue-32-worker-gate-secret",
    )
    return create_app(settings=settings, runtime=runtime), runtime, settings


def _login(client: TestClient) -> dict[str, str]:
    response = client.post(
        "/api/auth/login", json={"password": _PASSWORD},
        headers={"Origin": _ORIGIN},
    )
    assert response.status_code == 200, response.text
    return {
        "Origin": _ORIGIN,
        "X-CSRF-Token": response.json()["csrf_token"],
    }


def _project(client: TestClient, headers: dict[str, str]) -> dict[str, Any]:
    response = client.post(
        "/api/projects",
        json={"name": "A", "problem": "alpha", "roles": "high:1"},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()


def _upload(
    client: TestClient, project_id: str, headers: dict[str, str],
    filename: str, body: bytes,
) -> Any:
    return client.post(
        f"/api/projects/{project_id}/files",
        files={"file": (filename, body)},
        headers={**headers, "X-Danus-Upload-Filename": filename},
    )


def _make_conflict(
    client: TestClient, project_id: str, headers: dict[str, str],
    *, filename: str = "notes.md", old: bytes = b"old", new: bytes = b"new",
) -> tuple[dict[str, Any], dict[str, Any]]:
    current = _upload(client, project_id, headers, filename, old)
    assert current.status_code == 201, current.text
    conflict = _upload(client, project_id, headers, filename, new)
    assert conflict.status_code == 409, conflict.text
    return current.json(), conflict.json()


def _state_snapshot(
    app: Any, runtime: GateRuntime, project: dict[str, Any],
    conflict: dict[str, Any],
) -> dict[str, Any]:
    store = app.state.console_store
    row = store.conflict(conflict["conflict_id"], project["id"])
    assert row is not None
    materials = runtime.project_context_dir(project["runtime_name"]) / "materials"
    blobs = {
        path.name: path.read_bytes()
        for path in materials.iterdir()
        if path.is_file() and not path.is_symlink()
    }
    return {
        "conflict": row,
        "current": store.file(conflict["current"]["id"], project["id"]),
        "incoming": store.file(conflict["incoming"]["id"], project["id"]),
        "cleanup_jobs": store.file_cleanup_jobs(project["id"]),
        "blobs": blobs,
    }


def _rejection_audit(database_path: Path, project_id: str) -> dict[str, Any]:
    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM audit_events WHERE project_id=? AND action='file_conflict' "
            "AND outcome='replace_rejected_workers_not_stopped' ORDER BY id DESC LIMIT 1",
            (project_id,),
        ).fetchone()
    assert row is not None
    return dict(row)


def _set_persisted_terminal_group(
    adapter: DanusRuntimeAdapter, runtime_name: str, pid: int | None,
) -> Path:
    worker_dir = adapter.agents_root / runtime_name / "workers" / "high"
    status_path = worker_dir / ".status.json"
    status = json.loads(status_path.read_text(encoding="utf-8"))
    status.update({"state": "stopped", "round": 1, "started_at": 1.0})
    if pid is None:
        status.pop("pid", None)
    else:
        status["pid"] = pid
    status_path.write_text(json.dumps(status), encoding="utf-8")
    (worker_dir / ".pid").unlink(missing_ok=True)
    (worker_dir / ".process.json").unlink(missing_ok=True)
    if pid is not None:
        adapter._store_host_group_identity(
            runtime_name, "high", P.WorkerProcessIdentity(
                pid=pid, boot_id="test-boot", start_time="1",
                cmdline=P.expected_worker_cmdline(L.WorkerLayout(worker_dir)),
            ),
        )
    return worker_dir


def _host_identity(adapter: DanusRuntimeAdapter, runtime_name: str, worker: str,
                   *, pid: int = 4242) -> P.WorkerProcessIdentity:
    worker_dir = adapter.agents_root / runtime_name / "workers" / worker
    return P.WorkerProcessIdentity(
        pid=pid, boot_id="test-boot", start_time="1",
        cmdline=P.expected_worker_cmdline(L.WorkerLayout(worker_dir)),
    )


def _unsafe_projection(mode: str) -> Any:
    config = {"workers": ["high"]}
    if mode == "live":
        workers: Any = [{
            "worker": "high", "process_identity": "matched",
            "alive": True, "raw_alive": True, "state": "running",
        }]
    elif mode == "mismatch":
        workers = [{
            "worker": "high", "process_identity": "mismatch",
            "alive": False, "raw_alive": True, "state": "stale",
        }]
    elif mode == "unknown":
        workers = [{
            "worker": "high", "process_identity": "unknown",
            "alive": False, "raw_alive": False, "state": "stopped",
        }]
    elif mode == "descendant_membership_unavailable":
        workers = [{
            "worker": "high", "process_identity": "dead",
            "alive": False, "raw_alive": False, "state": "stopped",
            "process_exit_proof": {
                "status": "unknown", "reason": "descendant_membership_unavailable",
                "inspection_complete": True, "source": "host_process_group",
                "pgid": 4242, "live_process_count": 0,
                "project_reference_count": 0,
                "descendant_membership_verified": False,
            },
        }]
    elif mode == "malformed":
        workers = "not-a-roster"
    elif mode == "roster_mismatch":
        workers = []
    else:
        raise AssertionError(mode)
    return {"config": config, "workers": workers}


@pytest.mark.parametrize(
    ("mode", "expected_reason", "worker_reason"),
    [
        ("live", "workers_not_stopped", "worker_live"),
        ("mismatch", "workers_not_stopped", "worker_identity_mismatch"),
        ("unknown", "workers_not_stopped", "worker_identity_unknown"),
        (
            "descendant_membership_unavailable", "workers_not_stopped",
            "worker_descendant_membership_unverified",
        ),
        ("malformed", "invalid_status_projection", None),
        ("roster_mismatch", "roster_mismatch", None),
        ("status_failure", "status_unavailable", None),
    ],
)
def test_replace_fails_closed_and_preserves_conflict_and_blobs(
    tmp_path: Path, mode: str, expected_reason: str,
    worker_reason: str | None,
) -> None:
    app, runtime, settings = _make_app(tmp_path)
    with TestClient(app, base_url=_ORIGIN) as client:
        headers = _login(client)
        project = _project(client, headers)
        _current, conflict = _make_conflict(client, project["id"], headers)
        before = _state_snapshot(app, runtime, project, conflict)
        runtime.status_calls = 0
        if mode == "status_failure":
            runtime.status_failure = OSError("injected status failure")
        else:
            runtime.status_projection = _unsafe_projection(mode)

        response = client.post(
            f"/api/projects/{project['id']}/file-conflicts/{conflict['conflict_id']}",
            json={"choice": "replace"}, headers=headers,
        )

        assert response.status_code == 409, response.text
        assert response.json() == {
            "detail": (
                "Replace requires every Worker to be terminal and its "
                "complete process group exit to be verified"
            ),
            "error_code": "replace_workers_not_stopped",
            "status": "replace_blocked",
        }
        assert runtime.status_calls == 1
        assert runtime.stopped == []
        assert _state_snapshot(app, runtime, project, conflict) == before

        audit = _rejection_audit(settings.database_path, project["id"])
        details = json.loads(audit["details"])
        assert details["choice"] == "replace"
        assert details["conflict_id"] == conflict["conflict_id"]
        assert details["error_code"] == "replace_workers_not_stopped"
        assert details["reason"] == expected_reason
        if worker_reason is None:
            assert details["blocked_workers"] == []
        else:
            assert details["blocked_workers"] == [{
                "worker": "high", "reason": worker_reason,
            }]
        if mode == "status_failure":
            assert details["status_error"] == "OSError"


@pytest.mark.parametrize(
    "worker",
    [
        {
            "worker": "high", "process_identity": "dead",
            "alive": False, "raw_alive": False, "state": "stopped",
        },
        {"worker": "high", "alive": False, "state": "stopped"},
        {"worker": "high", "alive": False, "state": "created"},
    ],
)
def test_replace_allows_verified_dead_stopped_or_never_started_roster(
    tmp_path: Path, worker: dict[str, Any],
) -> None:
    app, runtime, _settings = _make_app(tmp_path)
    with TestClient(app, base_url=_ORIGIN) as client:
        headers = _login(client)
        project = _project(client, headers)
        current, conflict = _make_conflict(client, project["id"], headers)
        old_blob = (
            runtime.project_context_dir(project["runtime_name"])
            / "materials" / current["sha256"]
        )
        runtime.status_projection = {
            "config": {"workers": ["high"]}, "workers": [worker],
        }
        runtime.status_calls = 0

        response = client.post(
            f"/api/projects/{project['id']}/file-conflicts/{conflict['conflict_id']}",
            json={"choice": "replace"}, headers=headers,
        )

        assert response.status_code == 200, response.text
        assert response.json()["status"] == "replaced"
        assert runtime.status_calls == 1
        assert runtime.stopped == []
        assert not old_blob.exists()


def test_new_version_and_cancel_bypass_replace_worker_gate(tmp_path: Path) -> None:
    app, runtime, _settings = _make_app(tmp_path)
    with TestClient(app, base_url=_ORIGIN) as client:
        headers = _login(client)
        project = _project(client, headers)
        _current, version_conflict = _make_conflict(
            client, project["id"], headers, filename="version.md",
            old=b"version-old", new=b"version-new",
        )
        _other, cancel_conflict = _make_conflict(
            client, project["id"], headers, filename="cancel.md",
            old=b"cancel-old", new=b"cancel-new",
        )
        runtime.status_failure = AssertionError("non-Replace choice called status")
        runtime.status_calls = 0

        versioned = client.post(
            f"/api/projects/{project['id']}/file-conflicts/"
            f"{version_conflict['conflict_id']}",
            json={"choice": "new_version"}, headers=headers,
        )
        cancelled = client.post(
            f"/api/projects/{project['id']}/file-conflicts/"
            f"{cancel_conflict['conflict_id']}",
            json={"choice": "cancel"}, headers=headers,
        )

        assert versioned.status_code == 200, versioned.text
        assert cancelled.status_code == 200, cancelled.text
        assert runtime.status_calls == 0


def test_replace_status_proof_precedes_mutation_and_holds_project_lock(
    tmp_path: Path,
) -> None:
    app, runtime, _settings = _make_app(tmp_path)
    with TestClient(app, base_url=_ORIGIN) as client:
        headers = _login(client)
        project = _project(client, headers)
        _current, replace_conflict = _make_conflict(
            client, project["id"], headers, filename="replace.md",
            old=b"replace-old", new=b"replace-new",
        )
        _other, version_conflict = _make_conflict(
            client, project["id"], headers, filename="version.md",
            old=b"version-old", new=b"version-new",
        )
        before = _state_snapshot(app, runtime, project, replace_conflict)
        runtime.status_projection = {
            "config": {"workers": ["high"]},
            "workers": [{
                "worker": "high", "process_identity": "dead",
                "alive": False, "raw_alive": False, "state": "stopped",
            }],
        }

        inspected = threading.Event()

        def inspect_before_status_returns() -> None:
            assert _state_snapshot(app, runtime, project, replace_conflict) == before
            inspected.set()

        runtime.inspect_status = inspect_before_status_returns
        runtime.block_status = True
        second_started = threading.Event()
        second_mutated = threading.Event()
        original_resolve_new_version = app.state.console_store.resolve_new_version

        def observed_resolve_new_version(*args: Any, **kwargs: Any) -> Any:
            second_mutated.set()
            return original_resolve_new_version(*args, **kwargs)

        app.state.console_store.resolve_new_version = observed_resolve_new_version

        def replace_request() -> Any:
            return client.post(
                f"/api/projects/{project['id']}/file-conflicts/"
                f"{replace_conflict['conflict_id']}",
                json={"choice": "replace"}, headers=headers,
            )

        def version_request() -> Any:
            second_started.set()
            return client.post(
                f"/api/projects/{project['id']}/file-conflicts/"
                f"{version_conflict['conflict_id']}",
                json={"choice": "new_version"}, headers=headers,
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            replacing = executor.submit(replace_request)
            assert runtime.status_entered.wait(timeout=2)
            assert inspected.is_set()
            versioning = executor.submit(version_request)
            assert second_started.wait(timeout=2)
            assert not second_mutated.wait(timeout=0.15)
            assert _state_snapshot(app, runtime, project, replace_conflict) == before
            runtime.release_status.set()
            replaced = replacing.result(timeout=5)
            versioned = versioning.result(timeout=5)

        assert replaced.status_code == 200, replaced.text
        assert versioned.status_code == 200, versioned.text
        assert second_mutated.is_set()


def test_runtime_exit_projection_blocks_orphan_descendant_after_leader_exit(
    tmp_path: Path,
) -> None:
    adapter = DanusRuntimeAdapter(
        tmp_path / "agents", _allow_legacy_process_test_seam=True,
    )
    adapter.create_project("A", "alpha", "high:1", max_parallel_workers=1)
    child_pid_path = tmp_path / "orphan.pid"
    script = (
        "import pathlib,subprocess; "
        "child=subprocess.Popen(['sleep','30']); "
        f"pathlib.Path({str(child_pid_path)!r}).write_text(str(child.pid))"
    )
    leader = subprocess.Popen([sys.executable, "-c", script], start_new_session=True)
    child_pid: int | None = None
    try:
        leader.wait(timeout=3)
        deadline = time.time() + 3
        while time.time() < deadline and not child_pid_path.exists():
            time.sleep(0.02)
        assert child_pid_path.exists()
        child_pid = int(child_pid_path.read_text(encoding="utf-8"))
        _set_persisted_terminal_group(adapter, "A", leader.pid)

        worker = adapter.worker_exit_projection("A")["workers"][0]

        assert worker["process_identity"] == "dead"
        assert worker["process_exit_proof"] == {
            "status": "blocked",
            "reason": "process_group_live_or_reused",
            "inspection_complete": True,
            "source": "host_process_group",
            "pgid": leader.pid,
            "live_process_count": 1,
            "project_reference_count": 0,
            "descendant_membership_verified": False,
        }
    finally:
        if leader.poll() is None:
            leader.kill()
        leader.wait(timeout=3)
        if child_pid is not None:
            try:
                os.kill(child_pid, 9)
            except ProcessLookupError:
                pass


def test_runtime_exit_projection_distinguishes_never_started_from_lost_group_evidence(
    tmp_path: Path,
) -> None:
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    adapter.create_project("A", "alpha", "high:1", max_parallel_workers=1)

    never_started = adapter.worker_exit_projection("A")["workers"][0]
    assert never_started["process_exit_proof"]["status"] == "verified_dead"
    assert never_started["process_exit_proof"]["source"] == "never_started"

    _set_persisted_terminal_group(adapter, "A", None)
    evidence_lost = adapter.worker_exit_projection("A")["workers"][0]
    assert evidence_lost["process_exit_proof"]["status"] == "unknown"
    assert evidence_lost["process_exit_proof"]["reason"] == "missing_host_process_group"
    assert evidence_lost["process_exit_proof"]["inspection_complete"] is False


@pytest.mark.parametrize(
    ("mode", "processes", "expected_reason"),
    [
        (
            "pid_reuse",
            [{
                "pid": 4242, "pgid": 9000, "start_time": "2",
                "group_member": False, "reused_leader_pid": True,
                "references_project": False,
            }],
            "leader_pid_reused",
        ),
        (
            "pgid_reuse",
            [{
                "pid": 5000, "pgid": 4242, "start_time": "3",
                "group_member": True, "reused_leader_pid": False,
                "references_project": False,
            }],
            "process_group_live_or_reused",
        ),
        (
            "project_reference",
            [{
                "pid": 5001, "pgid": 5001, "start_time": "4",
                "group_member": False, "reused_leader_pid": False,
                "references_project": True,
            }],
            "project_process_reference",
        ),
    ],
)
def test_runtime_exit_projection_fails_closed_on_reuse_and_project_processes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str,
    processes: list[dict[str, Any]], expected_reason: str,
) -> None:
    adapter = DanusRuntimeAdapter(tmp_path / mode / "agents")
    adapter.create_project("A", "alpha", "high:1", max_parallel_workers=1)
    _set_persisted_terminal_group(adapter, "A", 4242)
    monkeypatch.setattr(
        adapter, "_project_process_projection",
        lambda _root, groups: copy.deepcopy(processes) if groups == {4242} else [],
    )

    proof = adapter.worker_exit_projection("A")["workers"][0]["process_exit_proof"]

    assert proof["status"] == "blocked"
    assert proof["reason"] == expected_reason
    assert proof["inspection_complete"] is True


def test_runtime_exit_projection_fails_closed_when_process_inspection_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    adapter.create_project("A", "alpha", "high:1", max_parallel_workers=1)
    _set_persisted_terminal_group(adapter, "A", 4242)

    def unavailable(_root: Path, _groups: set[int]) -> list[dict[str, Any]]:
        raise RuntimeSafetyError("injected procfs failure")

    monkeypatch.setattr(adapter, "_project_process_projection", unavailable)
    proof = adapter.worker_exit_projection("A")["workers"][0]["process_exit_proof"]

    assert proof == {
        "status": "unknown",
        "reason": "process_inspection_failed",
        "inspection_complete": False,
        "source": "host_process_group",
        "pgid": 4242,
        "live_process_count": 0,
        "project_reference_count": 0,
        "descendant_membership_verified": False,
    }


def test_runtime_empty_pgid_scan_still_requires_owned_descendant_membership(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    adapter.create_project("A", "alpha", "high:1", max_parallel_workers=1)
    _set_persisted_terminal_group(adapter, "A", 4242)
    monkeypatch.setattr(
        adapter, "_project_process_projection", lambda _root, _groups: [],
    )

    proof = adapter.worker_exit_projection("A")["workers"][0]["process_exit_proof"]

    assert proof["status"] == "unknown"
    assert proof["reason"] == "descendant_membership_unavailable"
    assert proof["inspection_complete"] is True
    assert proof["descendant_membership_verified"] is False


def test_runtime_accepts_started_worker_only_with_owned_empty_membership_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    adapter.create_project("A", "alpha", "high:1", max_parallel_workers=1)
    _set_persisted_terminal_group(adapter, "A", 4242)
    monkeypatch.setattr(
        adapter, "_project_process_projection", lambda _root, _groups: [],
    )
    monkeypatch.setattr(
        adapter, "_descendant_membership_projection",
        lambda _runtime, _worker, _identity: {
            "status": "empty", "inspection_complete": True,
        },
    )

    proof = adapter.worker_exit_projection("A")["workers"][0]["process_exit_proof"]

    assert proof["status"] == "verified_dead"
    assert proof["reason"] is None
    assert proof["descendant_membership_verified"] is True


def _supervisor_identity_fixture(
    adapter: DanusRuntimeAdapter,
) -> tuple[L.WorkerLayout, P.WorkerProcessIdentity, dict[str, Any], dict[str, Any]]:
    worker_dir = adapter.agents_root / "A" / "workers" / "high"
    wl = L.WorkerLayout(worker_dir)
    unit = runtime_module.S.worker_unit(wl)
    slice_name = runtime_module.S.worker_slice(wl)
    invocation = "a" * 32
    slice_invocation = "b" * 32
    identity = P.WorkerProcessIdentity(
        pid=4242, boot_id="fixture-boot", start_time="fixture-start",
        cmdline=P.expected_worker_cmdline(wl),
    )
    ledger: dict[str, Any] = {
        "schema": 2, "worker_dir": str(worker_dir.resolve()),
        "unit": unit, "slice": slice_name,
        "main_pid": identity.pid, "main_pid_start_time": identity.start_time,
        "worker_argv": list(identity.cmdline), "boot_id": identity.boot_id,
        "invocation_id": invocation, "slice_invocation_id": slice_invocation,
        "unit_cgroup": f"/user.slice/{slice_name}/{unit}",
        "slice_cgroup": f"/user.slice/{slice_name}",
    }
    proof = {
        "schema": 2, "worker_dir": str(worker_dir.resolve()),
        "unit": unit, "slice": slice_name,
        "invocation_id": invocation, "slice_invocation_id": slice_invocation,
        "boot_id": identity.boot_id, "reason": "cgroup-empty", "populated": False,
        "main_pid": identity.pid, "main_pid_start_time": identity.start_time,
        "worker_argv": list(identity.cmdline),
    }
    return wl, identity, ledger, proof


@pytest.mark.parametrize("state", ["active", "orphaned", "error"])
def test_supervisor_projection_rejects_live_or_failed_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: str,
) -> None:
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    adapter.create_project("A", "alpha", "high:1", max_parallel_workers=1)
    wl, identity, ledger, proof = _supervisor_identity_fixture(adapter)
    monkeypatch.setattr(runtime_module.S, "read_ledger", lambda _wl: ledger)
    if state == "error":
        def raise_boundary(_wl):
            raise runtime_module.S.SystemdBoundaryError("reused boundary")
        monkeypatch.setattr(runtime_module.S, "inspect_worker_boundary", raise_boundary)
    else:
        monkeypatch.setattr(
            runtime_module.S, "inspect_worker_boundary",
            lambda _wl: runtime_module.S.WorkerBoundaryStatus(
                state, 4242, True, ledger["unit"], ledger["slice"],
                ledger["invocation_id"], state,
            ),
        )
    monkeypatch.setattr(runtime_module.S, "read_exit_proof", lambda _wl: proof)

    result = adapter._descendant_membership_projection("A", "high", identity)

    assert result["status"] != "empty"
    assert result["inspection_complete"] is False
    assert result["source"] == "systemd_scope"


def test_supervisor_projection_rejects_stale_ledger_and_identity_reuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    adapter.create_project("A", "alpha", "high:1", max_parallel_workers=1)
    _wl, identity, ledger, _proof = _supervisor_identity_fixture(adapter)
    monkeypatch.setattr(runtime_module.S, "read_ledger", lambda _wl: ledger)

    def reused(_wl):
        raise runtime_module.S.SystemdBoundaryError("recorded Worker service unit was reused")

    monkeypatch.setattr(runtime_module.S, "inspect_worker_boundary", reused)
    result = adapter._descendant_membership_projection("A", "high", identity)
    assert result["status"] == "unavailable"
    assert result["reason"] == "boundary_error"

    monkeypatch.setattr(
        runtime_module.S, "inspect_worker_boundary",
        lambda _wl: runtime_module.S.WorkerBoundaryStatus(
            "absent", None, False, ledger["unit"], ledger["slice"],
            ledger["invocation_id"], "cgroup-empty",
        ),
    )
    monkeypatch.setattr(runtime_module.S, "read_exit_proof", lambda _wl: {
        **_proof, "main_pid": 4343,
    })
    result = adapter._descendant_membership_projection("A", "high", identity)
    assert result["status"] == "unavailable"
    assert result["reason"] == "identity_mismatch"


def test_supervisor_projection_accepts_only_absent_exact_exit_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    adapter.create_project("A", "alpha", "high:1", max_parallel_workers=1)
    _wl, identity, ledger, proof = _supervisor_identity_fixture(adapter)
    monkeypatch.setattr(runtime_module.S, "read_ledger", lambda _wl: ledger)
    monkeypatch.setattr(
        runtime_module.S, "inspect_worker_boundary",
        lambda _wl: runtime_module.S.WorkerBoundaryStatus(
            "absent", None, False, ledger["unit"], ledger["slice"],
            ledger["invocation_id"], "cgroup-empty",
        ),
    )
    monkeypatch.setattr(runtime_module.S, "read_exit_proof", lambda _wl: proof)

    result = adapter._descendant_membership_projection("A", "high", identity)

    assert result == {
        "status": "empty", "inspection_complete": True,
        "source": "systemd_scope", "reason": None,
        "boundary_state": "absent", "populated": False,
    }


def test_worker_exit_projection_uses_exact_proof_when_journal_was_not_published(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    adapter.create_project("A", "alpha", "high:1", max_parallel_workers=1)
    worker_dir = _set_persisted_terminal_group(adapter, "A", 4242)
    # Keep the model/status PID as a consistency check, but remove the legacy
    # host journal so this exercises the supervisor exit-proof fallback.
    journal = adapter.agents_root / ".danus-web-process-groups/A/high.json"
    journal.unlink()
    wl, identity, ledger, proof = _supervisor_identity_fixture(adapter)
    assert worker_dir == wl.dir
    monkeypatch.setattr(runtime_module.S, "read_ledger", lambda _wl: None)
    monkeypatch.setattr(runtime_module.S, "read_exit_proof", lambda _wl: proof)
    monkeypatch.setattr(
        runtime_module.S, "inspect_worker_boundary",
        lambda _wl: runtime_module.S.WorkerBoundaryStatus(
            "absent", None, False, ledger["unit"], ledger["slice"],
            ledger["invocation_id"], "cgroup-empty",
        ),
    )
    monkeypatch.setattr(adapter, "_project_process_projection", lambda _root, _groups: [])

    worker = adapter.worker_exit_projection("A")["workers"][0]

    assert worker["process_exit_proof"]["status"] == "verified_dead"
    assert worker["process_exit_proof"]["source"] == "systemd_exit_proof"
    assert worker["process_exit_proof"]["descendant_membership_verified"] is True


def test_runtime_rejects_tampered_status_group_and_duplicate_host_groups(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    adapter.create_project("A", "alpha", "high:2", max_parallel_workers=2)
    root = adapter.agents_root / "A" / "workers"
    for name in ("high", "high2"):
        status_path = root / name / ".status.json"
        status = json.loads(status_path.read_text(encoding="utf-8"))
        status.update({"state": "stopped", "round": 1, "pid": 4242})
        status_path.write_text(json.dumps(status), encoding="utf-8")
        adapter._store_host_group_identity(
            "A", name, P.WorkerProcessIdentity(
                pid=4242, boot_id="test-boot", start_time="1",
                cmdline=P.expected_worker_cmdline(L.WorkerLayout(root / name)),
            ),
        )
    monkeypatch.setattr(
        adapter, "_project_process_projection", lambda _root, _groups: [],
    )

    duplicate = adapter.worker_exit_projection("A")["workers"]
    assert {row["process_exit_proof"]["reason"] for row in duplicate} == {
        "duplicate_host_process_group",
    }

    status_path = root / "high2" / ".status.json"
    status = json.loads(status_path.read_text(encoding="utf-8"))
    status["pid"] = 4343
    status_path.write_text(json.dumps(status), encoding="utf-8")
    tampered = adapter.worker_exit_projection("A")["workers"]
    by_name = {row["worker"]: row for row in tampered}
    assert by_name["high2"]["process_exit_proof"]["reason"] == "host_process_group_mismatch"


def test_runtime_rejects_malformed_model_writable_identity_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    adapter.create_project("A", "alpha", "high:1", max_parallel_workers=1)
    worker_dir = _set_persisted_terminal_group(adapter, "A", 4242)
    (worker_dir / ".process.json").write_text("{truncated", encoding="utf-8")
    monkeypatch.setattr(
        adapter, "_project_process_projection", lambda _root, _groups: [],
    )

    proof = adapter.worker_exit_projection("A")["workers"][0]["process_exit_proof"]

    assert proof["status"] == "unknown"
    assert proof["reason"] == "control_record_inspection_failed"
    assert proof["inspection_complete"] is False


def test_duplicate_create_preserves_existing_host_journal_and_exit_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    adapter.create_project("A", "alpha", "high:1", max_parallel_workers=1)
    _set_persisted_terminal_group(adapter, "A", 4242)
    monkeypatch.setattr(
        adapter, "_project_process_projection", lambda _root, _groups: [],
    )
    monkeypatch.setattr(
        adapter, "_descendant_membership_projection",
        lambda _runtime, _worker, _identity: {
            "status": "empty", "inspection_complete": True,
        },
    )
    journal = adapter.agents_root / ".danus-web-process-groups/A/high.json"
    before_bytes = journal.read_bytes()
    before_digest = hashlib.sha256(before_bytes).hexdigest()
    before_proof = copy.deepcopy(
        adapter.worker_exit_projection("A")["workers"][0]["process_exit_proof"],
    )

    with pytest.raises(RuntimeOperationError, match="already exists"):
        adapter.create_project("A", "replacement", "high:1", max_parallel_workers=1)

    after_bytes = journal.read_bytes()
    assert after_bytes == before_bytes
    assert hashlib.sha256(after_bytes).hexdigest() == before_digest
    assert adapter.worker_exit_projection("A")["workers"][0][
        "process_exit_proof"
    ] == before_proof


def test_host_journal_has_an_independent_private_atomic_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The security journal must not inherit scaffold writer API changes."""
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    scaffold_calls: list[Path] = []

    def baseline_atomic_write(path: Path, text: str) -> None:
        scaffold_calls.append(path)
        path.write_text(text, encoding="utf-8")

    monkeypatch.setattr(runtime_module, "atomic_write", baseline_atomic_write)

    adapter._store_host_group_identity(
        "A", "high", _host_identity(adapter, "A", "high"),
    )

    journal = adapter.agents_root / ".danus-web-process-groups/A/high.json"
    assert scaffold_calls == []
    assert json.loads(journal.read_text(encoding="utf-8"))["pgid"] == 4242
    assert stat_module.S_IMODE(journal.stat().st_mode) == 0o600


def test_host_journal_atomically_replaces_symlink_without_touching_referent(
    tmp_path: Path,
) -> None:
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    project = adapter._host_group_project_dir("A", create=True)
    assert project is not None
    outside = tmp_path / "outside.json"
    outside.write_text("operator-owned", encoding="utf-8")
    journal = project / "high.json"
    journal.symlink_to(outside)

    adapter._store_host_group_identity(
        "A", "high", _host_identity(adapter, "A", "high"),
    )

    assert outside.read_text(encoding="utf-8") == "operator-owned"
    assert not journal.is_symlink()
    assert journal.is_file()
    assert stat_module.S_IMODE(journal.stat().st_mode) == 0o600


def test_host_journal_retries_random_temporary_name_collisions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    project = adapter._host_group_project_dir("A", create=True)
    assert project is not None
    outside = tmp_path / "outside.tmp"
    outside.write_text("do-not-touch", encoding="utf-8")
    collision = project / ".danus-web-collision.tmp"
    collision.symlink_to(outside)
    tokens = iter(("collision", "available"))
    monkeypatch.setattr(
        runtime_module.secrets, "token_hex", lambda _size: next(tokens),
    )

    adapter._store_host_group_identity(
        "A", "high", _host_identity(adapter, "A", "high"),
    )

    journal = project / "high.json"
    assert json.loads(journal.read_text(encoding="utf-8"))["pgid"] == 4242
    assert collision.is_symlink()
    assert outside.read_text(encoding="utf-8") == "do-not-touch"
    assert not (project / ".danus-web-available.tmp").exists()


def test_successful_create_discards_only_its_crash_stale_host_journal(
    tmp_path: Path,
) -> None:
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    worker_dir = adapter.agents_root / "B/workers/high"
    adapter._store_host_group_identity(
        "B", "high", P.WorkerProcessIdentity(
            pid=4242, boot_id="stale-boot", start_time="1",
            cmdline=P.expected_worker_cmdline(L.WorkerLayout(worker_dir)),
        ),
    )
    journal = adapter.agents_root / ".danus-web-process-groups/B/high.json"
    assert journal.is_file()

    adapter.create_project("B", "beta", "high:1", max_parallel_workers=1)

    assert not journal.exists()
    proof = adapter.worker_exit_projection("B")["workers"][0]["process_exit_proof"]
    assert proof["status"] == "verified_dead"
    assert proof["source"] == "never_started"


def test_create_serializes_stale_cleanup_with_concurrent_journal_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = DanusRuntimeAdapter(tmp_path / "agents")
    original_new = runtime_module.cli.do_new
    writer_started = threading.Event()
    writer_done = threading.Event()
    writers: list[threading.Thread] = []

    def raced_new(*args: Any, **kwargs: Any) -> dict[str, Any]:
        result = original_new(*args, **kwargs)
        worker_dir = adapter.agents_root / "C/workers/high"

        def write_new_identity() -> None:
            writer_started.set()
            adapter._store_host_group_identity(
                "C", "high", P.WorkerProcessIdentity(
                    pid=4343, boot_id="new-boot", start_time="2",
                    cmdline=P.expected_worker_cmdline(L.WorkerLayout(worker_dir)),
                ),
            )
            writer_done.set()

        writer = threading.Thread(target=write_new_identity)
        writers.append(writer)
        writer.start()
        assert writer_started.wait(timeout=1)
        assert not writer_done.wait(timeout=0.1)
        return result

    monkeypatch.setattr(runtime_module.cli, "do_new", raced_new)

    adapter.create_project("C", "gamma", "high:1", max_parallel_workers=1)
    writers[0].join(timeout=2)

    assert writer_done.is_set()
    journal = adapter.agents_root / ".danus-web-process-groups/C/high.json"
    assert json.loads(journal.read_text(encoding="utf-8"))["pgid"] == 4343


def test_production_adapter_replace_and_delete_use_full_exit_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = DanusRuntimeAdapter(
        tmp_path / "agents", _allow_legacy_process_test_seam=True,
    )
    settings = AppSettings(
        database_path=tmp_path / "console.sqlite3",
        password_hash=hash_password(_PASSWORD),
        cookie_secure=True, allowed_origins={_ORIGIN},
        lifecycle_hmac_secret=b"issue-32-production-proof",
    )
    calls: list[str] = []
    original_projection = runtime.worker_exit_projection

    def observed_projection(runtime_name: str) -> dict[str, Any]:
        calls.append(runtime_name)
        return original_projection(runtime_name)

    monkeypatch.setattr(runtime, "worker_exit_projection", observed_projection)
    app = create_app(settings=settings, runtime=runtime)
    with TestClient(app, base_url=_ORIGIN) as client:
        headers = _login(client)
        project = _project(client, headers)
        _current, conflict = _make_conflict(client, project["id"], headers)

        replaced = client.post(
            f"/api/projects/{project['id']}/file-conflicts/{conflict['conflict_id']}",
            json={"choice": "replace"}, headers=headers,
        )
        assert replaced.status_code == 200, replaced.text

        deleted = client.request(
            "DELETE", f"/api/projects/{project['id']}",
            json={"confirm_name": project["name"]}, headers=headers,
        )
        assert deleted.status_code == 200, deleted.text

    # Two upload pre-body gates, Replace, and project deletion all share the
    # exact production runtime proof source.
    assert calls == ["A", "A", "A", "A"]


@pytest.mark.parametrize(
    ("proof_reason", "expected_worker_reason"),
    [
        ("process_group_live_or_reused", "worker_process_group_live_or_reused"),
        ("leader_pid_reused", "worker_process_identity_reused"),
        ("process_inspection_failed", "worker_process_inspection_failed"),
        (
            "descendant_membership_unavailable",
            "worker_descendant_membership_unverified",
        ),
        (None, "worker_process_group_unverified"),
    ],
)
def test_every_upload_rejects_incomplete_group_proof_before_reading_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    proof_reason: str | None, expected_worker_reason: str,
) -> None:
    app, runtime, settings = _make_app(tmp_path)
    with TestClient(app, base_url=_ORIGIN) as client:
        headers = _login(client)
        project = _project(client, headers)
        proof: dict[str, Any] | None
        if proof_reason is None:
            proof = None
        else:
            proof = {
                "status": "unknown" if proof_reason == "process_inspection_failed" else "blocked",
                "reason": proof_reason,
                "inspection_complete": proof_reason != "process_inspection_failed",
                "source": "host_process_group", "pgid": 4242,
                "live_process_count": 1 if "live" in proof_reason else 0,
                "project_reference_count": 0,
                "descendant_membership_verified": False,
            }
        runtime.status_projection = {
            "config": {"workers": ["high"]},
            "workers": [{
                "worker": "high", "process_identity": "dead",
                "alive": False, "raw_alive": False, "state": "stopped",
                "process_exit_proof": proof,
            }],
        }
        form_calls = 0

        def forbidden_form(*_args: Any, **_kwargs: Any) -> Any:
            nonlocal form_calls
            form_calls += 1
            raise AssertionError("multipart parser must not be called")

        monkeypatch.setattr(StarletteRequest, "form", forbidden_form)
        response = _upload(
            client, project["id"], headers, "first.md",
            b"unread-process-group-blocked-body",
        )

        assert response.status_code == 409, response.text
        assert response.json()["error_code"] == "file_upload_workers_not_stopped"
        assert form_calls == 0
        audit = _rejection_audit_for_upload(settings.database_path, project["id"])
        details = json.loads(audit["details"])
        assert details["blocked_workers"] == [{
            "worker": "high", "reason": expected_worker_reason,
        }]


def _rejection_audit_for_upload(database_path: Path, project_id: str) -> dict[str, Any]:
    with sqlite3.connect(database_path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM audit_events WHERE project_id=? AND action='file_upload' "
            "AND outcome='rejected_workers_not_stopped' ORDER BY id DESC LIMIT 1",
            (project_id,),
        ).fetchone()
    assert row is not None
    return dict(row)
