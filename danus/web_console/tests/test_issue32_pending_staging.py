"""Private pending-staging and maintenance-gate regressions for Issue #32."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from pathlib import Path
from typing import Any

import pytest
from starlette.requests import Request as StarletteRequest
from starlette.testclient import TestClient

import danus.web_console.app as app_module
import danus.web_console.files as files_module
from danus.web_console.app import AppSettings, create_app
from danus.web_console.files import (
    control_staging_root,
    encode_upload_filename,
    material_root,
)
from danus.web_console.security import hash_password, project_lifecycle_capability
from danus.web_console.store import ConsoleStore
from danus.web_console.tests.test_issue32_security import (
    ArtifactRuntime,
    CaptureMainAgent,
)


_ORIGIN = "https://testserver"
_PASSWORD = "correct horse battery staple"
_SECRET = b"issue-32-pending-staging-secret"


class ObservedRuntime(ArtifactRuntime):
    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self.status_override: dict[str, Any] | None = None
        self.status_calls = 0
        self.start_calls = 0
        self.resume_calls = 0
        self.memory_calls = 0
        self.fact_calls = 0

    def status_project(self, runtime_name: str) -> dict[str, Any]:
        self.status_calls += 1
        if self.status_override is not None:
            return json.loads(json.dumps(self.status_override))
        return super().status_project(runtime_name)

    def start_project(self, runtime_name: str) -> dict[str, Any]:
        self.start_calls += 1
        return super().start_project(runtime_name)

    def resume_project(
        self, runtime_name: str, *, worker: str | None = None,
    ) -> dict[str, Any]:
        self.resume_calls += 1
        return super().resume_project(runtime_name, worker=worker)

    def memory_projection(self, runtime_name: str) -> dict[str, Any]:
        self.memory_calls += 1
        return super().memory_projection(runtime_name)

    def fact_graph_projection(self, runtime_name: str) -> dict[str, Any]:
        self.fact_calls += 1
        return super().fact_graph_projection(runtime_name)


def _settings(tmp_path: Path) -> AppSettings:
    return AppSettings(
        database_path=tmp_path / "console.sqlite3",
        password_hash=hash_password(_PASSWORD),
        cookie_secure=True,
        allowed_origins={_ORIGIN},
        lifecycle_hmac_secret=_SECRET,
        orchestration_poll_seconds=3600,
        deadline_poll_seconds=3600,
    )


def _make_app(
    tmp_path: Path, *, runtime: ObservedRuntime | None = None,
    main_agent: CaptureMainAgent | None = None,
    settings: AppSettings | None = None,
) -> tuple[Any, ObservedRuntime, CaptureMainAgent, AppSettings]:
    runtime = runtime or ObservedRuntime(tmp_path / "projects")
    main_agent = main_agent or CaptureMainAgent()
    settings = settings or _settings(tmp_path)
    return (
        create_app(settings=settings, runtime=runtime, main_agent=main_agent),
        runtime,
        main_agent,
        settings,
    )


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


def _project(
    client: TestClient, headers: dict[str, str], name: str = "A",
) -> dict[str, Any]:
    response = client.post(
        "/api/projects",
        json={"name": name, "problem": f"problem {name}", "roles": "high:1"},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()


def _upload(
    client: TestClient, project_id: str, headers: dict[str, str],
    filename: str, body: bytes, *, declared: str | None = None,
):
    return client.post(
        f"/api/projects/{project_id}/files",
        files={"file": (filename, body)},
        headers={
            **headers,
            "X-Danus-Upload-Filename": (
                encode_upload_filename(filename) if declared is None else declared
            ),
        },
    )


def _broker(
    client: TestClient, project: dict[str, Any], payload: dict[str, Any],
):
    token = project_lifecycle_capability(
        _SECRET, project["id"], project["runtime_name"],
    )
    return client.post(
        f"/internal/api/projects/{project['id']}/lifecycle",
        json=payload, headers={"Authorization": f"Bearer {token}"},
    )


def _staging(
    runtime: ObservedRuntime, project: dict[str, Any],
) -> tuple[Path, Path]:
    context = Path(runtime.project_context_dir(project["runtime_name"]))
    materials = material_root(context)
    return materials, control_staging_root(context, materials)


def _table_count(database: Path, table: str, project_id: str) -> int:
    with sqlite3.connect(database) as connection:
        return int(connection.execute(
            f"SELECT COUNT(*) FROM {table} WHERE project_id=?", (project_id,),
        ).fetchone()[0])


@pytest.mark.parametrize(
    "declared",
    [None, "%GG.md", "notes%2emd", "%FF.md", "e%CC%81.md", "%e8%B5%84%E6%96%99.md", "bad%2Fname.md"],
)
def test_upload_header_is_rejected_before_multipart_form_is_consumed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, declared: str | None,
) -> None:
    app, _runtime, _main, _settings_value = _make_app(tmp_path)
    with TestClient(app, base_url=_ORIGIN, client=("127.0.0.1", 50140)) as client:
        headers = _login(client)
        project = _project(client, headers)
        calls = 0

        def forbidden_form(*_args: Any, **_kwargs: Any) -> Any:
            nonlocal calls
            calls += 1
            raise AssertionError("multipart parser must not be called")

        monkeypatch.setattr(StarletteRequest, "form", forbidden_form)
        request_headers = dict(headers)
        if declared is not None:
            request_headers["X-Danus-Upload-Filename"] = declared
        response = client.post(
            f"/api/projects/{project['id']}/files",
            files={"file": ("notes.md", b"body")}, headers=request_headers,
        )

        assert response.status_code == 400
        assert calls == 0
        assert app.state.console_store.files(project["id"]) == []


def test_live_worker_conflict_preflight_reads_no_form_and_mutates_no_file_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, runtime, _main, settings = _make_app(tmp_path)
    with TestClient(app, base_url=_ORIGIN, client=("127.0.0.1", 50141)) as client:
        headers = _login(client)
        project = _project(client, headers)
        current = _upload(
            client, project["id"], headers, "notes.md", b"current bytes",
        )
        assert current.status_code == 201, current.text
        materials, staging = _staging(runtime, project)
        before_materials = {
            path.name: path.read_bytes() for path in materials.iterdir()
            if path.is_file() and not path.is_symlink()
        }
        before_staging = list(staging.iterdir())
        runtime.status_override = {
            "config": {"workers": ["high"]},
            "workers": [{
                "worker": "high", "process_identity": "matched",
                "alive": True, "raw_alive": True, "state": "running",
            }],
        }
        calls = 0

        def forbidden_form(*_args: Any, **_kwargs: Any) -> Any:
            nonlocal calls
            calls += 1
            raise AssertionError("multipart parser must not be called")

        monkeypatch.setattr(StarletteRequest, "form", forbidden_form)
        response = _upload(
            client, project["id"], headers, "notes.md", b"unread replacement",
        )

        assert response.status_code == 409, response.text
        assert response.json()["error_code"] == "file_conflict_workers_not_stopped"
        assert calls == 0
        assert _table_count(settings.database_path, "files", project["id"]) == 1
        assert _table_count(settings.database_path, "file_conflicts", project["id"]) == 0
        assert list(staging.iterdir()) == before_staging
        assert {
            path.name: path.read_bytes() for path in materials.iterdir()
            if path.is_file() and not path.is_symlink()
        } == before_materials


def test_live_worker_first_upload_rejects_before_body_and_dead_worker_allows_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, runtime, _main, settings = _make_app(tmp_path)
    with TestClient(
        app, base_url=_ORIGIN, client=("127.0.0.1", 50156),
    ) as client:
        headers = _login(client)
        project = _project(client, headers)
        runtime.status_override = {
            "config": {"workers": ["high"]},
            "workers": [{
                "worker": "high", "process_identity": "matched",
                "alive": True, "raw_alive": True, "state": "running",
            }],
        }
        calls = 0

        def forbidden_form(*_args: Any, **_kwargs: Any) -> Any:
            nonlocal calls
            calls += 1
            raise AssertionError("multipart parser must not be called")

        original_form = StarletteRequest.form
        monkeypatch.setattr(StarletteRequest, "form", forbidden_form)
        secret_body = b"body-must-never-reach-the-server-boundary"
        blocked = _upload(
            client, project["id"], headers, "first.md", secret_body,
        )
        assert blocked.status_code == 409, blocked.text
        assert blocked.json()["error_code"] == "file_upload_workers_not_stopped"
        assert calls == 0
        assert _table_count(settings.database_path, "files", project["id"]) == 0
        assert _table_count(settings.database_path, "file_conflicts", project["id"]) == 0
        assert secret_body not in settings.database_path.read_bytes()
        context = Path(runtime.project_context_dir(project["runtime_name"]))
        assert all(
            secret_body not in path.read_bytes()
            for path in context.rglob("*") if path.is_file()
        )

        monkeypatch.setattr(StarletteRequest, "form", original_form)
        runtime.status_override = {
            "config": {"workers": ["high"]},
            "workers": [{
                "worker": "high", "process_identity": "dead",
                "alive": False, "raw_alive": False, "state": "stopped",
            }],
        }
        accepted = _upload(
            client, project["id"], headers, "first.md", b"safe after exit",
        )
        assert accepted.status_code == 201, accepted.text


def test_dead_worker_conflict_bytes_are_private_random_and_mode_0600(
    tmp_path: Path,
) -> None:
    app, runtime, _main, _settings_value = _make_app(tmp_path)
    with TestClient(app, base_url=_ORIGIN, client=("127.0.0.1", 50142)) as client:
        headers = _login(client)
        project = _project(client, headers)
        filename = "资料.md"
        assert _upload(
            client, project["id"], headers, filename, b"old",
        ).status_code == 201
        conflict = _upload(
            client, project["id"], headers, filename, "新版本".encode(),
        )
        assert conflict.status_code == 409, conflict.text

        incoming = app.state.console_store.file(
            conflict.json()["incoming"]["id"], project["id"],
        )
        assert incoming is not None
        materials, staging = _staging(runtime, project)
        staged = staging / incoming["staging_name"]
        context = Path(runtime.project_context_dir(project["runtime_name"])).resolve()
        assert staged.read_bytes() == "新版本".encode()
        assert context not in staged.resolve().parents
        assert staged.name.startswith(".staged-")
        assert staged.name != incoming["sha256"]
        assert len(staged.name) == len(".staged-") + 64
        assert stat.S_IMODE(staged.stat().st_mode) == 0o600
        assert stat.S_IMODE(staging.stat().st_mode) == 0o700
        assert not (materials / incoming["sha256"]).exists()


def test_pending_conflict_blocks_all_activation_seams_without_side_effects(
    tmp_path: Path,
) -> None:
    app, runtime, main, _settings_value = _make_app(tmp_path)
    with TestClient(app, base_url=_ORIGIN, client=("127.0.0.1", 50143)) as client:
        headers = _login(client)
        project = _project(client, headers)
        app.state.console_store.confirm_initial_direction(project["id"], time.time())
        assert _upload(client, project["id"], headers, "notes.md", b"old").status_code == 201
        assert _upload(client, project["id"], headers, "notes.md", b"new").status_code == 409

        runtime.status_calls = runtime.start_calls = runtime.resume_calls = 0
        blocked_start = client.post(
            f"/api/projects/{project['id']}/runs",
            json={"duration_seconds": 60}, headers=headers,
        )
        assert blocked_start.status_code == 409
        assert blocked_start.json()["error_code"] == "pending_file_conflict"
        assert app.state.console_store.active_run(project["id"]) is None

        now = time.time()
        app.state.console_store.add_run({
            "id": uuid.uuid4().hex, "project_id": project["id"],
            "duration_seconds": 600, "started_at": now,
            "deadline": now + 600, "status": "running",
        })
        public_resume = client.post(
            f"/api/projects/{project['id']}/resume", json={}, headers=headers,
        )
        internal_start = _broker(client, project, {"action": "start"})
        internal_resume = _broker(client, project, {"action": "resume"})
        message = client.post(
            f"/api/projects/{project['id']}/messages",
            json={"text": "do not run", "attachment_ids": []}, headers=headers,
        )
        for response in (public_resume, internal_start, internal_resume, message):
            assert response.status_code == 409, response.text
            assert response.json()["error_code"] == "pending_file_conflict"

        runtime.memory_calls = runtime.fact_calls = 0
        client.portal.call(app.state.execute_orchestration_beat, project)
        assert runtime.start_calls == 0
        assert runtime.resume_calls == 0
        assert runtime.status_calls == 0
        assert runtime.memory_calls == 0
        assert runtime.fact_calls == 0
        assert main.calls == []
        assert app.state.console_store.messages(project["id"]) == []


def test_conflict_upload_serializes_internal_start_across_body_parse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, runtime, _main, _settings_value = _make_app(tmp_path)
    with TestClient(app, base_url=_ORIGIN, client=("127.0.0.1", 50144)) as client:
        headers = _login(client)
        project = _project(client, headers)
        app.state.console_store.confirm_initial_direction(project["id"], time.time())
        assert _upload(client, project["id"], headers, "notes.md", b"old").status_code == 201
        now = time.time()
        app.state.console_store.add_run({
            "id": uuid.uuid4().hex, "project_id": project["id"],
            "duration_seconds": 600, "started_at": now,
            "deadline": now + 600, "status": "starting",
        })
        original_form = StarletteRequest.form
        entered = threading.Event()
        release = threading.Event()

        async def blocking_form(self: StarletteRequest, *args: Any, **kwargs: Any):
            entered.set()
            released = await asyncio.to_thread(release.wait, 5)
            assert released, "test did not release multipart parsing"
            return await original_form(self, *args, **kwargs)

        monkeypatch.setattr(StarletteRequest, "form", blocking_form)
        with ThreadPoolExecutor(max_workers=5) as executor:
            upload_future = executor.submit(
                _upload, client, project["id"], headers, "notes.md", b"new",
            )
            assert entered.wait(timeout=5)
            start_future = executor.submit(
                _broker, client, project, {"action": "start"},
            )
            resume_future = executor.submit(
                _broker, client, project, {"action": "resume"},
            )
            message_future = executor.submit(
                client.post,
                f"/api/projects/{project['id']}/messages",
                json={"text": "must wait", "attachment_ids": []},
                headers=headers,
            )
            for blocked in (start_future, resume_future, message_future):
                with pytest.raises(FutureTimeout):
                    blocked.result(timeout=0.1)
            release.set()
            upload_response = upload_future.result(timeout=5)
            start_response = start_future.result(timeout=5)
            resume_response = resume_future.result(timeout=5)
            message_response = message_future.result(timeout=5)

        assert upload_response.status_code == 409, upload_response.text
        assert "conflict_id" in upload_response.json()
        for response in (start_response, resume_response, message_response):
            assert response.status_code == 409, response.text
            assert response.json()["error_code"] == "pending_file_conflict"
        assert runtime.start_calls == 0
        assert runtime.resume_calls == 0
        assert app.state.main_agent_adapter.calls == []


def test_blocked_replace_preserves_current_conflict_and_private_staging(
    tmp_path: Path,
) -> None:
    app, runtime, _main, _settings_value = _make_app(tmp_path)
    with TestClient(app, base_url=_ORIGIN, client=("127.0.0.1", 50145)) as client:
        headers = _login(client)
        project = _project(client, headers)
        current = _upload(client, project["id"], headers, "notes.md", b"old").json()
        conflict_response = _upload(
            client, project["id"], headers, "notes.md", b"new",
        )
        assert conflict_response.status_code == 409
        conflict = conflict_response.json()
        incoming = app.state.console_store.file(conflict["incoming"]["id"], project["id"])
        assert incoming is not None
        materials, staging = _staging(runtime, project)
        staged = staging / incoming["staging_name"]
        snapshot = {
            "conflict": app.state.console_store.conflict(conflict["conflict_id"], project["id"]),
            "current": app.state.console_store.file(current["id"], project["id"]),
            "incoming": incoming,
            "staged": staged.read_bytes(),
            "materials": {path.name: path.read_bytes() for path in materials.iterdir()},
        }
        runtime.status_override = {
            "config": {"workers": ["high"]},
            "workers": [{
                "worker": "high", "process_identity": "matched",
                "alive": True, "raw_alive": True, "state": "running",
            }],
        }

        response = client.post(
            f"/api/projects/{project['id']}/file-conflicts/{conflict['conflict_id']}",
            json={"choice": "replace"}, headers=headers,
        )
        assert response.status_code == 409, response.text
        assert staged.read_bytes() == snapshot["staged"]
        assert app.state.console_store.conflict(
            conflict["conflict_id"], project["id"],
        ) == snapshot["conflict"]
        assert app.state.console_store.file(
            current["id"], project["id"],
        ) == snapshot["current"]
        assert app.state.console_store.file(
            conflict["incoming"]["id"], project["id"],
        ) == snapshot["incoming"]
        assert {path.name: path.read_bytes() for path in materials.iterdir()} == snapshot["materials"]


@pytest.mark.parametrize("choice", ["new_version", "replace"])
def test_resolution_promotes_only_after_choice_and_removes_staged_blob(
    tmp_path: Path, choice: str,
) -> None:
    app, runtime, _main, _settings_value = _make_app(tmp_path)
    with TestClient(app, base_url=_ORIGIN, client=("127.0.0.1", 50146)) as client:
        headers = _login(client)
        project = _project(client, headers)
        current = _upload(client, project["id"], headers, "notes.md", b"old").json()
        conflict_response = _upload(
            client, project["id"], headers, "notes.md", b"new bytes",
        )
        conflict = conflict_response.json()
        incoming = app.state.console_store.file(conflict["incoming"]["id"], project["id"])
        assert incoming is not None
        materials, staging = _staging(runtime, project)
        staged = staging / incoming["staging_name"]
        destination = materials / incoming["sha256"]
        assert staged.exists() and not destination.exists()

        response = client.post(
            f"/api/projects/{project['id']}/file-conflicts/{conflict['conflict_id']}",
            json={"choice": choice}, headers=headers,
        )
        assert response.status_code == 200, response.text
        assert not staged.exists()
        assert destination.read_bytes() == b"new bytes"
        resolved = app.state.console_store.file(incoming["id"], project["id"])
        assert resolved is not None
        assert resolved["staging_name"] is None
        assert resolved["processing_status"] == "available"
        if choice == "replace":
            assert app.state.console_store.file(current["id"], project["id"]) is None


def test_cancel_fsyncs_unlink_before_deleting_pending_database_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, runtime, _main, _settings_value = _make_app(tmp_path)
    with TestClient(app, base_url=_ORIGIN, client=("127.0.0.1", 50147)) as client:
        headers = _login(client)
        project = _project(client, headers)
        assert _upload(client, project["id"], headers, "notes.md", b"old").status_code == 201
        conflict_response = _upload(
            client, project["id"], headers, "notes.md", b"cancel me",
        )
        conflict = conflict_response.json()
        incoming = app.state.console_store.file(conflict["incoming"]["id"], project["id"])
        assert incoming is not None
        _materials, staging = _staging(runtime, project)
        staged = staging / incoming["staging_name"]
        events: list[tuple[str, bool]] = []
        original_fsync = app_module.fsync_directory
        original_cancel = app.state.console_store.cancel_staged_conflict

        def observed_fsync(directory: Path) -> None:
            if Path(directory) == staging:
                events.append(("fsync", staged.exists()))
            original_fsync(directory)

        def observed_cancel(*args: Any, **kwargs: Any) -> dict[str, Any]:
            events.append(("db", staged.exists()))
            assert app.state.console_store.file(incoming["id"], project["id"]) is not None
            return original_cancel(*args, **kwargs)

        monkeypatch.setattr(app_module, "fsync_directory", observed_fsync)
        monkeypatch.setattr(
            app.state.console_store, "cancel_staged_conflict", observed_cancel,
        )
        response = client.post(
            f"/api/projects/{project['id']}/file-conflicts/{conflict['conflict_id']}",
            json={"choice": "cancel"}, headers=headers,
        )

        assert response.status_code == 200, response.text
        assert events[:2] == [("fsync", False), ("db", False)]
        assert app.state.console_store.file(incoming["id"], project["id"]) is None
        assert app.state.console_store.conflict(conflict["conflict_id"], project["id"]) is None


@pytest.mark.parametrize("choice", [{}, [], 7, None])
def test_conflict_choice_type_is_rejected_without_mutation(
    tmp_path: Path, choice: Any,
) -> None:
    app, _runtime, _main, _settings_value = _make_app(tmp_path)
    with TestClient(
        app, base_url=_ORIGIN, client=("127.0.0.1", 50162),
    ) as client:
        headers = _login(client)
        project = _project(client, headers)
        current = _upload(client, project["id"], headers, "notes.md", b"old").json()
        conflict = _upload(client, project["id"], headers, "notes.md", b"new").json()
        before = app.state.console_store.conflict(conflict["conflict_id"], project["id"])

        response = client.post(
            f"/api/projects/{project['id']}/file-conflicts/{conflict['conflict_id']}",
            json={"choice": choice}, headers=headers,
        )
        assert response.status_code == 400, response.text
        assert app.state.console_store.conflict(
            conflict["conflict_id"], project["id"],
        ) == before
        assert app.state.console_store.file(current["id"], project["id"])[
            "is_current"
        ] == 1


def test_material_publish_and_new_version_commit_audit_in_same_store_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, _runtime, _main, settings = _make_app(tmp_path)
    with TestClient(
        app, base_url=_ORIGIN, client=("127.0.0.1", 50163),
    ) as client:
        headers = _login(client)
        project = _project(client, headers)
        original_audit = app.state.console_store.audit

        def reject_separate_success_audit(
            action: str, outcome: str, *args: Any, **kwargs: Any,
        ) -> None:
            if (action, outcome) in {
                ("file_upload", "success"),
                ("file_conflict", "new_version"),
            }:
                raise AssertionError("publish audit must be in the DB transaction")
            original_audit(action, outcome, *args, **kwargs)

        monkeypatch.setattr(
            app.state.console_store, "audit", reject_separate_success_audit,
        )
        first = _upload(
            client, project["id"], headers, "notes.md", b"first",
        )
        assert first.status_code == 201, first.text
        conflict = _upload(
            client, project["id"], headers, "notes.md", b"second",
        ).json()
        resolved = client.post(
            f"/api/projects/{project['id']}/file-conflicts/{conflict['conflict_id']}",
            json={"choice": "new_version"}, headers=headers,
        )
        assert resolved.status_code == 200, resolved.text

        with sqlite3.connect(settings.database_path) as connection:
            available = connection.execute(
                "SELECT COUNT(*) FROM files WHERE project_id=? AND processing_status='available'",
                (project["id"],),
            ).fetchone()[0]
            upload_audit = connection.execute(
                "SELECT COUNT(*) FROM audit_events WHERE project_id=? "
                "AND action='file_upload' AND outcome='success'",
                (project["id"],),
            ).fetchone()[0]
            version_audit = connection.execute(
                "SELECT COUNT(*) FROM audit_events WHERE project_id=? "
                "AND action='file_conflict' AND outcome='new_version'",
                (project["id"],),
            ).fetchone()[0]
        assert available == 2
        assert upload_audit == 1
        assert version_audit == 1


@pytest.mark.parametrize("window", ["legacy_material", "promoted", "duplicate"])
def test_restart_reconciles_pending_crash_windows_back_to_private_staging(
    tmp_path: Path, window: str,
) -> None:
    runtime = ObservedRuntime(tmp_path / "projects")
    settings = _settings(tmp_path)
    app, runtime, _main, _settings_value = _make_app(
        tmp_path, runtime=runtime, settings=settings,
    )
    with TestClient(app, base_url=_ORIGIN, client=("127.0.0.1", 50148)) as client:
        headers = _login(client)
        project = _project(client, headers)
        assert _upload(client, project["id"], headers, "notes.md", b"old").status_code == 201
        conflict_response = _upload(
            client, project["id"], headers, "notes.md", b"recovery bytes",
        )
        conflict = conflict_response.json()
        incoming = app.state.console_store.file(conflict["incoming"]["id"], project["id"])
        assert incoming is not None
        materials, staging = _staging(runtime, project)
        staged = staging / incoming["staging_name"]
        public = materials / incoming["sha256"]

    if window in {"legacy_material", "promoted"}:
        os.replace(staged, public)
    else:
        shutil.copyfile(staged, public)
    if window == "legacy_material":
        with sqlite3.connect(settings.database_path) as connection:
            connection.execute(
                "UPDATE files SET staging_name=NULL WHERE id=?",
                (incoming["id"],),
            )

    restarted, _runtime, _main, _settings_value = _make_app(
        tmp_path, runtime=runtime, settings=settings,
    )
    with TestClient(restarted, base_url=_ORIGIN):
        recovered = restarted.state.console_store.file(incoming["id"], project["id"])
        assert recovered is not None
        recovered_staged = staging / recovered["staging_name"]
        assert recovered_staged.read_bytes() == b"recovery bytes"
        assert not public.exists()
        assert stat.S_IMODE(recovered_staged.stat().st_mode) == 0o600
        audit_details = "\n".join(
            str(row["details"])
            for row in _audit_rows(settings.database_path, project["id"])
        )
        assert ".staged-" not in audit_details


def _audit_rows(database: Path, project_id: str) -> list[dict[str, Any]]:
    with sqlite3.connect(database) as connection:
        connection.row_factory = sqlite3.Row
        return [dict(row) for row in connection.execute(
            "SELECT * FROM audit_events WHERE project_id=? ORDER BY id",
            (project_id,),
        )]


def test_project_delete_erases_external_staging_before_database_project(
    tmp_path: Path,
) -> None:
    app, runtime, _main, _settings_value = _make_app(tmp_path)
    with TestClient(app, base_url=_ORIGIN, client=("127.0.0.1", 50149)) as client:
        headers = _login(client)
        project = _project(client, headers)
        assert _upload(client, project["id"], headers, "notes.md", b"old").status_code == 201
        conflict = _upload(client, project["id"], headers, "notes.md", b"new")
        assert conflict.status_code == 409
        _materials, staging = _staging(runtime, project)
        assert any(staging.iterdir())

        response = client.request(
            "DELETE", f"/api/projects/{project['id']}",
            json={"confirm_name": project["name"]}, headers=headers,
        )
        assert response.status_code == 200, response.text
        assert not staging.exists()
        assert app.state.console_store.project(project["id"]) is None


def test_restart_purges_only_unreferenced_regular_content_addressed_blobs(
    tmp_path: Path,
) -> None:
    runtime = ObservedRuntime(tmp_path / "projects")
    settings = _settings(tmp_path)
    app, runtime, _main, _settings_value = _make_app(
        tmp_path, runtime=runtime, settings=settings,
    )
    with TestClient(
        app, base_url=_ORIGIN, client=("127.0.0.1", 50151),
    ) as client:
        headers = _login(client)
        project = _project(client, headers)
        referenced = _upload(
            client, project["id"], headers, "kept.md", b"referenced",
        ).json()
        materials, _staging_dir = _staging(runtime, project)

    orphan_body = b"promoted before database crash"
    orphan = materials / hashlib.sha256(orphan_body).hexdigest()
    orphan.write_bytes(orphan_body)
    non_hash_artifact = materials / "report.md"
    non_hash_artifact.write_text("artifact", encoding="utf-8")
    unsafe_hash_directory = materials / ("f" * 64)
    unsafe_hash_directory.mkdir()

    restarted, _runtime, _main, _settings_value = _make_app(
        tmp_path, runtime=runtime, settings=settings,
    )
    with TestClient(
        restarted, base_url=_ORIGIN, client=("127.0.0.1", 50152),
    ):
        assert not orphan.exists()
        assert (materials / referenced["sha256"]).read_bytes() == b"referenced"
        assert non_hash_artifact.read_text(encoding="utf-8") == "artifact"
        assert unsafe_hash_directory.is_dir()


@pytest.mark.parametrize("failure", ["chmod", "fsync"])
def test_post_rename_upload_failure_cleans_or_reserves_until_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str,
) -> None:
    app, runtime, _main, _settings_value = _make_app(tmp_path)
    with TestClient(
        app, base_url=_ORIGIN, client=("127.0.0.1", 50157),
    ) as client:
        headers = _login(client)
        project = _project(client, headers)
        body = b"post rename failure bytes"
        digest = hashlib.sha256(body).hexdigest()
        materials, staging = _staging(runtime, project)
        destination = materials / digest
        if failure == "chmod":
            original_chmod = files_module.os.chmod

            def fail_destination_chmod(path: Any, *args: Any, **kwargs: Any) -> None:
                if Path(path) == destination:
                    raise OSError("injected post-rename chmod failure")
                original_chmod(path, *args, **kwargs)

            monkeypatch.setattr(files_module.os, "chmod", fail_destination_chmod)
        else:
            original_files_fsync = files_module.fsync_directory
            original_app_fsync = app_module.fsync_directory

            def fail_material_fsync(directory: Path) -> None:
                if Path(directory) == materials:
                    raise OSError("injected post-rename fsync failure")
                original_files_fsync(directory)

            def fail_cleanup_fsync(directory: Path) -> None:
                if Path(directory) == materials:
                    raise OSError("injected cleanup fsync failure")
                original_app_fsync(directory)

            monkeypatch.setattr(files_module, "fsync_directory", fail_material_fsync)
            monkeypatch.setattr(app_module, "fsync_directory", fail_cleanup_fsync)

        response = _upload(
            client, project["id"], headers, "notes.md", body,
        )
        assert response.status_code == 500, response.text
        assert not destination.exists()
        assert not any(staging.iterdir())

        if failure == "chmod":
            assert app.state.console_store.project_maintenance_reason(project["id"]) is None
            assert _table_count(
                _settings_value.database_path, "files", project["id"],
            ) == 0
        else:
            assert app.state.console_store.project_maintenance_reason(
                project["id"],
            ) == "pending_file_reservation"
            reserved = app.state.console_store.file_by_hash(project["id"], digest)
            assert reserved is not None
            assert reserved["processing_status"] == "pending"
            monkeypatch.undo()
            retried = client.post(
                f"/api/projects/{project['id']}/file-cleanups/retry",
                json={}, headers=headers,
            )
            assert retried.status_code == 200, retried.text
            assert retried.json()["cleanup_pending"] is False
            assert app.state.console_store.project_maintenance_reason(project["id"]) is None


def test_restart_cleans_ordinary_promotion_before_database_finalize(
    tmp_path: Path,
) -> None:
    runtime = ObservedRuntime(tmp_path / "projects")
    settings = _settings(tmp_path)
    app, runtime, _main, _settings_value = _make_app(
        tmp_path, runtime=runtime, settings=settings,
    )
    with TestClient(
        app, base_url=_ORIGIN, client=("127.0.0.1", 50158),
    ) as client:
        headers = _login(client)
        project = _project(client, headers)
        materials, staging = _staging(runtime, project)
        body = b"ordinary crash window"
        digest = hashlib.sha256(body).hexdigest()
        staged_name = ".staged-" + "a" * 64
        staged = staging / staged_name
        staged.write_bytes(body)
        staged.chmod(0o600)
        file_id = uuid.uuid4().hex
        app.state.console_store.add_file({
            "id": file_id, "project_id": project["id"],
            "logical_name": "ordinary.md", "content_type": "text/markdown",
            "kind": "markdown", "size": len(body), "sha256": digest,
            "storage_name": digest, "staging_name": staged_name,
            "version": 1, "is_current": 0, "processing_status": "pending",
            "read_status": "not_read", "uploaded_at": time.time(),
        })
        public = materials / digest
        os.replace(staged, public)

    restarted, _runtime, _main, _settings_value = _make_app(
        tmp_path, runtime=runtime, settings=settings,
    )
    with TestClient(
        restarted, base_url=_ORIGIN, client=("127.0.0.1", 50159),
    ):
        assert not public.exists()
        assert not staged.exists()
        assert restarted.state.console_store.file(file_id, project["id"]) is None
        assert restarted.state.console_store.project_maintenance_reason(project["id"]) is None


def test_restart_rejects_non_private_staged_blob_instead_of_lifting_gate(
    tmp_path: Path,
) -> None:
    runtime = ObservedRuntime(tmp_path / "projects")
    settings = _settings(tmp_path)
    app, runtime, _main, _settings_value = _make_app(
        tmp_path, runtime=runtime, settings=settings,
    )
    with TestClient(
        app, base_url=_ORIGIN, client=("127.0.0.1", 50153),
    ) as client:
        headers = _login(client)
        project = _project(client, headers)
        assert _upload(client, project["id"], headers, "notes.md", b"old").status_code == 201
        conflict = _upload(client, project["id"], headers, "notes.md", b"new").json()
        incoming = app.state.console_store.file(conflict["incoming"]["id"], project["id"])
        assert incoming is not None
        _materials, staging = _staging(runtime, project)
        staged = staging / incoming["staging_name"]

    staged.chmod(0o644)
    restarted, _runtime, _main, _settings_value = _make_app(
        tmp_path, runtime=runtime, settings=settings,
    )
    with TestClient(
        restarted, base_url=_ORIGIN, client=("127.0.0.1", 50154),
    ):
        assert not staged.exists()
        assert restarted.state.console_store.file(incoming["id"], project["id"]) is None
        assert restarted.state.console_store.conflict(
            conflict["conflict_id"], project["id"],
        ) is None
        assert restarted.state.console_store.project_maintenance_reason(project["id"]) is None


def test_failed_replace_cleanup_blocks_every_activation_seam(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, runtime, main, _settings_value = _make_app(tmp_path)
    with TestClient(
        app, base_url=_ORIGIN, client=("127.0.0.1", 50155),
    ) as client:
        headers = _login(client)
        project = _project(client, headers)
        app.state.console_store.confirm_initial_direction(project["id"], time.time())
        assert _upload(client, project["id"], headers, "notes.md", b"old").status_code == 201
        conflict = _upload(client, project["id"], headers, "notes.md", b"new").json()
        original_unlink = Path.unlink

        def fail_quarantine(path: Path, *args: Any, **kwargs: Any) -> None:
            if path.name.startswith(".delete-"):
                raise OSError("locator must never be projected")
            original_unlink(path, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", fail_quarantine)
        replaced = client.post(
            f"/api/projects/{project['id']}/file-conflicts/{conflict['conflict_id']}",
            json={"choice": "replace"}, headers=headers,
        )
        assert replaced.status_code == 202, replaced.text
        assert replaced.json()["cleanup_pending"] is True
        monkeypatch.undo()

        runtime.status_calls = runtime.start_calls = runtime.resume_calls = 0
        blocked_start = client.post(
            f"/api/projects/{project['id']}/runs",
            json={"duration_seconds": 60}, headers=headers,
        )
        assert blocked_start.status_code == 409
        assert blocked_start.json()["error_code"] == "file_cleanup_pending"
        now = time.time()
        app.state.console_store.add_run({
            "id": uuid.uuid4().hex, "project_id": project["id"],
            "duration_seconds": 600, "started_at": now,
            "deadline": now + 600, "status": "running",
        })
        responses = [
            client.post(f"/api/projects/{project['id']}/resume", json={}, headers=headers),
            _broker(client, project, {"action": "start"}),
            _broker(client, project, {"action": "resume"}),
            client.post(
                f"/api/projects/{project['id']}/messages",
                json={"text": "must remain blocked", "attachment_ids": []},
                headers=headers,
            ),
        ]
        for response in responses:
            assert response.status_code == 409, response.text
            assert response.json()["error_code"] == "file_cleanup_pending"

        runtime.memory_calls = runtime.fact_calls = 0
        client.portal.call(app.state.execute_orchestration_beat, project)
        assert runtime.status_calls == 0
        assert runtime.start_calls == 0
        assert runtime.resume_calls == 0
        assert runtime.memory_calls == 0
        assert runtime.fact_calls == 0
        assert main.calls == []
        assert app.state.console_store.messages(project["id"]) == []
        projection = client.get(
            f"/api/projects/{project['id']}/file-cleanups",
        ).json()
        assert projection["jobs"][0]["last_error"] == "OSError"
        assert ".delete-" not in json.dumps(projection)


@pytest.mark.parametrize("location", ["quarantine", "original"])
def test_cleanup_retry_safely_unlinks_dangling_symlink_before_lifting_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, location: str,
) -> None:
    app, runtime, _main, _settings_value = _make_app(tmp_path)
    with TestClient(
        app, base_url=_ORIGIN, client=("127.0.0.1", 50160),
    ) as client:
        headers = _login(client)
        project = _project(client, headers)
        assert _upload(client, project["id"], headers, "notes.md", b"old").status_code == 201
        conflict = _upload(client, project["id"], headers, "notes.md", b"new").json()
        original_unlink = Path.unlink

        def fail_quarantine(path: Path, *args: Any, **kwargs: Any) -> None:
            if path.name.startswith(".delete-"):
                raise OSError("injected unlink failure")
            original_unlink(path, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", fail_quarantine)
        replaced = client.post(
            f"/api/projects/{project['id']}/file-conflicts/{conflict['conflict_id']}",
            json={"choice": "replace"}, headers=headers,
        )
        assert replaced.status_code == 202, replaced.text
        monkeypatch.undo()
        job = app.state.console_store.file_cleanup_jobs(project["id"])[0]
        materials, _staging_dir = _staging(runtime, project)
        quarantine = materials / job["quarantine_name"]
        original = materials / job["original_storage_name"]
        target = quarantine
        if location == "original":
            os.replace(quarantine, original)
            target = original
        target.unlink()
        target.symlink_to(materials / "missing-target")
        assert target.is_symlink() and not target.exists()

        retried = client.post(
            f"/api/projects/{project['id']}/file-cleanups/retry",
            json={}, headers=headers,
        )
        assert retried.status_code == 200, retried.text
        assert not target.is_symlink()
        assert app.state.console_store.file_cleanup_jobs(project["id"]) == []
        assert app.state.console_store.project_maintenance_reason(project["id"]) is None


def test_nonregular_cleanup_target_stays_typed_pending_and_projection_never_claims_ok(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    app, runtime, _main, _settings_value = _make_app(tmp_path)
    with TestClient(
        app, base_url=_ORIGIN, client=("127.0.0.1", 50161),
    ) as client:
        headers = _login(client)
        project = _project(client, headers)
        assert _upload(client, project["id"], headers, "notes.md", b"old").status_code == 201
        conflict = _upload(client, project["id"], headers, "notes.md", b"new").json()
        original_unlink = Path.unlink

        def fail_quarantine(path: Path, *args: Any, **kwargs: Any) -> None:
            if path.name.startswith(".delete-"):
                raise OSError("injected unlink failure")
            original_unlink(path, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", fail_quarantine)
        replaced = client.post(
            f"/api/projects/{project['id']}/file-conflicts/{conflict['conflict_id']}",
            json={"choice": "replace"}, headers=headers,
        )
        assert replaced.status_code == 202, replaced.text
        monkeypatch.undo()
        job = app.state.console_store.file_cleanup_jobs(project["id"])[0]
        materials, _staging_dir = _staging(runtime, project)
        quarantine = materials / job["quarantine_name"]
        quarantine.unlink()
        quarantine.mkdir()

        retried = client.post(
            f"/api/projects/{project['id']}/file-cleanups/retry",
            json={}, headers=headers,
        )
        assert retried.status_code == 202, retried.text
        assert retried.json()["cleanup_pending"] is True
        assert retried.json()["maintenance_reason"] == "file_cleanup_pending"
        projection = client.get(
            f"/api/projects/{project['id']}/file-cleanups",
        ).json()
        assert projection["status"] == "cleanup_pending"
        assert projection["maintenance_reason"] == "file_cleanup_pending"
        assert projection["jobs"][0]["last_error"] == "FileValidationError"
        assert quarantine.is_dir()


def test_store_schema_migration_adds_nullable_staging_name_to_old_files_table(
    tmp_path: Path,
) -> None:
    database = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE projects (
                id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
                runtime_name TEXT NOT NULL UNIQUE, problem TEXT NOT NULL,
                roles TEXT NOT NULL DEFAULT 'high:3,xhigh:4', worker_model TEXT,
                max_parallel_workers INTEGER NOT NULL DEFAULT 1,
                initial_direction_confirmed_at REAL, created_at REAL NOT NULL
            );
            CREATE TABLE files (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                logical_name TEXT NOT NULL, content_type TEXT NOT NULL,
                kind TEXT NOT NULL, size INTEGER NOT NULL, sha256 TEXT NOT NULL,
                storage_name TEXT NOT NULL, version INTEGER NOT NULL,
                is_current INTEGER NOT NULL, processing_status TEXT NOT NULL,
                read_status TEXT NOT NULL, uploaded_at REAL NOT NULL,
                UNIQUE(project_id, logical_name, version),
                UNIQUE(project_id, sha256)
            );
            """
        )

    ConsoleStore(database)
    with sqlite3.connect(database) as connection:
        columns = {
            str(row[1]): row for row in connection.execute("PRAGMA table_info(files)")
        }
    assert "staging_name" in columns
    assert columns["staging_name"][3] == 0


def test_existing_material_destination_must_match_expected_digest_and_size(
    tmp_path: Path,
) -> None:
    app, runtime, _main, _settings_value = _make_app(tmp_path)
    with TestClient(app, base_url=_ORIGIN, client=("127.0.0.1", 50150)) as client:
        headers = _login(client)
        project = _project(client, headers)
        body = b"authenticated bytes"
        digest = hashlib.sha256(body).hexdigest()
        materials, _staging_dir = _staging(runtime, project)
        destination = materials / digest
        destination.write_bytes(b"attacker bytes")

        response = _upload(
            client, project["id"], headers, "notes.md", body,
        )
        assert response.status_code == 400, response.text
        assert not destination.exists()
        assert app.state.console_store.files(project["id"]) == []
