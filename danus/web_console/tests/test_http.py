"""Authenticated Web Console HTTP seam tests for the first vertical slice."""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from danus.execution import layout as L
from danus.web_console.config import ProviderModelCatalog
from danus.web_console.app import AppSettings, _public_main_agent_error, create_app
from danus.web_console.main_agent import MainAgentError
from danus.web_console.security import hash_password, project_lifecycle_capability
from danus.web_console.store import ConsoleStore


class FakeRuntime:
    def __init__(self, root: Path):
        self.root = root
        self.created = []
        self.started = []
        self.stopped = []
        self.statuses = {}
        self.deadlines = {}
        self.cleared_deadlines = []
        self.configs = {}
        self.controls = []

    def project_context_dir(self, runtime_name):
        project = self.root / runtime_name
        project.mkdir(parents=True, exist_ok=True)
        return project

    def clear_deadline(self, runtime_name):
        self.cleared_deadlines.append(runtime_name)

    def write_deadline(self, runtime_name, deadline):
        self.deadlines[runtime_name] = deadline

    def create_project(self, runtime_name, problem, roles, model=None, max_parallel_workers=None):
        self.created.append((runtime_name, problem, roles, model))
        project = self.root / runtime_name
        project.mkdir(parents=True, exist_ok=True)
        (project / "PROBLEM.md").write_text(problem + "\n", encoding="utf-8")
        parsed = L.parse_roles(roles)
        self.configs[runtime_name] = {
            "roles": roles,
            "model": model,
            "worker_model": model,
            "max_parallel_workers": max_parallel_workers or 1,
        }
        self.statuses[runtime_name] = [{
            "worker": worker,
            "alive": False,
            "state": "created",
            "round": 0,
            "role": base,
            "model": model,
            "reasoning_effort": base,
            "author": worker,
            "task": "# Task\n\n(unassigned — the main agent writes your assignment here via `danus assign`; you read this file at the start of every round)\n",
            "assigned": False,
        } for worker, base in parsed]
        return {"runtime_name": runtime_name, "project_dir": str(project), "workers": self.statuses[runtime_name]}

    def assign_worker(self, runtime_name, worker, task):
        for row in self.statuses.get(runtime_name, []):
            if row["worker"] == worker:
                row["assigned"] = True
                row["task"] = task
                return {"worker": worker, "result": "assigned"}
        raise RuntimeError("worker not found")

    def start_project(self, runtime_name):
        self.started.append(runtime_name)
        self.statuses[runtime_name] = [
            {**worker, "alive": True, "state": "running", "round": max(1, int(worker.get("round", 0)) + 1)}
            for worker in self.statuses.get(runtime_name, [])
        ]
        return {"workers": self.statuses[runtime_name]}

    def stop_project(self, runtime_name):
        self.stopped.append(runtime_name)
        self.statuses[runtime_name] = [
            {**worker, "alive": False, "state": "stopped"}
            for worker in self.statuses.get(runtime_name, [])
        ]
        return {"workers": self.statuses[runtime_name]}

    def status_project(self, runtime_name):
        return {"config": self.configs.get(runtime_name, {}), "workers": self.statuses.get(runtime_name, [])}

    def pause_project(self, runtime_name, *, worker=None):
        self.controls.append(("pause", runtime_name, worker))
        return {"status": "pause_requested", "worker": worker}

    def resume_project(self, runtime_name, *, worker=None):
        self.controls.append(("resume", runtime_name, worker))
        return {"status": "resume_requested", "workers": []}

    def force_stop_project(self, runtime_name, *, worker=None, term_timeout=5.0):
        self.controls.append(("force_stop", runtime_name, worker))
        return {"status": "force_stopped", "workers": []}

    def reclaim_project(self, runtime_name, *, worker=None, execute=False, confirmation_token=None):
        self.controls.append(("reclaim", runtime_name, worker, execute, confirmation_token))
        if execute:
            return {"status": "reclaimed", "remaining_project_processes": [], "workers": []}
        return {"dry_run": True, "safe_to_execute": True, "confirmation_token": "confirm-token", "workers": []}

    def logs_projection(self, runtime_name, worker=None, tail=200, *, max_bytes=65536):
        return {
            "worker": worker,
            "tail": tail,
            "max_bytes": max_bytes,
            "entries": [{"worker": worker or "high", "name": "loop.log", "lines": ["status"]}],
        }

    def fact_graph_projection(self, runtime_name):
        return {"nodes": [], "edges": [], "max_depth": 0}

    def memory_projection(self, runtime_name):
        return {"total": 0, "channels": []}

    def reports_projection(self, runtime_name):
        return {"files": []}

    def outputs_projection(self, runtime_name):
        return {"files": []}

    def delete_project(self, runtime_name):
        self.statuses.pop(runtime_name, None)
        self.configs.pop(runtime_name, None)
        return {"deleted": runtime_name}

    def assign_all(self, runtime_name, *, task="do the assigned work"):
        for worker in self.statuses.get(runtime_name, []):
            worker["assigned"] = True
            worker["task"] = task


class FakeMemoryRuntime(FakeRuntime):
    def __init__(self, root: Path):
        super().__init__(root)
        self.memory_entries = {}

    def memory_projection(self, runtime_name):
        return self.memory_entries.get(runtime_name, {"total": 0, "channels": []})


_LIFECYCLE_SECRET = b"test-lifecycle-hmac-secret"


def _app(tmp_path: Path):
    runtime = FakeMemoryRuntime(tmp_path / "projects")
    settings = AppSettings(
        database_path=tmp_path / "console.sqlite3",
        password_hash=hash_password("correct horse battery staple"),
        cookie_secure=True,
        allowed_origins={"https://testserver"},
        lifecycle_hmac_secret=_LIFECYCLE_SECRET,
    )
    return create_app(settings=settings, runtime=runtime), runtime


def _login(client: TestClient):
    response = client.post(
        "/api/auth/login",
        json={"password": "correct horse battery staple"},
        headers={"Origin": "https://testserver"},
    )
    assert response.status_code == 200
    assert "secure" in response.headers["set-cookie"].lower()
    assert "httponly" in response.headers["set-cookie"].lower()
    assert "samesite=strict" in response.headers["set-cookie"].lower()
    return response.json()["csrf_token"]


def _broker_lifecycle(
    client: TestClient, project: dict, action: str, *, worker: str | None = None,
    task: str | None = None, secret: bytes = _LIFECYCLE_SECRET,
):
    token = project_lifecycle_capability(secret, project["id"], project["runtime_name"])
    with TestClient(
        client.app, base_url="http://127.0.0.1:8080", client=("127.0.0.1", 50123),
    ) as internal:
        return internal.post(
            f"/internal/api/projects/{project['id']}/lifecycle",
            json={
                "action": action,
                **({"worker": worker} if worker else {}),
                **({"task": task} if task is not None else {}),
            },
            headers={"Authorization": f"Bearer {token}"},
        )


def _broker_start(client: TestClient, project: dict, *, secret: bytes = _LIFECYCLE_SECRET):
    return _broker_lifecycle(client, project, "start", secret=secret)


def _broker_stop(client: TestClient, project: dict, *, secret: bytes = _LIFECYCLE_SECRET):
    return _broker_lifecycle(client, project, "stop", secret=secret)


def test_authentication_cookie_csrf_and_project_boundary(tmp_path: Path):
    # Exercise denial on one app instance; the successful flow uses an isolated
    # instance so the deliberately failed attempt cannot trigger throttling.
    bad_app, _ = _app(tmp_path / "bad")
    with TestClient(bad_app, base_url="https://testserver") as bad_client:
        assert bad_client.get("/api/projects").status_code == 401
        bad = bad_client.post("/api/auth/login", json={"password": "wrong"})
        assert bad.status_code == 401 and bad.json() == {"detail": "invalid credentials"}
    app, runtime = _app(tmp_path / "good")
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client)
        assert client.get("/api/auth/me").json()["authenticated"] is True
        session_info = client.get("/api/auth/session").json()
        assert session_info["authenticated"] is True
        csrf = session_info["csrf_token"]

        denied = client.post("/api/projects", json={"name": "A", "problem": "alpha"})
        assert denied.status_code == 403
        created = client.post(
            "/api/projects",
            json={"name": "A", "problem": "alpha", "roles": "high:1"},
            headers={"X-CSRF-Token": csrf, "Origin": "https://testserver"},
        )
        assert created.status_code == 201
        project = created.json()
        assert project["name"] == "A"
        project_id = project["id"]
        assert runtime.created[0][1] == "alpha"

        listed = client.get("/api/projects")
        assert listed.status_code == 200 and listed.json()[0]["id"] == project_id
        assert client.get(f"/api/projects/{project_id}").json()["name"] == "A"

        cross_site = client.post(
            "/api/projects",
            json={"name": "B", "problem": "beta"},
            headers={"X-CSRF-Token": csrf, "Origin": "https://evil.example"},
        )
        assert cross_site.status_code == 403
        assert len(runtime.created) == 1


@pytest.mark.parametrize(
    ("value", "detail"),
    [
        (True, "duration_seconds must be an integer"),
        ("43200", "duration_seconds must be an integer"),
        (12.5, "duration_seconds must be an integer"),
        (0, "duration_seconds must be between 1 and 604800"),
        (-1, "duration_seconds must be between 1 and 604800"),
        (604801, "duration_seconds must be between 1 and 604800"),
    ],
)
def test_project_run_budget_rejects_invalid_types_and_bounds(
    tmp_path: Path, value, detail: str,
):
    app, runtime = _app(tmp_path)
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client)
        project = client.post(
            "/api/projects", json={"name": "A", "problem": "alpha", "roles": "high:1"},
            headers={"X-CSRF-Token": csrf, "Origin": "https://testserver"},
        ).json()
        runtime.assign_all(project["runtime_name"])

        response = client.post(
            f"/api/projects/{project['id']}/runs",
            json={"duration_seconds": value},
            headers={"X-CSRF-Token": csrf, "Origin": "https://testserver"},
        )

        assert response.status_code == 400
        assert response.json() == {"detail": detail}
        assert client.get(f"/api/projects/{project['id']}/runtime").json().get("run") is None


def test_project_run_deadline_and_graceful_stop_are_scoped(tmp_path: Path):
    app, runtime = _app(tmp_path)
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client)
        a = client.post(
            "/api/projects", json={"name": "A", "problem": "alpha", "roles": "high:1"},
            headers={"X-CSRF-Token": csrf, "Origin": "https://testserver"},
        ).json()
        b = client.post(
            "/api/projects", json={"name": "B", "problem": "beta", "roles": "high:1"},
            headers={"X-CSRF-Token": csrf, "Origin": "https://testserver"},
        ).json()
        runtime.assign_all(a["runtime_name"])
        runtime.assign_all(b["runtime_name"])
        start = client.post(
            f"/api/projects/{a['id']}/runs", json={"duration_seconds": 43200},
            headers={"X-CSRF-Token": csrf, "Origin": "https://testserver"},
        )
        assert start.status_code == 202
        run = start.json()
        assert run["status"] == "start_requested"
        assert run["duration_seconds"] == 43200
        assert 43190 <= run["deadline"] - time.time() <= 43210
        projected_run = client.get(f"/api/projects/{a['id']}/runtime").json()["run"]
        assert projected_run["duration_seconds"] == 43200
        assert projected_run["started_at"] <= projected_run["deadline"]
        # The browser records the bounded run intent; only the project Main
        # Agent may request the normal Worker start through the host broker.
        assert runtime.started == []
        assert runtime.deadlines[a["runtime_name"]] == run["deadline"]

        stopped = client.post(
            f"/api/projects/{a['id']}/stop", json={},
            headers={"X-CSRF-Token": csrf, "Origin": "https://testserver"},
        )
        assert stopped.status_code == 202
        assert stopped.json()["status"] == "stop_requested"
        # Public graceful stop records operator intent only. The browser must
        # activate the Main Agent, whose authenticated broker request executes it.
        assert runtime.stopped == []
        stored = app.state.console_store.run(run["run_id"])
        assert stored["status"] == "stopping"
        assert stored["outcome"] == "operator_stop_intent"
        assert _broker_stop(client, a).status_code == 202
        assert runtime.stopped == [a["runtime_name"]]
        assert runtime.stopped != [b["runtime_name"]]
        b_workers = client.get(f"/api/projects/{b['id']}/runtime").json()["workers"]
        assert len(b_workers) == 1
        assert b_workers[0]["worker"] == "high"
        assert b_workers[0]["alive"] is False


def test_initial_direction_confirmation_gates_assignment(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DANUS_CONSULT_TRANSPORT", "off")
    app, runtime = _app(tmp_path)
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client)
        headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        project = client.post("/api/projects", json={"name": "A", "problem": "alpha", "roles": "high:1"}, headers=headers).json()
        blocked = _broker_lifecycle(client, project, "assign", worker="high", task="direction")
        assert blocked.status_code == 409
        assert "initial direction confirmation" in blocked.json()["detail"]
        no_guidance = client.post(f"/api/projects/{project['id']}/initial-direction/confirm", json={"confirm": "A"}, headers=headers)
        assert no_guidance.status_code == 409
        runtime.memory_entries[project["runtime_name"]] = {"total": 1, "channels": [{"kind": "master_guidance", "entries": [{"claim": "direction", "evidence": "guidance-source: consult-derived"}]}]}
        mismatch = client.post(f"/api/projects/{project['id']}/initial-direction/confirm", json={"confirm": "A"}, headers=headers)
        assert mismatch.status_code == 409
        runtime.memory_entries[project["runtime_name"]]["channels"][0]["entries"][0]["evidence"] = "guidance-source: offline-main-agent"
        wrong = client.post(f"/api/projects/{project['id']}/initial-direction/confirm", json={"confirm": "wrong"}, headers=headers)
        assert wrong.status_code == 409
        confirmed = client.post(f"/api/projects/{project['id']}/initial-direction/confirm", json={"confirm": "A"}, headers=headers)
        assert confirmed.status_code == 200
        assert confirmed.json()["initial_direction_confirmed"] is True
        assigned = _broker_lifecycle(client, project, "assign", worker="high", task="direction")
        assert assigned.status_code == 200
        assert runtime.statuses[project["runtime_name"]][0]["assigned"] is True
        assert runtime.statuses[project["runtime_name"]][0]["task"] == "direction"


def test_internal_lifecycle_broker_is_loopback_only_and_project_capability_scoped(
    tmp_path: Path,
):
    secret = b"test-lifecycle-hmac-secret"
    runtime = FakeRuntime(tmp_path / "projects")
    settings = AppSettings(
        database_path=tmp_path / "console.sqlite3",
        password_hash=hash_password("correct horse battery staple"),
        cookie_secure=True,
        allowed_origins={"https://testserver"},
        lifecycle_base_url="http://127.0.0.1:8080",
        lifecycle_hmac_secret=secret,
    )
    app = create_app(settings=settings, runtime=runtime)
    with TestClient(
        app, base_url="https://testserver", client=("127.0.0.1", 50123),
    ) as client:
        csrf = _login(client)
        headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        a = client.post(
            "/api/projects",
            json={"name": "A", "problem": "alpha", "roles": "high:1"},
            headers=headers,
        ).json()
        b = client.post(
            "/api/projects",
            json={"name": "B", "problem": "beta", "roles": "high:1"},
            headers=headers,
        ).json()
        runtime.assign_all(a["runtime_name"])
        intent = client.post(
            f"/api/projects/{a['id']}/runs",
            json={"duration_seconds": 60},
            headers=headers,
        ).json()
        url = f"/internal/api/projects/{a['id']}/lifecycle"
        wrong = project_lifecycle_capability(secret, b["id"], b["runtime_name"])
        assert client.post(
            url, json={"action": "start"},
            headers={"Authorization": f"Bearer {wrong}"},
        ).status_code == 403
        token = project_lifecycle_capability(secret, a["id"], a["runtime_name"])
        started = client.post(
            url, json={"action": "start"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert started.status_code == 200
        assert started.json() == {
            "status": "running", "run_id": intent["run_id"],
            "workers": ["high"],
        }
        assert runtime.started == [a["runtime_name"]]
        stopped = client.post(
            url, json={"action": "stop"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert stopped.status_code == 202
        assert stopped.json() == {
            "status": "stop_requested", "run_id": intent["run_id"],
        }
        assert runtime.stopped == [a["runtime_name"]]

    with TestClient(
        app, base_url="http://127.0.0.1:8080", client=("203.0.113.9", 50124),
    ) as remote:
        denied = remote.post(
            f"/internal/api/projects/{a['id']}/lifecycle",
            json={"action": "stop"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert denied.status_code == 403
        assert runtime.stopped == [a["runtime_name"]]


def test_fresh_start_intent_is_not_promoted_by_preexisting_live_roster(tmp_path: Path):
    app, runtime = _app(tmp_path)
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client)
        headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        project = client.post(
            "/api/projects",
            json={"name": "A", "problem": "alpha", "roles": "high:1"},
            headers=headers,
        ).json()
        runtime.assign_all(project["runtime_name"])
        # Simulate a stale/pre-existing worker from outside this fresh run intent.
        runtime.statuses[project["runtime_name"]][0].update(
            {"alive": True, "state": "running", "round": 9}
        )

        intent = client.post(
            f"/api/projects/{project['id']}/runs",
            json={"duration_seconds": 60}, headers=headers,
        ).json()
        observed = client.get(
            f"/api/projects/{project['id']}/runs/{intent['run_id']}"
        ).json()

        assert observed["status"] == "starting"
        assert observed["start_attempt_generation"] == 0
        assert observed["start_attempt_outcome"] is None
        assert runtime.started == []

        # The authenticated Main Agent broker attempt establishes this run's
        # generation and may then adopt the exact already-running roster.
        assert _broker_start(client, project).status_code == 200
        running = client.get(
            f"/api/projects/{project['id']}/runs/{intent['run_id']}"
        ).json()
        assert running["status"] == "running"
        assert running["start_attempt_generation"] == 1
        assert running["start_attempt_outcome"] == "started"


def test_internal_lifecycle_broker_reports_partial_start_for_incomplete_roster(
    tmp_path: Path,
):
    class PartialRuntime(FakeRuntime):
        def start_project(self, runtime_name):
            self.started.append(runtime_name)
            workers = self.statuses[runtime_name]
            self.statuses[runtime_name] = [
                {**worker, "alive": index == 0, "state": "running" if index == 0 else "created"}
                for index, worker in enumerate(workers)
            ]
            return {"workers": self.statuses[runtime_name]}

    secret = b"test-lifecycle-hmac-secret"
    runtime = PartialRuntime(tmp_path / "projects")
    settings = AppSettings(
        database_path=tmp_path / "console.sqlite3",
        password_hash=hash_password("correct horse battery staple"),
        cookie_secure=True,
        allowed_origins={"https://testserver"},
        lifecycle_hmac_secret=secret,
    )
    app = create_app(settings=settings, runtime=runtime)
    with TestClient(
        app, base_url="https://testserver", client=("127.0.0.1", 50123),
    ) as client:
        csrf = _login(client)
        headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        project = client.post(
            "/api/projects",
            json={"name": "A", "problem": "alpha", "roles": "high:1,xhigh:1"},
            headers=headers,
        ).json()
        runtime.assign_all(project["runtime_name"])
        intent = client.post(
            f"/api/projects/{project['id']}/runs",
            json={"duration_seconds": 60}, headers=headers,
        ).json()
        token = project_lifecycle_capability(
            secret, project["id"], project["runtime_name"],
        )
        response = client.post(
            f"/internal/api/projects/{project['id']}/lifecycle",
            json={"action": "start"},
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 502
        assert response.json() == {
            "detail": "project workers only partially started",
            "status": "partial_start",
            "run_id": intent["run_id"],
            "expected_workers": ["high", "xhigh"],
            "alive_workers": ["high"],
            "not_running_workers": ["xhigh"],
        }
        run = client.get(
            f"/api/projects/{project['id']}/runs/{intent['run_id']}"
        ).json()
        assert run["status"] == "starting"
        assert run["outcome"] == "partial_start:xhigh"
        assert run["start_attempt_generation"] == 1
        assert run["start_attempt_outcome"] == "partial_start"

        # Only a persisted partial broker attempt may be reconciled to running.
        runtime.statuses[project["runtime_name"]][1].update(
            {"alive": True, "state": "running"}
        )
        reconciled = client.get(
            f"/api/projects/{project['id']}/runs/{intent['run_id']}"
        ).json()
        assert reconciled["status"] == "running"
        assert reconciled["outcome"] == "broker_start_reconciled:1"


def test_runtime_poll_reconciles_graceful_stop_to_terminal_run(tmp_path: Path):
    app, runtime = _app(tmp_path)
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client)
        headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        project = client.post("/api/projects", json={"name": "A", "problem": "alpha", "roles": "high:1"}, headers=headers).json()
        runtime.assign_all(project["runtime_name"])
        started = client.post(f"/api/projects/{project['id']}/runs", json={"duration_seconds": 3600}, headers=headers).json()
        assert _broker_start(client, project).status_code == 200
        assert client.get(f"/api/projects/{project['id']}/runs/{started['run_id']}").json()["status"] == "running"
        assert client.post(f"/api/projects/{project['id']}/runs/{started['run_id']}/stop", json={}, headers=headers).status_code == 202
        stopping = client.get(f"/api/projects/{project['id']}/runs/{started['run_id']}").json()
        assert stopping["status"] == "stopping"
        assert stopping["outcome"] == "operator_stop_intent"
        assert runtime.stopped == []
        assert _broker_stop(client, project).status_code == 202
        terminal = client.get(f"/api/projects/{project['id']}/runs/{started['run_id']}").json()
        assert terminal["status"] == "stopped"
        assert terminal["outcome"] == "graceful_stop"
        assert terminal["stopped_at"] is not None


def test_runtime_poll_reconciles_unexpected_worker_exit(tmp_path: Path):
    app, runtime = _app(tmp_path)
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client); headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        project = client.post("/api/projects", json={"name": "A", "problem": "alpha"}, headers=headers).json()
        runtime.assign_all(project["runtime_name"])
        started = client.post(f"/api/projects/{project['id']}/runs", json={"duration_seconds": 3600}, headers=headers).json()
        assert _broker_start(client, project).status_code == 200
        client.get(f"/api/projects/{project['id']}/workers")
        runtime.statuses[project["runtime_name"]] = [{"worker": "high", "alive": False, "state": "error", "round": 2, "assigned": True, "task": "do the assigned work"}]
        client.get(f"/api/projects/{project['id']}/workers")
        terminal = client.get(f"/api/projects/{project['id']}/runs/{started['run_id']}").json()
        assert terminal["status"] == "stopped"
        assert terminal["outcome"] == "worker_error"
        assert terminal["stopped_at"] is not None


def test_run_lookup_is_project_scoped(tmp_path: Path):
    app, runtime = _app(tmp_path)
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client)
        headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        a = client.post("/api/projects", json={"name": "A", "problem": "alpha", "roles": "high:1"}, headers=headers).json()
        b = client.post("/api/projects", json={"name": "B", "problem": "beta", "roles": "high:1"}, headers=headers).json()
        runtime.assign_all(a["runtime_name"])
        run = client.post(f"/api/projects/{a['id']}/runs", json={"duration_seconds": 60}, headers=headers).json()
        assert client.get(f"/api/projects/{a['id']}/runs/{run['run_id']}").status_code == 200
        assert client.get(f"/api/projects/{b['id']}/runs/{run['run_id']}").status_code == 404
        assert client.post(f"/api/projects/{b['id']}/runs/{run['run_id']}/stop", json={}, headers=headers).status_code == 404


def test_logout_revokes_session_and_csrf_is_required(tmp_path: Path):
    app, _ = _app(tmp_path)
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client)
        assert client.post("/api/auth/logout", json={}, headers={"Origin": "https://testserver"}).status_code == 403
        assert client.post("/api/auth/logout", json={}, headers={"Origin": "https://testserver", "X-CSRF-Token": csrf}).status_code == 200
        denied_response = client.get("/api/projects")
        assert denied_response.status_code == 401
        assert denied_response.headers["x-content-type-options"] == "nosniff"
        assert denied_response.headers["cache-control"] == "no-store"


def test_runtime_start_failure_is_persisted_without_success_claim(tmp_path: Path):
    class FailingRuntime(FakeRuntime):
        def start_project(self, runtime_name):
            from danus.web_console.runtime import RuntimeOperationError
            raise RuntimeOperationError("worker launch failed")

    secret = b"failing-runtime-lifecycle-secret"
    runtime = FailingRuntime(tmp_path / "projects")
    settings = AppSettings(
        database_path=tmp_path / "console.sqlite3",
        password_hash=hash_password("correct horse battery staple"),
        cookie_secure=True,
        allowed_origins={"https://testserver"},
        lifecycle_hmac_secret=secret,
    )
    app = create_app(settings=settings, runtime=runtime)
    with TestClient(
        app, base_url="https://testserver", client=("127.0.0.1", 50123),
    ) as client:
        csrf = _login(client)
        headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        project = client.post(
            "/api/projects", json={"name": "A", "problem": "alpha"}, headers=headers,
        ).json()
        runtime.assign_all(project["runtime_name"])
        intent = client.post(
            f"/api/projects/{project['id']}/runs",
            json={"duration_seconds": 60}, headers=headers,
        )
        assert intent.status_code == 202
        token = project_lifecycle_capability(
            secret, project["id"], project["runtime_name"],
        )
        response = client.post(
            f"/internal/api/projects/{project['id']}/lifecycle",
            json={"action": "start"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 502
        assert response.json() == {"detail": "project workers could not be started"}
        import sqlite3
        with sqlite3.connect(tmp_path / "console.sqlite3") as db:
            status, outcome, generation, attempt_outcome = db.execute(
                "SELECT status,outcome,start_attempt_generation,start_attempt_outcome FROM runs"
            ).fetchone()
        assert status == "starting"
        assert outcome == "start_failed: worker launch failed"
        assert generation == 1
        assert attempt_outcome == "failed"
        assert runtime.cleared_deadlines == []


def test_real_runtime_adapter_keeps_two_project_contexts_isolated(tmp_path: Path):
    from danus.web_console.runtime import DanusRuntimeAdapter
    from danus.orchestration import cli
    original_spawn = cli.spawn_loop
    cli.spawn_loop = lambda worker_dir: 999_999_999
    try:
        adapter = DanusRuntimeAdapter(tmp_path / "agents")
        a = adapter.create_project("A", "alpha problem", "high:1", max_parallel_workers=1)
        b = adapter.create_project("B", "beta problem", "high:1", max_parallel_workers=1)
        assert (tmp_path / "agents" / "A" / "PROBLEM.md").read_text() == "alpha problem\n"
        assert (tmp_path / "agents" / "B" / "PROBLEM.md").read_text() == "beta problem\n"
        assert set(project["project"] for project in adapter.list_projects()) == {"A", "B"}
        assert a["project_dir"] != b["project_dir"]
        status_a = adapter.status_project("A")
        status_b = adapter.status_project("B")
        assert status_a["config"]["max_parallel_workers"] == 1
        assert status_a["workers"][0]["worker"] == "high"
        assert status_a["workers"][0]["assigned"] is False
        assert "unassigned" in status_a["workers"][0]["task"]
        assert status_b["workers"][0]["worker"] == "high"
        local_memory = tmp_path / "agents" / "A" / "workers" / "high" / "local_memory"
        (local_memory / "events.jsonl").write_text(
            '{"event_type": "search_math_results", "query": "Hodge decomposition"}\n',
            encoding="utf-8",
        )
        (local_memory / "notes.jsonl").write_text(
            '{"round": 2, "note": "resume from verified lemma", "fact_id": "abc123"}\n'
            '{"round": 3, "result": "verified Hodge lemma", "next": "build the Lefschetz bridge"}\n',
            encoding="utf-8",
        )
        status = adapter.status_project("A")["workers"][0]
        assert status["local_memory_count"] == 3
        assert status["checkpoint"] == {
            "message": "verified Hodge lemma\n\nNext: build the Lefschetz bridge",
            "source": "notes",
            "round": 3,
            "fact_id": None,
        }
    finally:
        cli.spawn_loop = original_spawn


def test_project_file_library_dedup_conflict_replace_version_and_cancel(tmp_path: Path):
    app, runtime = _app(tmp_path)
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client)
        headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        project = client.post("/api/projects", json={"name": "A", "problem": "alpha"}, headers=headers).json()
        pid = project["id"]
        def upload(name, body):
            return client.post(f"/api/projects/{pid}/files", files={"file": (name, body)}, headers=headers)
        first = upload("notes.md", b"one")
        assert first.status_code == 201 and first.json()["sha256"]
        same = upload("notes.md", b"one")
        assert same.status_code == 200 and same.json()["id"] == first.json()["id"]
        conflict = upload("notes.md", b"two")
        assert conflict.status_code == 409
        conflict_data = conflict.json()
        replaced = client.post(f"/api/projects/{pid}/file-conflicts/{conflict_data['conflict_id']}", json={"choice": "replace"}, headers=headers)
        assert replaced.status_code == 200 and replaced.json()["current"] is True
        files = client.get(f"/api/projects/{pid}/files").json()
        assert len(files) == 2 and sum(f["current"] for f in files) == 1
        conflict2 = upload("notes.md", b"three")
        assert conflict2.status_code == 409
        versioned = client.post(f"/api/projects/{pid}/file-conflicts/{conflict2.json()['conflict_id']}", json={"choice": "new_version"}, headers=headers)
        assert versioned.status_code == 200
        files = client.get(f"/api/projects/{pid}/files").json()
        assert len(files) == 3 and sum(f["current"] for f in files) == 1
        conflict3 = upload("notes.md", b"four")
        assert conflict3.status_code == 409
        cancelled = client.post(f"/api/projects/{pid}/file-conflicts/{conflict3.json()['conflict_id']}", json={"choice": "cancel"}, headers=headers)
        assert cancelled.status_code == 200
        assert len(client.get(f"/api/projects/{pid}/files").json()) == 3
        assert runtime.started == []


def test_cancelled_or_replaced_hash_can_be_uploaded_again(tmp_path: Path):
    app, _ = _app(tmp_path)
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client); headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        project = client.post("/api/projects", json={"name": "A", "problem": "alpha"}, headers=headers).json(); pid = project["id"]
        def upload(body): return client.post(f"/api/projects/{pid}/files", files={"file": ("notes.md", body)}, headers=headers)
        first = upload(b"one").json(); conflict = upload(b"two").json()
        assert client.post(f"/api/projects/{pid}/file-conflicts/{conflict['conflict_id']}", json={"choice":"cancel"}, headers=headers).status_code == 200
        retry = upload(b"two")
        assert retry.status_code == 409
        assert client.post(f"/api/projects/{pid}/file-conflicts/{retry.json()['conflict_id']}", json={"choice":"new_version"}, headers=headers).status_code == 200


def test_restart_after_stop_does_not_require_projection_poll(tmp_path: Path):
    app, runtime = _app(tmp_path)
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client); headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        project = client.post("/api/projects", json={"name":"A", "problem":"alpha"}, headers=headers).json()
        runtime.assign_all(project["runtime_name"])
        first = client.post(f"/api/projects/{project['id']}/runs", json={"duration_seconds":3600}, headers=headers).json()
        assert client.post(f"/api/projects/{project['id']}/runs/{first['run_id']}/stop", json={}, headers=headers).status_code == 202
        second = client.post(f"/api/projects/{project['id']}/runs", json={"duration_seconds":3600}, headers=headers)
        assert second.status_code == 202


def test_project_file_allowlist_and_isolation(tmp_path: Path):
    app, _ = _app(tmp_path)
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client)
        headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        a = client.post("/api/projects", json={"name": "A", "problem": "alpha"}, headers=headers).json()
        b = client.post("/api/projects", json={"name": "B", "problem": "beta"}, headers=headers).json()
        bad = client.post(f"/api/projects/{a['id']}/files", files={"file": ("run.sh", b"echo nope")}, headers=headers)
        assert bad.status_code == 400
        good = client.post(f"/api/projects/{a['id']}/files", files={"file": ("paper.tex", b"\\section{A}")}, headers=headers)
        assert good.status_code == 201
        assert client.get(f"/api/projects/{b['id']}/files").json() == []
        assert client.get(f"/api/projects/{b['id']}/files/{good.json()['id']}").status_code == 404


def test_main_agent_session_resume_attachment_and_project_isolation(tmp_path: Path):
    class FakeMainAgent:
        def __init__(self): self.calls = []
        def send(self, **kwargs):
            self.calls.append(kwargs)
            sid = kwargs["session_id"] or "session-A"
            return {"session_id": sid, "reply": "reply:" + kwargs["message"], "status": "completed", "seconds": 0.1, "read_status": "not_read"}
    main = FakeMainAgent()
    runtime = FakeRuntime(tmp_path / "projects")
    lifecycle_secret = b"main-agent-lifecycle-secret"
    settings = AppSettings(
        database_path=tmp_path / "console.sqlite3",
        password_hash=hash_password("correct horse battery staple"),
        cookie_secure=True,
        allowed_origins={"https://testserver"},
        lifecycle_base_url="http://127.0.0.1:8080",
        lifecycle_hmac_secret=lifecycle_secret,
    )
    app = create_app(settings=settings, runtime=runtime, main_agent=main)
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client); headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        a = client.post("/api/projects", json={"name": "A", "problem": "alpha"}, headers=headers).json()
        b = client.post("/api/projects", json={"name": "B", "problem": "beta"}, headers=headers).json()
        uploaded = client.post(f"/api/projects/{a['id']}/files", files={"file": ("source.md", b"source")}, headers=headers).json()
        first = client.post(f"/api/projects/{a['id']}/messages", json={"text": "hello", "attachment_ids": [uploaded["id"]]}, headers=headers)
        assert first.status_code == 201 and first.json()["session_id"] == "session-A"
        second = client.post(f"/api/projects/{a['id']}/messages", json={"text": "continue", "attachment_ids": []}, headers=headers)
        assert second.status_code == 201 and second.json()["session_id"] == "session-A"
        assert main.calls[0]["context_dir"] == tmp_path / "projects" / "A"
        assert main.calls[0]["attachments"][0]["path"].startswith(str(tmp_path / "projects" / "A"))
        assert main.calls[0]["lifecycle_url"] == (
            f"http://127.0.0.1:8080/internal/api/projects/{a['id']}/lifecycle"
        )
        assert main.calls[0]["lifecycle_token"] == project_lifecycle_capability(
            lifecycle_secret, a["id"], a["runtime_name"],
        )
        listed_messages = client.get(f"/api/projects/{a['id']}/messages").json()
        assert listed_messages[0]["attachment_ids"] == [uploaded["id"]]
        assert client.get(f"/api/projects/{a['id']}/files").json()[0]["read_status"] == "not_read"
        assert client.get(f"/api/projects/{a['id']}/messages").json()[0]["status"] == "completed"
        foreign = client.post(f"/api/projects/{b['id']}/messages", json={"text": "no", "attachment_ids": [uploaded["id"]]}, headers=headers)
        assert foreign.status_code == 404
        assert len(client.get(f"/api/projects/{b['id']}/messages").json()) == 0


def test_malformed_main_agent_result_marks_message_failed(tmp_path: Path):
    class BrokenMain:
        backend = "codex"
        def send(self, **kwargs): return {"reply": "ok"}
    app, runtime = _app(tmp_path)
    # Reuse app construction with broken adapter and the same settings shape.
    settings = AppSettings(database_path=tmp_path / "broken.sqlite3", password_hash=hash_password("correct horse battery staple"), cookie_secure=True, allowed_origins={"https://testserver"})
    app = create_app(settings=settings, runtime=FakeRuntime(tmp_path / "broken-projects"), main_agent=BrokenMain())
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client); headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        project = client.post("/api/projects", json={"name":"A", "problem":"alpha"}, headers=headers).json()
        response = client.post(f"/api/projects/{project['id']}/messages", json={"text":"hello", "attachment_ids":[]}, headers=headers)
        assert response.status_code == 502
        messages = client.get(f"/api/projects/{project['id']}/messages").json()
        assert messages[0]["status"] == "failed"
        events = client.get(f"/api/projects/{project['id']}/main-agent-events").json()["events"]
        assert [event["type"] for event in events] == ["turn.failed"]
        assert events[0]["status"] == "failed"


def test_main_agent_timeout_public_error_is_fail_closed():
    error = MainAgentError("raw timeout diagnostics", code="timeout", retryable=False)

    public = _public_main_agent_error(error)

    assert "不要直接重试" in public
    assert "重复操作" in public
    assert "raw timeout diagnostics" not in public


def test_main_agent_transient_failure_is_visible_and_keeps_resumable_session(tmp_path: Path):
    class RetryingMain:
        backend = "codex"
        progress = []

        def send(self, **kwargs):
            event = {
                "status": "retrying", "attempt": 2, "max_attempts": 3,
                "delay_seconds": 2, "error_code": "server_overloaded",
                "message": "Selected model is at capacity. Please try a different model.",
                "session_id": "sid-overloaded",
            }
            kwargs["on_progress"](event)
            self.progress.append(event)
            raise MainAgentError(
                "main agent turn failed: Selected model is at capacity. Please try a different model.",
                code="server_overloaded", session_id="sid-overloaded",
                retryable=True, safe_to_retry=True, attempts=3,
            )

    main = RetryingMain()
    settings = AppSettings(
        database_path=tmp_path / "retry.sqlite3",
        password_hash=hash_password("correct horse battery staple"),
        cookie_secure=True,
        allowed_origins={"https://testserver"},
    )
    app = create_app(
        settings=settings,
        runtime=FakeRuntime(tmp_path / "retry-projects"),
        main_agent=main,
    )
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client)
        headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        project = client.post(
            "/api/projects", json={"name": "A", "problem": "alpha"}, headers=headers,
        ).json()
        response = client.post(
            f"/api/projects/{project['id']}/messages",
            json={"text": "hello", "attachment_ids": []}, headers=headers,
        )

        assert response.status_code == 502
        assert response.json() == {
            "detail": "上游模型当前繁忙；自动重试后仍未完成，请稍后再试。",
            "error_code": "server_overloaded",
            "provider_retryable": True,
            "retryable": True,
            "attempts": 3,
        }
        messages = client.get(f"/api/projects/{project['id']}/messages").json()
        assert [message["status"] for message in messages] == ["failed", "failed"]
        assert all(message["error"] == "上游模型当前繁忙；自动重试后仍未完成，请稍后再试。" for message in messages)
        stored_session = app.state.console_store.agent_session(project["id"])
        assert stored_session["session_id"] == "sid-overloaded"
        assert stored_session["status"] == "inactive"
        assert main.progress[0]["error_code"] == "server_overloaded"


def test_main_agent_retry_progress_is_visible_while_the_post_is_still_running(tmp_path: Path):
    class SlowRetryingMain:
        backend = "codex"

        def __init__(self):
            self.progress_sent = threading.Event()
            self.release = threading.Event()

        def send(self, **kwargs):
            kwargs["on_progress"]({
                "status": "retrying", "attempt": 2, "max_attempts": 3,
                "delay_seconds": 2, "error_code": "server_overloaded",
                "message": "Selected model is at capacity. Please try a different model.",
                "session_id": "sid-progress",
            })
            self.progress_sent.set()
            assert self.release.wait(timeout=5)
            return {
                "session_id": "sid-progress", "reply": "recovered",
                "status": "completed", "seconds": 0.1,
                "read_status": "unknown", "attempts": 2,
            }

    main = SlowRetryingMain()
    settings = AppSettings(
        database_path=tmp_path / "progress.sqlite3",
        password_hash=hash_password("correct horse battery staple"),
        cookie_secure=True,
        allowed_origins={"https://testserver"},
    )
    app = create_app(
        settings=settings,
        runtime=FakeRuntime(tmp_path / "progress-projects"),
        main_agent=main,
    )
    with TestClient(app, base_url="https://testserver") as poster, TestClient(app, base_url="https://testserver") as observer:
        poster_csrf = _login(poster)
        observer_csrf = _login(observer)
        poster_headers = {"X-CSRF-Token": poster_csrf, "Origin": "https://testserver"}
        observer_headers = {"X-CSRF-Token": observer_csrf, "Origin": "https://testserver"}
        project = poster.post(
            "/api/projects", json={"name": "A", "problem": "alpha"},
            headers=poster_headers,
        ).json()
        result = {}

        def submit():
            result["response"] = poster.post(
                f"/api/projects/{project['id']}/messages",
                json={"text": "hello", "attachment_ids": []},
                headers=poster_headers,
            )

        thread = threading.Thread(target=submit)
        thread.start()
        assert main.progress_sent.wait(timeout=5)
        in_flight = observer.get(
            f"/api/projects/{project['id']}/messages", headers=observer_headers,
        ).json()
        assert len(in_flight) == 1
        assert in_flight[0]["status"] == "retrying"
        assert "第 2/3 次尝试" in in_flight[0]["error"]

        main.release.set()
        thread.join(timeout=5)
        assert not thread.is_alive()
        assert result["response"].status_code == 201
        completed = observer.get(
            f"/api/projects/{project['id']}/messages", headers=observer_headers,
        ).json()
        assert [message["status"] for message in completed] == ["completed", "completed"]
        assert completed[1]["text"] == "recovered"


def test_concurrent_main_agent_messages_resume_the_session_created_by_the_first_turn(tmp_path: Path):
    class SerializedMain:
        backend = "codex"

        def __init__(self):
            self.calls = []
            self.first_started = threading.Event()
            self.release_first = threading.Event()

        def send(self, **kwargs):
            self.calls.append(kwargs["session_id"])
            if len(self.calls) == 1:
                self.first_started.set()
                assert self.release_first.wait(timeout=5)
                return {
                    "session_id": "sid-first", "reply": "first", "status": "completed",
                    "seconds": 0.1, "read_status": "unknown", "attempts": 1,
                }
            return {
                "session_id": kwargs["session_id"], "reply": "second", "status": "completed",
                "seconds": 0.1, "read_status": "unknown", "attempts": 1,
            }

    main = SerializedMain()
    settings = AppSettings(
        database_path=tmp_path / "serialized.sqlite3",
        password_hash=hash_password("correct horse battery staple"),
        cookie_secure=True,
        allowed_origins={"https://testserver"},
    )
    app = create_app(
        settings=settings,
        runtime=FakeRuntime(tmp_path / "serialized-projects"),
        main_agent=main,
    )
    with TestClient(app, base_url="https://testserver") as client:
        headers = {"X-CSRF-Token": _login(client), "Origin": "https://testserver"}
        project = client.post(
            "/api/projects", json={"name": "A", "problem": "alpha"},
            headers=headers,
        ).json()
        responses = {}

        def submit(key, text):
            responses[key] = client.post(
                f"/api/projects/{project['id']}/messages",
                json={"text": text, "attachment_ids": []}, headers=headers,
            )

        first_thread = threading.Thread(target=submit, args=("first", "one"))
        second_thread = threading.Thread(target=submit, args=("second", "two"))
        first_thread.start()
        assert main.first_started.wait(timeout=5)
        second_thread.start()
        time.sleep(0.1)
        assert main.calls == [None]
        main.release_first.set()
        first_thread.join(timeout=5)
        second_thread.join(timeout=5)

        assert responses["first"].status_code == 201
        assert responses["second"].status_code == 201
        assert main.calls == [None, "sid-first"]


def test_main_agent_events_are_persisted_and_project_scoped(tmp_path: Path):
    class StreamingMain:
        backend = "codex"

        def send(self, **kwargs):
            for event in [
                {"type": "turn.started", "detail": "Main Agent 会话已建立"},
                {"type": "agent.progress", "detail": "公开的推理进度摘要。"},
                {"type": "agent.message", "detail": "我先检查项目状态。"},
                {"type": "tool.started", "tool": "exec_command", "detail": "danus-web-agent status", "call_id": "call-1"},
                {"type": "tool.completed", "tool": "exec_command", "detail": "exit 0", "status": "completed", "call_id": "call-1"},
                {"type": "turn.completed", "detail": "Main Agent 已完成本次回复"},
            ]:
                kwargs["on_progress"](event)
            return {
                "session_id": "sid-events", "reply": "done", "status": "completed",
                "seconds": 0.1, "read_status": "unknown", "attempts": 1,
            }

    settings = AppSettings(
        database_path=tmp_path / "events.sqlite3",
        password_hash=hash_password("correct horse battery staple"),
        cookie_secure=True,
        allowed_origins={"https://testserver"},
    )
    app = create_app(
        settings=settings,
        runtime=FakeRuntime(tmp_path / "event-projects"),
        main_agent=StreamingMain(),
    )
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client)
        headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        a = client.post("/api/projects", json={"name": "A", "problem": "alpha"}, headers=headers).json()
        b = client.post("/api/projects", json={"name": "B", "problem": "beta"}, headers=headers).json()
        response = client.post(
            f"/api/projects/{a['id']}/messages",
            json={"text": "hello", "attachment_ids": []}, headers=headers,
        )
        assert response.status_code == 201

        events = client.get(f"/api/projects/{a['id']}/main-agent-events").json()["events"]
        assert [event["type"] for event in events] == [
            "turn.started", "agent.progress", "agent.message", "tool.started", "tool.completed", "turn.completed",
        ]
        assert events[3]["tool"] == "exec_command"
        assert events[3]["detail"] == "danus-web-agent status"
        assert events[3]["call_id"] == "call-1"
        assert events[4]["call_id"] == "call-1"
        assert all(event["message_id"] == response.json()["message_id"] for event in events)
        assert all("main_agent_session_id" in event for event in events)
        assert all("run_id" in event for event in events)
        assert client.get(f"/api/projects/{b['id']}/main-agent-events").json() == {"events": [], "last_id": 0}
        assert client.get("/api/projects/foreign/main-agent-events").status_code == 404


def test_read_only_projections_are_authenticated_and_project_scoped(tmp_path: Path):
    app, runtime = _app(tmp_path)
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client); headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        project = client.post("/api/projects", json={"name": "A", "problem": "alpha"}, headers=headers).json()
        runtime.assign_all(project["runtime_name"])
        pid = project["id"]
        for endpoint in ("workers", "logs", "fact-graph", "memory", "reports", "outputs"):
            assert client.get(f"/api/projects/{pid}/{endpoint}").status_code == 200
            assert client.get(f"/api/projects/foreign/{endpoint}").status_code == 404
        assert client.get("/api/projects/foreign/logs").status_code == 404


def test_deadline_rejects_new_main_agent_work(tmp_path: Path):
    class FakeClockRuntime(FakeRuntime):
        def __init__(self, root):
            super().__init__(root); self.deadline = None
        def write_deadline(self, runtime_name, deadline): self.deadline = deadline
    class Main:
        def send(self, **kwargs): raise AssertionError("must not activate after deadline")
    runtime = FakeClockRuntime(tmp_path / "projects")
    settings = AppSettings(database_path=tmp_path / "console.sqlite3", password_hash=hash_password("correct horse battery staple"), cookie_secure=True, allowed_origins={"https://testserver"})
    app = create_app(settings=settings, runtime=runtime, main_agent=Main())
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client); headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        project = client.post("/api/projects", json={"name": "A", "problem": "alpha"}, headers=headers).json()
        runtime.assign_all(project["runtime_name"])
        run = client.post(f"/api/projects/{project['id']}/runs", json={"duration_seconds": 1}, headers=headers).json()
        import sqlite3
        with sqlite3.connect(tmp_path / "console.sqlite3") as db:
            db.execute("UPDATE runs SET deadline=?", (0,)); db.commit()
        response = client.post(f"/api/projects/{project['id']}/messages", json={"text": "late", "attachment_ids": []}, headers=headers)
        assert response.status_code == 409
        # Deadline enforcement is the host safety boundary and remains direct.
        assert runtime.stopped == [project["runtime_name"]]


def test_project_deletion_requires_stop_confirmation_and_isolation(tmp_path: Path):
    app, runtime = _app(tmp_path)
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client); headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        a = client.post("/api/projects", json={"name": "A", "problem": "alpha"}, headers=headers).json()
        b = client.post("/api/projects", json={"name": "B", "problem": "beta"}, headers=headers).json()
        assert client.request("DELETE", f"/api/projects/{a['id']}", json={"confirm_name": "wrong"}, headers=headers).status_code == 400
        runtime.assign_all(a["runtime_name"])
        client.post(f"/api/projects/{a['id']}/runs", json={"duration_seconds": 60}, headers=headers)
        assert client.request("DELETE", f"/api/projects/{a['id']}", json={"confirm_name": "A"}, headers=headers).status_code == 409
        client.post(f"/api/projects/{a['id']}/stop", json={}, headers=headers)
        deleted = client.request("DELETE", f"/api/projects/{a['id']}", json={"confirm_name": "A"}, headers=headers)
        assert deleted.status_code == 200
        assert client.get(f"/api/projects/{a['id']}").status_code == 404
        assert client.get(f"/api/projects/{b['id']}").status_code == 200


def test_provider_model_catalog_uses_configured_endpoint_without_exposing_credentials(monkeypatch):
    captured = {}

    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self):
            return json.dumps({"data": [
                {"id": "gpt-5.6-luna", "owned_by": "provider"},
                {"id": "gpt-image-2", "owned_by": "provider"},
            ]}).encode()

    def opener(request, *, timeout):
        captured["url"] = request.full_url
        captured["authorization"] = request.get_header("Authorization")
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setenv("OPENAI_BASE_URL", "https://provider.example/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "catalog-secret")
    snapshot = ProviderModelCatalog(opener=opener, now=lambda: 123.0).snapshot(
        default_worker_model="gpt-5.5",
    )

    assert captured == {
        "url": "https://provider.example/v1/models",
        "authorization": "Bearer catalog-secret",
        "timeout": 5.0,
    }
    by_id = {row["id"]: row for row in snapshot["models"]}
    assert by_id["gpt-5.6-luna"]["selectable"] is True
    assert by_id["gpt-image-2"]["selectable"] is False
    assert "catalog-secret" not in json.dumps(snapshot)


def test_config_project_capacity_and_assignment_gate_are_server_enforced(tmp_path: Path, monkeypatch):
    class Catalog:
        def snapshot(self, **kwargs):
            return {
                "models": [
                    {"id": "gpt-5.6-luna", "selectable": True},
                    {"id": "gpt-image-2", "selectable": False},
                ],
                "provider": {"credential_configured": True},
                "cached": False,
                "stale": False,
            }

    class Main:
        backend = "codex"
        model = "gpt-5.6-luna"
        effort = "xhigh"

    monkeypatch.setenv("DANUS_CONSULT_TRANSPORT", "off")
    runtime = FakeRuntime(tmp_path / "projects")
    settings = AppSettings(
        database_path=tmp_path / "console.sqlite3",
        password_hash=hash_password("correct horse battery staple"),
        cookie_secure=True,
        allowed_origins={"https://testserver"},
        default_max_parallel_workers=2,
    )
    app = create_app(settings=settings, runtime=runtime, main_agent=Main(), model_catalog=Catalog())
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client); headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        config = client.get("/api/config").json()
        assert config["default_max_parallel_workers"] == 2
        assert config["main_agent"] == {
            "backend": "codex", "model": "gpt-5.6-luna", "effort": "xhigh",
            "provider_configured": False,
        }
        assert config["strategy"]["transport"] == "off"
        assert [row["id"] for row in config["worker_models"]] == ["gpt-5.6-luna", "gpt-image-2"]

        project = client.post("/api/projects", json={
            "name": "A", "problem": "alpha", "roles": "high:1,xhigh:1",
            "model": "gpt-5.6-luna", "max_parallel_workers": 2,
        }, headers=headers).json()
        assert project["worker_model"] == "gpt-5.6-luna"
        assert project["max_parallel_workers"] == 2

        rejected = client.post(
            f"/api/projects/{project['id']}/runs",
            json={"duration_seconds": 60}, headers=headers,
        )
        assert rejected.status_code == 409
        assert rejected.json()["unassigned_workers"] == ["high", "xhigh"]
        assert runtime.started == []

        runtime.assign_all(project["runtime_name"])
        accepted = client.post(
            f"/api/projects/{project['id']}/runs",
            json={"duration_seconds": 60}, headers=headers,
        )
        assert accepted.status_code == 202
        assert runtime.started == []


def test_orchestration_projection_reads_real_session_guidance_and_tasks(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DANUS_CONSULT_TRANSPORT", "off")
    runtime = FakeMemoryRuntime(tmp_path / "projects")
    settings = AppSettings(
        database_path=tmp_path / "console.sqlite3",
        password_hash=hash_password("correct horse battery staple"),
        cookie_secure=True,
        allowed_origins={"https://testserver"},
    )
    app = create_app(settings=settings, runtime=runtime)
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client); headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        project = client.post("/api/projects", json={
            "name": "A", "problem": "alpha", "roles": "high:1,xhigh:1",
        }, headers=headers).json()
        runtime.statuses[project["runtime_name"]][0].update({"assigned": True, "task": "Explore branch A"})
        runtime.memory_entries[project["runtime_name"]] = {"total": 2, "channels": [
            {"kind": "master_guidance", "entries": [{"claim": "Split into branches A and B", "evidence": "guidance-source: offline-main-agent"}]},
            {"kind": "elaboration", "entries": [{"claim": "The missing bridge is compactness"}]},
        ]}
        app.state.console_store.upsert_agent_session(
            project["id"], "session-1", "inactive", time.time(), backend="codex",
        )

        projection = client.get(f"/api/projects/{project['id']}/orchestration").json()
        assert projection["main_agent"]["status"] == "inactive"
        assert projection["main_agent"]["session_id_present"] is True
        assert projection["assigned_workers"] == 1
        assert projection["unassigned_workers"] == ["xhigh"]
        assert projection["workers"][0]["task"] == "Explore branch A"
        assert projection["master_guidance"]["claim"] == "Split into branches A and B"
        assert projection["guidance_source"] == "offline-main-agent"
        assert projection["guidance_transport"] == "off"
        assert projection["elaboration"]["claim"] == "The missing bridge is compactness"

        monkeypatch.setenv("DANUS_CONSULT_TRANSPORT", "gpt_pro")
        runtime.memory_entries[project["runtime_name"]]["channels"][0]["entries"][0]["evidence"] = "guidance-source: consult-derived"
        enabled_projection = client.get(f"/api/projects/{project['id']}/orchestration").json()
        assert enabled_projection["guidance_source"] == "consult-derived"
        assert enabled_projection["guidance_transport"] == "gpt_pro"

def test_main_agent_event_retention_is_project_scoped(tmp_path: Path):
    store = ConsoleStore(tmp_path / "retention.sqlite3")
    store.MAIN_AGENT_EVENT_RETENTION = 3
    for project_id in ("p1", "p2"):
        store.add_project({
            "id": project_id, "name": project_id, "runtime_name": project_id,
            "problem": "problem", "roles": "high:1", "worker_model": None,
            "max_parallel_workers": 1, "created_at": 1.0,
        })
        store.add_message({
            "id": f"m-{project_id}", "project_id": project_id, "role": "user",
            "text": "hello", "status": "submitted", "created_at": 1.0, "error": None,
        })

    for index in range(5):
        store.add_main_agent_event(
            project_id="p1", message_id="m-p1", event_type="agent.message",
            payload={"detail": str(index)}, created_at=float(index),
        )
    store.add_main_agent_event(
        project_id="p2", message_id="m-p2", event_type="turn.started",
        payload={"detail": "other project"}, created_at=1.0,
    )

    assert [event["detail"] for event in store.main_agent_events("p1")] == ["2", "3", "4"]
    assert [event["detail"] for event in store.main_agent_events("p2")] == ["other project"]


def test_runtime_and_run_projection_report_partial_graceful_stop_progress(tmp_path: Path):
    class DrainingRuntime(FakeRuntime):
        def stop_project(self, runtime_name):
            self.stopped.append(runtime_name)
            for worker in self.statuses.get(runtime_name, []):
                if worker.get("alive"):
                    worker["stop_requested"] = True
            return {"workers": self.statuses[runtime_name]}

    runtime = DrainingRuntime(tmp_path / "projects")
    settings = AppSettings(
        database_path=tmp_path / "console.sqlite3",
        password_hash=hash_password("correct horse battery staple"),
        cookie_secure=True,
        allowed_origins={"https://testserver"},
        lifecycle_hmac_secret=_LIFECYCLE_SECRET,
    )
    app = create_app(settings=settings, runtime=runtime)
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client)
        headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        project = client.post(
            "/api/projects",
            json={"name": "A", "problem": "alpha", "roles": "high:8"},
            headers=headers,
        ).json()
        runtime.assign_all(project["runtime_name"])
        run = client.post(
            f"/api/projects/{project['id']}/runs",
            json={"duration_seconds": 3600},
            headers=headers,
        ).json()
        assert _broker_start(client, project).status_code == 200
        for worker in runtime.statuses[project["runtime_name"]]:
            worker.update({"process_identity": "matched", "alive": True, "state": "running"})
        runtime.statuses[project["runtime_name"]][-1].update({
            "process_identity": "dead", "alive": False, "state": "stopped",
        })

        assert client.post(
            f"/api/projects/{project['id']}/runs/{run['run_id']}/stop",
            json={}, headers=headers,
        ).status_code == 202
        assert _broker_stop(client, project).status_code == 202

        projection = client.get(f"/api/projects/{project['id']}/runtime").json()
        expected_run = {
            "id": run["run_id"],
            "status": "stopping",
            "deadline": run["deadline"],
            "expected_workers": 8,
            "live_workers": 7,
            "stop_pending_workers": 7,
            "stopped_workers": 1,
            "stale_workers": 0,
        }
        assert {key: projection["run"][key] for key in expected_run} == expected_run
        assert projection["progress"] == {
            "expected_workers": 8,
            "live_workers": 7,
            "stop_pending_workers": 7,
            "stopped_workers": 1,
            "stale_workers": 0,
        }
        run_projection = client.get(
            f"/api/projects/{project['id']}/runs/{run['run_id']}"
        ).json()
        assert run_projection["stop_pending_workers"] == 7
        assert run_projection["stopped_workers"] == 1


def test_worker_safety_controls_are_authenticated_confirmed_and_project_scoped(tmp_path: Path):
    app, runtime = _app(tmp_path)
    with TestClient(app, base_url="https://testserver") as client:
        project = None
        assert client.post("/api/projects/missing/pause", json={}).status_code == 401
        csrf = _login(client)
        headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        project = client.post(
            "/api/projects", json={"name": "A", "problem": "alpha"}, headers=headers,
        ).json()
        pid = project["id"]
        runtime.assign_all(project["runtime_name"])
        started = client.post(
            f"/api/projects/{pid}/runs", json={"duration_seconds": 60}, headers=headers,
        )
        assert started.status_code == 202
        assert _broker_start(client, project).status_code == 200

        paused = client.post(f"/api/projects/{pid}/pause", json={"worker": "high"}, headers=headers)
        assert paused.status_code == 202 and paused.json()["status"] == "pause_intent"
        assert runtime.controls == []
        assert _broker_lifecycle(client, project, "pause", worker="high").status_code == 202

        resumed = client.post(f"/api/projects/{pid}/resume", json={"worker": "high"}, headers=headers)
        assert resumed.status_code == 202 and resumed.json()["status"] == "resume_intent"
        assert _broker_lifecycle(client, project, "resume", worker="high").status_code == 202
        denied = client.post(f"/api/projects/{pid}/force-stop", json={"confirm": "wrong"}, headers=headers)
        assert denied.status_code == 409
        forced = client.post(
            f"/api/projects/{pid}/force-stop",
            json={"worker": "high", "confirm": project["name"]}, headers=headers,
        )
        assert forced.status_code == 200 and forced.json()["status"] == "force_stopped"
        plan = client.post(f"/api/projects/{pid}/reclaim", json={"worker": "high"}, headers=headers)
        assert plan.status_code == 200 and plan.json()["dry_run"] is True
        reclaimed = client.post(
            f"/api/projects/{pid}/reclaim",
            json={"worker": "high", "execute": True, "confirmation_token": "confirm-token", "confirm": project["name"]},
            headers=headers,
        )
        assert reclaimed.status_code == 200 and reclaimed.json()["status"] == "reclaimed"
        assert runtime.controls == [
            ("pause", "A", "high"),
            ("resume", "A", "high"),
            ("force_stop", "A", "high"),
            ("reclaim", "A", "high", False, None),
            ("reclaim", "A", "high", True, "confirm-token"),
        ]
        assert client.post("/api/projects/foreign/reclaim", json={}, headers=headers).status_code == 404


def test_selected_force_stop_keeps_run_active_when_other_workers_remain_live(tmp_path: Path):
    app, runtime = _app(tmp_path)
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client)
        headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        project = client.post(
            "/api/projects",
            json={"name": "A", "problem": "alpha", "roles": "high:1,xhigh:1"},
            headers=headers,
        ).json()
        for worker in runtime.statuses[project["runtime_name"]]:
            worker["assigned"] = True
        started = client.post(
            f"/api/projects/{project['id']}/runs",
            json={"duration_seconds": 60}, headers=headers,
        )
        assert started.status_code == 202
        assert _broker_start(client, project).status_code == 200
        assert client.get(
            f"/api/projects/{project['id']}/runs/{started.json()['run_id']}"
        ).json()["status"] == "running"

        forced = client.post(
            f"/api/projects/{project['id']}/force-stop",
            json={"worker": "high", "confirm": project["name"]}, headers=headers,
        )
        assert forced.status_code == 200
        run = client.get(
            f"/api/projects/{project['id']}/runs/{started.json()['run_id']}"
        ).json()
        assert run["status"] == "running"
        assert run["outcome"] == "main_agent_start"


def test_log_http_projection_is_authenticated_scoped_and_forwards_bounds(tmp_path: Path):
    class LogRuntime(FakeRuntime):
        def __init__(self, root):
            super().__init__(root)
            self.log_calls = []

        def logs_projection(self, runtime_name, worker=None, tail=200, *, max_bytes=65536):
            self.log_calls.append((runtime_name, worker, tail, max_bytes))
            return {
                "worker": worker, "tail": tail, "max_bytes": max_bytes,
                "fetched_at": 123.0, "entries": [],
            }

    runtime = LogRuntime(tmp_path / "projects")
    settings = AppSettings(
        database_path=tmp_path / "console.sqlite3",
        password_hash=hash_password("correct horse battery staple"),
        cookie_secure=True,
        allowed_origins={"https://testserver"},
    )
    app = create_app(settings=settings, runtime=runtime)
    with TestClient(app, base_url="https://testserver") as client:
        assert client.get("/api/projects/unknown/logs").status_code == 401
        csrf = _login(client)
        headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        a = client.post("/api/projects", json={"name": "A", "problem": "alpha"}, headers=headers).json()
        client.post("/api/projects", json={"name": "B", "problem": "beta"}, headers=headers)

        response = client.get(
            f"/api/projects/{a['id']}/logs?worker=high&tail=7&max_bytes=4096"
        )
        assert response.status_code == 200
        assert runtime.log_calls == [("A", "high", 7, 4096)]
        assert response.json()["fetched_at"] == 123.0
        assert client.get(f"/api/projects/{a['id']}/logs?tail=bad").status_code == 400
        assert client.get(f"/api/projects/{a['id']}/logs?worker=../B").status_code == 400
def test_deadline_supervisor_enforces_expiry_without_browser_polling(tmp_path: Path):
    class DeadlineRuntime(FakeRuntime):
        def __init__(self, root):
            super().__init__(root)
            self.deadline_enforced = threading.Event()

        def enforce_deadline(self, runtime_name):
            self.deadline_enforced.set()
            self.statuses[runtime_name] = [
                {**worker, "alive": False, "raw_alive": False, "state": "terminated"}
                for worker in self.statuses.get(runtime_name, [])
            ]
            return {"workers": [
                {"worker": worker["worker"], "result": "killed"}
                for worker in self.statuses[runtime_name]
            ]}

    runtime = DeadlineRuntime(tmp_path / "projects")
    settings = AppSettings(
        database_path=tmp_path / "console.sqlite3",
        password_hash=hash_password("correct horse battery staple"),
        cookie_secure=True,
        allowed_origins={"https://testserver"},
        lifecycle_hmac_secret=_LIFECYCLE_SECRET,
        deadline_poll_seconds=0.05,
    )
    app = create_app(settings=settings, runtime=runtime)
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client)
        headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        project = client.post(
            "/api/projects", json={"name": "A", "problem": "alpha"}, headers=headers,
        ).json()
        runtime.assign_all(project["runtime_name"])
        started = client.post(
            f"/api/projects/{project['id']}/runs",
            json={"duration_seconds": 1}, headers=headers,
        )
        assert started.status_code == 202
        assert _broker_start(client, project).status_code == 200

        assert runtime.deadline_enforced.wait(timeout=2.5)
        run = client.get(
            f"/api/projects/{project['id']}/runs/{started.json()['run_id']}"
        ).json()
        assert run["status"] == "stopped"
        assert run["outcome"] == "deadline_enforced"


def test_running_run_reports_degraded_when_any_expected_worker_disappears(tmp_path: Path):
    app, runtime = _app(tmp_path)
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client)
        headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        project = client.post(
            "/api/projects",
            json={"name": "A", "problem": "alpha", "roles": "high:1,xhigh:1"},
            headers=headers,
        ).json()
        runtime.assign_all(project["runtime_name"])
        started = client.post(
            f"/api/projects/{project['id']}/runs",
            json={"duration_seconds": 60}, headers=headers,
        )
        assert _broker_start(client, project).status_code == 200
        runtime.statuses[project["runtime_name"]][-1].update({
            "alive": False, "raw_alive": False, "state": "error",
        })

        projection = client.get(f"/api/projects/{project['id']}/runtime").json()
        assert projection["run"]["status"] == "running"
        assert projection["run"]["outcome"].startswith("degraded_missing:")
        assert projection["run"]["not_running_workers"] == ["xhigh"]
        assert projection["run"]["alive_workers"] == ["high"]
        run = client.get(
            f"/api/projects/{project['id']}/runs/{started.json()['run_id']}"
        ).json()
        assert run["outcome"].startswith("degraded_missing:")


def test_broker_stop_refusal_keeps_unresolved_raw_process_nonterminal(tmp_path: Path):
    class RefusingRuntime(FakeRuntime):
        def stop_project(self, runtime_name):
            worker = self.statuses[runtime_name][0]
            worker.update({
                "alive": False, "raw_alive": True,
                "process_identity": "mismatch", "state": "stale",
            })
            return {"workers": [{"worker": worker["worker"], "result": "identity-mismatch"}]}

    runtime = RefusingRuntime(tmp_path / "projects")
    settings = AppSettings(
        database_path=tmp_path / "console.sqlite3",
        password_hash=hash_password("correct horse battery staple"),
        cookie_secure=True,
        allowed_origins={"https://testserver"},
        lifecycle_hmac_secret=_LIFECYCLE_SECRET,
    )
    app = create_app(settings=settings, runtime=runtime)
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client)
        headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        project = client.post(
            "/api/projects", json={"name": "A", "problem": "alpha"}, headers=headers,
        ).json()
        runtime.assign_all(project["runtime_name"])
        started = client.post(
            f"/api/projects/{project['id']}/runs",
            json={"duration_seconds": 60}, headers=headers,
        )
        assert _broker_start(client, project).status_code == 200
        assert client.post(
            f"/api/projects/{project['id']}/stop", json={}, headers=headers,
        ).status_code == 202

        refused = _broker_stop(client, project)
        assert refused.status_code == 409
        projection = client.get(f"/api/projects/{project['id']}/runtime").json()
        assert projection["run"]["status"] == "stopping"
        assert projection["run"]["outcome"].startswith("main_agent_stop_refused:")
        assert runtime.statuses[project["runtime_name"]][0]["raw_alive"] is True


def test_pause_and_resume_are_rejected_after_stop_intent(tmp_path: Path):
    app, runtime = _app(tmp_path)
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client)
        headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        project = client.post(
            "/api/projects", json={"name": "A", "problem": "alpha"}, headers=headers,
        ).json()
        runtime.assign_all(project["runtime_name"])
        started = client.post(
            f"/api/projects/{project['id']}/runs",
            json={"duration_seconds": 60}, headers=headers,
        )
        assert started.status_code == 202
        assert _broker_start(client, project).status_code == 200
        assert client.post(
            f"/api/projects/{project['id']}/stop", json={}, headers=headers,
        ).status_code == 202

        assert client.post(
            f"/api/projects/{project['id']}/pause", json={}, headers=headers,
        ).status_code == 409
        assert client.post(
            f"/api/projects/{project['id']}/resume", json={}, headers=headers,
        ).status_code == 409
        assert _broker_lifecycle(client, project, "pause").status_code == 409
        assert _broker_lifecycle(client, project, "resume").status_code == 409
        assert not any(control[0] in {"pause", "resume"} for control in runtime.controls)


def test_deadline_does_not_claim_terminal_for_unresolved_raw_process(tmp_path: Path):
    class RefusingDeadlineRuntime(FakeRuntime):
        def __init__(self, root):
            super().__init__(root)
            self.deadline_attempted = threading.Event()

        def enforce_deadline(self, runtime_name):
            self.deadline_attempted.set()
            self.statuses[runtime_name][0].update({
                "alive": False, "raw_alive": True,
                "process_identity": "mismatch", "state": "stale",
            })
            return {"workers": [{"worker": "high", "result": "identity-mismatch"}]}

    runtime = RefusingDeadlineRuntime(tmp_path / "projects")
    settings = AppSettings(
        database_path=tmp_path / "console.sqlite3",
        password_hash=hash_password("correct horse battery staple"),
        cookie_secure=True,
        allowed_origins={"https://testserver"},
        lifecycle_hmac_secret=_LIFECYCLE_SECRET,
        deadline_poll_seconds=0.05,
    )
    app = create_app(settings=settings, runtime=runtime)
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client)
        headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        project = client.post(
            "/api/projects", json={"name": "A", "problem": "alpha"}, headers=headers,
        ).json()
        runtime.assign_all(project["runtime_name"])
        started = client.post(
            f"/api/projects/{project['id']}/runs",
            json={"duration_seconds": 1}, headers=headers,
        )
        assert _broker_start(client, project).status_code == 200

        assert runtime.deadline_attempted.wait(timeout=2.5)
        run = client.get(
            f"/api/projects/{project['id']}/runs/{started.json()['run_id']}"
        ).json()
        assert run["status"] == "stopping"
        assert run["outcome"].startswith("deadline_force_failed:")
        assert runtime.statuses[project["runtime_name"]][0]["raw_alive"] is True


def test_deadline_supervisor_is_not_blocked_by_main_agent_turn(tmp_path: Path):
    class BlockingMain:
        backend = "codex"
        started = threading.Event()
        release = threading.Event()

        def send(self, **kwargs):
            self.started.set()
            assert self.release.wait(timeout=5)
            return {
                "session_id": "sid-blocking", "reply": "done", "status": "completed",
                "seconds": 0.1, "read_status": "unknown", "attempts": 1,
            }

    class DeadlineRuntime(FakeRuntime):
        def __init__(self, root):
            super().__init__(root)
            self.deadline_enforced = threading.Event()

        def enforce_deadline(self, runtime_name):
            self.deadline_enforced.set()
            self.statuses[runtime_name] = [
                {**worker, "alive": False, "raw_alive": False, "state": "terminated"}
                for worker in self.statuses[runtime_name]
            ]
            return {"workers": [
                {"worker": worker["worker"], "result": "killed"}
                for worker in self.statuses[runtime_name]
            ]}

    runtime = DeadlineRuntime(tmp_path / "projects")
    main = BlockingMain()
    settings = AppSettings(
        database_path=tmp_path / "console.sqlite3",
        password_hash=hash_password("correct horse battery staple"),
        cookie_secure=True, allowed_origins={"https://testserver"},
        lifecycle_hmac_secret=_LIFECYCLE_SECRET, deadline_poll_seconds=0.05,
    )
    app = create_app(settings=settings, runtime=runtime, main_agent=main)
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client)
        headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        project = client.post(
            "/api/projects", json={"name": "A", "problem": "alpha"}, headers=headers,
        ).json()
        runtime.assign_all(project["runtime_name"])
        assert client.post(
            f"/api/projects/{project['id']}/runs",
            json={"duration_seconds": 1}, headers=headers,
        ).status_code == 202
        assert _broker_start(client, project).status_code == 200
        response = {}
        thread = threading.Thread(target=lambda: response.setdefault(
            "message", client.post(
                f"/api/projects/{project['id']}/messages",
                json={"text": "monitor", "attachment_ids": []}, headers=headers,
            )
        ))
        thread.start()
        try:
            assert main.started.wait(timeout=2)
            assert runtime.deadline_enforced.wait(timeout=2.5)
        finally:
            main.release.set()
            thread.join(timeout=5)
        assert response["message"].status_code == 201


def test_broker_scopes_status_and_assignment_without_shared_python_access(tmp_path: Path):
    app, runtime = _app(tmp_path)
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client)
        headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        project = client.post(
            "/api/projects", json={"name": "A", "problem": "alpha"}, headers=headers,
        ).json()
        app.state.console_store.confirm_initial_direction(project["id"], time.time())

        assigned = _broker_lifecycle(
            client, project, "assign", worker="high", task="prove the scoped lemma",
        )
        assert assigned.status_code == 200
        assert assigned.json()["status"] == "assigned"
        status = _broker_lifecycle(client, project, "status")
        assert status.status_code == 200
        worker = status.json()["workers"][0]
        assert worker["worker"] == "high"
        assert worker["assigned"] is True
        assert worker["task"] == "prove the scoped lemma"
