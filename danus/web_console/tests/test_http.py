"""Authenticated Web Console HTTP seam tests for the first vertical slice."""
from __future__ import annotations

import time
from pathlib import Path

from starlette.testclient import TestClient

from danus.web_console.app import AppSettings, create_app
from danus.web_console.security import hash_password


class FakeRuntime:
    def __init__(self, root: Path):
        self.root = root
        self.created = []
        self.started = []
        self.stopped = []
        self.statuses = {}
        self.deadlines = {}
        self.cleared_deadlines = []

    def project_context_dir(self, runtime_name):
        project = self.root / runtime_name
        project.mkdir(parents=True, exist_ok=True)
        return project

    def clear_deadline(self, runtime_name):
        self.cleared_deadlines.append(runtime_name)

    def write_deadline(self, runtime_name, deadline):
        self.deadlines[runtime_name] = deadline

    def create_project(self, runtime_name, problem, roles, model=None):
        self.created.append((runtime_name, problem, roles, model))
        project = self.root / runtime_name
        project.mkdir(parents=True, exist_ok=True)
        (project / "PROBLEM.md").write_text(problem + "\n", encoding="utf-8")
        self.statuses[runtime_name] = []
        return {"runtime_name": runtime_name, "project_dir": str(project), "workers": []}

    def start_project(self, runtime_name):
        self.started.append(runtime_name)
        self.statuses[runtime_name] = [{"worker": "high", "alive": True, "state": "running", "round": 1}]
        return {"workers": self.statuses[runtime_name]}

    def stop_project(self, runtime_name):
        self.stopped.append(runtime_name)
        self.statuses[runtime_name] = [{"worker": "high", "alive": False, "state": "stopped", "round": 1}]
        return {"workers": self.statuses[runtime_name]}

    def status_project(self, runtime_name):
        return {"workers": self.statuses.get(runtime_name, [])}

    def logs_projection(self, runtime_name, worker=None, tail=200):
        return {"entries": [{"worker": worker or "high", "name": "loop.log", "lines": ["status"]}]}

    def fact_graph_projection(self, runtime_name):
        return {"nodes": [], "edges": [], "max_depth": 0}

    def reports_projection(self, runtime_name):
        return {"files": []}

    def outputs_projection(self, runtime_name):
        return {"files": []}


def _app(tmp_path: Path):
    runtime = FakeRuntime(tmp_path / "projects")
    settings = AppSettings(
        database_path=tmp_path / "console.sqlite3",
        password_hash=hash_password("correct horse battery staple"),
        cookie_secure=True,
        allowed_origins={"https://testserver"},
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
        assert client.get("/api/auth/session").json()["authenticated"] is True

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
        start = client.post(
            f"/api/projects/{a['id']}/runs", json={"duration_seconds": 43200},
            headers={"X-CSRF-Token": csrf, "Origin": "https://testserver"},
        )
        assert start.status_code == 202
        run = start.json()
        assert run["status"] == "start_requested"
        assert 43190 <= run["deadline"] - time.time() <= 43210
        assert runtime.started == [a["runtime_name"]]
        assert runtime.started != [b["runtime_name"]]

        stopped = client.post(
            f"/api/projects/{a['id']}/stop", json={},
            headers={"X-CSRF-Token": csrf, "Origin": "https://testserver"},
        )
        assert stopped.status_code == 202
        assert stopped.json()["status"] == "stop_requested"
        assert runtime.stopped == [a["runtime_name"]]
        assert runtime.stopped != [b["runtime_name"]]
        assert client.get(f"/api/projects/{b['id']}/runtime").json()["workers"] == []


def test_run_lookup_is_project_scoped(tmp_path: Path):
    app, runtime = _app(tmp_path)
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client)
        headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        a = client.post("/api/projects", json={"name": "A", "problem": "alpha", "roles": "high:1"}, headers=headers).json()
        b = client.post("/api/projects", json={"name": "B", "problem": "beta", "roles": "high:1"}, headers=headers).json()
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

    runtime = FailingRuntime(tmp_path / "projects")
    settings = AppSettings(database_path=tmp_path / "console.sqlite3", password_hash=hash_password("correct horse battery staple"), cookie_secure=True, allowed_origins={"https://testserver"})
    app = create_app(settings=settings, runtime=runtime)
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client)
        headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        project = client.post("/api/projects", json={"name": "A", "problem": "alpha"}, headers=headers).json()
        response = client.post(f"/api/projects/{project['id']}/runs", json={"duration_seconds": 60}, headers=headers)
        assert response.status_code == 502
        assert response.json() == {"detail": "project run could not be started"}
        import sqlite3
        with sqlite3.connect(tmp_path / "console.sqlite3") as db:
            assert db.execute("SELECT status FROM runs").fetchone()[0] == "failed"
        assert runtime.cleared_deadlines == ["A"]


def test_real_runtime_adapter_keeps_two_project_contexts_isolated(tmp_path: Path):
    from danus.web_console.runtime import DanusRuntimeAdapter
    from danus.orchestration import cli
    original_spawn = cli.spawn_loop
    cli.spawn_loop = lambda worker_dir: 999_999_999
    try:
        adapter = DanusRuntimeAdapter(tmp_path / "agents")
        a = adapter.create_project("A", "alpha problem", "high:1")
        b = adapter.create_project("B", "beta problem", "high:1")
        assert (tmp_path / "agents" / "A" / "PROBLEM.md").read_text() == "alpha problem\n"
        assert (tmp_path / "agents" / "B" / "PROBLEM.md").read_text() == "beta problem\n"
        assert set(project["project"] for project in adapter.list_projects()) == {"A", "B"}
        assert a["project_dir"] != b["project_dir"]
        assert adapter.status_project("A")["workers"][0]["worker"] == "high"
        assert adapter.status_project("B")["workers"][0]["worker"] == "high"
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
    settings = AppSettings(database_path=tmp_path / "console.sqlite3", password_hash=hash_password("correct horse battery staple"), cookie_secure=True, allowed_origins={"https://testserver"})
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
        foreign = client.post(f"/api/projects/{b['id']}/messages", json={"text": "no", "attachment_ids": [uploaded["id"]]}, headers=headers)
        assert foreign.status_code == 404
        assert len(client.get(f"/api/projects/{b['id']}/messages").json()) == 0


def test_read_only_projections_are_authenticated_and_project_scoped(tmp_path: Path):
    app, runtime = _app(tmp_path)
    with TestClient(app, base_url="https://testserver") as client:
        csrf = _login(client); headers = {"X-CSRF-Token": csrf, "Origin": "https://testserver"}
        project = client.post("/api/projects", json={"name": "A", "problem": "alpha"}, headers=headers).json()
        pid = project["id"]
        for endpoint in ("workers", "logs", "fact-graph", "reports", "outputs"):
            assert client.get(f"/api/projects/{pid}/{endpoint}").status_code == 200
            assert client.get(f"/api/projects/foreign/{endpoint}").status_code == 404
        assert client.get("/api/projects/foreign/logs").status_code == 404
