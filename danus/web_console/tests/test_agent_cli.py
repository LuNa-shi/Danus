"""Contract tests for the project-scoped Main Agent lifecycle CLI."""
from __future__ import annotations

import json
from pathlib import Path

from danus.web_console import agent_cli


class _Response:
    def __init__(self, payload: dict):
        self._payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self._payload


def test_start_posts_scoped_intent_to_host_broker_without_spawning_locally(
    tmp_path: Path, monkeypatch, capsys,
):
    root = tmp_path / "projects"
    project = root / "A"
    project.mkdir(parents=True)
    monkeypatch.setenv("DANUS_PROJECT_SCOPE", "A")
    monkeypatch.setenv("DANUS_AGENTS_ROOT", str(root))
    monkeypatch.setenv("DANUS_PROJECT_DIR", str(project))
    monkeypatch.setenv(
        "DANUS_WEB_LIFECYCLE_URL",
        "http://127.0.0.1:8080/internal/api/projects/project-a/lifecycle",
    )
    monkeypatch.setenv("DANUS_WEB_LIFECYCLE_TOKEN", "project-capability")
    monkeypatch.setattr(
        agent_cli.cli, "do_start",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("local start called")),
    )
    requests = []

    def open_request(request, *, timeout):
        requests.append((request, timeout))
        return _Response({"status": "running", "workers": ["high"]})

    monkeypatch.setattr(agent_cli.urllib.request, "urlopen", open_request)

    assert agent_cli.main(["start"]) == 0

    request, timeout = requests[0]
    assert request.full_url.endswith("/internal/api/projects/project-a/lifecycle")
    assert request.get_method() == "POST"
    assert request.get_header("Authorization") == "Bearer project-capability"
    assert json.loads(request.data) == {"action": "start"}
    assert timeout == 30
    assert json.loads(capsys.readouterr().out) == {
        "status": "running", "workers": ["high"],
    }


def test_stop_posts_to_host_broker_while_status_remains_project_local(
    tmp_path: Path, monkeypatch, capsys,
):
    root = tmp_path / "projects"
    project = root / "A"
    project.mkdir(parents=True)
    monkeypatch.setenv("DANUS_PROJECT_SCOPE", "A")
    monkeypatch.setenv("DANUS_AGENTS_ROOT", str(root))
    monkeypatch.setenv("DANUS_PROJECT_DIR", str(project))
    monkeypatch.setenv("DANUS_WEB_LIFECYCLE_URL", "http://127.0.0.1/lifecycle/A")
    monkeypatch.setenv("DANUS_WEB_LIFECYCLE_TOKEN", "project-capability")
    monkeypatch.setattr(
        agent_cli.cli, "do_stop",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("local stop called")),
    )
    monkeypatch.setattr(
        agent_cli.cli, "do_status",
        lambda target, *, root: [{"worker": "high", "target": target, "root": str(root)}],
    )
    requests = []

    def open_request(request, *, timeout):
        requests.append(request)
        return _Response({"status": "stop_requested"})

    monkeypatch.setattr(agent_cli.urllib.request, "urlopen", open_request)

    assert agent_cli.main(["stop"]) == 0
    assert json.loads(requests[0].data) == {"action": "stop"}
    assert json.loads(capsys.readouterr().out) == {"status": "stop_requested"}

    assert agent_cli.main(["status"]) == 0
    assert json.loads(capsys.readouterr().out) == [{
        "worker": "high", "target": "A", "root": str(root.resolve()),
    }]
    assert len(requests) == 1
