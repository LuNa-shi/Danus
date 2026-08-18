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
    requests = []

    def open_request(request, *, timeout):
        payload = json.loads(request.data)
        requests.append(request)
        return _Response(
            {"status": "stop_requested"}
            if payload["action"] == "stop"
            else {"workers": [{"worker": "high", "alive": True}]}
        )

    monkeypatch.setattr(agent_cli.urllib.request, "urlopen", open_request)

    assert agent_cli.main(["stop"]) == 0
    assert json.loads(requests[0].data) == {"action": "stop"}
    assert json.loads(capsys.readouterr().out) == {"status": "stop_requested"}

    assert agent_cli.main(["status"]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "workers": [{"worker": "high", "alive": True}],
    }
    assert json.loads(requests[1].data) == {"action": "status"}
    assert len(requests) == 2


def test_pause_and_resume_post_worker_target_to_host_broker(
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
    requests = []

    def open_request(request, *, timeout):
        requests.append(json.loads(request.data))
        return _Response({"status": "accepted"})

    monkeypatch.setattr(agent_cli.urllib.request, "urlopen", open_request)

    assert agent_cli.main(["pause", "high"]) == 0
    assert json.loads(capsys.readouterr().out) == {"status": "accepted"}
    assert agent_cli.main(["resume", "high"]) == 0
    assert json.loads(capsys.readouterr().out) == {"status": "accepted"}
    assert requests == [
        {"action": "pause", "worker": "high"},
        {"action": "resume", "worker": "high"},
    ]


def test_assign_posts_task_to_project_capability_broker(tmp_path: Path, monkeypatch, capsys):
    root = tmp_path / "projects"
    project = root / "A"
    project.mkdir(parents=True)
    monkeypatch.setenv("DANUS_PROJECT_SCOPE", "A")
    monkeypatch.setenv("DANUS_AGENTS_ROOT", str(root))
    monkeypatch.setenv("DANUS_PROJECT_DIR", str(project))
    monkeypatch.setenv("DANUS_WEB_LIFECYCLE_URL", "http://127.0.0.1/lifecycle/A")
    monkeypatch.setenv("DANUS_WEB_LIFECYCLE_TOKEN", "project-capability")
    requests = []

    def open_request(request, *, timeout):
        requests.append(json.loads(request.data))
        return _Response({"status": "assigned", "worker": "high"})

    monkeypatch.setattr(agent_cli.urllib.request, "urlopen", open_request)
    assert agent_cli.main(["assign", "high", "--task", "prove the lemma"]) == 0
    assert requests == [{"action": "assign", "worker": "high", "task": "prove the lemma"}]
    assert json.loads(capsys.readouterr().out)["status"] == "assigned"


def test_artifact_commands_post_explicit_operator_forks(tmp_path: Path, monkeypatch, capsys):
    root = tmp_path / "projects"; project = root / "A"; project.mkdir(parents=True)
    monkeypatch.setenv("DANUS_PROJECT_SCOPE", "A"); monkeypatch.setenv("DANUS_AGENTS_ROOT", str(root)); monkeypatch.setenv("DANUS_PROJECT_DIR", str(project))
    monkeypatch.setenv("DANUS_WEB_LIFECYCLE_URL", "http://127.0.0.1/lifecycle/A"); monkeypatch.setenv("DANUS_WEB_LIFECYCLE_TOKEN", "token")
    requests = []
    def open_request(request, *, timeout):
        requests.append(json.loads(request.data)); return _Response({"status": "ok"})
    monkeypatch.setattr(agent_cli.urllib.request, "urlopen", open_request)
    assert agent_cli.main(["finalize", "fact-1", "--paper-id", "paper-1", "--operator-confirmed"]) == 0
    assert agent_cli.main(["human-summary", "--language", "zh", "--operator-confirmed"]) == 0
    assert agent_cli.main(["write-paper", "--paper-id", "paper-1", "--fact-id", "fact-1", "--instructions", "brief", "--stop-workers", "--operator-confirmed"]) == 0
    capsys.readouterr()
    assert requests == [
        {"action": "finalize", "fact_ids": ["fact-1"], "paper_id": "paper-1", "operator_confirmed": True},
        {"action": "human-summary", "language": "zh", "operator_confirmed": True},
        {"action": "write-paper", "paper_id": "paper-1", "fact_ids": ["fact-1"], "instructions": "brief", "stop_workers": True, "operator_confirmed": True},
    ]
