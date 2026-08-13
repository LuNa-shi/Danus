"""Direct contract tests for the project-scoped Main Agent adapter."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from danus.web_console.main_agent import MainAgentAdapter, MainAgentError


def _claude_result(*, result="ok", session_id="123e4567-e89b-12d3-a456-426614174000", is_error=False, subtype="success"):
    return json.dumps({
        "type": "result", "subtype": subtype, "is_error": is_error,
        "result": result, "session_id": session_id, "duration_ms": 120,
    })


def _args(tmp_path: Path):
    return {
        "context_dir": tmp_path, "session_id": None, "message": "hello",
        "manifest": [], "project_state": {"project_id": "p"}, "attachments": [],
    }

def test_default_backend_is_codex():
    assert MainAgentAdapter().backend == "codex"


def test_claude_success_uses_inline_scoped_mcp_and_persists_no_project_config(tmp_path: Path):
    calls = []
    def runner(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(returncode=0, stdout=_claude_result(), stderr="")

    adapter = MainAgentAdapter(backend="claude", runner=runner, claude_bin="claude")
    result = adapter.send(**_args(tmp_path))

    assert result["reply"] == "ok"
    assert result["session_id"] == "123e4567-e89b-12d3-a456-426614174000"
    cmd, kwargs = calls[0]
    assert "--mcp-config" in cmd
    config = json.loads(cmd[cmd.index("--mcp-config") + 1])
    assert config["mcpServers"]["danus"]["env"]["DANUS_ROLE"] == "main"
    assert config["mcpServers"]["danus"]["env"]["DANUS_PROJECT_SCOPE"] == tmp_path.name
    assert "--system-prompt-file" in cmd
    assert "--allowed-tools" in cmd
    assert "Bash" not in cmd
    assert kwargs["cwd"] == str(tmp_path)
    assert not (tmp_path / ".danus-web-mcp.json").exists()


@pytest.mark.parametrize("returncode", [0, 1])
def test_claude_error_result_is_not_success(tmp_path: Path, returncode: int):
    def runner(cmd, **kwargs):
        return SimpleNamespace(returncode=returncode, stdout=_claude_result(result="Invalid API key", is_error=True), stderr="")

    adapter = MainAgentAdapter(backend="claude", runner=runner)
    with pytest.raises(MainAgentError, match="failed|no reply|successful"):
        adapter.send(**_args(tmp_path))


def test_codex_new_command_is_project_scoped_and_readable(tmp_path: Path):
    calls = []
    def runner(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout=json.dumps({"type": "session_meta", "payload": {"session_id": "sid-1"}}) + "\n" + json.dumps({"type": "event_msg", "payload": {"type": "agent_message", "message": "ok"}}), stderr="")
    adapter = MainAgentAdapter(backend="codex", runner=runner, codex_bin="codex")
    adapter.send(**_args(tmp_path))
    cmd = calls[0]
    assert "--approve-for-me" in cmd
    assert "--dangerously-bypass-approvals-and-sandbox" not in cmd
    assert str(tmp_path) in cmd
    assert any(str(x).startswith("mcp_servers.danus=") for x in cmd)


def test_codex_default_effort_honors_server_environment(tmp_path: Path, monkeypatch):
    calls = []
    monkeypatch.setenv("DANUS_CODEX_EFFORT", "xhigh")
    def runner(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(returncode=0, stdout=json.dumps({"type": "session_meta", "payload": {"session_id": "sid-1"}}) + "\n" + json.dumps({"type": "event_msg", "payload": {"type": "agent_message", "message": "ok"}}), stderr="")

    MainAgentAdapter(backend="codex", runner=runner, codex_bin="codex").send(**_args(tmp_path))
    cmd, kwargs = calls[0]
    assert 'model_reasoning_effort="xhigh"' in cmd
    assert kwargs["env"]["DANUS_PY"]
    assert kwargs["env"]["DANUS_PROJECT_SCOPE"] == tmp_path.name


def test_codex_failure_preserves_original_stderr(tmp_path: Path):
    error = "Not inside a trusted directory and --skip-git-repo-check was not specified."
    def runner(cmd, **kwargs):
        return SimpleNamespace(returncode=1, stdout="", stderr=error)

    adapter = MainAgentAdapter(backend="codex", runner=runner, codex_bin="codex")
    with pytest.raises(MainAgentError, match="trusted directory"):
        adapter.send(**_args(tmp_path))


def test_codex_parser_accepts_current_event_message_shape():
    stream = "\n".join([
        json.dumps({"type": "session_meta", "payload": {"session_id": "sid-1"}}),
        json.dumps({"type": "event_msg", "payload": {"type": "agent_message", "message": "first"}}),
        json.dumps({"type": "event_msg", "payload": {"type": "agent_message", "message": "last"}}),
        json.dumps({"type": "event_msg", "payload": {"type": "task_complete", "last_agent_message": "last"}}),
    ])
    assert MainAgentAdapter._parse_codex(stream) == ("sid-1", "last")


def test_codex_resume_keeps_resume_options_before_session(tmp_path: Path):
    calls = []
    def runner(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout=json.dumps({"type": "thread.started", "thread_id": "sid-2"}) + "\n" + json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": "ok"}}), stderr="")

    adapter = MainAgentAdapter(backend="codex", runner=runner, codex_bin="codex")
    adapter.send(**(_args(tmp_path) | {"session_id": "sid-1"}))
    cmd = calls[0]
    assert cmd[1] == "exec" and "resume" in cmd
    assert cmd.index("resume") < cmd.index("sid-1")
    assert cmd.index("-C") < cmd.index("resume")
    assert "--approve-for-me" in cmd
    assert "--config" in cmd and any(str(x).startswith("mcp_servers.danus=") for x in cmd)
    assert cmd[-2:] == ["sid-1", "-"]
