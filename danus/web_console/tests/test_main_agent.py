"""Direct contract tests for the project-scoped Main Agent adapter."""
from __future__ import annotations

import json
import shutil
import subprocess
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


def test_codex_default_falls_back_to_installed_cli_when_repo_wrapper_unprovisioned(monkeypatch):
    from danus import codex

    wrapper = Path(__file__).resolve().parents[3] / "bin" / "codex"
    monkeypatch.delenv("DANUS_CODEX_BIN", raising=False)
    monkeypatch.setattr(codex, "resolve_bin", lambda: str(wrapper))
    monkeypatch.setattr(shutil, "which", lambda name: "/system/bin/codex" if name == "codex" else None)

    assert MainAgentAdapter._resolve_codex() == "/system/bin/codex"


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
    assert config["mcpServers"]["danus"]["env"]["PYTHONPATH"] == str(Path(__file__).resolve().parents[3])
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
    assert "--sandbox" not in cmd
    assert 'approval_policy="never"' not in cmd
    assert str(tmp_path) in cmd
    mcp_config = next(str(x) for x in cmd if str(x).startswith("mcp_servers.danus="))
    assert "PYTHONPATH=" in mcp_config
    assert str(Path(__file__).resolve().parents[3]) in mcp_config


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


def test_codex_environment_passes_server_side_provider_credentials(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "redacted-test-key")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://example.invalid/v1")

    env = MainAgentAdapter(backend="codex", codex_bin="codex")._env(tmp_path)

    assert env["OPENAI_API_KEY"] == "redacted-test-key"
    assert env["OPENAI_BASE_URL"] == "https://example.invalid/v1"


def test_codex_environment_passes_only_explicit_danus_strategy_configuration(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DANUS_CONSULT_TRANSPORT", "gpt_pro")
    monkeypatch.setenv("DANUS_CONSULT_API_KEY", "strategy-key")
    monkeypatch.setenv("DANUS_CONSULT_BASE_URL", "https://strategy.example/v1")
    monkeypatch.setenv("DANUS_CONSULT_MODEL", "gpt-5.6-luna")
    monkeypatch.setenv("UNRELATED_HOST_SECRET", "must-not-leak")

    env = MainAgentAdapter(backend="codex", codex_bin="codex")._env(tmp_path)

    assert env["DANUS_CONSULT_TRANSPORT"] == "gpt_pro"
    assert env["DANUS_CONSULT_API_KEY"] == "strategy-key"
    assert env["DANUS_CONSULT_BASE_URL"] == "https://strategy.example/v1"
    assert env["DANUS_CONSULT_MODEL"] == "gpt-5.6-luna"
    assert "UNRELATED_HOST_SECRET" not in env


def test_main_agent_prompt_honors_strategy_off_as_server_policy(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DANUS_CONSULT_TRANSPORT", "off")

    prompt = MainAgentAdapter(backend="codex", codex_bin="codex")._prompt(**{
        "message": "initialize",
        "manifest": [],
        "project_state": {"project_id": "p"},
        "attachments": [],
    })

    assert "strategy consult is OFF" in prompt
    assert "Do not invoke `consult`" in prompt
    assert "record the elaboration and master_guidance" in prompt


def test_main_agent_prompt_never_hardcodes_strategy_model_when_enabled(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DANUS_CONSULT_TRANSPORT", "gpt_pro")
    monkeypatch.setenv("DANUS_CONSULT_MODEL", "deployment-model")

    prompt = MainAgentAdapter(backend="codex", codex_bin="codex")._prompt(**{
        "message": "initialize",
        "manifest": [],
        "project_state": {"project_id": "p"},
        "attachments": [],
    })

    assert "strategy consult transport is gpt_pro" in prompt
    assert "Use the server-configured transport and model" in prompt


def test_codex_environment_imports_danus_outside_repo(tmp_path: Path):
    env = MainAgentAdapter(backend="codex", codex_bin="codex")._env(tmp_path)

    result = subprocess.run(
        [env["DANUS_PY"], "-c", "import danus"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_codex_allows_cli_configured_model_when_server_does_not_set_one(tmp_path: Path, monkeypatch):
    calls = []
    monkeypatch.delenv("DANUS_CODEX_MODEL", raising=False)
    monkeypatch.delenv("CODEX_API_MODEL", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("CODEX_API_BASE_URL", raising=False)
    monkeypatch.delenv("DANUS_CODEX_API_KEY", raising=False)

    def runner(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout=json.dumps({"type": "session_meta", "payload": {"session_id": "sid-1"}}) + "\n" + json.dumps({"type": "event_msg", "payload": {"type": "agent_message", "message": "ok"}}), stderr="")

    MainAgentAdapter(backend="codex", runner=runner, codex_bin="codex").send(**_args(tmp_path))
    assert "--model" not in calls[0]


def test_codex_builds_direct_provider_from_server_base_url_and_key(tmp_path: Path, monkeypatch):
    calls = []
    monkeypatch.setenv("OPENAI_API_KEY", "redacted-test-key")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://provider.example/v1")

    def runner(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout=json.dumps({"type": "session_meta", "payload": {"session_id": "sid-1"}}) + "\n" + json.dumps({"type": "event_msg", "payload": {"type": "agent_message", "message": "ok"}}), stderr="")

    MainAgentAdapter(backend="codex", runner=runner, codex_bin="codex").send(**_args(tmp_path))
    command = calls[0]
    assert 'model_provider="danus_web"' in command
    assert command[command.index("--model") + 1] == "gpt-5.5"
    assert any('model_providers.danus_web={' in str(value) and 'base_url="https://provider.example/v1"' in str(value) and 'env_key="OPENAI_API_KEY"' in str(value) for value in command)
    assert not any("ahproxy" in str(value) for value in command)


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


def test_codex_parser_accepts_nested_assistant_content():
    stream = "\n".join([
        json.dumps({"type": "thread.started", "thread_id": "sid-nested"}),
        json.dumps({"type": "item.completed", "item": {
            "type": "message", "role": "assistant",
            "content": [{"type": "output_text", "text": "visible "}, {"text": "reply"}],
        }}),
    ])
    assert MainAgentAdapter._parse_codex(stream) == ("sid-nested", "visible reply")


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
    assert "--sandbox" not in cmd
    assert 'approval_policy="never"' not in cmd
    assert "--config" in cmd and any(str(x).startswith("mcp_servers.danus=") for x in cmd)
    assert cmd[-2:] == ["sid-1", "-"]
