"""Direct contract tests for the project-scoped Main Agent adapter."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
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


def _codex_success(*, session_id: str = "sid-1", message: str = "ok") -> str:
    return "\n".join([
        json.dumps({"type": "session_meta", "payload": {"session_id": session_id}}),
        json.dumps({"type": "event_msg", "payload": {"type": "agent_message", "message": message}}),
        json.dumps({"type": "event_msg", "payload": {"type": "task_complete", "last_agent_message": message}}),
    ])


def test_default_runner_streams_stdout_lines_before_process_completion(tmp_path: Path):
    lines = []
    result = MainAgentAdapter._default_runner(
        [sys.executable, "-c", "print('one', flush=True); print('two', flush=True)"],
        input="", cwd=str(tmp_path), env=dict(os.environ), timeout=5,
        on_stdout_line=lines.append,
    )

    assert result.returncode == 0
    assert lines == ["one", "two"]
    assert result.stdout == "one\ntwo\n"


def test_default_runner_bounds_captured_stdout_and_stderr(tmp_path: Path):
    script = (
        "import sys; "
        "[(print('x'*200000), print('e'*20000, file=sys.stderr)) for _ in range(100)]"
    )
    result = MainAgentAdapter._default_runner(
        [sys.executable, "-c", script],
        input="", cwd=str(tmp_path), env=dict(os.environ), timeout=10,
        on_stdout_line=lambda _line: None,
    )

    assert result.returncode == 0
    assert "<CODEX_STDOUT_CAPTURE_TRUNCATED>" in result.stdout
    assert len(result.stdout) < 14 * 1024 * 1024
    assert len(result.stderr) <= 100 * 16384


@pytest.mark.skipif(os.name != "posix", reason="process-group signals are POSIX-only")
def test_default_runner_timeout_terminates_the_entire_process_group(tmp_path: Path):
    child_pid_file = tmp_path / "child.pid"
    child_code = "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"
    parent_code = (
        "import pathlib,subprocess,sys,time; "
        f"child=subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
        f"pathlib.Path({str(child_pid_file)!r}).write_text(str(child.pid)); "
        "print('started', flush=True); time.sleep(60)"
    )

    with pytest.raises(subprocess.TimeoutExpired):
        MainAgentAdapter._default_runner(
            [sys.executable, "-c", parent_code],
            input="", cwd=str(tmp_path), env=dict(os.environ), timeout=0.15,
            on_stdout_line=lambda _line: None,
        )

    child_pid = int(child_pid_file.read_text())
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        stat = Path(f"/proc/{child_pid}/stat")
        try:
            process_disappeared = (
                not stat.exists() or stat.read_text().split()[2] == "Z"
            )
        except (FileNotFoundError, ProcessLookupError):
            process_disappeared = True
        if process_disappeared:
            break
        time.sleep(0.02)
    else:
        pytest.fail(f"timed-out subprocess child {child_pid} is still running")


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
        return SimpleNamespace(returncode=0, stdout=_codex_success(), stderr="")
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
        return SimpleNamespace(returncode=0, stdout=_codex_success(), stderr="")

    MainAgentAdapter(backend="codex", runner=runner, codex_bin="codex").send(**_args(tmp_path))
    cmd, kwargs = calls[0]
    assert 'model_reasoning_effort="xhigh"' in cmd
    assert "DANUS_PY" not in kwargs["env"]
    assert kwargs["env"]["DANUS_PROJECT_SCOPE"] == tmp_path.name


def test_codex_environment_passes_server_side_provider_credentials(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "redacted-test-key")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://example.invalid/v1")

    env = MainAgentAdapter(backend="codex", codex_bin="codex")._env(tmp_path)

    assert env["OPENAI_API_KEY"] == "redacted-test-key"
    assert env["OPENAI_BASE_URL"] == "https://example.invalid/v1"


def test_main_agent_environment_receives_only_project_scoped_lifecycle_capability(
    tmp_path: Path, monkeypatch,
):
    captured = {}
    monkeypatch.setenv("DANUS_WEB_LIFECYCLE_HMAC_SECRET", "must-not-leak")
    monkeypatch.setenv("DANUS_WEB_LIFECYCLE_URL", "http://127.0.0.1/other-project")
    monkeypatch.setenv("DANUS_WEB_LIFECYCLE_TOKEN", "other-project-token")

    def runner(_cmd, **kwargs):
        captured.update(kwargs["env"])
        return SimpleNamespace(returncode=0, stdout=_codex_success(), stderr="")

    adapter = MainAgentAdapter(backend="codex", runner=runner, codex_bin="codex")
    adapter.send(
        **_args(tmp_path),
        lifecycle_url=(
            "http://127.0.0.1:8080/internal/api/projects/project-a/lifecycle"
        ),
        lifecycle_token="project-a-capability",
    )

    assert captured["DANUS_WEB_LIFECYCLE_URL"].endswith(
        "/internal/api/projects/project-a/lifecycle"
    )
    assert captured["DANUS_WEB_LIFECYCLE_TOKEN"] == "project-a-capability"
    assert "other-project" not in json.dumps(captured)
    assert "DANUS_WEB_LIFECYCLE_HMAC_SECRET" not in captured


def test_artifact_confirmation_is_turn_local_and_redacted_from_prompt_and_events(
    tmp_path: Path, monkeypatch,
):
    token = "artifact-confirmation-secret-value"
    monkeypatch.setenv("DANUS_WEB_ARTIFACT_CONFIRMATION_TOKEN", "inherited-must-not-leak")
    calls = []
    events = []

    def runner(_cmd, **kwargs):
        calls.append(kwargs)
        return SimpleNamespace(
            returncode=0, stdout=_codex_success(message=f"tool accidentally echoed {token}"),
            stderr="",
        )

    adapter = MainAgentAdapter(backend="codex", runner=runner, codex_bin="codex")
    clean = adapter._env(tmp_path)
    assert "DANUS_WEB_ARTIFACT_CONFIRMATION_TOKEN" not in clean

    result = adapter.send(
        **_args(tmp_path), artifact_confirmation_token=token,
        on_progress=events.append,
    )

    assert calls[0]["env"]["DANUS_WEB_ARTIFACT_CONFIRMATION_TOKEN"] == token
    assert token not in calls[0]["input"]
    assert token not in json.dumps(events)
    assert token not in json.dumps(result)
    assert "<REDACTED>" in result["reply"]


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
    assert "offline-main-agent" in prompt
    assert "must not describe it as consult-derived" in prompt


def test_main_agent_prompt_requires_consult_derived_guidance_and_operator_confirmation(monkeypatch):
    monkeypatch.setenv("DANUS_CONSULT_TRANSPORT", "gpt_pro")
    prompt = MainAgentAdapter(backend="codex", codex_bin="codex")._prompt(**{
        "message": "initialize",
        "manifest": [],
        "project_state": {"project_id": "p"},
        "attachments": [],
    })
    assert "strategy consult transport is gpt_pro" in prompt
    assert "consult-derived guidance" in prompt
    assert "wait for operator confirmation before assigning Workers" in prompt


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


def test_codex_environment_exposes_only_the_self_bootstrapping_broker(tmp_path: Path):
    env = MainAgentAdapter(backend="codex", codex_bin="codex")._env(tmp_path)

    result = subprocess.run(
        [env["DANUS_WEB_AGENT_BIN"], "--help"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )

    assert "DANUS_PY" not in env
    assert "PYTHONPATH" not in env
    assert result.returncode == 0, result.stderr
    assert "danus-web-agent" in result.stdout
    wrapper_text = Path(env["DANUS_WEB_AGENT_BIN"]).read_text(encoding="utf-8")
    assert '--header "Authorization: Bearer $token"' not in wrapper_text
    assert "curl --config -" in wrapper_text


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
        return SimpleNamespace(returncode=0, stdout=_codex_success(), stderr="")

    MainAgentAdapter(backend="codex", runner=runner, codex_bin="codex").send(**_args(tmp_path))
    assert "--model" not in calls[0]


def test_codex_builds_direct_provider_from_server_base_url_and_key(tmp_path: Path, monkeypatch):
    calls = []
    monkeypatch.setenv("OPENAI_API_KEY", "redacted-test-key")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://provider.example/v1")

    def runner(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout=_codex_success(), stderr="")

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


def test_codex_retries_transient_failure_by_resuming_the_same_thread(tmp_path: Path):
    calls = []
    progress = []
    overloaded = "\n".join([
        json.dumps({"type": "thread.started", "thread_id": "sid-retry"}),
        json.dumps({"type": "event_msg", "payload": {
            "type": "task_complete",
            "last_agent_message": None,
            "error": {
                "message": "Selected model is at capacity. Please try a different model.",
                "codex_error_info": "server_overloaded",
            },
        }}),
    ])
    completed = "\n".join([
        json.dumps({"type": "thread.started", "thread_id": "sid-retry"}),
        json.dumps({"type": "event_msg", "payload": {"type": "agent_message", "message": "completed after retry"}}),
        json.dumps({"type": "event_msg", "payload": {"type": "task_complete", "last_agent_message": "completed after retry"}}),
    ])

    def runner(cmd, **kwargs):
        calls.append((cmd, kwargs))
        if len(calls) == 1:
            return SimpleNamespace(returncode=1, stdout=overloaded, stderr="")
        return SimpleNamespace(returncode=0, stdout=completed, stderr="")

    adapter = MainAgentAdapter(
        backend="codex",
        runner=runner,
        codex_bin="codex",
        max_attempts=2,
        retry_base_seconds=0,
        sleeper=lambda _: None,
    )
    result = adapter.send(**_args(tmp_path), on_progress=progress.append)

    assert result["reply"] == "completed after retry"
    assert result["session_id"] == "sid-retry"
    assert result["attempts"] == 2
    assert len(calls) == 2
    assert calls[1][0][-3:] == ["resume", "sid-retry", "-"]
    assert "Continue the interrupted Main Agent turn" in calls[1][1]["input"]
    assert progress[0] == {"type": "process.started", "status": "active", "detail": "Main Agent Process activated"}
    assert progress[1:] == [{
        "type": "turn.retry",
        "status": "retrying",
        "attempt": 2,
        "max_attempts": 2,
        "delay_seconds": 0,
        "error_code": "server_overloaded",
        "message": "Selected model is at capacity. Please try a different model.",
        "detail": "Selected model is at capacity. Please try a different model.",
        "session_id": "sid-retry",
    }]


def test_codex_does_not_replay_a_turn_after_tool_activity(tmp_path: Path):
    calls = []
    overloaded_after_tool = "\n".join([
        json.dumps({"type": "thread.started", "thread_id": "sid-side-effects"}),
        json.dumps({"type": "item.completed", "item": {
            "type": "command_execution", "command": "danus-web-agent assign high task",
        }}),
        json.dumps({"type": "event_msg", "payload": {
            "type": "task_complete",
            "last_agent_message": None,
            "error": {
                "message": "Selected model is at capacity. Please try a different model.",
                "codex_error_info": "server_overloaded",
            },
        }}),
    ])

    def runner(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=1, stdout=overloaded_after_tool, stderr="")

    adapter = MainAgentAdapter(
        backend="codex", runner=runner, codex_bin="codex",
        max_attempts=3, retry_base_seconds=0, sleeper=lambda _: None,
    )
    with pytest.raises(MainAgentError, match="Selected model is at capacity") as raised:
        adapter.send(**_args(tmp_path))

    assert len(calls) == 1
    assert raised.value.session_id == "sid-side-effects"
    assert raised.value.retryable is True
    assert raised.value.safe_to_retry is False
    assert raised.value.observed_tool_activity is True


def test_codex_requires_an_explicit_success_terminal_event(tmp_path: Path):
    stream = "\n".join([
        json.dumps({"type": "thread.started", "thread_id": "sid-truncated"}),
        json.dumps({"type": "event_msg", "payload": {"type": "agent_message", "message": "partial reply"}}),
    ])

    def runner(cmd, **kwargs):
        return SimpleNamespace(returncode=0, stdout=stream, stderr="")

    adapter = MainAgentAdapter(
        backend="codex", runner=runner, codex_bin="codex", max_attempts=1,
    )
    with pytest.raises(MainAgentError, match="terminal completion"):
        adapter.send(**_args(tmp_path))


def test_codex_terminal_error_overrides_partial_reply_even_without_message(tmp_path: Path):
    stream = "\n".join([
        json.dumps({"type": "thread.started", "thread_id": "sid-partial"}),
        json.dumps({"type": "event_msg", "payload": {"type": "agent_message", "message": "partial reply"}}),
        json.dumps({"type": "event_msg", "payload": {
            "type": "task_complete", "last_agent_message": "partial reply",
            "error": {"codex_error_info": "server_overloaded"},
        }}),
    ])

    def runner(cmd, **kwargs):
        return SimpleNamespace(returncode=0, stdout=stream, stderr="")

    adapter = MainAgentAdapter(
        backend="codex", runner=runner, codex_bin="codex",
        max_attempts=1, retry_base_seconds=0,
    )
    with pytest.raises(MainAgentError) as raised:
        adapter.send(**_args(tmp_path))

    assert raised.value.code == "server_overloaded"
    assert raised.value.session_id == "sid-partial"


def test_codex_response_completed_tool_output_blocks_automatic_retry(tmp_path: Path):
    calls = []
    stream = "\n".join([
        json.dumps({"type": "thread.started", "thread_id": "sid-envelope"}),
        json.dumps({"type": "response.completed", "response": {"output": [
            {"type": "function_call", "name": "exec_command", "arguments": "{}"},
        ]}}),
        json.dumps({"type": "event_msg", "payload": {
            "type": "task_complete", "last_agent_message": None,
            "error": {
                "message": "Selected model is at capacity.",
                "codex_error_info": "server_overloaded",
            },
        }}),
    ])

    def runner(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=1, stdout=stream, stderr="")

    adapter = MainAgentAdapter(
        backend="codex", runner=runner, codex_bin="codex",
        max_attempts=3, retry_base_seconds=0, sleeper=lambda _: None,
    )
    with pytest.raises(MainAgentError) as raised:
        adapter.send(**_args(tmp_path))

    assert len(calls) == 1
    assert raised.value.observed_tool_activity is True


def test_codex_timeout_preserves_session_and_tool_activity_from_partial_output(tmp_path: Path):
    stream = "\n".join([
        json.dumps({"type": "thread.started", "thread_id": "sid-timeout"}),
        json.dumps({"type": "item.completed", "item": {"type": "command_execution", "command": "status"}}),
    ])

    def runner(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=10, output=stream)

    adapter = MainAgentAdapter(backend="codex", runner=runner, codex_bin="codex")
    with pytest.raises(MainAgentError, match="timed out") as raised:
        adapter.send(**_args(tmp_path))

    assert raised.value.session_id == "sid-timeout"
    assert raised.value.code == "turn_timeout_exhausted"
    assert raised.value.retryable is False
    assert raised.value.safe_to_retry is False
    assert raised.value.observed_tool_activity is True


def test_codex_exhaustion_surfaces_structured_error_and_preserves_session(tmp_path: Path):
    calls = []
    progress = []
    overloaded = "\n".join([
        json.dumps({"type": "thread.started", "thread_id": "sid-overloaded"}),
        json.dumps({"type": "event_msg", "payload": {
            "type": "task_complete",
            "last_agent_message": None,
            "error": {
                "message": "Selected model is at capacity. api_key=retry-secret-value",
                "codex_error_info": "server_overloaded",
            },
        }}),
    ])

    def runner(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=1, stdout=overloaded, stderr="")

    adapter = MainAgentAdapter(
        backend="codex", runner=runner, codex_bin="codex",
        max_attempts=2, retry_base_seconds=0, sleeper=lambda _: None,
    )
    with pytest.raises(MainAgentError, match="Selected model is at capacity") as raised:
        adapter.send(**_args(tmp_path), on_progress=progress.append)

    assert len(calls) == 2
    assert calls[1][-3:] == ["resume", "sid-overloaded", "-"]
    assert raised.value.code == "server_overloaded"
    assert raised.value.session_id == "sid-overloaded"
    assert raised.value.retryable is True
    assert raised.value.safe_to_retry is True
    assert raised.value.attempts == 2
    assert "retry-secret-value" not in json.dumps(progress, ensure_ascii=False)
    assert "<REDACTED>" in json.dumps(progress, ensure_ascii=False)


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


@pytest.mark.parametrize("secret", [
    "curl -u alice:supersecret https://example.test",
    "curl -H 'Cookie: session=abc123xyz' https://example.test",
    "-----BEGIN PRIVATE KEY-----\nMIIBVwIBADANBgkqh\n-----END PRIVATE KEY-----",
    "postgresql://alice:supersecret@db.internal/app",
    "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz1234567890",
    "gl" + "pat-" + "abcdefghijklmnopqrstuvwxyz",
    "xo" + "xb-" + "123456789012-123456789012-abcdefghijklmnopqrstuvwx",
    "AI" + "zaSyDUMMYDUMMYDUMMYDUMMYDUMMYDUMMY",
    "h" + "f_" + "abcdefghijklmnopqrstuvwxyz123456",
    "np" + "m_" + "abcdefghijklmnopqrstuvwxyz123456",
    "AK" + "IAIOSFODNN7EXAMPLE",
    "ey" + "JhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature",
    '{"headers":{"X-Session":"abc123xyz"}}',
])
def test_main_agent_event_redaction_covers_common_credential_shapes(secret: str):
    rendered = MainAgentAdapter._safe_display_value(secret)

    assert secret not in rendered
    assert "supersecret" not in rendered
    assert "abc123xyz" not in rendered
    assert "MIIBVwIBADANBgkqh" not in rendered
    assert "<REDACTED" in rendered


def test_codex_tool_progress_summaries_never_include_command_arguments_or_file_content():
    command_events = MainAgentAdapter._codex_progress_events(json.dumps({
        "type": "item.started",
        "item": {"type": "command_execution", "command": "echo arbitrary-unclassified-secret"},
    }))
    file_events = MainAgentAdapter._codex_progress_events(json.dumps({
        "type": "item.completed",
        "item": {"type": "file_change", "changes": "arbitrary-unclassified-secret"},
    }))

    assert command_events[0]["detail"] == "命令：echo"
    assert file_events[0]["detail"] == "文件变更状态已更新（具体内容未展示）"
    assert "arbitrary-unclassified-secret" not in json.dumps(command_events + file_events, ensure_ascii=False)


def test_codex_redacts_credentials_from_the_final_reply(tmp_path: Path):
    stdout = _codex_success(message="api_key=arbitrary-unclassified-secret")
    adapter = MainAgentAdapter(
        backend="codex", codex_bin="codex",
        runner=lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=stdout, stderr=""),
    )

    result = adapter.send(**_args(tmp_path))

    assert "arbitrary-unclassified-secret" not in result["reply"]
    assert result["reply"] == "api_key=<REDACTED>"


def test_codex_streams_safe_agent_and_tool_events_before_final_reply(tmp_path: Path):
    events = []
    lines = [
        json.dumps({"type": "thread.started", "thread_id": "sid-stream"}),
        json.dumps({"type": "response_item", "payload": {
            "type": "reasoning",
            "summary": [{"type": "summary_text", "text": "Safe emitted reasoning summary"}],
            "encrypted_content": "private reasoning must not be exposed",
        }}),
        json.dumps({"type": "event_msg", "payload": {
            "type": "agent_message", "message": "我先检查项目状态。",
        }}),
        json.dumps({"type": "response_item", "payload": {
            "type": "function_call", "name": "exec_command",
            "arguments": json.dumps({"cmd": "danus-web-agent status", "api_key": "must-not-leak"}),
            "call_id": "call-1",
        }}),
        json.dumps({"type": "response_item", "payload": {
            "type": "function_call_output", "call_id": "call-1",
            "output": "Process exited with code 0\nAuthorization: Bearer must-not-leak",
        }}),
        json.dumps({"type": "event_msg", "payload": {
            "type": "task_complete", "last_agent_message": "完成。",
        }}),
    ]

    def runner(cmd, **kwargs):
        for line in lines:
            kwargs["on_stdout_line"](line)
        return SimpleNamespace(returncode=0, stdout="\n".join(lines), stderr="")

    adapter = MainAgentAdapter(backend="codex", runner=runner, codex_bin="codex")
    result = adapter.send(**_args(tmp_path), on_progress=events.append)

    assert result["reply"] == "完成。"
    assert [event["type"] for event in events] == [
        "process.started", "session.started", "agent.progress", "agent.message", "tool.started", "tool.completed", "turn.completed",
    ]
    assert events[2]["detail"] == "Safe emitted reasoning summary"
    assert events[4]["tool"] == "exec_command"
    assert "danus-web-agent status" in events[4]["detail"]
    assert "must-not-leak" not in json.dumps(events, ensure_ascii=False)
    assert "敏感参数已隐藏" in json.dumps(events, ensure_ascii=False)
    assert "content hidden by safety policy" in json.dumps(events, ensure_ascii=False)
    assert "private reasoning" not in json.dumps(events, ensure_ascii=False)


def test_codex_0148_jsonl_transient_error_then_completed_is_success(tmp_path: Path):
    events = []
    lines = [
        json.dumps({"type": "thread.started", "thread_id": "sid-0148"}),
        json.dumps({"type": "turn.started"}),
        json.dumps({"type": "error", "message": "Reconnecting... 1/5"}),
        json.dumps({"type": "item.completed", "item": {
            "id": "item-1", "type": "agent_message", "text": "DANUS_MAIN_AGENT_OK",
        }}),
        json.dumps({"type": "turn.completed", "usage": {"input_tokens": 1, "output_tokens": 1}}),
    ]

    def runner(cmd, **kwargs):
        for line in lines:
            kwargs["on_stdout_line"](line)
        return SimpleNamespace(returncode=0, stdout="\n".join(lines), stderr="")

    adapter = MainAgentAdapter(backend="codex", runner=runner, codex_bin="codex")
    result = adapter.send(**_args(tmp_path), on_progress=events.append)

    assert result["session_id"] == "sid-0148"
    assert result["reply"] == "DANUS_MAIN_AGENT_OK"
    assert result["status"] == "completed"
    assert [event["type"] for event in events] == [
        "process.started", "session.started", "turn.started", "agent.message", "turn.completed",
    ]


def test_codex_resume_keeps_resume_options_before_session(tmp_path: Path):
    calls = []
    def runner(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout=_codex_success(session_id="sid-1"), stderr="")

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


def test_web_main_agent_uses_broker_only_contract_and_hides_generic_repo_bin(tmp_path: Path, monkeypatch):
    adapter = MainAgentAdapter(backend="codex", codex_bin="/usr/bin/codex")
    repo = Path(__file__).resolve().parents[3]
    root = tmp_path / "projects" / "A"
    root.mkdir(parents=True)
    monkeypatch.setenv("PATH", f"{repo / 'bin'}:/usr/bin")

    env = adapter._env(
        root,
        lifecycle_url="http://127.0.0.1:8080/internal/api/projects/p/lifecycle",
        lifecycle_token="project-capability",
    )
    prompt = adapter._prompt(
        message="start", manifest=[], project_state={"project_id": "p"}, attachments=[],
    )

    assert str(repo / "bin") not in env["PATH"].split(os.pathsep)
    assert env["DANUS_WEB_AGENT_BIN"] == str(repo / "bin" / "danus-web-agent")
    assert "PYTHONPATH" not in env
    assert "DANUS_ROOT" not in env
    assert "DANUS_PY" not in env
    assert str(Path(sys.executable).parent.absolute()) not in env["PATH"].split(os.pathsep)
    assert "Never invoke the generic `danus start`" in prompt
    assert "$DANUS_WEB_AGENT_BIN start" in prompt
    assert "danus stop <project>" not in prompt


def test_claude_streams_safe_tool_results_and_turn_events(tmp_path: Path):
    events = []
    session_id = "123e4567-e89b-12d3-a456-426614174000"
    lines = [
        json.dumps({"type": "system", "subtype": "init", "session_id": session_id}),
        json.dumps({"type": "assistant", "message": {"content": [
            {"type": "text", "text": "Checking Worker state."},
            {"type": "tool_use", "id": "tool-1", "name": "Bash", "input": {"command": "danus-web-agent status"}},
        ]}}),
        json.dumps({"type": "user", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "tool-1", "content": json.dumps({"status": "running", "workers": [{"worker": "high", "result": "started"}]})},
        ]}}),
        json.dumps({
            "type": "result", "subtype": "success", "is_error": False,
            "session_id": session_id, "result": "done", "duration_ms": 125,
        }),
    ]

    def runner(cmd, **kwargs):
        assert cmd[cmd.index("--output-format") + 1] == "stream-json"
        for line in lines:
            kwargs["on_stdout_line"](line)
        return SimpleNamespace(returncode=0, stdout="\n".join(lines), stderr="")

    adapter = MainAgentAdapter(backend="claude", runner=runner, claude_bin="claude")
    result = adapter.send(**_args(tmp_path), on_progress=events.append)

    assert result["reply"] == "done"
    assert [event["type"] for event in events] == [
        "process.started", "session.started", "agent.message", "tool.started", "tool.completed", "turn.completed",
    ]
    assert events[3]["call_id"] == "tool-1"
    assert events[4]["call_id"] == "tool-1"
    assert events[4]["tool"] == "Bash"
    assert events[4]["duration_seconds"] >= 0
    assert '"status": "running"' in events[4]["detail"]
    assert events[5]["duration_seconds"] == 0.125


def test_exec_command_detail_unwraps_shell_launchers_before_redaction():
    assert MainAgentAdapter._tool_call_detail(
        "exec_command", ["/usr/bin/zsh", "-lc", "danus-web-agent status"],
    ) == "命令：danus-web-agent status"
    assert MainAgentAdapter._tool_call_detail(
        "exec_command", {"cmd": "/bin/bash -lc 'printf hello && pwd'"},
    ) == "命令：printf"
    assert MainAgentAdapter._tool_call_detail(
        "exec_command", ["/bin/bash", "--norc", "-c", "danus-web-agent status"],
    ) == "命令：danus-web-agent status"
    assignment = MainAgentAdapter._tool_call_detail(
        "exec_command", ["/bin/zsh", "-lc", "danus-web-agent assign secret-worker --task secret-task"],
    )
    assert assignment == "命令：danus-web-agent assign"
    assert "secret-worker" not in assignment
    assert "secret-task" not in assignment
    assert MainAgentAdapter._tool_call_detail(
        "exec_command", ["/bin/bash", "--rcfile", "/tmp/bashrc", "-c", "git status --short"],
    ) == "命令：git"
    secret = MainAgentAdapter._tool_call_detail(
        "exec_command", ["/bin/sh", "-c", "curl -H 'Authorization: Bearer top-secret' https://example.test"],
    )
    assert secret == "命令：curl"
    assert "top-secret" not in secret
    unclassified = MainAgentAdapter._tool_call_detail(
        "exec_command", ["/bin/sh", "-c", "echo arbitrary-unclassified-secret"],
    )
    assert unclassified == "命令：echo"
    assert "arbitrary-unclassified-secret" not in unclassified


def test_codex_tool_result_keeps_safe_broker_outcome_and_hides_unclassified_text():
    broker = MainAgentAdapter._codex_progress_events(json.dumps({
        "type": "response_item",
        "payload": {
            "type": "function_call_output", "call_id": "call-1",
            "output": json.dumps({
                "status": "partial_start", "not_running_workers": ["xhigh"],
                "workers": [{"worker": "high", "result": "started"}],
            }),
        },
    }))[0]
    opaque = MainAgentAdapter._codex_progress_events(json.dumps({
        "type": "response_item",
        "payload": {
            "type": "function_call_output", "call_id": "call-2",
            "output": "arbitrary-unclassified-secret",
        },
    }))[0]

    assert broker["status"] == "completed"
    assert "partial_start" in broker["detail"]
    assert "xhigh" in broker["detail"]
    assert "arbitrary-unclassified-secret" not in opaque["detail"]
    assert "content hidden by safety policy" in opaque["detail"]
    rejected = MainAgentAdapter._codex_progress_events(json.dumps({
        "type": "response_item",
        "payload": {
            "type": "function_call_output", "call_id": "call-3",
            "output": json.dumps({"status": "rejected", "error": "identity mismatch"}),
        },
    }))[0]
    assert rejected["status"] == "failed"
    assert "identity mismatch" in rejected["detail"]


def test_claude_tool_boundary_and_final_reply_redact_raw_values(tmp_path: Path):
    started = MainAgentAdapter._claude_progress_events(json.dumps({
        "type": "assistant", "message": {"content": [{
            "type": "tool_use", "id": "tool-secret", "name": "Bash",
            "input": {"command": "echo arbitrary-unclassified-secret"},
        }]},
    }))[0]
    completed = MainAgentAdapter._claude_progress_events(json.dumps({
        "type": "user", "message": {"content": [{
            "type": "tool_result", "tool_use_id": "tool-secret",
            "content": "arbitrary-unclassified-secret",
        }]},
    }))[0]
    assert "arbitrary-unclassified-secret" not in started["detail"]
    assert "arbitrary-unclassified-secret" not in completed["detail"]

    stdout = _claude_result(result="api_key=must-not-leak")
    adapter = MainAgentAdapter(
        backend="claude",
        runner=lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=stdout, stderr=""),
    )
    result = adapter.send(**_args(tmp_path))
    assert "must-not-leak" not in result["reply"]
    assert result["reply"] == "api_key=<REDACTED>"


def test_progress_sink_failure_aborts_stream_instead_of_silently_losing_audit(tmp_path: Path):
    line = json.dumps({"type": "response_item", "payload": {
        "type": "function_call", "name": "exec_command",
        "arguments": json.dumps({"cmd": "danus-web-agent status"}), "call_id": "call-1",
    }})

    def runner(cmd, **kwargs):
        kwargs["on_stdout_line"](line)
        raise AssertionError("unreachable after sink failure")

    adapter = MainAgentAdapter(backend="codex", runner=runner, codex_bin="codex")
    with pytest.raises(RuntimeError, match="audit sink unavailable"):
        adapter.send(
            **_args(tmp_path),
            on_progress=lambda event: (_ for _ in ()).throw(RuntimeError("audit sink unavailable")),
        )


def test_codex_retries_share_one_absolute_timeout_budget(tmp_path: Path):
    calls = []; now = [0.0]
    overloaded = "\n".join([json.dumps({"type": "thread.started", "thread_id": "sid"}), json.dumps({"type": "event_msg", "payload": {"type": "task_complete", "error": {"codex_error_info": "server_overloaded"}}})])
    def runner(cmd, **kwargs):
        calls.append(kwargs["timeout"]); now[0] += 0.4
        return SimpleNamespace(returncode=1, stdout=overloaded, stderr="")
    def sleep(seconds): now[0] += seconds
    adapter = MainAgentAdapter(backend="codex", runner=runner, codex_bin="codex", timeout=1.0, max_attempts=3, retry_base_seconds=.2, retry_cap_seconds=.2, sleeper=sleep, clock=lambda: now[0])
    with pytest.raises(MainAgentError) as raised: adapter.send(**_args(tmp_path))
    assert raised.value.code == "turn_timeout_exhausted"
    assert calls == pytest.approx([1.0, 0.4])
    assert now[0] <= 1.0


def test_normalized_protocol_preserves_session_turn_and_unknown_envelopes():
    from danus.web_console.protocol import EventKind, normalize_provider_line, normalize_trace
    assert normalize_provider_line(json.dumps({"type": "thread.started", "thread_id": "s"}))[0].kind == EventKind.SESSION_STARTED
    assert normalize_provider_line(json.dumps({"type": "turn.started"}))[0].kind == EventKind.TURN_STARTED
    trace = normalize_trace("\n".join([json.dumps({"type": "thread.started", "thread_id": "s"}), "not-json", json.dumps({"type": "event_msg", "payload": {"type": "task_complete", "last_agent_message": "ok"}})]))
    assert trace.session_id == "s" and trace.reply == "ok" and trace.terminal_state == "completed" and trace.parse_uncertain


def test_normalized_trace_handles_duplicate_and_reordered_envelopes():
    from danus.web_console.protocol import normalize_trace
    lines = [
        json.dumps({"type": "event_msg", "payload": {"type": "task_complete", "last_agent_message": "done"}}),
        json.dumps({"type": "thread.started", "thread_id": "sid"}),
        json.dumps({"type": "thread.started", "thread_id": "sid"}),
    ]
    trace = normalize_trace("\n".join(lines))
    assert trace.session_id == "sid" and trace.reply == "done" and trace.terminal_state == "completed"


def test_codex_normalizes_each_provider_envelope_exactly_once(monkeypatch):
    from danus.web_console import protocol

    lines = [
        json.dumps({"type": "thread.started", "thread_id": "sid-once"}),
        json.dumps({"type": "turn.started"}),
        json.dumps({"type": "mystery.event", "value": 1}),
        "not-json",
        json.dumps({"type": "turn.completed"}),
    ]
    real_loads = protocol.json.loads
    parsed = []

    def counted_loads(value):
        parsed.append(value)
        return real_loads(value)

    monkeypatch.setattr(protocol.json, "loads", counted_loads)
    envelopes, trace = protocol.normalize_envelopes(lines)

    assert len(parsed) == len(lines)
    assert len(envelopes) == len(lines) - 1
    assert trace.session_id == "sid-once"
    assert trace.terminal_state == "completed"
    assert trace.parse_uncertain is True


def test_codex_two_turns_preserve_session_process_and_turn_event_semantics(tmp_path: Path):
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd)
        message = "first" if len(calls) == 1 else "second"
        lines = [
            json.dumps({"type": "thread.started", "thread_id": "sid-resume"}),
            json.dumps({"type": "turn.started"}),
            json.dumps({"type": "item.completed", "item": {
                "type": "agent_message", "text": message,
            }}),
            json.dumps({"type": "turn.completed"}),
        ]
        for line in lines:
            kwargs["on_stdout_line"](line)
        return SimpleNamespace(returncode=0, stdout="\n".join(lines), stderr="")

    adapter = MainAgentAdapter(backend="codex", runner=runner, codex_bin="codex")
    first_events = []
    first = adapter.send(**_args(tmp_path), on_progress=first_events.append)
    second_events = []
    second = adapter.send(
        **(_args(tmp_path) | {"session_id": first["session_id"]}),
        on_progress=second_events.append,
    )

    assert first["session_id"] == second["session_id"] == "sid-resume"
    assert first["reply"] == "first" and second["reply"] == "second"
    assert [event["type"] for event in first_events] == [
        "process.started", "session.started", "turn.started",
        "agent.message", "turn.completed",
    ]
    assert [event["type"] for event in second_events] == [
        "process.started", "turn.started", "agent.message", "turn.completed",
    ]
    assert second_events[0]["session_id"] == "sid-resume"
    assert second_events[1]["session_id"] == "sid-resume"
    assert calls[1][-3:] == ["resume", "sid-resume", "-"]


def test_codex_terminal_failure_is_not_cleared_by_reordered_completion():
    from danus.web_console.protocol import normalize_trace

    trace = normalize_trace("\n".join([
        json.dumps({"type": "turn.failed", "error": {
            "code": "terminal", "message": "failed",
        }}),
        json.dumps({"type": "turn.completed"}),
    ]))

    assert trace.terminal_state == "failed"
    assert trace.failure == ("terminal", "failed")


def test_codex_resume_rejects_a_different_provider_session_identity(tmp_path: Path):
    adapter = MainAgentAdapter(
        backend="codex", codex_bin="codex",
        runner=lambda *args, **kwargs: SimpleNamespace(
            returncode=0, stdout=_codex_success(session_id="sid-other"), stderr="",
        ),
    )

    with pytest.raises(MainAgentError, match="different session identity") as raised:
        adapter.send(**(_args(tmp_path) | {"session_id": "sid-known"}))

    assert raised.value.code == "session_identity_mismatch"
    assert raised.value.session_id == "sid-known"


@pytest.mark.parametrize("malformed", [
    {"type": "event_msg", "payload": []},
    {"type": "response_item", "payload": {"text": "missing type"}},
    {"type": "item.started", "item": "not-an-object"},
    {"type": "item.completed", "item": {}},
    {"type": "response.completed", "response": {"output": {}}},
])
def test_known_malformed_codex_envelopes_make_retry_unsafe(malformed):
    from danus.web_console.protocol import normalize_trace

    trace = normalize_trace("\n".join([
        json.dumps({"type": "thread.started", "thread_id": "sid-malformed"}),
        json.dumps(malformed),
        json.dumps({"type": "event_msg", "payload": {
            "type": "task_complete",
            "error": {"codex_error_info": "server_overloaded", "message": "retryable"},
        }}),
    ]))

    assert trace.failure == ("server_overloaded", "retryable")
    assert trace.parse_uncertain is True


def test_malformed_known_envelope_blocks_automatic_adapter_retry(tmp_path: Path):
    calls = []
    stream = "\n".join([
        json.dumps({"type": "thread.started", "thread_id": "sid-malformed"}),
        json.dumps({"type": "item.completed", "item": {}}),
        json.dumps({"type": "event_msg", "payload": {
            "type": "task_complete",
            "error": {"codex_error_info": "server_overloaded", "message": "retryable"},
        }}),
    ])

    def runner(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(returncode=1, stdout=stream, stderr="")

    adapter = MainAgentAdapter(
        backend="codex", codex_bin="codex", runner=runner,
        max_attempts=3, retry_base_seconds=0,
    )
    with pytest.raises(MainAgentError) as raised:
        adapter.send(**_args(tmp_path))

    assert len(calls) == 1
    assert raised.value.retryable is True
    assert raised.value.safe_to_retry is False


@pytest.mark.parametrize("terminal", [
    {"type": "turn.completed"},
    {"type": "turn.failed", "error": {"code": "failed", "message": "failed"}},
])
def test_new_stream_session_conflict_wins_over_terminal_and_stops_progress(
    tmp_path: Path, terminal,
):
    events = []
    lines = [
        json.dumps({"type": "thread.started", "thread_id": "sid-a"}),
        json.dumps({"type": "turn.started"}),
        json.dumps({"type": "thread.started", "thread_id": "sid-b"}),
        json.dumps({"type": "item.completed", "item": {
            "type": "agent_message", "text": "must-not-persist",
        }}),
        json.dumps(terminal),
    ]

    def runner(cmd, **kwargs):
        for line in lines:
            kwargs["on_stdout_line"](line)
        return SimpleNamespace(returncode=0, stdout="\n".join(lines), stderr="")

    adapter = MainAgentAdapter(backend="codex", codex_bin="codex", runner=runner)
    with pytest.raises(MainAgentError) as raised:
        adapter.send(**_args(tmp_path), on_progress=events.append)

    assert raised.value.code == "session_identity_mismatch"
    assert raised.value.session_id == "sid-a"
    assert [event["type"] for event in events] == [
        "process.started", "session.started", "turn.started",
    ]
    assert "sid-b" not in json.dumps(events)
    assert "must-not-persist" not in json.dumps(events)


def test_session_conflict_wins_over_timeout_and_uses_canonical_identity(tmp_path: Path):
    events = []
    lines = [
        json.dumps({"type": "thread.started", "thread_id": "sid-a"}),
        json.dumps({"type": "thread.started", "thread_id": "sid-b"}),
        json.dumps({"type": "item.completed", "item": {
            "type": "agent_message", "text": "must-not-persist",
        }}),
    ]

    def runner(cmd, **kwargs):
        for line in lines:
            kwargs["on_stdout_line"](line)
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=1, output="\n".join(lines))

    adapter = MainAgentAdapter(backend="codex", codex_bin="codex", runner=runner)
    with pytest.raises(MainAgentError) as raised:
        adapter.send(**_args(tmp_path), on_progress=events.append)

    assert raised.value.code == "session_identity_mismatch"
    assert raised.value.session_id == "sid-a"
    assert [event["type"] for event in events] == ["process.started", "session.started"]


def test_resume_conflict_never_publishes_the_mismatching_envelope(tmp_path: Path):
    events = []
    lines = [
        json.dumps({"type": "thread.started", "thread_id": "sid-other"}),
        json.dumps({"type": "turn.started"}),
        json.dumps({"type": "turn.completed"}),
    ]

    def runner(cmd, **kwargs):
        for line in lines:
            kwargs["on_stdout_line"](line)
        return SimpleNamespace(returncode=0, stdout="\n".join(lines), stderr="")

    adapter = MainAgentAdapter(backend="codex", codex_bin="codex", runner=runner)
    with pytest.raises(MainAgentError) as raised:
        adapter.send(
            **(_args(tmp_path) | {"session_id": "sid-known"}),
            on_progress=events.append,
        )

    assert raised.value.code == "session_identity_mismatch"
    assert raised.value.session_id == "sid-known"
    assert events == [{
        "type": "process.started", "status": "active",
        "detail": "Main Agent Process activated", "session_id": "sid-known",
    }]


def test_failed_turn_stops_all_later_stream_publication_and_reduction(tmp_path: Path):
    events = []
    lines = [
        json.dumps({"type": "thread.started", "thread_id": "sid-failed"}),
        json.dumps({"type": "turn.started"}),
        json.dumps({"type": "turn.failed", "error": {
            "code": "terminal", "message": "failed",
        }}),
        json.dumps({"type": "item.completed", "item": {
            "type": "agent_message", "text": "post-terminal-message",
        }}),
        json.dumps({"type": "item.started", "item": {
            "type": "command_execution", "command": "echo post-terminal-tool",
        }}),
        json.dumps({"type": "turn.completed"}),
    ]

    def runner(cmd, **kwargs):
        for line in lines:
            kwargs["on_stdout_line"](line)
        return SimpleNamespace(returncode=1, stdout="\n".join(lines), stderr="")

    adapter = MainAgentAdapter(backend="codex", codex_bin="codex", runner=runner)
    with pytest.raises(MainAgentError) as raised:
        adapter.send(**_args(tmp_path), on_progress=events.append)

    assert raised.value.code == "terminal"
    assert [event["type"] for event in events] == [
        "process.started", "session.started", "turn.started", "turn.failed",
    ]
    assert "post-terminal" not in json.dumps(events)


def test_new_legacy_session_meta_emits_session_once_and_resume_emits_none(tmp_path: Path):
    calls = []

    def runner(cmd, **kwargs):
        calls.append(cmd)
        lines = [
            json.dumps({"type": "session_meta", "payload": {"session_id": "sid-legacy"}}),
            json.dumps({"type": "thread.started", "thread_id": "sid-legacy"}),
            json.dumps({"type": "turn.started"}),
            json.dumps({"type": "event_msg", "payload": {
                "type": "agent_message", "content": [{"type": "text", "text": "ok"}],
            }}),
            json.dumps({"type": "turn.completed"}),
        ]
        for line in lines:
            kwargs["on_stdout_line"](line)
        return SimpleNamespace(returncode=0, stdout="\n".join(lines), stderr="")

    adapter = MainAgentAdapter(backend="codex", codex_bin="codex", runner=runner)
    first_events = []
    first = adapter.send(**_args(tmp_path), on_progress=first_events.append)
    resumed_events = []
    adapter.send(
        **(_args(tmp_path) | {"session_id": first["session_id"]}),
        on_progress=resumed_events.append,
    )

    assert [event["type"] for event in first_events].count("session.started") == 1
    assert [event["type"] for event in resumed_events].count("session.started") == 0
    assert first["reply"] == "ok"


def test_response_failed_nested_error_preserves_retry_classification(tmp_path: Path):
    calls = []
    failed = "\n".join([
        json.dumps({"type": "thread.started", "thread_id": "sid-response-failed"}),
        json.dumps({"type": "response.failed", "response": {"error": {
            "code": "server_overloaded", "message": "capacity",
        }}}),
    ])
    completed = "\n".join([
        json.dumps({"type": "thread.started", "thread_id": "sid-response-failed"}),
        json.dumps({"type": "item.completed", "item": {
            "type": "agent_message", "text": "recovered",
        }}),
        json.dumps({"type": "turn.completed"}),
    ])

    def runner(cmd, **kwargs):
        calls.append(cmd)
        return SimpleNamespace(
            returncode=1 if len(calls) == 1 else 0,
            stdout=failed if len(calls) == 1 else completed, stderr="",
        )

    adapter = MainAgentAdapter(
        backend="codex", codex_bin="codex", runner=runner,
        max_attempts=2, retry_base_seconds=0, sleeper=lambda _: None,
    )
    result = adapter.send(**_args(tmp_path))

    assert result["reply"] == "recovered"
    assert result["attempts"] == 2
    assert calls[1][-3:] == ["resume", "sid-response-failed", "-"]


def test_item_tool_phase_status_and_legacy_response_item_compatibility():
    started = MainAgentAdapter._codex_progress_events(json.dumps({
        "type": "item.started", "item": {
            "type": "mcp_tool_call", "name": "danus.fact_search", "id": "call-1",
        },
    }))[0]
    failed = MainAgentAdapter._codex_progress_events(json.dumps({
        "type": "item.completed", "item": {
            "type": "mcp_tool_call", "name": "danus.fact_search", "id": "call-1",
            "status": "failed", "error": {"message": "tool rejected"},
        },
    }))[0]
    web_completed = MainAgentAdapter._codex_progress_events(json.dumps({
        "type": "item.completed", "item": {
            "type": "web_search_call", "id": "call-2", "status": "completed",
            "result": {"status": "ok"},
        },
    }))[0]
    legacy = MainAgentAdapter._codex_progress_events(json.dumps({
        "type": "response_item", "payload": {
            "type": "function_call", "name": "exec_command", "call_id": "call-3",
            "arguments": "{}",
        },
    }))[0]

    assert (started["type"], started["status"]) == ("tool.started", "started")
    assert (failed["type"], failed["status"]) == ("tool.completed", "failed")
    assert "content hidden by safety policy" in failed["detail"]
    assert (web_completed["type"], web_completed["status"]) == ("tool.completed", "completed")
    assert (legacy["type"], legacy["status"]) == ("tool.started", "started")


@pytest.mark.parametrize(("field", "value", "expected"), [
    ("message", "message-shape", "message-shape"),
    ("text", "text-shape", "text-shape"),
    ("output_text", "output-shape", "output-shape"),
    ("content", [{"type": "output_text", "text": "content-shape"}], "content-shape"),
])
def test_legacy_event_message_text_shapes_share_one_decoder(field, value, expected):
    from danus.web_console.protocol import normalize_trace

    trace = normalize_trace("\n".join([
        json.dumps({"type": "thread.started", "thread_id": "sid-message"}),
        json.dumps({"type": "event_msg", "payload": {
            "type": "agent_message", field: value,
        }}),
        json.dumps({"type": "turn.completed"}),
    ]))

    assert trace.reply == expected


def test_streaming_adapter_decodes_each_provider_line_once(tmp_path: Path, monkeypatch):
    from danus.web_console import protocol

    lines = [
        json.dumps({"type": "thread.started", "thread_id": "sid-stream-once"}),
        json.dumps({"type": "turn.started"}),
        json.dumps({"type": "item.completed", "item": {
            "type": "agent_message", "text": "once",
        }}),
        "not-json",
        json.dumps({"type": "turn.completed"}),
    ]
    real_loads = protocol.json.loads
    decoded = []

    def counted_loads(value):
        decoded.append(value)
        return real_loads(value)

    monkeypatch.setattr(protocol.json, "loads", counted_loads)

    def runner(cmd, **kwargs):
        for line in lines:
            kwargs["on_stdout_line"](line)
        return SimpleNamespace(returncode=0, stdout="\n".join(lines), stderr="")

    result = MainAgentAdapter(
        backend="codex", codex_bin="codex", runner=runner,
    ).send(**_args(tmp_path), on_progress=lambda _: None)

    assert result["reply"] == "once"
    assert decoded == lines


def test_streaming_and_batch_protocol_reduction_are_identical():
    from danus.web_console.protocol import NormalizedTraceBuilder, normalize_trace

    lines = [
        json.dumps({"type": "session_meta", "payload": {"session_id": "sid-equal"}}),
        json.dumps({"type": "turn.started"}),
        json.dumps({"type": "error", "message": "Reconnecting... 1/5"}),
        json.dumps({"type": "item.completed", "item": {
            "type": "agent_message", "content": [{"text": "equal"}],
        }}),
        json.dumps({"type": "turn.completed"}),
    ]
    streaming = NormalizedTraceBuilder()
    for line in lines:
        streaming.consume_line(line)

    assert streaming.trace() == normalize_trace("\n".join(lines))


def test_post_terminal_tool_activity_blocks_retry_without_being_published(tmp_path: Path):
    calls = []
    events = []
    lines = [
        json.dumps({"type": "thread.started", "thread_id": "sid-post-terminal-tool"}),
        json.dumps({"type": "event_msg", "payload": {
            "type": "task_complete",
            "error": {"codex_error_info": "server_overloaded", "message": "capacity"},
        }}),
        json.dumps({"type": "item.completed", "item": {
            "type": "command_execution", "command": "danus-web-agent status",
            "exit_code": 0,
        }}),
    ]

    def runner(cmd, **kwargs):
        calls.append(cmd)
        for line in lines:
            kwargs["on_stdout_line"](line)
        return SimpleNamespace(returncode=1, stdout="\n".join(lines), stderr="")

    adapter = MainAgentAdapter(
        backend="codex", codex_bin="codex", runner=runner,
        max_attempts=3, retry_base_seconds=0,
    )
    with pytest.raises(MainAgentError) as raised:
        adapter.send(**_args(tmp_path), on_progress=events.append)

    assert len(calls) == 1
    assert raised.value.retryable is True
    assert raised.value.safe_to_retry is False
    assert raised.value.observed_tool_activity is True
    assert [event["type"] for event in events] == [
        "process.started", "session.started", "turn.failed",
    ]


@pytest.mark.parametrize("empty_error", [None, False, "", {}])
def test_legacy_task_complete_empty_error_is_success(empty_error):
    from danus.web_console.protocol import normalize_trace

    trace = normalize_trace("\n".join([
        json.dumps({"type": "thread.started", "thread_id": "sid-empty-error"}),
        json.dumps({"type": "event_msg", "payload": {
            "type": "agent_message", "message": "ok",
        }}),
        json.dumps({"type": "event_msg", "payload": {
            "type": "task_complete", "error": empty_error,
        }}),
    ]))

    assert trace.terminal_state == "completed"
    assert trace.failure is None
    assert trace.reply == "ok"


def test_malformed_thread_without_id_does_not_consume_session_started():
    from danus.web_console.protocol import EventKind, NormalizedTraceBuilder

    builder = NormalizedTraceBuilder()
    malformed = builder.consume_line(json.dumps({"type": "thread.started"}))
    valid = builder.consume_line(json.dumps({
        "type": "thread.started", "thread_id": "sid-valid",
    }))

    assert malformed is not None and malformed.events == ()
    assert valid is not None
    assert [event.kind for event in valid.events] == [EventKind.SESSION_STARTED]
    assert valid.events[0].session_id == "sid-valid"
    assert builder.trace().session_id == "sid-valid"
    assert builder.trace().parse_uncertain is True


@pytest.mark.parametrize("item", [
    {"type": "function_call_output", "call_id": "call-1", "error": "failed"},
    {"type": "custom_tool_call_output", "call_id": "call-2",
     "output": '{"status":"rejected"}'},
    {"type": "tool_search_output", "call_id": "call-3",
     "result": {"accepted": False}},
])
def test_tool_output_failure_status_is_normalized_in_typed_protocol(item):
    from danus.web_console.protocol import EventKind, normalize_provider_line

    event = normalize_provider_line(json.dumps({
        "type": "item.completed", "item": item,
    }))[0]

    assert event.kind == EventKind.TOOL_COMPLETED
    assert event.status == "failed"
