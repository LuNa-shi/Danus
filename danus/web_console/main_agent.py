"""Project-scoped Main Agent session adapter."""
from __future__ import annotations

from collections import deque
import json
import math
import os
import re
import shutil
import signal
import shlex
import subprocess
import threading
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from danus.strategy.config import resolve_transport

from .observability import redact_text
from .runtime import RuntimeErrorBase


class MainAgentError(RuntimeErrorBase):
    """A user-visible Main Agent turn failure with safe operational metadata."""

    def __init__(self, message: str, *, code: str | None = None,
                 session_id: str | None = None, retryable: bool = False,
                 safe_to_retry: bool = False, attempts: int = 1,
                 observed_tool_activity: bool = False):
        super().__init__(message)
        self.code = code
        self.session_id = session_id
        self.retryable = retryable
        self.safe_to_retry = safe_to_retry
        self.attempts = attempts
        self.observed_tool_activity = observed_tool_activity


class MainAgentAdapter:
    """Launch/resume one explicit Main Agent session per Project.

    Codex is the default because the deployment has a configured OpenAI-compatible
    Codex backend. Claude Code remains available as an explicit server-side
    backend when its own authentication is configured. The runner is injectable
    for HTTP-boundary tests.
    """

    def __init__(self, *, runner: Callable[..., Any] | None = None, backend: str = "codex",
                 claude_bin: str = "claude", codex_bin: str = "codex", model: str | None = None,
                 effort: str | None = None, timeout: float = 900.0,
                 max_attempts: int | None = None, retry_base_seconds: float | None = None,
                 retry_cap_seconds: float | None = None,
                 sleeper: Callable[[float], None] | None = None):
        if backend not in {"codex", "claude"}:
            raise ValueError("main-agent backend must be codex or claude")
        self.backend = backend
        self.claude_bin = os.environ.get("DANUS_WEB_CLAUDE_BIN", claude_bin)
        self.codex_bin = codex_bin if codex_bin != "codex" else os.environ.get("DANUS_CODEX_BIN") or self._resolve_codex()
        self.model = model
        self.effort = effort
        self.timeout = timeout
        configured_attempts = max_attempts if max_attempts is not None else self._int_env("DANUS_WEB_MAIN_AGENT_MAX_ATTEMPTS", 3)
        configured_base = retry_base_seconds if retry_base_seconds is not None else self._float_env("DANUS_WEB_MAIN_AGENT_RETRY_BASE_SECONDS", 2.0)
        configured_cap = retry_cap_seconds if retry_cap_seconds is not None else self._float_env("DANUS_WEB_MAIN_AGENT_RETRY_CAP_SECONDS", 8.0)
        self.max_attempts = min(5, max(1, configured_attempts))
        self.retry_base_seconds = configured_base if math.isfinite(configured_base) and configured_base >= 0 else 2.0
        self.retry_cap_seconds = configured_cap if math.isfinite(configured_cap) and configured_cap >= 0 else 8.0
        self._runner = runner or self._default_runner
        self._sleeper = sleeper or time.sleep

    @staticmethod
    def _int_env(name: str, default: int) -> int:
        try:
            return int(os.environ.get(name, str(default)))
        except ValueError:
            return default

    @staticmethod
    def _float_env(name: str, default: float) -> float:
        try:
            return float(os.environ.get(name, str(default)))
        except ValueError:
            return default

    @staticmethod
    def _resolve_codex() -> str:
        try:
            from danus import codex
            resolved = codex.resolve_bin()
        except Exception:
            return "codex"
        # `bin/codex` is the deployment wrapper, but it intentionally exits when
        # bootstrap has not produced runtime/runtime.env yet. A developer who
        # launches the Web Console directly should still be able to use an
        # already-installed Codex CLI from PATH. Keep the wrapper preference once
        # the self-contained runtime exists; this preserves deployment pinning.
        repo = Path(__file__).resolve().parents[2]
        wrapper = repo / "bin" / "codex"
        if resolved == str(wrapper) and not (repo / "runtime" / "runtime.env").is_file():
            system_codex = shutil.which("codex")
            if system_codex and system_codex != resolved:
                return system_codex
        return resolved

    @staticmethod
    def _default_runner(cmd, *, input, cwd, env, timeout, on_stdout_line=None):
        if on_stdout_line is None:
            return subprocess.run(
                cmd, input=input, capture_output=True, text=True,
                cwd=cwd, env=env, timeout=timeout,
            )

        process = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, cwd=cwd, env=env, bufsize=1, start_new_session=True,
        )
        stdout_head: list[str] = []
        stdout_tail: deque[str] = deque()
        stderr_tail: deque[str] = deque(maxlen=100)
        stdout_line_count = 0
        stdout_tail_chars = 0
        stdout_content_truncated = False
        timed_out = threading.Event()

        def drain_stderr() -> None:
            if process.stderr is not None:
                for line in iter(lambda: process.stderr.readline(1024 * 1024 + 1), ""):
                    stderr_tail.append(line[:16384])

        def signal_process_group(sig: int) -> None:
            try:
                os.killpg(process.pid, sig)
            except (ProcessLookupError, PermissionError):
                try:
                    process.send_signal(sig)
                except ProcessLookupError:
                    pass

        def terminate_on_timeout() -> None:
            timed_out.set()
            signal_process_group(signal.SIGTERM)
            for _ in range(10):
                try:
                    os.killpg(process.pid, 0)
                except (ProcessLookupError, PermissionError):
                    return
                time.sleep(0.1)
            # The parent may already be gone while a descendant still owns the pipes.
            signal_process_group(signal.SIGKILL)

        stderr_thread = threading.Thread(target=drain_stderr, daemon=True)
        timer = threading.Timer(timeout, terminate_on_timeout)
        stderr_thread.start()
        timer.start()
        try:
            if process.stdin is not None:
                try:
                    process.stdin.write(input)
                    process.stdin.close()
                except BrokenPipeError:
                    pass
            if process.stdout is not None:
                for line in iter(lambda: process.stdout.readline(1024 * 1024 + 1), ""):
                    stdout_line_count += 1
                    if len(line) > 262144:
                        stdout_content_truncated = True
                    captured = line[:262144]
                    if len(stdout_head) < 20:
                        stdout_head.append(captured)
                    else:
                        stdout_tail.append(captured)
                        stdout_tail_chars += len(captured)
                        while stdout_tail_chars > 8 * 1024 * 1024 and stdout_tail:
                            stdout_tail_chars -= len(stdout_tail.popleft())
                    on_stdout_line(line.rstrip("\n"))
            returncode = process.wait()
        except BaseException:
            signal_process_group(signal.SIGKILL)
            if process.poll() is None:
                process.wait()
            raise
        finally:
            timer.cancel()
            stderr_thread.join(timeout=2)

        capture_truncated = stdout_content_truncated or stdout_line_count > len(stdout_head) + len(stdout_tail)
        stdout = "".join(stdout_head)
        if capture_truncated:
            stdout += "\n<CODEX_STDOUT_CAPTURE_TRUNCATED>\n"
        stdout += "".join(stdout_tail)
        stderr = "".join(stderr_tail)
        if timed_out.is_set():
            raise subprocess.TimeoutExpired(
                cmd=cmd, timeout=timeout, output=stdout, stderr=stderr,
            )
        return subprocess.CompletedProcess(cmd, returncode, stdout, stderr)

    def _prompt(self, *, message: str, manifest: list[dict[str, Any]], project_state: dict[str, Any], attachments: list[dict[str, Any]]) -> str:
        repo = Path(__file__).resolve().parents[2]
        contract = repo / "agents" / "contracts" / "web_main_agent.md"
        contract_text = contract.read_text(encoding="utf-8") if contract.is_file() else ""
        strategy_transport = resolve_transport(None)
        if strategy_transport == "off":
            strategy_policy = (
                "SERVER STRATEGY POLICY: strategy consult is OFF for this deployment. "
                "Do not invoke `consult` or any external strategy model. Use your Main Agent "
                "orchestration judgment to prepare the elaboration and shared strategy. Record the "
                "strategy in the `master_guidance` channel with `guidance-source: offline-main-agent` "
                "in its evidence. This is offline Main-Agent-authored guidance: you must not describe "
                "it as consult-derived. At initialization, present the direction to the operator and "
                "wait for confirmation before assigning Workers through `danus-web-agent`."
            )
        else:
            strategy_policy = (
                f"SERVER STRATEGY POLICY: strategy consult transport is {strategy_transport}. "
                "Use the server-configured transport and model; do not hard-code or substitute a model id. "
                "Record the advisor direction as consult-derived guidance and wait for operator confirmation before assigning Workers."
            )
        return "\n".join([
            "You are the Danus Main Agent for exactly one Project.",
            "Follow the Main Agent contract below. Retain strategic orchestration authority; do not submit facts directly.",
            "Use the exact project-scoped command path in `$DANUS_WEB_AGENT_BIN` for status, assignment, and Worker lifecycle coordination (`start`, `pause`, `resume`, and graceful `stop`). It is the only allowed lifecycle command and is pinned to this Project. Do not edit Danus source code or access another Project. Use the Danus MCP tools for scoped memory and Fact Graph oversight; never submit facts as Main Agent.",
            strategy_policy,
            "MAIN AGENT CONTRACT:\n" + contract_text,
            "The Web Console supplies this project state and material manifest explicitly.",
            "Project state:", json.dumps(project_state, ensure_ascii=False, sort_keys=True),
            "Project File Manifest:", json.dumps(manifest, ensure_ascii=False, sort_keys=True),
            "Selected Conversation Attachments (read these first):", json.dumps(attachments, ensure_ascii=False, sort_keys=True),
            "Operator message:", message,
        ])

    def _env(
        self,
        root: Path,
        *,
        lifecycle_url: str | None = None,
        lifecycle_token: str | None = None,
    ) -> dict[str, str]:
        """Build a minimal server-side environment for the Main Agent.

        Codex needs its authentication/config homes and the Danus runtime wiring,
        but the web request must not forward unrelated host secrets to a
        model-generated subprocess.
        """
        inherited = os.environ
        keep = {
            "PATH", "HOME", "LANG", "LC_ALL", "TERM", "TMPDIR",
            # Codex auth/config variables are explicitly allowlisted. The API
            # key is intentionally inherited only when configured as the server
            # side Codex credential; unrelated host secrets are excluded.
            "CODEX_HOME", "DANUS_CODEX_API_KEY", "OPENAI_API_KEY", "OPENAI_BASE_URL",
            "CODEX_API_BASE_URL", "CODEX_API_MODEL",
            "DANUS_CODEX_BIN", "DANUS_CODEX_MODEL", "DANUS_CODEX_EFFORT",
            "DANUS_VERIFY_URL", "DANUS_VERIFY_TIMEOUT", "DANUS_RUNTIME",
            "DANUS_PY", "DANUS_WEB_AGENT_BIN",
            "DANUS_WEB_MAIN_AGENT_BACKEND",
            "DANUS_AGENTS_ROOT", "DANUS_ROOT", "CODEX_BACKEND",
            # The documented Main Agent loop may invoke the strategy consult.
            # Pass only its explicit Danus namespace; never forward unrelated
            # host credentials into the model-generated subprocess.
            "DANUS_CONSULT_TRANSPORT", "DANUS_CONSULT_API_KEY",
            "DANUS_CONSULT_BASE_URL", "DANUS_CONSULT_MODEL",
            "DANUS_CONSULT_PRICE_IN", "DANUS_CONSULT_PRICE_OUT",
            "DANUS_CONSULT_TIMEOUT", "DANUS_CONSULT_BACKGROUND",
            "DANUS_CONSULT_STORE", "DANUS_CONSULT_CLAUDE_CODE_MODEL",
            "DANUS_CONSULT_CLAUDE_CODE_BIN", "DANUS_CONSULT_CLAUDE_CODE_MAX_WALL",
            "DANUS_CONSULT_CLAUDE_CODE_PRICE_IN", "DANUS_CONSULT_CLAUDE_CODE_PRICE_OUT",
            "DANUS_CONSULT_CLAUDE_API_KEY", "DANUS_CONSULT_CLAUDE_API_BASE_URL",
            "DANUS_CONSULT_CLAUDE_API_MODEL", "DANUS_CONSULT_CLAUDE_API_FALLBACK",
            "DANUS_CONSULT_CLAUDE_API_PRICE_IN", "DANUS_CONSULT_CLAUDE_API_PRICE_OUT",
        }
        env = {key: value for key, value in inherited.items() if key in keep}
        # Claude subscription auth is intentionally inherited from its local
        # helper; custom Anthropic API routing must not be injected by the web
        # console into a Main Agent session.
        for key in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL"):
            env.pop(key, None)
        repo = Path(__file__).resolve().parents[2]
        env.update({
            "DANUS_ROLE": "main", "DANUS_AUTHOR": "main_agent",
            "DANUS_PROJECT_DIR": str(root), "DANUS_AGENTS_ROOT": str(root.parent),
            "DANUS_PROJECT_SCOPE": root.name,
            "DANUS_WEB_AGENT_BIN": str(repo / "bin" / "danus-web-agent"),
        })
        if (lifecycle_url is None) != (lifecycle_token is None):
            raise MainAgentError("incomplete lifecycle broker capability")
        if lifecycle_url is not None and lifecycle_token is not None:
            env["DANUS_WEB_LIFECYCLE_URL"] = lifecycle_url
            env["DANUS_WEB_LIFECYCLE_TOKEN"] = lifecycle_token
        # Codex receives the broker wrapper only by its exact environment path;
        # remove the repository bin directory so generic `danus start/stop`
        # cannot be selected from PATH. Claude has an explicit Bash allowlist,
        # so it may resolve the wrapper by name without gaining generic commands.
        repo_bin = (repo / "bin").resolve()
        path_parts = []
        for entry in env.get("PATH", "").split(os.pathsep) if env.get("PATH") else []:
            try:
                resolved_entry = Path(entry).absolute()
                if resolved_entry in {repo_bin, Path(sys.executable).parent.absolute()}:
                    continue
            except (OSError, RuntimeError):
                pass
            path_parts.append(entry)
        if self.backend == "claude":
            path_parts.insert(0, str(repo_bin))
        codex_dir = os.path.dirname(os.path.abspath(self.codex_bin)) if os.path.dirname(self.codex_bin) else ""
        if codex_dir and codex_dir not in path_parts:
            path_parts.insert(0, codex_dir)
        env["PATH"] = os.pathsep.join(path_parts)
        return env

    @staticmethod
    def _text_value(value: Any) -> str:
        """Normalize the text shapes emitted by Codex JSON events."""
        if isinstance(value, str):
            return value
        if isinstance(value, list):
            return "".join(MainAgentAdapter._text_value(item) for item in value)
        if isinstance(value, dict):
            for key in ("text", "value", "output_text", "message", "content"):
                if key in value:
                    text = MainAgentAdapter._text_value(value[key])
                    if text:
                        return text
        return ""

    @classmethod
    def _message_text(cls, obj: Any) -> str:
        if not isinstance(obj, dict):
            return ""
        for key in ("text", "message", "content", "output_text"):
            text = cls._text_value(obj.get(key))
            if text:
                return text
        return ""

    @staticmethod
    def _redact_display_text(value: str, limit: int = 1200) -> str:
        return redact_text(str(value or ""), limit=limit, replacement="<REDACTED>")

    @classmethod
    def _safe_display_value(cls, value: Any, limit: int = 1200) -> str:
        secret_names = re.compile(r"(?i)(api[_-]?key|token|secret|password|authorization|auth[_-]?token|session|cookie|credential|private[_-]?key|access[_-]?key)")

        def clean(item: Any) -> Any:
            if isinstance(item, dict):
                return {
                    str(key): "<REDACTED>" if secret_names.search(str(key)) else clean(inner)
                    for key, inner in item.items()
                }
            if isinstance(item, list):
                return [clean(inner) for inner in item]
            if isinstance(item, str):
                return cls._redact_display_text(item, limit=limit)
            if item is None or isinstance(item, (bool, int, float)):
                return item
            return cls._redact_display_text(str(item), limit=limit)

        parsed = value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except (json.JSONDecodeError, TypeError):
                parsed = value
        if isinstance(parsed, (dict, list)):
            rendered = json.dumps(clean(parsed), ensure_ascii=False, sort_keys=True)
        else:
            rendered = str(clean(parsed))
        return cls._redact_display_text(rendered, limit=limit)

    @classmethod
    def _tool_result_detail(cls, raw_result: Any) -> str:
        parsed = raw_result
        if isinstance(raw_result, str):
            try:
                parsed = json.loads(raw_result)
            except (json.JSONDecodeError, TypeError):
                parsed = raw_result
        allowed = {
            "status", "outcome", "detail", "error", "exit_code", "run_id",
            "worker", "workers", "alive_workers", "not_running_workers",
            "signals_sent", "remaining_project_processes", "safe_to_execute",
        }
        if isinstance(parsed, dict):
            selected = {key: parsed[key] for key in allowed if key in parsed}
            if selected:
                return cls._safe_display_value(selected, 1200)
        size = len(str(raw_result or ""))
        return f"Result returned ({size} characters; content hidden by safety policy)"

    @staticmethod
    def _tool_result_status(raw_result: Any, envelope: dict[str, Any] | None = None) -> str:
        envelope = envelope or {}
        if envelope.get("is_error") or envelope.get("error"):
            return "failed"
        parsed = raw_result
        if isinstance(raw_result, str):
            try:
                parsed = json.loads(raw_result)
            except (json.JSONDecodeError, TypeError):
                parsed = None
        if isinstance(parsed, dict) and (
            parsed.get("is_error") or parsed.get("error")
            or str(parsed.get("status") or "").lower() in {"failed", "error", "rejected"}
            or parsed.get("accepted") is False
        ):
            return "failed"
        return "completed"

    @classmethod
    def _tool_call_detail(cls, tool: str, raw_detail: Any) -> str:
        parsed = raw_detail
        if isinstance(raw_detail, str):
            try:
                parsed = json.loads(raw_detail)
            except (json.JSONDecodeError, TypeError):
                parsed = raw_detail
        lowered = str(tool or "").lower()
        if lowered in {"exec_command", "command_execution"}:
            command = (
                parsed.get("cmd") or parsed.get("command") or ""
                if isinstance(parsed, dict) else parsed
            )
            if isinstance(command, (list, tuple)):
                parts = [str(part) for part in command]
            else:
                try:
                    parts = shlex.split(str(command or ""))
                except ValueError:
                    parts = str(command or "").split()
            if not parts:
                return "命令执行"
            shell_names = {"sh", "bash", "zsh", "dash", "ksh"}
            shell = Path(parts[0]).name
            if shell in shell_names:
                command_flag = next(
                    (index for index, part in enumerate(parts[1:], start=1)
                     if part.startswith("-") and not part.startswith("--") and "c" in part[1:]),
                    None,
                )
                if command_flag is not None and command_flag + 1 < len(parts):
                    try:
                        inner_parts = shlex.split(parts[command_flag + 1])
                    except ValueError:
                        inner_parts = parts[command_flag + 1].split()
                    if inner_parts:
                        parts = inner_parts
            visible_count = 2 if parts[0].endswith("danus-web-agent") else 1
            summary = " ".join(parts[:visible_count])
            hidden = isinstance(parsed, dict) and any(
                re.search(r"(?i)(key|token|secret|password|authorization|session|cookie|credential)", str(key))
                for key in parsed
            )
            suffix = "；敏感参数已隐藏" if hidden else ""
            return cls._redact_display_text(f"命令：{summary}{suffix}", 500)
        if isinstance(parsed, dict):
            secret_names = re.compile(r"(?i)(key|token|secret|password|authorization|session|cookie|credential)")
            keys = sorted(str(key) for key in parsed if not secret_names.search(str(key)))
            identity = {
                str(key): parsed[key]
                for key in ("project", "worker", "kind", "role")
                if key in parsed and not secret_names.search(str(key))
            }
            pieces = [f"参数字段：{', '.join(keys[:20])}" if keys else "无公开参数"]
            if identity:
                pieces.append(cls._safe_display_value(identity, 500))
            if len(keys) != len(parsed):
                pieces.append("敏感参数已隐藏")
            return "；".join(pieces)[:800]
        return "参数已隐藏"

    @classmethod
    def _codex_progress_events(cls, line: str) -> list[dict[str, Any]]:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            return []
        kind = item.get("type")
        payload = item.get("payload") or {}
        events: list[dict[str, Any]] = []

        def from_object(obj: Any, phase: str) -> None:
            if not isinstance(obj, dict):
                return
            item_type = obj.get("type")
            if item_type == "reasoning":
                # Codex may emit an explicit operator-safe reasoning summary.
                # Never expose encrypted/private reasoning content; only the
                # plaintext summary field supplied by the runtime is observable.
                summary = cls._text_value(obj.get("summary"))
                if summary:
                    events.append({
                        "type": "agent.progress",
                        "detail": cls._redact_display_text(summary, 4000),
                    })
                return
            if item_type in {"agent_message", "message"}:
                role = obj.get("role", "assistant")
                text = cls._message_text(obj)
                if role == "assistant" and text:
                    events.append({"type": "agent.message", "detail": cls._redact_display_text(text, 4000)})
                return
            if item_type in {
                "function_call", "custom_tool_call", "tool_search_call", "web_search_call",
                "mcp_tool_call", "tool_call",
            }:
                tool = obj.get("name") or obj.get("tool") or item_type
                raw_detail = obj.get("arguments") or obj.get("input") or obj.get("query") or ""
                events.append({
                    "type": "tool.started", "tool": cls._redact_display_text(str(tool), 120),
                    "detail": cls._tool_call_detail(str(tool), raw_detail),
                    "call_id": cls._redact_display_text(str(obj.get("call_id") or obj.get("id") or ""), 200),
                    "status": "started",
                })
                return
            if item_type in {
                "function_call_output", "custom_tool_call_output", "tool_search_output",
            }:
                events.append({
                    "type": "tool.completed", "tool": "tool result",
                    "detail": cls._tool_result_detail(obj.get("output") or obj.get("result") or ""),
                    "call_id": cls._redact_display_text(str(obj.get("call_id") or obj.get("id") or ""), 200),
                    "status": cls._tool_result_status(obj.get("output") or obj.get("result") or "", obj),
                })
                return
            if item_type == "command_execution":
                command = obj.get("command") or obj.get("cmd") or ""
                completed = phase == "completed"
                exit_code = obj.get("exit_code")
                events.append({
                    "type": "tool.completed" if completed else "tool.started",
                    "tool": "exec_command",
                    "detail": (
                        f"exit_code={exit_code if exit_code is not None else 'unknown'}; "
                        + cls._tool_result_detail(obj.get("aggregated_output") or obj.get("output") or "")
                    ) if completed else cls._tool_call_detail("exec_command", command),
                    "status": "failed" if completed and exit_code else "completed" if completed else "started",
                    "call_id": cls._redact_display_text(str(obj.get("id") or obj.get("call_id") or ""), 200),
                })
                return
            if item_type == "file_change":
                events.append({
                    "type": "tool.completed" if phase == "completed" else "tool.started",
                    "tool": "file_change",
                    "detail": "文件变更状态已更新（具体内容未展示）",
                })

        if kind in {"thread.started", "turn.started"}:
            events.append({
                "type": "turn.started", "detail": "Main Agent 会话已建立",
                "session_id": item.get("thread_id") or payload.get("session_id") or payload.get("id"),
            })
        elif kind == "turn.completed":
            events.append({"type": "turn.completed", "detail": "Main Agent 已完成本次回复"})
        elif kind == "turn.failed":
            error = item.get("error") or payload.get("error") or {}
            message = error.get("message") if isinstance(error, dict) else str(error or "")
            events.append({"type": "turn.failed", "detail": cls._redact_display_text(message or "Main Agent 执行失败")})
        elif kind == "response_item":
            from_object(payload, "completed")
        elif kind in {"item.started", "item.completed"}:
            from_object(item.get("item") or {}, "completed" if kind == "item.completed" else "started")
        elif kind == "response.completed":
            response = item.get("response") or payload.get("response") or {}
            for output in response.get("output", []) if isinstance(response, dict) else []:
                from_object(output, "completed")
        elif kind == "event_msg":
            event_type = payload.get("type")
            if event_type == "agent_message":
                text = cls._message_text(payload)
                if text:
                    events.append({"type": "agent.message", "detail": cls._redact_display_text(text, 4000)})
            elif event_type == "task_complete":
                if payload.get("error") is not None:
                    error = payload.get("error")
                    message = error.get("message") if isinstance(error, dict) else str(error or "")
                    events.append({"type": "turn.failed", "detail": cls._redact_display_text(message or "Main Agent 执行失败")})
                else:
                    events.append({"type": "turn.completed", "detail": "Main Agent 已完成本次回复"})
            elif event_type and "tool_call" in str(event_type):
                completed = str(event_type).endswith(("end", "completed"))
                events.append({
                    "type": "tool.completed" if completed else "tool.started",
                    "tool": cls._redact_display_text(str(payload.get("tool") or payload.get("name") or "MCP tool"), 120),
                    "detail": cls._tool_result_detail(payload.get("result") or payload.get("output") or payload.get("error") or "") if completed else cls._tool_call_detail(str(payload.get("tool") or payload.get("name") or "MCP tool"), payload.get("arguments") or payload.get("input") or {}),
                    "status": "failed" if payload.get("error") else "completed" if completed else "started",
                    "call_id": cls._redact_display_text(str(payload.get("call_id") or payload.get("id") or ""), 200),
                })
        return events

    @classmethod
    def _claude_progress_events(cls, line: str) -> list[dict[str, Any]]:
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            return []
        kind = item.get("type")
        events: list[dict[str, Any]] = []
        if kind == "system" and item.get("subtype") == "init":
            events.append({
                "type": "turn.started", "detail": "Main Agent 会话已建立",
                "session_id": item.get("session_id"),
            })
        elif kind == "assistant":
            message = item.get("message") or {}
            for block in message.get("content", []) if isinstance(message, dict) else []:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "text" and block.get("text"):
                    events.append({
                        "type": "agent.message",
                        "detail": cls._redact_display_text(str(block["text"]), 4000),
                    })
                elif block.get("type") == "tool_use":
                    events.append({
                        "type": "tool.started",
                        "tool": cls._redact_display_text(str(block.get("name") or "tool"), 120),
                        "call_id": cls._redact_display_text(str(block.get("id") or ""), 200),
                        "status": "started",
                        "detail": cls._tool_call_detail(
                            str(block.get("name") or "tool"), block.get("input") or {},
                        ),
                    })
        elif kind == "user":
            message = item.get("message") or {}
            for block in message.get("content", []) if isinstance(message, dict) else []:
                if not isinstance(block, dict) or block.get("type") != "tool_result":
                    continue
                events.append({
                    "type": "tool.completed", "tool": "tool result",
                    "call_id": cls._redact_display_text(str(block.get("tool_use_id") or ""), 200),
                    "status": "failed" if block.get("is_error") else "completed",
                    "detail": cls._tool_result_detail(block.get("content") or ""),
                })
        elif kind == "result":
            failed = bool(item.get("is_error") or item.get("subtype") != "success")
            duration_ms = item.get("duration_ms")
            events.append({
                "type": "turn.failed" if failed else "turn.completed",
                "status": "failed" if failed else "completed",
                "detail": cls._redact_display_text(
                    str(item.get("error") or ("Main Agent 执行失败" if failed else "Main Agent 已完成本次回复")),
                    1200,
                ),
                "duration_seconds": float(duration_ms) / 1000 if isinstance(duration_ms, (int, float)) else None,
                "session_id": item.get("session_id") or item.get("sessionId"),
            })
        return events

    @classmethod
    def _parse_codex(cls, stdout: str) -> tuple[str | None, str]:
        thread_id = None
        reply = ""
        for line in (stdout or "").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind = item.get("type")
            payload = item.get("payload") or {}
            if kind == "thread.started":
                thread_id = item.get("thread_id") or thread_id
            elif kind == "session_meta":
                thread_id = payload.get("session_id") or payload.get("id") or thread_id
            if kind == "item.completed":
                obj = item.get("item") or {}
                if obj.get("type") in {"agent_message", "message"} and obj.get("role", "assistant") == "assistant":
                    reply = cls._message_text(obj) or reply
            elif kind == "event_msg" and payload.get("type") == "agent_message":
                reply = cls._message_text(payload) or reply
            elif kind == "event_msg" and payload.get("type") == "task_complete":
                reply = cls._text_value(payload.get("last_agent_message")) or reply
            elif kind in {"response.output_text.done", "response.completed"}:
                reply = cls._message_text(item) or cls._message_text(payload) or reply
        return thread_id, reply.strip()

    @staticmethod
    def _codex_terminal_state(stdout: str) -> str | None:
        state = None
        for line in (stdout or "").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind = item.get("type")
            payload = item.get("payload") or {}
            if kind == "event_msg" and payload.get("type") == "task_complete":
                state = "failed" if payload.get("error") is not None else "completed"
            elif kind in {"turn.failed", "response.failed", "error"}:
                state = "failed"
            elif kind == "turn.completed":
                state = "completed"
            elif kind == "response.completed":
                response = item.get("response") or payload.get("response") or {}
                failed = isinstance(response, dict) and (
                    response.get("error") is not None
                    or response.get("status") in {"failed", "cancelled", "incomplete"}
                )
                state = "failed" if failed else "completed"
        return state

    @classmethod
    def _parse_codex_failure(cls, stdout: str) -> tuple[str | None, str] | None:
        """Extract the final structured provider failure from Codex JSON events."""
        failure = None
        for line in (stdout or "").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind = item.get("type")
            payload = item.get("payload") or {}
            error = None
            has_terminal_error = False
            if kind == "event_msg" and payload.get("type") == "task_complete" and "error" in payload:
                error = payload.get("error")
                has_terminal_error = True
            elif kind in {"turn.failed", "response.failed", "error"}:
                error = item.get("error") or payload.get("error") or payload or item
                has_terminal_error = True
            if not has_terminal_error:
                continue
            if isinstance(error, dict):
                code = error.get("codex_error_info") or error.get("code") or error.get("type")
                message = cls._text_value(error.get("message")) or cls._text_value(error)
            else:
                code = None
                message = cls._text_value(error)
            safe_message = message.strip() if message else "Codex reported a terminal error."
            failure = (str(code) if code else None, safe_message)
        return failure


    @staticmethod
    def _codex_activity(stdout: str) -> tuple[bool, bool]:
        """Return (tool activity observed, parse uncertain) for retry safety."""
        observed_tool_activity = False
        parse_uncertain = False
        passive_item_types = {"agent_message", "message", "reasoning"}
        tool_item_types = {
            "command_execution", "file_change", "function_call", "function_call_output",
            "mcp_tool_call", "tool_call", "tool_search_call", "tool_search_output",
            "custom_tool_call", "custom_tool_call_output", "web_search_call",
        }
        passive_event_types = {
            "task_started", "task_complete", "user_message", "agent_message", "token_count",
        }
        for line in (stdout or "").splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                parse_uncertain = True
                continue
            kind = item.get("type")
            payload = item.get("payload") or {}
            if kind == "response_item":
                item_type = payload.get("type")
                if item_type in tool_item_types:
                    observed_tool_activity = True
                elif item_type not in passive_item_types:
                    parse_uncertain = True
            elif kind in {"item.started", "item.completed"}:
                nested = item.get("item") or {}
                item_type = nested.get("type")
                if item_type in tool_item_types:
                    observed_tool_activity = True
                elif item_type not in passive_item_types:
                    parse_uncertain = True
            elif kind == "response.completed":
                response = item.get("response") or payload.get("response") or {}
                output = response.get("output") if isinstance(response, dict) else None
                if not isinstance(output, list):
                    parse_uncertain = True
                for nested in output or []:
                    item_type = nested.get("type") if isinstance(nested, dict) else None
                    if item_type in tool_item_types:
                        observed_tool_activity = True
                    elif item_type not in passive_item_types:
                        parse_uncertain = True
            elif kind == "event_msg":
                event_type = payload.get("type")
                if event_type and (
                    "tool_call" in str(event_type)
                    or str(event_type).startswith(("exec_", "command_", "file_change"))
                ):
                    observed_tool_activity = True
                elif event_type not in passive_event_types:
                    parse_uncertain = True
            elif kind not in {
                "thread.started", "turn.started", "turn.completed",
                "session_meta", "world_state", "turn_context",
                "response.output_text.done", "turn.failed",
                "response.failed", "error",
            }:
                parse_uncertain = True
        return observed_tool_activity, parse_uncertain

    @staticmethod
    def _codex_mcp_config(root: Path, env: dict[str, str]) -> str:
        """Return one TOML inline-table override for the scoped Danus MCP."""
        def q(value: str) -> str:
            return json.dumps(str(value), ensure_ascii=False)
        python = env.get("DANUS_PY") or sys.executable
        fields = [
            f"command={q(python)}",
            'args=["-m","danus.gateway"]',
            "tool_timeout_sec=3600",
            "env={" + ",".join([
                f"DANUS_ROLE={q('main')}",
                f"DANUS_AUTHOR={q('main_agent')}",
                f"DANUS_PROJECT_DIR={q(root)}",
                f"DANUS_AGENTS_ROOT={q(root.parent)}",
                f"DANUS_PROJECT_SCOPE={q(root.name)}",
                f"DANUS_VERIFY_URL={q(env.get('DANUS_VERIFY_URL', ''))}",
                f"PYTHONPATH={q(str(Path(__file__).resolve().parents[2]))}",
            ]) + "}",
        ]
        return "mcp_servers.danus={" + ",".join(fields) + "}"

    def _send_codex(self, *, root: Path, session_id: str | None, prompt: str,
                    env: dict[str, str], on_progress: Callable[[dict[str, Any]], None] | None = None) -> dict[str, Any]:
        model = self.model or env.get("DANUS_CODEX_MODEL") or env.get("CODEX_API_MODEL")
        provider_base_url = env.get("OPENAI_BASE_URL") or env.get("CODEX_API_BASE_URL")
        provider_key_env = (
            "OPENAI_API_KEY" if env.get("OPENAI_API_KEY")
            else "DANUS_CODEX_API_KEY" if env.get("DANUS_CODEX_API_KEY")
            else None
        )
        direct_provider = bool(provider_base_url and provider_key_env)
        if direct_provider and not model:
            # The direct endpoint may not expose the model configured in the
            # operator's personal Codex home. Use the broadly available model
            # verified for Danus unless the server explicitly selects one.
            model = "gpt-5.5"
        effort = self.effort or env.get("DANUS_CODEX_EFFORT", "xhigh")
        mcp_config = self._codex_mcp_config(root, env)
        # The Main Agent needs to write Project-owned orchestration files through
        # the narrow broker. Codex auto-reviews approval requests and confines
        # approved commands to its workspace-write policy rooted at `cwd=root`;
        # the prompt and broker further constrain the lifecycle vocabulary.
        common = ["--json"]
        if direct_provider:
            provider_config = "model_providers.danus_web={" + ",".join([
                f"name={json.dumps('Danus Web API')}",
                f"base_url={json.dumps(provider_base_url)}",
                f"env_key={json.dumps(provider_key_env)}",
                f"wire_api={json.dumps('responses')}",
            ]) + "}"
            common += [
                "--config", 'model_provider="danus_web"',
                "--config", provider_config,
            ]
        if model:
            common += ["--model", model]
        common += ["--config", f'model_reasoning_effort="{effort}"',
                   "--approve-for-me",
                   "--skip-git-repo-check", "-C", str(root), "--config", mcp_config]

        def command(resume_id: str | None) -> list[str]:
            cmd = [self.codex_bin, "exec", *common]
            if resume_id:
                # Codex's resume parser accepts the common exec options only when
                # they precede the `resume` subcommand.
                cmd += ["resume", resume_id, "-"]
            else:
                cmd += ["-"]
            return cmd

        retryable_codes = {
            "server_overloaded", "rate_limit_exceeded", "service_unavailable",
            "upstream_timeout", "request_timeout", "timeout",
        }
        continuation = (
            "Continue the interrupted Main Agent turn after a transient provider failure. "
            "Do not repeat completed side effects. Inspect current Project state before any "
            "write, finish the remaining orchestration work, and return the final operator reply."
        )
        started = time.monotonic()
        active_session_id = session_id
        active_prompt = prompt
        last_progress_signature: tuple[Any, ...] | None = None
        tool_started_at: dict[str, float] = {}

        def emit_stdout_line(line: str) -> None:
            nonlocal last_progress_signature
            if on_progress is None:
                return
            for event in self._codex_progress_events(line):
                call_id = str(event.get("call_id") or "")
                if event.get("type") == "tool.started" and call_id:
                    tool_started_at[call_id] = time.monotonic()
                elif event.get("type") == "tool.completed" and call_id in tool_started_at:
                    event["duration_seconds"] = round(time.monotonic() - tool_started_at.pop(call_id), 3)
                if event.get("type") in {"turn.completed", "turn.failed"}:
                    event["duration_seconds"] = round(time.monotonic() - started, 3)
                signature = (
                    event.get("type"), event.get("tool"), event.get("detail"),
                    event.get("status"), event.get("call_id"),
                )
                if signature == last_progress_signature:
                    continue
                last_progress_signature = signature
                # Persistence is part of the control-plane audit boundary. A
                # failed sink aborts the turn instead of silently losing events.
                on_progress(event)

        for attempt in range(1, self.max_attempts + 1):
            try:
                result = self._runner(
                    command(active_session_id), input=active_prompt, cwd=str(root),
                    env=env, timeout=self.timeout, on_stdout_line=emit_stdout_line,
                )
            except subprocess.TimeoutExpired as exc:
                partial = getattr(exc, "stdout", None) or getattr(exc, "output", None) or ""
                if isinstance(partial, bytes):
                    partial = partial.decode("utf-8", errors="replace")
                actual_id, _ = self._parse_codex(str(partial))
                observed_tool_activity, _ = self._codex_activity(str(partial))
                raise MainAgentError(
                    "main agent turn timed out", code="timeout",
                    session_id=actual_id or active_session_id,
                    attempts=attempt, observed_tool_activity=observed_tool_activity,
                ) from exc
            except (FileNotFoundError, PermissionError, OSError) as exc:
                raise MainAgentError(
                    f"main agent process could not start: {exc}",
                    session_id=active_session_id, attempts=attempt,
                ) from exc

            stdout = getattr(result, "stdout", "") or ""
            actual_id, reply = self._parse_codex(stdout)
            failure = self._parse_codex_failure(stdout)
            terminal_state = self._codex_terminal_state(stdout)
            observed_tool_activity, parse_uncertain = self._codex_activity(stdout)
            chosen_id = actual_id or active_session_id
            if getattr(result, "returncode", 1) == 0 and reply and failure is None and terminal_state == "completed":
                if not chosen_id:
                    raise MainAgentError(
                        "main agent returned no session identity", attempts=attempt,
                    )
                return {
                    "session_id": chosen_id,
                    "reply": self._redact_display_text(reply, max(1, len(reply) + 1)),
                    "status": "completed", "seconds": round(time.monotonic() - started, 1),
                    "read_status": "unknown", "attempts": attempt,
                }

            code, structured_detail = failure or (None, "")
            stderr_detail = (getattr(result, "stderr", "") or "").strip()[-300:]
            if terminal_state is None and not structured_detail and not stderr_detail:
                structured_detail = "main agent returned without a terminal completion event"
            retryable = bool(code in retryable_codes)
            automatic_retry_safe = not observed_tool_activity and not parse_uncertain
            if retryable and automatic_retry_safe and attempt < self.max_attempts and chosen_id:
                delay = min(self.retry_cap_seconds, self.retry_base_seconds * (2 ** (attempt - 1)))
                if on_progress is not None:
                    safe_retry_detail = self._redact_display_text(structured_detail, 1200)
                    on_progress({
                        "type": "turn.retry",
                        "status": "retrying",
                        "attempt": attempt + 1,
                        "max_attempts": self.max_attempts,
                        "delay_seconds": delay,
                        "error_code": code,
                        "message": safe_retry_detail,
                        "detail": safe_retry_detail,
                        "session_id": chosen_id,
                    })
                self._sleeper(delay)
                active_session_id = chosen_id
                active_prompt = continuation
                continue

            detail = (structured_detail or stderr_detail).strip()[-300:]
            code_label = f" [{code}]" if code else ""
            raise MainAgentError(
                "main agent turn failed" + code_label + (f": {detail}" if detail else ""),
                code=code, session_id=chosen_id, retryable=retryable,
                safe_to_retry=retryable and automatic_retry_safe,
                attempts=attempt, observed_tool_activity=observed_tool_activity,
            )

        raise MainAgentError(
            "main agent turn failed", session_id=active_session_id,
            attempts=self.max_attempts,
        )


    def _send_claude(
        self, *, root: Path, session_id: str | None, prompt: str, env: dict[str, str],
        on_progress: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        repo = Path(__file__).resolve().parents[2]
        contract = repo / "agents" / "contracts" / "web_main_agent.md"
        if not contract.is_file() or not os.access(contract, os.R_OK):
            raise MainAgentError("main agent contract is unavailable")
        if session_id:
            try:
                uuid.UUID(str(session_id))
            except (ValueError, AttributeError) as exc:
                raise MainAgentError("stored Claude session identity is invalid") from exc
        mcp = {"mcpServers": {"danus": {
            "type": "stdio", "command": os.environ.get("DANUS_PY", sys.executable),
            "args": ["-m", "danus.gateway"],
            "env": {"DANUS_ROLE": "main", "DANUS_AUTHOR": "main_agent",
                    "DANUS_PROJECT_DIR": str(root), "DANUS_AGENTS_ROOT": str(root.parent),
                    "DANUS_PROJECT_SCOPE": root.name,
                    "DANUS_VERIFY_URL": env.get("DANUS_VERIFY_URL", ""),
                    "PYTHONPATH": env.get("PYTHONPATH", str(repo))},
        }}}
        new_session = session_id is None
        sid = session_id or str(uuid.uuid4())
        allowed = ["Read", "Glob", "Grep", "Bash(danus-web-agent status)", "Bash(danus-web-agent assign *)", "Bash(danus-web-agent start)", "Bash(danus-web-agent pause *)", "Bash(danus-web-agent resume *)", "Bash(danus-web-agent stop)",
                   "mcp__danus__gm_add", "mcp__danus__gm_search",
                   "mcp__danus__fact_search", "mcp__danus__fact_revoke",
                   "mcp__danus__search_arxiv_theorems"]
        cmd = [self.claude_bin, "-p", "--output-format", "stream-json", "--verbose", "--permission-mode", "dontAsk",
               "--setting-sources", "", "--strict-mcp-config", "--mcp-config", json.dumps(mcp),
               "--system-prompt-file", str(contract), "--add-dir", str(root),
               "--allowed-tools", *allowed, "--session-id" if new_session else "--resume", sid]
        started = time.monotonic()
        try:
            tool_started_at: dict[str, tuple[float, str]] = {}

            def emit_stdout_line(line: str) -> None:
                if on_progress is None:
                    return
                for event in self._claude_progress_events(line):
                    call_id = str(event.get("call_id") or "")
                    if event.get("type") == "tool.started" and call_id:
                        tool_started_at[call_id] = (
                            time.monotonic(), str(event.get("tool") or "tool"),
                        )
                    elif event.get("type") == "tool.completed" and call_id in tool_started_at:
                        started_at, tool_name = tool_started_at.pop(call_id)
                        event["tool"] = tool_name
                        event["duration_seconds"] = round(time.monotonic() - started_at, 3)
                    on_progress(event)

            result = self._runner(
                cmd, input=prompt, cwd=str(root), env=env, timeout=self.timeout,
                on_stdout_line=emit_stdout_line,
            )
        except subprocess.TimeoutExpired as exc:
            raise MainAgentError("main agent turn timed out") from exc
        except (FileNotFoundError, PermissionError, OSError) as exc:
            raise MainAgentError(f"main agent process could not start: {exc}") from exc
        parsed = None
        for line in reversed((getattr(result, "stdout", "") or "").splitlines()):
            try:
                parsed = json.loads(line)
                break
            except json.JSONDecodeError:
                continue
        if getattr(result, "returncode", 1) != 0 or (not parsed or parsed.get("type") != "result" or parsed.get("is_error")
                or parsed.get("subtype") != "success" or not (parsed.get("result") or "").strip()):
            raise MainAgentError("main agent returned no successful reply")
        returned_id = parsed.get("session_id") or parsed.get("sessionId")
        try:
            uuid.UUID(str(returned_id))
        except (ValueError, AttributeError) as exc:
            raise MainAgentError("main agent returned an invalid session identity") from exc
        reply = str(parsed["result"]).strip()
        return {"session_id": returned_id, "reply": self._redact_display_text(reply, max(1, len(reply) + 1)),
                "status": "completed", "seconds": round(time.monotonic() - started, 1),
                "read_status": parsed.get("read_status", "unknown")}

    def send(self, *, context_dir: Path, session_id: str | None, message: str,
             manifest: list[dict[str, Any]], project_state: dict[str, Any],
             attachments: list[dict[str, Any]],
             on_progress: Callable[[dict[str, Any]], None] | None = None,
             lifecycle_url: str | None = None,
             lifecycle_token: str | None = None) -> dict[str, Any]:
        raw_root = Path(context_dir)
        if raw_root.is_symlink():
            raise MainAgentError("project context directory must not be a symlink")
        root = raw_root.resolve()
        if not root.is_dir():
            raise MainAgentError("project context directory not found")
        if not isinstance(message, str) or not message.strip():
            raise MainAgentError("message must be non-empty")
        prompt = self._prompt(message=message, manifest=manifest, project_state=project_state, attachments=attachments)
        env = self._env(
            root,
            lifecycle_url=lifecycle_url,
            lifecycle_token=lifecycle_token,
        )
        result = self._send_codex(
            root=root, session_id=session_id, prompt=prompt, env=env,
            on_progress=on_progress,
        ) if self.backend == "codex" else self._send_claude(
            root=root, session_id=session_id, prompt=prompt, env=env,
            on_progress=on_progress,
        )
        return result
