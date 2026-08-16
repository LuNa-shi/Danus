"""Project-scoped Main Agent session adapter."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from danus.strategy.config import resolve_transport

from .runtime import RuntimeErrorBase


class MainAgentError(RuntimeErrorBase):
    pass


class MainAgentAdapter:
    """Launch/resume one explicit Main Agent session per Project.

    Codex is the default because the deployment has a configured OpenAI-compatible
    Codex backend. Claude Code remains available as an explicit server-side
    backend when its own authentication is configured. The runner is injectable
    for HTTP-boundary tests.
    """

    def __init__(self, *, runner: Callable[..., Any] | None = None, backend: str = "codex",
                 claude_bin: str = "claude", codex_bin: str = "codex", model: str | None = None,
                 effort: str | None = None, timeout: float = 900.0):
        if backend not in {"codex", "claude"}:
            raise ValueError("main-agent backend must be codex or claude")
        self.backend = backend
        self.claude_bin = os.environ.get("DANUS_WEB_CLAUDE_BIN", claude_bin)
        self.codex_bin = codex_bin if codex_bin != "codex" else os.environ.get("DANUS_CODEX_BIN") or self._resolve_codex()
        self.model = model
        self.effort = effort
        self.timeout = timeout
        self._runner = runner or self._default_runner

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
    def _default_runner(cmd, *, input, cwd, env, timeout):
        return subprocess.run(cmd, input=input, capture_output=True, text=True, cwd=cwd, env=env, timeout=timeout)

    def _prompt(self, *, message: str, manifest: list[dict[str, Any]], project_state: dict[str, Any], attachments: list[dict[str, Any]]) -> str:
        repo = Path(__file__).resolve().parents[2]
        contract = repo / "agents" / "contracts" / "main_agent.md"
        contract_text = contract.read_text(encoding="utf-8") if contract.is_file() else ""
        strategy_transport = resolve_transport(None)
        if strategy_transport == "off":
            strategy_policy = (
                "SERVER STRATEGY POLICY: strategy consult is OFF for this deployment. "
                "Do not invoke `consult` or any external strategy model. Use your Main Agent "
                "orchestration judgment to record the elaboration and master_guidance through "
                "the project-scoped Danus MCP tools, then assign Workers through `danus-web-agent`."
            )
        else:
            strategy_policy = (
                f"SERVER STRATEGY POLICY: strategy consult transport is {strategy_transport}. "
                "Use the server-configured transport and model; do not hard-code or substitute a model id."
            )
        return "\n".join([
            "You are the Danus Main Agent for exactly one Project.",
            "Follow the Main Agent contract below. Retain strategic orchestration authority; do not submit facts directly.",
            "Use the project-scoped `danus-web-agent` command for status, assignment, and graceful worker lifecycle coordination. It is the only allowed lifecycle command and is pinned to this Project. Do not edit Danus source code or access another Project. Use the Danus MCP tools for scoped memory and Fact Graph oversight; never submit facts as Main Agent.",
            strategy_policy,
            "MAIN AGENT CONTRACT:\n" + contract_text,
            "The Web Console supplies this project state and material manifest explicitly.",
            "Project state:", json.dumps(project_state, ensure_ascii=False, sort_keys=True),
            "Project File Manifest:", json.dumps(manifest, ensure_ascii=False, sort_keys=True),
            "Selected Conversation Attachments (read these first):", json.dumps(attachments, ensure_ascii=False, sort_keys=True),
            "Operator message:", message,
        ])

    def _env(self, root: Path) -> dict[str, str]:
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
            "DANUS_ROOT": str(repo),
            # Pin the MCP server to the interpreter running the Web Console when
            # scripts/env.sh did not explicitly provide a Danus runtime Python.
            "DANUS_PY": env.get("DANUS_PY") or sys.executable,
            # Codex runs from the Project context, not the source checkout. In a
            # developer launch without bootstrap's installed venv, the scoped
            # lifecycle CLI and MCP gateway still need to import this checkout.
            # Do not inherit an arbitrary host PYTHONPATH; expose only Danus.
            "PYTHONPATH": str(repo),
        })
        # A project-scoped main session must be able to invoke the repository's
        # lifecycle CLI, whose wrapper sources scripts/env.sh. Keep the repo bin
        # directory ahead of the inherited PATH without exposing arbitrary cwd.
        bin_dirs = [str(repo / "bin")]
        codex_dir = os.path.dirname(os.path.abspath(self.codex_bin)) if os.path.dirname(self.codex_bin) else ""
        if codex_dir:
            bin_dirs.append(codex_dir)
        path_parts = env.get("PATH", "").split(os.pathsep) if env.get("PATH") else []
        for bin_dir in reversed(bin_dirs):
            if bin_dir not in path_parts:
                env["PATH"] = bin_dir + (os.pathsep + env.get("PATH", "") if env.get("PATH") else "")
                path_parts.insert(0, bin_dir)
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
                f"PYTHONPATH={q(env.get('PYTHONPATH', ''))}",
            ]) + "}",
        ]
        return "mcp_servers.danus={" + ",".join(fields) + "}"

    def _send_codex(self, *, root: Path, session_id: str | None, prompt: str, env: dict[str, str]) -> dict[str, Any]:
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
        cmd = [self.codex_bin, "exec", *common]
        if session_id:
            # Codex's resume parser accepts the common exec options only when
            # they precede the `resume` subcommand.
            cmd += ["resume", session_id, "-"]
        else:
            cmd += ["-"]
        started = time.monotonic()
        try:
            result = self._runner(cmd, input=prompt, cwd=str(root), env=env, timeout=self.timeout)
        except subprocess.TimeoutExpired as exc:
            raise MainAgentError("main agent turn timed out") from exc
        except (FileNotFoundError, PermissionError, OSError) as exc:
            raise MainAgentError(f"main agent process could not start: {exc}") from exc
        actual_id, reply = self._parse_codex(getattr(result, "stdout", ""))
        if getattr(result, "returncode", 1) != 0 or not reply:
            detail = (getattr(result, "stderr", "") or "").strip()[-300:]
            raise MainAgentError("main agent turn failed" + (f": {detail}" if detail else ""))
        chosen_id = actual_id or session_id
        if not chosen_id:
            raise MainAgentError("main agent returned no session identity")
        return {"session_id": chosen_id, "reply": reply,
                "status": "completed", "seconds": round(time.monotonic() - started, 1),
                "read_status": "unknown"}

    def _send_claude(self, *, root: Path, session_id: str | None, prompt: str, env: dict[str, str]) -> dict[str, Any]:
        repo = Path(__file__).resolve().parents[2]
        contract = repo / "agents" / "contracts" / "main_agent.md"
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
        allowed = ["Read", "Glob", "Grep", "Bash(danus-web-agent status)", "Bash(danus-web-agent assign *)", "Bash(danus-web-agent start)", "Bash(danus-web-agent stop)",
                   "mcp__danus__gm_add", "mcp__danus__gm_search",
                   "mcp__danus__fact_search", "mcp__danus__fact_revoke",
                   "mcp__danus__search_arxiv_theorems"]
        cmd = [self.claude_bin, "-p", "--output-format", "json", "--permission-mode", "dontAsk",
               "--setting-sources", "", "--strict-mcp-config", "--mcp-config", json.dumps(mcp),
               "--system-prompt-file", str(contract), "--add-dir", str(root),
               "--allowed-tools", *allowed, "--session-id" if new_session else "--resume", sid]
        started = time.monotonic()
        try:
            result = self._runner(cmd, input=prompt, cwd=str(root), env=env, timeout=self.timeout)
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
        return {"session_id": returned_id, "reply": parsed["result"].strip(),
                "status": "completed", "seconds": round(time.monotonic() - started, 1),
                "read_status": parsed.get("read_status", "unknown")}

    def send(self, *, context_dir: Path, session_id: str | None, message: str, manifest: list[dict[str, Any]], project_state: dict[str, Any], attachments: list[dict[str, Any]]) -> dict[str, Any]:
        raw_root = Path(context_dir)
        if raw_root.is_symlink():
            raise MainAgentError("project context directory must not be a symlink")
        root = raw_root.resolve()
        if not root.is_dir():
            raise MainAgentError("project context directory not found")
        if not isinstance(message, str) or not message.strip():
            raise MainAgentError("message must be non-empty")
        prompt = self._prompt(message=message, manifest=manifest, project_state=project_state, attachments=attachments)
        result = self._send_codex(root=root, session_id=session_id, prompt=prompt, env=self._env(root)) if self.backend == "codex" else self._send_claude(root=root, session_id=session_id, prompt=prompt, env=self._env(root))
        return result
