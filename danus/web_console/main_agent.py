"""Project-scoped Main Agent session adapter."""
from __future__ import annotations

import json
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from .runtime import RuntimeErrorBase


class MainAgentError(RuntimeErrorBase):
    pass


class MainAgentAdapter:
    """Launch/resume one explicit Claude Code session per Project.

    The runner is injectable. The adapter never uses the stateless strategy
    consult transport and never starts from the repository root.
    """

    def __init__(self, *, runner: Callable[..., Any] | None = None, claude_bin: str = "claude", timeout: float = 900.0):
        self.claude_bin = claude_bin
        self.timeout = timeout
        self._runner = runner or self._default_runner

    @staticmethod
    def _default_runner(cmd, *, input, cwd, env, timeout):
        return subprocess.run(cmd, input=input, capture_output=True, text=True, cwd=cwd, env=env, timeout=timeout)

    def _prompt(self, *, message: str, manifest: list[dict[str, Any]], project_state: dict[str, Any], attachments: list[dict[str, Any]]) -> str:
        return "\n".join([
            "You are the Danus Main Agent for exactly one Project.",
            "Retain strategic orchestration authority; do not submit facts directly.",
            "The Web Console supplies this project state and material manifest explicitly.",
            "Project state:", json.dumps(project_state, ensure_ascii=False, sort_keys=True),
            "Project File Manifest:", json.dumps(manifest, ensure_ascii=False, sort_keys=True),
            "Selected Conversation Attachments (read these first):", json.dumps(attachments, ensure_ascii=False, sort_keys=True),
            "Operator message:", message,
        ])

    def send(self, *, context_dir: Path, session_id: str | None, message: str, manifest: list[dict[str, Any]], project_state: dict[str, Any], attachments: list[dict[str, Any]]) -> dict[str, Any]:
        root = Path(context_dir).resolve()
        if not root.is_dir():
            raise MainAgentError("project context directory not found")
        if not message.strip():
            raise MainAgentError("message must be non-empty")
        prompt = self._prompt(message=message, manifest=manifest, project_state=project_state, attachments=attachments)
        new_session = session_id is None
        session_id = session_id or str(uuid.uuid4())
        cmd = [self.claude_bin, "-p", "--output-format", "json", "--permission-mode", "bypassPermissions", "--setting-sources", "", "--strict-mcp-config", "--session-id" if new_session else "--resume", session_id]
        env = {"DANUS_ROLE": "main", "DANUS_AUTHOR": "main_agent", "DANUS_PROJECT_DIR": str(root), "DANUS_AGENTS_ROOT": str(root.parent), "PATH": __import__("os").environ.get("PATH", "")}
        started = time.time()
        try:
            result = self._runner(cmd, input=prompt, cwd=str(root), env=env, timeout=self.timeout)
        except subprocess.TimeoutExpired as exc:
            raise MainAgentError("main agent turn timed out") from exc
        if getattr(result, "returncode", 1) != 0:
            raise MainAgentError("main agent turn failed")
        parsed = None
        for line in reversed((getattr(result, "stdout", "") or "").splitlines()):
            try:
                parsed = json.loads(line)
                break
            except json.JSONDecodeError:
                continue
        if not parsed or not (parsed.get("result") or "").strip():
            raise MainAgentError("main agent returned no reply")
        return {"session_id": session_id, "reply": parsed["result"], "status": "completed", "seconds": round(time.time() - started, 1), "read_status": parsed.get("read_status", "unknown")}
