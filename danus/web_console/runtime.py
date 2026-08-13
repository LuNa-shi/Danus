"""Adapter from the Web Console control plane to Danus runtime APIs."""
from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

from danus.execution import layout as L
from danus.execution.scaffold import atomic_write
from danus.orchestration import cli

_PROJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


class RuntimeErrorBase(Exception):
    pass


class RuntimeNotFound(RuntimeErrorBase):
    pass


class RuntimeOperationError(RuntimeErrorBase):
    pass


def validate_runtime_name(name: str) -> str:
    if not isinstance(name, str) or not _PROJECT_RE.fullmatch(name):
        raise ValueError("invalid project name")
    return name


class DanusRuntimeAdapter:
    """Project-scoped runtime adapter; all process/filesystem authority stays in Danus."""

    def __init__(self, agents_root: Path | None = None):
        # The adapter is constructed once with a server-owned root.
        self.agents_root = Path(agents_root).resolve() if agents_root else L.agents_root()

    def _project_dir(self, runtime_name: str) -> Path:
        validate_runtime_name(runtime_name)
        project = (self.agents_root / runtime_name).resolve()
        if project.parent != self.agents_root or not project.is_dir():
            raise RuntimeNotFound(runtime_name)
        return project

    def list_projects(self) -> list[dict[str, Any]]:
        return self._call(cli.do_list)

    def create_project(self, runtime_name: str, problem: str, roles: str, model: str | None = None) -> dict[str, Any]:
        validate_runtime_name(runtime_name)
        if not isinstance(problem, str) or not problem.strip():
            raise ValueError("problem must be non-empty")
        try:
            result = cli.do_new(runtime_name, roles=roles, model=model, root=self.agents_root)
            project = Path(result["project_dir"]).resolve()
            if project.parent != self.agents_root:
                raise RuntimeOperationError("runtime returned project outside configured root")
            atomic_write(project / "PROBLEM.md", problem if problem.endswith("\n") else problem + "\n")
            return result
        except (SystemExit, ValueError) as exc:
            raise RuntimeOperationError(str(exc)) from exc

    def _call(self, fn, *args, **kwargs):
        try:
            return fn(*args, root=self.agents_root, **kwargs)
        except SystemExit as exc:
            raise RuntimeOperationError(str(exc)) from exc

    def start_project(self, runtime_name: str) -> dict[str, Any]:
        self._project_dir(runtime_name)
        return {"workers": self._call(cli.do_start, runtime_name)}

    def stop_project(self, runtime_name: str) -> dict[str, Any]:
        self._project_dir(runtime_name)
        return {"workers": self._call(cli.do_stop, runtime_name, force=False)}

    def status_project(self, runtime_name: str) -> dict[str, Any]:
        self._project_dir(runtime_name)
        return {"workers": self._call(cli.do_status, runtime_name)}

    def write_deadline(self, runtime_name: str, deadline: float) -> None:
        project = self._project_dir(runtime_name)
        if deadline <= time.time():
            raise ValueError("deadline must be in the future")
        atomic_write(project / L.DEADLINE_FILE, f"{deadline:.6f}\n")
