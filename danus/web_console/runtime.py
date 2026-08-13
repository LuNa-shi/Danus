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
        candidate = self.agents_root / runtime_name
        # Check the directory entry before resolving it: a symlinked project root
        # must never become a trusted context or deletion target.
        if candidate.is_symlink():
            raise RuntimeOperationError("project root must not be a symlink")
        project = candidate.resolve()
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
        except (SystemExit, ValueError, OSError) as exc:
            raise RuntimeOperationError(str(exc)) from exc

    def _call(self, fn, *args, **kwargs):
        try:
            return fn(*args, root=self.agents_root, **kwargs)
        except SystemExit as exc:
            message = str(exc)
            if "no workers for target" in message and fn in (cli.do_status, cli.do_start, cli.do_stop):
                return []
            raise RuntimeOperationError(message) from exc

    def start_project(self, runtime_name: str) -> dict[str, Any]:
        self._project_dir(runtime_name)
        return {"workers": self._call(cli.do_start, runtime_name)}

    def stop_project(self, runtime_name: str) -> dict[str, Any]:
        self._project_dir(runtime_name)
        return {"workers": self._call(cli.do_stop, runtime_name, force=False)}

    def status_project(self, runtime_name: str) -> dict[str, Any]:
        self._project_dir(runtime_name)
        return {"workers": self._call(cli.do_status, runtime_name)}

    def _safe_relative_files(self, runtime_name: str, relative: str, *, limit: int = 1000) -> list[dict[str, Any]]:
        root = self._project_dir(runtime_name)
        target = (root / relative).resolve()
        if root not in target.parents and target != root:
            raise RuntimeOperationError("projection path escapes project")
        if not target.is_dir():
            return []
        rows = []
        for path in sorted(target.rglob("*")):
            if len(rows) >= limit:
                break
            if not path.is_file() or path.is_symlink():
                continue
            try:
                rows.append({"name": str(path.relative_to(root)), "size": path.stat().st_size})
            except OSError:
                continue
        return rows

    def logs_projection(self, runtime_name: str, worker: str | None = None, tail: int = 200) -> dict[str, Any]:
        root = self._project_dir(runtime_name)
        workers = [worker] if worker else L.list_workers(runtime_name, self.agents_root)
        entries = []
        for name in workers:
            if not name or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", name):
                continue
            log_dir = (root / "workers" / name / "logs").resolve()
            if log_dir.parent.parent.parent != root or not log_dir.is_dir():
                continue
            for path in sorted(log_dir.glob("*.log")):
                try:
                    text = path.read_text(encoding="utf-8", errors="replace").splitlines()[-tail:]
                    entries.append({"worker": name, "name": path.name, "lines": text})
                except OSError:
                    continue
        return {"entries": entries}

    def fact_graph_projection(self, runtime_name: str) -> dict[str, Any]:
        from danus.observability.app import build_factgraph
        return build_factgraph(self._project_dir(runtime_name))

    def reports_projection(self, runtime_name: str) -> dict[str, Any]:
        return {"files": self._safe_relative_files(runtime_name, "reports")}

    def delete_project(self, runtime_name: str) -> dict[str, Any]:
        """Delete a stopped project tree without following symlinks."""
        root = self._project_dir(runtime_name)
        projection = self.status_project(runtime_name)
        if any(worker.get("alive") for worker in projection.get("workers", [])):
            raise RuntimeOperationError("project is still running")
        if root.parent != self.agents_root or root == self.agents_root:
            raise RuntimeOperationError("invalid project root")
        import shutil
        # Refuse symlinked project roots; remove only this exact server-owned tree.
        if root.is_symlink():
            raise RuntimeOperationError("project root must not be a symlink")
        try:
            shutil.rmtree(root)
        except OSError as exc:
            raise RuntimeOperationError("project deletion failed") from exc
        return {"deleted": runtime_name}

    def outputs_projection(self, runtime_name: str) -> dict[str, Any]:
        return {"files": self._safe_relative_files(runtime_name, "outputs")}
    def project_context_dir(self, runtime_name: str) -> Path:
        return self._project_dir(runtime_name)

    def write_deadline(self, runtime_name: str, deadline: float) -> None:
        project = self._project_dir(runtime_name)
        if deadline <= time.time():
            raise ValueError("deadline must be in the future")
        try:
            atomic_write(project / L.DEADLINE_FILE, f"{deadline:.6f}\n")
        except OSError as exc:
            raise RuntimeOperationError("deadline could not be written") from exc

    def clear_deadline(self, runtime_name: str) -> None:
        project = self._project_dir(runtime_name)
        try:
            (project / L.DEADLINE_FILE).unlink(missing_ok=True)
        except OSError as exc:
            raise RuntimeOperationError("deadline could not be cleared") from exc
