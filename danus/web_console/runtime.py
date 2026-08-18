"""Adapter from the Web Console control plane to Danus runtime APIs."""
from __future__ import annotations

import json
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

    def create_project(
        self,
        runtime_name: str,
        problem: str,
        roles: str,
        model: str | None = None,
        *,
        max_parallel_workers: int | None = None,
    ) -> dict[str, Any]:
        validate_runtime_name(runtime_name)
        if not isinstance(problem, str) or not problem.strip():
            raise ValueError("problem must be non-empty")
        try:
            result = cli.do_new(
                runtime_name,
                roles=roles,
                model=model,
                root=self.agents_root,
                max_parallel_workers=max_parallel_workers,
            )
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

    def assign_worker(self, runtime_name: str, worker: str, task: str) -> dict[str, Any]:
        self._project_dir(runtime_name)
        if not isinstance(task, str) or not task.strip():
            raise RuntimeOperationError("task must be non-empty")
        return self._call(cli.do_assign, f"{runtime_name}/{worker}", task)

    def start_project(self, runtime_name: str) -> dict[str, Any]:
        self._project_dir(runtime_name)
        return {"workers": self._call(cli.do_start, runtime_name)}

    def stop_project(self, runtime_name: str) -> dict[str, Any]:
        self._project_dir(runtime_name)
        return {"workers": self._call(cli.do_stop, runtime_name, force=False)}

    def enforce_deadline(self, runtime_name: str) -> dict[str, Any]:
        """Hard-stop an expired Run through identity-verified host handles."""
        self._project_dir(runtime_name)
        return {"workers": self._call(cli.do_stop, runtime_name, force=True)}

    def status_project(self, runtime_name: str) -> dict[str, Any]:
        root = self._project_dir(runtime_name)
        workers = self._call(cli.do_status, runtime_name)
        for worker in workers:
            memory_count, checkpoint = self._worker_checkpoint(root, str(worker.get("worker", "")))
            worker["local_memory_count"] = memory_count
            worker["checkpoint"] = checkpoint
        return {"config": self.project_config(runtime_name), "workers": workers}

    def project_config(self, runtime_name: str) -> dict[str, Any]:
        root = self._project_dir(runtime_name)
        meta: dict[str, Any] = {}
        path = root / "project.json"
        if path.is_file() and not path.is_symlink():
            try:
                parsed = json.loads(path.read_text(encoding="utf-8"))
                meta = parsed if isinstance(parsed, dict) else {}
            except (json.JSONDecodeError, OSError):
                meta = {}
        max_parallel = meta.get("max_parallel_workers")
        try:
            max_parallel = int(max_parallel) if max_parallel is not None else None
        except (TypeError, ValueError):
            max_parallel = None
        return {
            "roles": meta.get("roles"),
            "workers": meta.get("workers") if isinstance(meta.get("workers"), list) else L.list_workers(runtime_name, self.agents_root),
            "model": meta.get("model"),
            "worker_model": meta.get("worker_model") or meta.get("model"),
            "max_parallel_workers": max_parallel,
        }

    @staticmethod
    def _worker_checkpoint(root: Path, worker: str) -> tuple[int, dict[str, Any] | None]:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", worker):
            return 0, None
        memory_dir = (root / "workers" / worker / "local_memory").resolve()
        if memory_dir.parent.parent.parent != root or not memory_dir.is_dir():
            return 0, None
        count = 0
        candidates: list[tuple[float, int, dict[str, Any]]] = []
        for path in sorted(memory_dir.glob("*.jsonl")):
            if path.is_symlink() or not path.is_file():
                continue
            try:
                modified = path.stat().st_mtime
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for index, line in enumerate(lines):
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(entry, dict):
                    continue
                count += 1
                message = next(
                    (
                        value.strip()
                        for key in ("note", "event", "claim", "summary", "result", "plan", "state", "event_type")
                        if isinstance((value := entry.get(key)), str) and value.strip()
                    ),
                    None,
                )
                if message is None:
                    continue
                next_step = entry.get("next")
                if isinstance(next_step, str) and next_step.strip():
                    message = f"{message}\n\nNext: {next_step.strip()}"
                candidates.append((modified, index, {
                    "message": message,
                    "source": path.stem,
                    "round": entry.get("round"),
                    "fact_id": entry.get("fact_id"),
                }))
        return count, max(candidates, key=lambda item: (item[0], item[1]))[2] if candidates else None

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

    def memory_projection(self, runtime_name: str) -> dict[str, Any]:
        from danus.observability.app import build_channel, build_channels
        root = self._project_dir(runtime_name)
        channels = []
        total = 0
        for summary in build_channels(root).get("channels", []):
            count = int(summary.get("count", 0) or 0)
            total += count
            if not count:
                continue
            detail = build_channel(str(summary["kind"]), root)
            channels.append({**summary, "entries": detail.get("entries", [])[:6]})
        return {"total": total, "channels": channels}

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
