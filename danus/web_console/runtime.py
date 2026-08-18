"""Adapter from the Web Console control plane to Danus runtime APIs."""
from __future__ import annotations

import json
import os
import re
import secrets
import stat as stat_module
import time
from pathlib import Path
from typing import Any

from danus.execution import layout as L
from danus.execution import processes as P
from danus.execution.scaffold import atomic_write
from danus.orchestration import cli

from .observability import redact_text

_PROJECT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


class RuntimeErrorBase(Exception):
    pass


class RuntimeNotFound(RuntimeErrorBase):
    pass


class RuntimeOperationError(RuntimeErrorBase):
    pass


class RuntimeSafetyError(RuntimeOperationError):
    """A requested destructive action failed a process-identity safety gate."""


def validate_runtime_name(name: str) -> str:
    if not isinstance(name, str) or not _PROJECT_RE.fullmatch(name):
        raise ValueError("invalid project name")
    return name


class DanusRuntimeAdapter:
    """Project-scoped runtime adapter; all process/filesystem authority stays in Danus."""

    def __init__(self, agents_root: Path | None = None):
        # The adapter is constructed once with a server-owned root.
        self.agents_root = Path(agents_root).resolve() if agents_root else L.agents_root()
        self._reclaim_tokens: dict[str, tuple[str, float]] = {}

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
        # Terminal graceful stop supersedes any cooperative pause marker.
        for worker_dir in self._target_worker_dirs(runtime_name):
            (worker_dir / L.PAUSE_FILE).unlink(missing_ok=True)
        return {"workers": self._call(cli.do_stop, runtime_name, force=False)}

    def enforce_deadline(self, runtime_name: str) -> dict[str, Any]:
        """Hard-stop an expired Run through identity-verified host handles."""
        for worker_dir in self._target_worker_dirs(runtime_name):
            (worker_dir / L.PAUSE_FILE).unlink(missing_ok=True)
        return {"workers": self._call(cli.do_stop, runtime_name, force=True)}
    def _target_worker_dirs(self, runtime_name: str, worker: str | None = None) -> list[Path]:
        root = self._project_dir(runtime_name)
        names = [worker] if worker is not None else L.list_workers(runtime_name, self.agents_root)
        result: list[Path] = []
        for name in names:
            if not isinstance(name, str):
                raise RuntimeOperationError("invalid worker")
            worker_dir = self._worker_dir(root, name)
            if worker_dir is None:
                raise RuntimeOperationError(f"worker not found: {name}")
            result.append(worker_dir)
        if not result:
            raise RuntimeOperationError("project has no workers")
        return result

    def pause_project(self, runtime_name: str, *, worker: str | None = None) -> dict[str, Any]:
        for worker_dir in self._target_worker_dirs(runtime_name, worker):
            pause = worker_dir / L.PAUSE_FILE
            if pause.is_symlink():
                raise RuntimeSafetyError("pause marker must not be a symlink")
            pause.touch()
        return {"status": "pause_requested", "worker": worker}

    def resume_project(self, runtime_name: str, *, worker: str | None = None) -> dict[str, Any]:
        """Resume only pause-marked Workers after Main Agent authorization."""
        resumed: list[dict[str, Any]] = []
        for worker_dir in self._target_worker_dirs(runtime_name, worker):
            pause = worker_dir / L.PAUSE_FILE
            if pause.is_symlink():
                raise RuntimeSafetyError("pause marker must not be a symlink")
            if not pause.exists():
                continue
            pause.unlink()
            target = f"{runtime_name}/{worker_dir.name}"
            resumed.extend(self._call(cli.do_start, target))
        return {"status": "resume_requested", "workers": resumed}

    @staticmethod
    def _merge_worker_status(worker_dir: Path, **fields: Any) -> None:
        path = worker_dir / L.STATUS_FILE
        try:
            current = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
        except (OSError, json.JSONDecodeError):
            current = {}
        current.update(fields)
        current["worker"] = worker_dir.name
        current["updated_at"] = time.time()
        atomic_write(path, json.dumps(current, ensure_ascii=False, indent=2))

    @staticmethod
    def _public_identity(identity: P.WorkerProcessIdentity | None) -> dict[str, Any] | None:
        if identity is None:
            return None
        return {
            "pid": identity.pid, "boot_id": identity.boot_id,
            "start_time": identity.start_time,
        }

    @staticmethod
    def _inspect_worker_process(worker_dir: Path, pid: Any) -> dict[str, Any]:
        """Distinguish unavailable inspection from a proven identity mismatch."""
        try:
            parsed_pid = int(pid)
        except (TypeError, ValueError):
            return {"status": "dead", "pid": None}
        if parsed_pid <= 0 or not P.process_alive(parsed_pid):
            return {"status": "dead", "pid": parsed_pid}
        wl = L.WorkerLayout(worker_dir)
        persisted = P.read_worker_identity(wl)
        try:
            record = P.DEFAULT_PROCFS.process_record(parsed_pid)
            boot_id = P.DEFAULT_PROCFS.boot_id()
        except (OSError, ValueError, IndexError, UnicodeError):
            return {"status": "unknown", "pid": parsed_pid}
        observed = P.WorkerProcessIdentity(
            pid=parsed_pid, boot_id=boot_id,
            start_time=str(record["start_time"]),
            cmdline=tuple(record["cmdline"]),
        )
        if observed.cmdline != P.expected_worker_cmdline(wl):
            return {
                "status": "mismatch", "pid": parsed_pid,
                "observed_identity": DanusRuntimeAdapter._public_identity(observed),
                "persisted_identity": DanusRuntimeAdapter._public_identity(persisted),
            }
        if persisted is None:
            return {
                "status": "unknown", "pid": parsed_pid,
                "observed_identity": DanusRuntimeAdapter._public_identity(observed),
            }
        return {
            "status": "matched" if observed == persisted else "mismatch",
            "pid": parsed_pid,
            "observed_identity": DanusRuntimeAdapter._public_identity(observed),
            "persisted_identity": DanusRuntimeAdapter._public_identity(persisted),
        }

    def force_stop_project(
        self, runtime_name: str, *, worker: str | None = None, term_timeout: float = 5.0,
    ) -> dict[str, Any]:
        targets = self._target_worker_dirs(runtime_name, worker)
        verified: list[tuple[Path, dict[str, Any]]] = []
        # Validate every target before the first destructive signal so a
        # multi-Worker request cannot partially execute and then fail safety.
        for worker_dir in targets:
            pid_path = worker_dir / L.PID_FILE
            try:
                pid = int(pid_path.read_text(encoding="utf-8").strip())
            except (OSError, ValueError):
                persisted = P.read_worker_identity(L.WorkerLayout(worker_dir))
                if persisted is not None:
                    pid = persisted.pid
                elif P.processes_with_argv_path(worker_dir):
                    raise RuntimeSafetyError(
                        f"worker {worker_dir.name} has unverified project processes; reclaim required"
                    )
                else:
                    verified.append((worker_dir, {"status": "dead", "pid": None}))
                    continue
            identity = self._inspect_worker_process(worker_dir, pid)
            if identity.get("status") != "matched":
                raise RuntimeSafetyError(
                    f"worker {worker_dir.name} process identity is {identity.get('status')}"
                )
            verified.append((worker_dir, identity))

        rows: list[dict[str, Any]] = []
        for worker_dir, identity in verified:
            if identity.get("status") == "dead":
                rows.append({"worker": worker_dir.name, "outcome": "not-running", "signals_sent": []})
                continue
            signals_sent: list[str] = []
            outcome = P.force_stop_worker(
                L.WorkerLayout(worker_dir), term_timeout=term_timeout,
                kill_timeout=1.0, on_signal=signals_sent.append,
            )
            if outcome != "killed":
                raise RuntimeSafetyError(
                    f"worker {worker_dir.name} force stop failed closed: {outcome}"
                )
            self._merge_worker_status(
                worker_dir, state="terminated", control_outcome="emergency_force_stop",
            )
            rows.append({
                "worker": worker_dir.name,
                "verified_identity": identity,
                "signals_sent": signals_sent,
                "descendants_verified": True,
                "outcome": "terminated",
            })
        return {"status": "force_stopped", "workers": rows}

    @staticmethod
    def _project_processes(root: Path) -> list[dict[str, Any]]:
        return P.processes_with_argv_path(root)

    @staticmethod
    def _clear_provider_lock_artifacts(root: Path) -> list[str]:
        cleared: list[str] = []
        single = root / ".worker-provider.lock"
        if single.exists() and not single.is_symlink():
            single.unlink(missing_ok=True)
            cleared.append(single.name)
        directory = root / ".worker-provider.lock.d"
        if directory.is_dir() and not directory.is_symlink():
            for path in directory.iterdir():
                if path.is_file() and not path.is_symlink():
                    path.unlink(missing_ok=True)
                    cleared.append(str(path.relative_to(root)))
            try:
                directory.rmdir()
            except OSError:
                pass
        return cleared

    def reclaim_project(
        self, runtime_name: str, *, worker: str | None = None, execute: bool = False,
        confirmation_token: str | None = None,
    ) -> dict[str, Any]:
        root = self._project_dir(runtime_name)
        worker_dirs = self._target_worker_dirs(runtime_name, worker)
        key = f"{runtime_name}:{worker or '*'}"
        plans: list[dict[str, Any]] = []
        safe = True
        for worker_dir in worker_dirs:
            wl = L.WorkerLayout(worker_dir)
            pid = P.read_pid(wl)
            identity = self._inspect_worker_process(worker_dir, pid)
            persisted = P.read_worker_identity(wl)
            # A dead leader may leave exact descendants in its launch-time
            # process group. A mismatched reused PID is never used as a PGID.
            orphan_records = (
                P.process_group_members(persisted.pid)
                if persisted is not None and identity.get("status") == "dead"
                else []
            )
            orphans = [
                {key: record[key] for key in ("pid", "ppid", "pgid", "state", "start_time")}
                for record in orphan_records
            ]
            worker_safe = identity.get("status") in {"dead", "mismatch"}
            safe = safe and worker_safe
            stale_artifacts = [
                name for name in (L.PID_FILE, L.STOP_FILE, L.PAUSE_FILE, L.PROCESS_IDENTITY_FILE)
                if (worker_dir / name).exists()
            ]
            plans.append({
                "worker": worker_dir.name,
                "process_identity": identity.get("status"),
                "pid": pid,
                "persisted_identity": self._public_identity(persisted),
                "orphan_processes": orphans,
                "stale_artifacts": stale_artifacts,
                "safe_to_execute": worker_safe,
            })
        if not execute:
            token = secrets.token_urlsafe(24)
            self._reclaim_tokens[key] = (token, time.monotonic() + 60.0)
            return {
                "dry_run": True, "safe_to_execute": safe, "workers": plans,
                "confirmation_token": token,
            }
        expected = self._reclaim_tokens.pop(key, None)
        if expected is None or expected[1] < time.monotonic() or not secrets.compare_digest(
            expected[0], confirmation_token or ""
        ):
            raise RuntimeSafetyError("invalid or expired reclaim confirmation")
        if not safe:
            raise RuntimeSafetyError("reclaim plan contains live or unknown Worker processes")

        # Destructive process work happens first, while all stale artifacts and
        # identities remain available for diagnosis if verification fails.
        for worker_dir, plan in zip(worker_dirs, plans):
            persisted = plan.get("persisted_identity")
            if plan.get("orphan_processes"):
                if not isinstance(persisted, dict) or not isinstance(persisted.get("pid"), int):
                    raise RuntimeSafetyError("orphan reclaim lacks persisted process-group identity")
                try:
                    plan["orphan_termination"] = P.terminate_orphan_process_group(
                        int(persisted["pid"]), term_timeout=5.0, kill_timeout=1.0,
                    )
                except (RuntimeError, OSError) as exc:
                    raise RuntimeSafetyError(f"orphan reclaim failed closed: {exc}") from exc

        unresolved_targets = {
            worker_dir.name: self._project_processes(worker_dir)
            for worker_dir in worker_dirs
            if self._project_processes(worker_dir)
        }
        if unresolved_targets:
            raise RuntimeSafetyError(
                "reclaim left selected Worker processes: "
                + ",".join(sorted(unresolved_targets))
            )
        remaining = self._project_processes(root)
        if worker is None and remaining:
            raise RuntimeSafetyError("project-wide reclaim could not prove zero Project processes")

        for worker_dir in worker_dirs:
            for name in (L.PID_FILE, L.STOP_FILE, L.PAUSE_FILE, L.PROCESS_IDENTITY_FILE):
                (worker_dir / name).unlink(missing_ok=True)
            self._merge_worker_status(
                worker_dir, state="reclaimed", control_outcome="stale_reclaim",
            )
        cleared_locks = self._clear_provider_lock_artifacts(root) if not remaining else []
        return {
            "status": "reclaimed", "workers": plans,
            "cleared_lock_artifacts": cleared_locks,
            "remaining_project_processes": remaining,
        }

    def status_project(self, runtime_name: str) -> dict[str, Any]:
        root = self._project_dir(runtime_name)
        workers = self._call(cli.do_status, runtime_name)
        for worker in workers:
            name = str(worker.get("worker", ""))
            memory_count, checkpoint = self._worker_checkpoint(root, name)
            worker["local_memory_count"] = memory_count
            worker["checkpoint"] = checkpoint
            worker_dir = self._worker_dir(root, name)
            identity = self._process_identity(worker_dir, worker.get("pid"))
            worker["process_identity"] = identity
            process_record = worker_dir / L.PROCESS_IDENTITY_FILE if worker_dir is not None else None
            worker["reclaim_candidate"] = bool(
                identity in {"dead", "mismatch"}
                and (
                    worker.get("pid") is not None
                    or (process_record is not None and process_record.is_file() and not process_record.is_symlink())
                )
            )
            # A numeric PID is not liveness. Only an identity-matched Worker is
            # safe to report as alive or to target with an emergency signal.
            worker["alive"] = identity == "matched"
            stop = worker_dir / L.STOP_FILE if worker_dir is not None else None
            worker["stop_requested"] = bool(
                stop is not None and stop.exists() and not stop.is_symlink()
            )
            pause = worker_dir / L.PAUSE_FILE if worker_dir is not None else None
            worker["pause_requested"] = bool(
                pause is not None and pause.exists() and not pause.is_symlink()
            )
            worker["desired_state"] = (
                "stopped" if worker["stop_requested"]
                else "paused" if worker["pause_requested"]
                else "running"
            )
        return {"config": self.project_config(runtime_name), "workers": workers}

    @staticmethod
    def _worker_dir(root: Path, worker: str) -> Path | None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", worker):
            return None
        raw = root / "workers" / worker
        if raw.is_symlink():
            return None
        resolved = raw.resolve()
        return resolved if resolved.parent == root / "workers" and resolved.is_dir() else None

    @staticmethod
    def _process_identity(worker_dir: Path | None, pid: Any) -> str:
        """Return the conservative state from the single process inspector."""
        if worker_dir is None:
            return "unknown"
        return str(DanusRuntimeAdapter._inspect_worker_process(worker_dir, pid).get("status", "unknown"))

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

    def logs_projection(
        self,
        runtime_name: str,
        worker: str | None = None,
        tail: int = 200,
        *,
        max_bytes: int = 64 * 1024,
    ) -> dict[str, Any]:
        """Return bounded log tails opened relative to a no-follow directory fd."""
        root = self._project_dir(runtime_name)
        if tail < 1 or max_bytes < 1:
            raise ValueError("tail and max_bytes must be positive")
        if worker is not None and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", worker):
            raise ValueError("invalid worker name")
        workers = [worker] if worker else L.list_workers(runtime_name, self.agents_root)
        entries: list[dict[str, Any]] = []
        fetched_at = time.time()
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        for name in workers:
            if not name:
                continue
            worker_dir = self._worker_dir(root, name)
            if worker_dir is None:
                continue
            raw_log_dir = worker_dir / L.LOGS_DIR
            if raw_log_dir.is_symlink() or not raw_log_dir.is_dir():
                continue
            log_dir = raw_log_dir.resolve()
            if log_dir.parent != worker_dir:
                continue
            try:
                directory_fd = os.open(log_dir, directory_flags)
            except OSError as exc:
                raise RuntimeOperationError(f"log directory unavailable for Worker {name}") from exc
            try:
                names = [entry for entry in os.listdir(directory_fd) if entry.endswith(".log")]
                names.sort(key=lambda entry: self._log_sort_key(Path(entry)))
                for log_name in names:
                    if "/" in log_name or log_name in {".", ".."}:
                        continue
                    try:
                        listed_stat = os.stat(log_name, dir_fd=directory_fd, follow_symlinks=False)
                        if not stat_module.S_ISREG(listed_stat.st_mode):
                            continue
                        file_fd = os.open(log_name, file_flags, dir_fd=directory_fd)
                        stat = os.fstat(file_fd)
                        if not stat_module.S_ISREG(stat.st_mode):
                            os.close(file_fd)
                            continue
                        with os.fdopen(file_fd, "rb", closefd=True) as handle:
                            offset = max(0, stat.st_size - max_bytes)
                            handle.seek(offset)
                            data = handle.read(max_bytes)
                        if offset:
                            boundary = data.find(b"\n")
                            data = data[boundary + 1:] if boundary >= 0 else b""
                        # Redact the whole bounded value so multi-line PEM and
                        # header shapes cannot escape line-at-a-time filtering.
                        decoded = redact_text(data.decode("utf-8", errors="replace"), limit=max_bytes)
                        available = decoded.splitlines()
                        selected = available[-tail:]
                        round_match = re.fullmatch(r"round_(\d+)\.log", log_name)
                        entries.append({
                            "worker": name,
                            "name": log_name,
                            "kind": "loop" if log_name == "loop.log" else "round" if round_match else "other",
                            "round": int(round_match.group(1)) if round_match else None,
                            "size": stat.st_size,
                            "modified_at": stat.st_mtime,
                            "truncated": bool(offset or len(available) > tail),
                            "empty": stat.st_size == 0,
                            "returned_lines": len(selected),
                            "lines": selected,
                        })
                    except OSError as exc:
                        raise RuntimeOperationError(f"log file unavailable for Worker {name}") from exc
            finally:
                os.close(directory_fd)
        return {
            "worker": worker,
            "tail": tail,
            "max_bytes": max_bytes,
            "fetched_at": fetched_at,
            "entries": entries,
        }

    @staticmethod
    def _log_sort_key(path: Path) -> tuple[int, int, str]:
        if path.name == "loop.log":
            return (0, 0, path.name)
        match = re.fullmatch(r"round_(\d+)\.log", path.name)
        if match:
            return (1, int(match.group(1)), path.name)
        return (2, 0, path.name)

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

    def write_human_summary(self, runtime_name: str, language: str | None = None) -> dict[str, Any]:
        from danus.human_summary.server import summary_write
        return summary_write(project=str(self._project_dir(runtime_name)), language=language)

    def write_paper_artifact(self, runtime_name: str, *, paper_id: str | None = None,
                             stop_workers: bool = False, fact_ids: list[str] | None = None,
                             instructions: str | None = None) -> dict[str, Any]:
        from danus.write_paper.server import paper_write
        return paper_write(project=str(self._project_dir(runtime_name)), paper_id=paper_id,
                           stop_workers=stop_workers, fact_ids=fact_ids, instructions=instructions)

    def finalize_suggestions(self, runtime_name: str) -> dict[str, Any]:
        from danus.core import FactGraph
        from danus.write_paper import assemble
        root = self._project_dir(runtime_name)
        return {"suggested": assemble._terminal_facts(FactGraph(root))}

    def finalize_target(self, runtime_name: str, fact_ids: list[str], paper_id: str | None = None) -> dict[str, Any]:
        from danus.core import FactGraph
        from danus.write_paper import assemble
        root = self._project_dir(runtime_name)
        graph = FactGraph(root)
        unknown = [fid for fid in fact_ids if not graph.exists(fid)]
        if unknown: raise RuntimeOperationError(f"unknown verified fact id(s): {', '.join(unknown)}")
        if not fact_ids: raise RuntimeOperationError("at least one verified fact is required")
        path = assemble.write_target_fact_ids(root, list(dict.fromkeys(fact_ids)), paper_id)
        return {"target_file": str(path.relative_to(root)), "target_fact_ids": list(dict.fromkeys(fact_ids)), "paper_id": paper_id}

    def artifacts_projection(self, runtime_name: str, *, limit: int = 1000) -> dict[str, Any]:
        root = self._project_dir(runtime_name)
        candidates = [root / "TARGET.md", root / "report", root / "paper", root / "papers", root / "outputs", root / "reports"]
        rows: list[dict[str, Any]] = []
        seen: set[str] = set()
        for candidate in candidates:
            paths = [candidate] if candidate.is_file() else sorted(candidate.rglob("*")) if candidate.is_dir() else []
            for path in paths:
                if len(rows) >= limit or path.is_symlink() or not path.is_file():
                    continue
                try:
                    relative = path.relative_to(root)
                    resolved = path.resolve()
                    if resolved != path or str(relative) in seen or root not in resolved.parents:
                        continue
                    size = path.stat().st_size
                except (OSError, ValueError):
                    continue
                rel = str(relative)
                seen.add(rel)
                lower = rel.lower()
                kind = "target" if relative.name == "TARGET.md" else "report" if rel.startswith("report/") or rel.startswith("reports/") else "paper" if rel.startswith("paper/") or rel.startswith("papers/") else "output"
                rows.append({"path": rel, "name": relative.name, "size": size, "kind": kind, "content_type": "application/pdf" if lower.endswith(".pdf") else "text/plain" if lower.endswith((".md", ".txt", ".log")) else "text/latex" if lower.endswith((".tex", ".ltx")) else "application/octet-stream"})
        return {"files": rows}

    def artifact_bytes(self, runtime_name: str, relative: str, *, max_bytes: int = 2 * 1024 * 1024) -> tuple[bytes, str]:
        root = self._project_dir(runtime_name)
        if not relative or Path(relative).is_absolute() or "\\" in relative or any(part in {"", ".", ".."} for part in Path(relative).parts):
            raise RuntimeOperationError("invalid artifact path")
        path = root / relative
        resolved = path.resolve()
        if root not in resolved.parents or path.is_symlink() or not path.is_file():
            raise RuntimeOperationError("artifact not found")
        if path.stat().st_size > max_bytes:
            raise RuntimeOperationError("artifact too large")
        return path.read_bytes(), "application/pdf" if path.suffix.lower() == ".pdf" else "text/plain; charset=utf-8" if path.suffix.lower() in {".md", ".txt", ".log"} else "text/latex; charset=utf-8" if path.suffix.lower() in {".tex", ".ltx"} else "application/octet-stream"

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
