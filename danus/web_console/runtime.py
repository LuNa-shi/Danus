"""Adapter from the Web Console control plane to Danus runtime APIs."""
from __future__ import annotations

import contextlib
import fcntl
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
from danus.execution import systemd_scope as S
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


def _atomic_write_private(path: Path, text: str) -> None:
    """Durably replace one journal record without following mutable names."""
    data = text.encode("utf-8")
    directory_fd = -1
    temporary_fd = -1
    temporary_name: str | None = None
    try:
        directory_fd = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        directory_info = os.fstat(directory_fd)
        if (
            not stat_module.S_ISDIR(directory_info.st_mode)
            or directory_info.st_uid != os.geteuid()
            or stat_module.S_IMODE(directory_info.st_mode) != 0o700
        ):
            raise RuntimeSafetyError("unsafe host process-group journal")

        flags = (
            os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        )
        for _ in range(128):
            candidate = f".danus-web-{secrets.token_hex(16)}.tmp"
            try:
                temporary_fd = os.open(
                    candidate, flags, 0o600, dir_fd=directory_fd,
                )
            except FileExistsError:
                continue
            temporary_name = candidate
            break
        else:
            raise RuntimeSafetyError(
                "host process-group journal temporary unavailable"
            )

        os.fchmod(temporary_fd, 0o600)
        temporary_info = os.fstat(temporary_fd)
        if (
            not stat_module.S_ISREG(temporary_info.st_mode)
            or temporary_info.st_uid != os.geteuid()
            or stat_module.S_IMODE(temporary_info.st_mode) != 0o600
        ):
            raise RuntimeSafetyError("unsafe host process-group journal temporary")
        remaining = memoryview(data)
        while remaining:
            try:
                written = os.write(temporary_fd, remaining)
            except InterruptedError:
                continue
            if written <= 0:  # pragma: no cover - defensive kernel contract
                raise OSError("short host process-group journal write")
            remaining = remaining[written:]
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = -1

        # Replacing the directory entry is safe even when an attacker pre-seeded
        # a symlink: the referent is never opened or modified.
        os.replace(
            temporary_name, path.name,
            src_dir_fd=directory_fd, dst_dir_fd=directory_fd,
        )
        temporary_name = None
        os.fsync(directory_fd)
    except RuntimeSafetyError:
        raise
    except (OSError, UnicodeError) as exc:
        raise RuntimeSafetyError("host process-group journal write failed") from exc
    finally:
        if temporary_fd >= 0:
            try:
                os.close(temporary_fd)
            except OSError:
                pass
        if temporary_name is not None and directory_fd >= 0:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except OSError:
                pass
        if directory_fd >= 0:
            try:
                os.close(directory_fd)
            except OSError:
                pass


class DanusRuntimeAdapter:
    """Project-scoped runtime adapter; all process/filesystem authority stays in Danus."""

    def __init__(
        self, agents_root: Path | None = None, *,
        _allow_legacy_process_test_seam: bool = False,
    ):
        # The adapter is constructed once with a server-owned root.
        self.agents_root = Path(agents_root).resolve() if agents_root else L.agents_root()
        self._reclaim_tokens: dict[str, tuple[str, float]] = {}
        # Private Python-only injection for legacy process unit tests. No env,
        # config, HTTP, or CLI input can enable this in a deployed adapter.
        self._allow_legacy_process_test_seam = bool(_allow_legacy_process_test_seam)

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

    def _boundary_status(self, worker_dir: Path) -> S.WorkerBoundaryStatus | None:
        """Read the host-owned seam when a durable Worker ledger exists."""

        wl = L.WorkerLayout(worker_dir)
        if self._allow_legacy_process_test_seam and not S.ledger_path(wl).is_file():
            return None
        return S.inspect_worker_boundary(wl)

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
        # Serialize name ownership with host-journal writers. In particular, a
        # duplicate create must fail before the existing Project's launch proof
        # is touched, while a genuinely new name may discard a crash-stale
        # journal only after its scaffold is fully initialized.
        with self._host_journal_lock(runtime_name):
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
                    raise RuntimeOperationError(
                        "runtime returned project outside configured root"
                    )
                atomic_write(
                    project / "PROBLEM.md",
                    problem if problem.endswith("\n") else problem + "\n",
                )
            except (SystemExit, ValueError, OSError) as exc:
                raise RuntimeOperationError(str(exc)) from exc
            self._clear_host_group_identities(runtime_name, lock_held=True)
            return result

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
        workers = self._call(cli.do_start, runtime_name)
        self._record_live_worker_groups(runtime_name)
        return {"workers": workers}

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
        self._record_live_worker_groups(runtime_name, worker=worker)
        return {"status": "resume_requested", "workers": resumed}

    def _record_live_worker_groups(
        self, runtime_name: str, *, worker: str | None = None,
    ) -> None:
        for worker_dir in self._target_worker_dirs(runtime_name, worker):
            wl = L.WorkerLayout(worker_dir)
            if not self._allow_legacy_process_test_seam:
                # Managed Workers deliberately have no Project-visible PID
                # file. Capture the host journal identity from the durable
                # systemd ledger instead, so a later terminal gate can bind an
                # exit proof to this exact invocation.
                try:
                    ledger = S.read_ledger(wl)
                    boundary = S.inspect_worker_boundary(wl)
                except S.SystemdBoundaryError as exc:
                    raise RuntimeSafetyError(
                        f"worker {worker_dir.name} supervisor identity unavailable"
                    ) from exc
                if ledger is None:
                    if boundary.state == "absent":
                        continue
                    raise RuntimeSafetyError(
                        f"worker {worker_dir.name} supervisor ledger is missing"
                    )
                if boundary.state != "active":
                    if boundary.state == "absent":
                        continue
                    raise RuntimeSafetyError(
                        f"worker {worker_dir.name} supervisor boundary is {boundary.state}"
                    )
                try:
                    identity = P.WorkerProcessIdentity(
                        pid=int(ledger["main_pid"]),
                        boot_id=str(ledger["boot_id"]),
                        start_time=str(ledger["main_pid_start_time"]),
                        # The journal's public identity format predates the
                        # isolated worker_entry argv. Keep its canonical
                        # Worker cmdline while the ledger remains the source
                        # of the actual service argv/cgroup proof.
                        cmdline=P.expected_worker_cmdline(wl),
                    )
                except (KeyError, TypeError, ValueError) as exc:
                    raise RuntimeSafetyError(
                        f"worker {worker_dir.name} supervisor identity is malformed"
                    ) from exc
                self._store_host_group_identity(runtime_name, worker_dir.name, identity)
                continue
            pid = P.read_pid(L.WorkerLayout(worker_dir))
            if P.process_alive(pid) and not self._capture_host_group_identity(worker_dir, pid):
                raise RuntimeSafetyError(
                    f"worker {worker_dir.name} launch identity could not be journaled"
                )

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

    @staticmethod
    def _read_worker_control_json(
        worker_dir: Path, name: str,
    ) -> tuple[bool, dict[str, Any]]:
        """Read one Worker control record without following a swapped symlink."""
        directory_fd = -1
        file_fd = -1
        try:
            directory_fd = os.open(
                worker_dir,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                file_fd = os.open(
                    name,
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=directory_fd,
                )
            except FileNotFoundError:
                return False, {}
            info = os.fstat(file_fd)
            if not stat_module.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                raise RuntimeSafetyError(f"unsafe Worker control record: {name}")
            chunks: list[bytes] = []
            remaining = 65537
            while remaining > 0:
                chunk = os.read(file_fd, min(remaining, 16384))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > 65536:
                raise RuntimeSafetyError(f"oversized Worker control record: {name}")
            value = json.loads(raw.decode("utf-8"))
            if not isinstance(value, dict):
                raise RuntimeSafetyError(f"invalid Worker control record: {name}")
            return True, value
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise RuntimeSafetyError(f"invalid Worker control record: {name}") from exc
        except OSError as exc:
            raise RuntimeSafetyError(f"Worker control record unavailable: {name}") from exc
        finally:
            if file_fd >= 0:
                os.close(file_fd)
            if directory_fd >= 0:
                os.close(directory_fd)

    def _host_group_project_dir(
        self, runtime_name: str, *, create: bool,
    ) -> Path | None:
        """Resolve the model-inaccessible host journal for Worker launch groups."""
        validate_runtime_name(runtime_name)
        root = self.agents_root / ".danus-web-process-groups"
        project = root / runtime_name
        for path in (root, project):
            if create:
                try:
                    os.mkdir(path, 0o700)
                    path.chmod(0o700)
                except FileExistsError:
                    pass
                except FileNotFoundError:
                    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    os.mkdir(path, 0o700)
                    path.chmod(0o700)
                except OSError as exc:
                    raise RuntimeSafetyError("host process-group journal unavailable") from exc
            try:
                info = path.lstat()
            except FileNotFoundError:
                if not create:
                    return None
                raise RuntimeSafetyError("host process-group journal disappeared")
            except OSError as exc:
                raise RuntimeSafetyError("host process-group journal unavailable") from exc
            if (
                not stat_module.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat_module.S_IMODE(info.st_mode) != 0o700
            ):
                raise RuntimeSafetyError("unsafe host process-group journal")
        return project

    @contextlib.contextmanager
    def _host_journal_lock(self, runtime_name: str):
        """Serialize one Project name across scaffold and journal mutation."""
        validate_runtime_name(runtime_name)
        lock_fd = -1
        try:
            self.agents_root.mkdir(mode=0o700, parents=True, exist_ok=True)
            root_info = self.agents_root.lstat()
            if (
                not stat_module.S_ISDIR(root_info.st_mode)
                or root_info.st_uid != os.geteuid()
            ):
                raise RuntimeSafetyError("unsafe agents root for journal lock")
            lock_fd = os.open(
                self.agents_root / f".danus-web-journal-{runtime_name}.lock",
                os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            lock_info = os.fstat(lock_fd)
            if (
                not stat_module.S_ISREG(lock_info.st_mode)
                or lock_info.st_uid != os.geteuid()
                or stat_module.S_IMODE(lock_info.st_mode) != 0o600
            ):
                raise RuntimeSafetyError("unsafe host journal lock")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
        except RuntimeSafetyError:
            if lock_fd >= 0:
                os.close(lock_fd)
            raise
        except OSError as exc:
            if lock_fd >= 0:
                os.close(lock_fd)
            raise RuntimeSafetyError("host journal lock unavailable") from exc
        try:
            yield
        finally:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)

    def _store_host_group_identity(
        self, runtime_name: str, worker: str, identity: P.WorkerProcessIdentity,
        *, lock_held: bool = False,
    ) -> None:
        if not _PROJECT_RE.fullmatch(worker):
            raise RuntimeSafetyError("invalid Worker name for process-group journal")
        scope = (
            contextlib.nullcontext() if lock_held
            else self._host_journal_lock(runtime_name)
        )
        with scope:
            project = self._host_group_project_dir(runtime_name, create=True)
            if project is None:
                raise RuntimeSafetyError("host process-group journal unavailable")
            path = project / f"{worker}.json"
            _atomic_write_private(path, json.dumps({
                "version": 1, "runtime_name": runtime_name, "worker": worker,
                "pgid": identity.pid, "identity": identity.as_dict(),
            }, sort_keys=True))

    def _read_host_group_identity(
        self, runtime_name: str, worker: str, worker_dir: Path,
    ) -> tuple[bool, P.WorkerProcessIdentity | None]:
        if not _PROJECT_RE.fullmatch(worker):
            raise RuntimeSafetyError("invalid Worker name for process-group journal")
        project = self._host_group_project_dir(runtime_name, create=False)
        if project is None:
            return False, None
        exists, record = self._read_worker_control_json(project, f"{worker}.json")
        if not exists:
            return False, None
        path = project / f"{worker}.json"
        try:
            if stat_module.S_IMODE(path.lstat().st_mode) != 0o600:
                raise RuntimeSafetyError("unsafe host process-group record mode")
        except OSError as exc:
            raise RuntimeSafetyError("host process-group record unavailable") from exc
        identity = P.WorkerProcessIdentity.from_mapping(record.get("identity"))
        wl = L.WorkerLayout(worker_dir)
        if (
            record.get("version") != 1
            or record.get("runtime_name") != runtime_name
            or record.get("worker") != worker
            or identity is None
            or record.get("pgid") != identity.pid
            or identity.cmdline != P.expected_worker_cmdline(wl)
        ):
            raise RuntimeSafetyError("invalid host process-group record")
        return True, identity

    def _capture_host_group_identity(self, worker_dir: Path, pid: Any) -> bool:
        try:
            parsed_pid = int(pid)
        except (TypeError, ValueError):
            return False
        wl = L.WorkerLayout(worker_dir)
        identity = P.capture_worker_identity(wl, parsed_pid)
        if identity is None:
            return False
        try:
            if os.getpgid(parsed_pid) != parsed_pid:
                return False
        except (OSError, ProcessLookupError, PermissionError):
            return False
        self._store_host_group_identity(wl.project, wl.name, identity)
        return True

    def _clear_host_group_identities(
        self, runtime_name: str, *, lock_held: bool = False,
    ) -> None:
        scope = (
            contextlib.nullcontext() if lock_held
            else self._host_journal_lock(runtime_name)
        )
        with scope:
            project = self._host_group_project_dir(runtime_name, create=False)
            if project is None:
                return
            try:
                for path in project.iterdir():
                    if path.is_symlink() or not path.is_file():
                        raise RuntimeSafetyError(
                            "unsafe host process-group journal entry"
                        )
                    path.unlink()
                project.rmdir()
                root = project.parent
                try:
                    root.rmdir()
                except OSError:
                    pass
            except OSError as exc:
                raise RuntimeSafetyError(
                    "host process-group journal cleanup failed"
                ) from exc

    @staticmethod
    def _path_is_within(raw: str, root: Path) -> bool:
        """Match procfs path projections without resolving mutable symlinks."""
        if not raw.startswith("/"):
            return False
        if raw.endswith(" (deleted)"):
            raw = raw[:-10]
        candidate = os.path.normpath(raw)
        trusted = os.path.normpath(str(root))
        try:
            return os.path.commonpath((candidate, trusted)) == trusted
        except (OSError, ValueError):
            return False

    @classmethod
    def _project_process_projection(
        cls, root: Path, process_groups: set[int],
    ) -> list[dict[str, Any]]:
        """Return the conservative procfs projection relevant to one Project.

        A record is retained when it is a member of a persisted Worker launch
        group or holds a path association to the Project through argv, cwd,
        process root, executable, an open fd, or a mapped file. Mandatory
        PID/PGID/argv inspection is fail-closed. Supplementary path inspection
        is defense in depth and is not treated as a complete descendant set;
        worker_exit_projection separately requires an owned supervisor proof.
        """
        procfs = P.DEFAULT_PROCFS
        proc_root = procfs.root
        try:
            entries = sorted(
                (entry for entry in proc_root.iterdir() if entry.name.isdigit()),
                key=lambda entry: int(entry.name),
            )
        except OSError as exc:
            raise RuntimeSafetyError("process table inspection unavailable") from exc

        projection: list[dict[str, Any]] = []
        effective_uid = os.geteuid()
        for entry in entries:
            pid = int(entry.name)
            try:
                record = procfs.process_record(pid)
            except FileNotFoundError:
                continue
            except (OSError, ValueError, IndexError, UnicodeError) as exc:
                if not entry.exists():
                    continue
                raise RuntimeSafetyError("process record inspection unavailable") from exc
            if record.get("state") == "Z":
                continue
            try:
                pgid = int(record["pgid"])
                start_time = str(record["start_time"])
            except (KeyError, TypeError, ValueError) as exc:
                raise RuntimeSafetyError("invalid process record projection") from exc

            references_project = any(
                isinstance(argument, str) and cls._path_is_within(argument, root)
                for argument in record.get("cmdline", [])
            )
            group_member = pgid in process_groups
            reused_leader_pid = pid in process_groups and pgid != pid

            # Worker descendants run with the Web Console uid. Different-uid
            # processes are relevant only when their kernel PGID still matches
            # a persisted Worker launch group, which was established above.
            try:
                status = (entry / "status").read_text(encoding="utf-8")
                uid_line = next(
                    line for line in status.splitlines() if line.startswith("Uid:")
                )
                uid_fields = uid_line.split()[1:]
                same_uid = len(uid_fields) >= 2 and int(uid_fields[1]) == effective_uid
            except FileNotFoundError:
                continue
            except (OSError, StopIteration, ValueError) as exc:
                if not entry.exists():
                    continue
                raise RuntimeSafetyError("process ownership inspection unavailable") from exc

            # PGID membership and absolute argv associations are the mandatory
            # complete projection above. These extra kernel path associations
            # strengthen detection when procfs permits ptrace-style reads.
            # An unrelated same-uid process may deliberately be non-dumpable;
            # its denied cwd/fd/maps cannot invalidate the complete PGID/argv
            # proof, while a known group member or argv match is already a
            # blocker without consulting these supplementary entries.
            if same_uid and not group_member and not references_project:
                for link_name in ("cwd", "root", "exe"):
                    try:
                        target = os.readlink(entry / link_name)
                    except FileNotFoundError:
                        if not entry.exists():
                            break
                        continue
                    except PermissionError:
                        continue
                    except OSError as exc:
                        if not entry.exists():
                            break
                        raise RuntimeSafetyError("process path inspection unavailable") from exc
                    references_project = references_project or cls._path_is_within(target, root)

                if entry.exists():
                    fd_dir = entry / "fd"
                    try:
                        descriptors = list(fd_dir.iterdir())
                    except FileNotFoundError:
                        descriptors = []
                    except PermissionError:
                        descriptors = []
                    except OSError as exc:
                        if not entry.exists():
                            descriptors = []
                        else:
                            raise RuntimeSafetyError("process fd inspection unavailable") from exc
                    for descriptor in descriptors:
                        try:
                            target = os.readlink(descriptor)
                        except FileNotFoundError:
                            continue
                        except PermissionError:
                            continue
                        except OSError as exc:
                            if not entry.exists():
                                break
                            raise RuntimeSafetyError("process fd inspection unavailable") from exc
                        references_project = references_project or cls._path_is_within(target, root)

                if entry.exists():
                    try:
                        maps = (entry / "maps").read_text(
                            encoding="utf-8", errors="surrogateescape",
                        )
                    except FileNotFoundError:
                        maps = ""
                    except PermissionError:
                        maps = ""
                    except OSError as exc:
                        if not entry.exists():
                            maps = ""
                        else:
                            raise RuntimeSafetyError("process map inspection unavailable") from exc
                    for line in maps.splitlines():
                        fields = line.split(maxsplit=5)
                        if len(fields) == 6 and cls._path_is_within(fields[5], root):
                            references_project = True
                            break

            # Re-read the stable kernel identity after inspecting mutable procfs
            # entries. PID reuse or an inspection-time identity change is not a
            # usable absence proof.
            try:
                after = procfs.process_record(pid)
            except FileNotFoundError:
                continue
            except (OSError, ValueError, IndexError, UnicodeError) as exc:
                if not entry.exists():
                    continue
                raise RuntimeSafetyError("process identity recheck unavailable") from exc
            if (
                str(after.get("start_time")) != start_time
                or int(after.get("pgid", -1)) != pgid
            ):
                raise RuntimeSafetyError("process identity changed during inspection")
            if group_member or reused_leader_pid or references_project:
                projection.append({
                    "pid": pid, "pgid": pgid, "start_time": start_time,
                    "group_member": group_member,
                    "reused_leader_pid": reused_leader_pid,
                    "references_project": references_project,
                })
        return projection

    def _descendant_membership_projection(
        self, runtime_name: str, worker: str,
        identity: P.WorkerProcessIdentity,
    ) -> dict[str, Any]:
        """Return an exact, host-owned empty-membership proof for one Worker.

        The Web gate must never infer that a Worker is dead from a missing
        leader, an empty PGID scan, or a model-writable status file. The
        systemd boundary is the authority: an active/orphaned/error/reused
        invocation is always unavailable, and only ``inspect_worker_boundary``
        followed by a matching durable ``exit_proof`` can return ``empty``.
        """

        def unavailable(reason: str, **fields: Any) -> dict[str, Any]:
            result: dict[str, Any] = {
                "status": "unavailable", "inspection_complete": False,
                "source": "systemd_scope", "reason": reason,
            }
            result.update(fields)
            return result

        # Resolve the exact Project/Worker directory independently of every
        # caller-provided identity. This also rejects a symlinked Worker root.
        try:
            root = self._project_dir(runtime_name)
            worker_dir = self._worker_dir(root, worker)
            if worker_dir is None:
                return unavailable("worker_identity_mismatch")
            wl = L.WorkerLayout(worker_dir)
        except (RuntimeErrorBase, ValueError, OSError):
            return unavailable("project_identity_mismatch")

        if not isinstance(identity, P.WorkerProcessIdentity):
            return unavailable("worker_identity_mismatch")
        if (
            identity.pid <= 1
            or not identity.boot_id
            or not identity.start_time
            or identity.cmdline != P.expected_worker_cmdline(wl)
        ):
            return unavailable("worker_identity_mismatch")

        # Read the ledger before reconciliation: inspect_worker_boundary may
        # retire it after proving the exact pinned cgroup empty and publish the
        # terminal proof that we need to bind below.
        try:
            ledger = S.read_ledger(wl)
        except S.SystemdBoundaryError:
            return unavailable("ledger_error")

        try:
            boundary = S.inspect_worker_boundary(wl)
        except S.SystemdBoundaryError:
            # A stale/reused unit, cgroup replacement, manager mismatch, or
            # any inspection race is evidence loss—not an empty proof.
            return unavailable("boundary_error")

        state = getattr(boundary, "state", None)
        if state != "absent" or getattr(boundary, "populated", True) is not False:
            return unavailable(
                "boundary_active" if state == "active"
                else "boundary_orphaned" if state == "orphaned"
                else "boundary_not_empty",
                boundary_state=state,
            )

        try:
            proof = S.read_exit_proof(wl)
        except S.SystemdBoundaryError:
            return unavailable("exit_proof_error", boundary_state=state)
        if proof is None:
            return unavailable("exit_proof_missing", boundary_state=state)

        expected_unit = S.worker_unit(wl)
        expected_slice = S.worker_slice(wl)
        if (
            proof.get("worker_dir") != str(wl.dir.resolve())
            or proof.get("unit") != expected_unit
            or proof.get("slice") != expected_slice
        ):
            return unavailable("exit_proof_identity_mismatch", boundary_state=state)

        # A ledger captured before reconciliation is the strongest identity
        # source. Bind every process field that the Web host journal carries;
        # never compare against a PID alone.
        if ledger is not None:
            try:
                ledger_identity = (
                    int(ledger["main_pid"]), str(ledger["boot_id"]),
                    str(ledger["main_pid_start_time"]),
                )
            except (KeyError, TypeError, ValueError):
                return unavailable("ledger_identity_mismatch", boundary_state=state)
            if ledger_identity != (identity.pid, identity.boot_id, identity.start_time):
                return unavailable("identity_mismatch", boundary_state=state)
            # The terminal proof may outlive the live ledger.  When both are
            # still available, bind every optional launch-identity field too;
            # otherwise a proof from a different PID/start/argv could be
            # accepted merely because its invocation/cgroup labels happened
            # to match.
            for key in ("main_pid", "main_pid_start_time", "worker_argv"):
                if key in proof and proof.get(key) != ledger.get(key):
                    return unavailable("identity_mismatch", boundary_state=state)
            for key in ("invocation_id", "slice_invocation_id", "boot_id"):
                if proof.get(key) != ledger.get(key):
                    return unavailable("exit_proof_identity_mismatch", boundary_state=state)
            # If the proof carries cgroup identity, it must be byte-for-byte
            # identical to the ledger's pinned directory/events identity.
            for prefix in ("unit", "slice"):
                for suffix in (
                    "cgroup", "cgroup_dev", "cgroup_ino",
                    "events_dev", "events_ino",
                ):
                    key = f"{prefix}_{suffix}"
                    if key in proof and proof.get(key) != ledger.get(key):
                        return unavailable("exit_proof_cgroup_mismatch", boundary_state=state)
        else:
            # Once the ledger has been retired, the terminal proof must carry
            # the complete launch identity itself; a legacy proof without it is
            # deliberately not enough to authorize a destructive gate.
            try:
                proof_identity = (
                    int(proof["main_pid"]), str(proof["boot_id"]),
                    str(proof["main_pid_start_time"]),
                )
            except (KeyError, TypeError, ValueError):
                return unavailable("exit_proof_identity_missing", boundary_state=state)
            if proof_identity != (identity.pid, identity.boot_id, identity.start_time):
                return unavailable("identity_mismatch", boundary_state=state)
            argv = proof.get("worker_argv")
            if not isinstance(argv, list) or not argv:
                return unavailable("exit_proof_identity_missing", boundary_state=state)

        return {
            "status": "empty", "inspection_complete": True,
            "source": "systemd_scope", "reason": None,
            "boundary_state": state, "populated": False,
        }

    def worker_exit_projection(self, runtime_name: str) -> dict[str, Any]:
        """Return status plus the strongest available fail-closed exit proof.

        The host journal pins the exact launch PGID outside model-writable
        Project state. PGID and Project-path scans find ordinary orphans and
        reuse, but do not by themselves constitute a complete descendant proof;
        an ever-started Worker additionally requires the host-supervisor seam
        above to prove its owned membership set empty.
        """
        root = self._project_dir(runtime_name)
        projection = self.status_project(runtime_name)
        workers = projection.get("workers")
        if not isinstance(workers, list):
            raise RuntimeSafetyError("invalid Worker status roster")

        prepared: dict[str, dict[str, Any]] = {}
        process_groups: set[int] = set()
        for worker in workers:
            if not isinstance(worker, dict) or not isinstance(worker.get("worker"), str):
                raise RuntimeSafetyError("invalid Worker status entry")
            name = str(worker["worker"])
            worker_dir = self._worker_dir(root, name)
            if worker_dir is None or name in prepared:
                raise RuntimeSafetyError("invalid Worker status roster")
            wl = L.WorkerLayout(worker_dir)
            try:
                identity_exists, identity_record = self._read_worker_control_json(
                    worker_dir, L.PROCESS_IDENTITY_FILE,
                )
                status_exists, status_record = self._read_worker_control_json(
                    worker_dir, L.STATUS_FILE,
                )
                host_exists, host_identity = self._read_host_group_identity(
                    runtime_name, name, worker_dir,
                )
            except RuntimeSafetyError:
                prepared[name] = {
                    "worker": worker, "reason": "control_record_inspection_failed",
                }
                continue
            persisted = P.WorkerProcessIdentity.from_mapping(identity_record)
            if identity_exists and persisted is None:
                prepared[name] = {
                    "worker": worker, "reason": "invalid_persisted_identity",
                }
                continue
            if persisted is not None and persisted.cmdline != P.expected_worker_cmdline(wl):
                prepared[name] = {
                    "worker": worker, "reason": "invalid_persisted_identity",
                }
                continue

            state = str(worker.get("state") or "").lower()
            status_state = str(status_record.get("state") or "").lower()
            if not status_exists or not status_state:
                prepared[name] = {
                    "worker": worker, "reason": "missing_status_record",
                }
                continue
            if status_state != state:
                prepared[name] = {
                    "worker": worker, "reason": "status_projection_changed",
                }
                continue
            status_pid = status_record.get("pid") if status_exists else None
            if isinstance(status_pid, bool):
                status_pid = None
            try:
                status_pid = int(status_pid) if status_pid is not None else None
            except (TypeError, ValueError):
                status_pid = None
            if status_exists and status_record.get("pid") is not None and (
                status_pid is None or status_pid <= 0
            ):
                prepared[name] = {
                    "worker": worker, "reason": "invalid_persisted_process_group",
                }
                continue

            if not host_exists:
                # A Worker can reach a terminal boundary before the caller
                # records its live journal (for example a short max-rounds
                # run). The supervisor's durable exit proof is an equivalent
                # host identity source, but only when it carries the complete
                # launch identity; never_started remains the sole no-proof
                # success case.
                if not self._allow_legacy_process_test_seam:
                    try:
                        exit_proof = S.read_exit_proof(wl)
                    except S.SystemdBoundaryError:
                        prepared[name] = {
                            "worker": worker,
                            "reason": "exit_proof_inspection_failed",
                        }
                        continue
                    if exit_proof is not None:
                        try:
                            proof_identity = P.WorkerProcessIdentity(
                                pid=int(exit_proof["main_pid"]),
                                boot_id=str(exit_proof["boot_id"]),
                                start_time=str(exit_proof["main_pid_start_time"]),
                                cmdline=P.expected_worker_cmdline(wl),
                            )
                        except (KeyError, TypeError, ValueError):
                            prepared[name] = {
                                "worker": worker,
                                "reason": "exit_proof_identity_missing",
                            }
                            continue
                        status_pid = status_record.get("pid")
                        if status_pid is not None:
                            try:
                                if int(status_pid) != proof_identity.pid:
                                    prepared[name] = {
                                        "worker": worker,
                                        "reason": "host_process_group_mismatch",
                                    }
                                    continue
                            except (TypeError, ValueError):
                                prepared[name] = {
                                    "worker": worker,
                                    "reason": "invalid_persisted_process_group",
                                }
                                continue
                        prepared[name] = {
                            "worker": worker, "source": "systemd_exit_proof",
                            "pgid": proof_identity.pid,
                            "host_identity": proof_identity,
                        }
                        process_groups.add(proof_identity.pid)
                        continue
                never_started = (
                    state == "created" and status_state == "created"
                    and worker.get("pid") is None
                    and not identity_exists
                    and status_pid is None
                    and not any(key in status_record for key in ("started_at", "round_started_at"))
                    and int(status_record.get("round", 0) or 0) == 0
                )
                if not never_started:
                    prepared[name] = {
                        "worker": worker, "reason": "missing_host_process_group",
                    }
                    continue
                prepared[name] = {
                    "worker": worker, "source": "never_started", "pgid": None,
                }
                continue
            if host_identity is None:
                prepared[name] = {
                    "worker": worker, "reason": "invalid_host_process_group",
                }
                continue
            pgid = host_identity.pid
            if status_pid != pgid:
                prepared[name] = {
                    "worker": worker, "reason": "host_process_group_mismatch",
                }
                continue
            if persisted is not None and persisted != host_identity:
                prepared[name] = {
                    "worker": worker, "reason": "worker_identity_record_mismatch",
                }
                continue
            process_groups.add(pgid)
            prepared[name] = {
                "worker": worker, "source": "host_process_group",
                "pgid": pgid, "host_identity": host_identity,
            }

        by_group: dict[int, list[str]] = {}
        for name, item in prepared.items():
            pgid = item.get("pgid")
            if isinstance(pgid, int):
                by_group.setdefault(pgid, []).append(name)
        for names in by_group.values():
            if len(names) > 1:
                for name in names:
                    prepared[name]["reason"] = "duplicate_host_process_group"

        try:
            processes = self._project_process_projection(root, process_groups)
        except RuntimeSafetyError:
            processes = None

        for name, item in prepared.items():
            worker = item["worker"]
            reason = item.get("reason")
            pgid = item.get("pgid")
            proof: dict[str, Any] = {
                "status": "unknown", "reason": reason or "process_inspection_failed",
                "inspection_complete": False, "source": item.get("source"),
                "pgid": pgid, "live_process_count": 0,
                "project_reference_count": 0,
                "descendant_membership_verified": False,
            }
            if reason is not None:
                worker["process_exit_proof"] = proof
                continue
            if processes is None:
                worker["process_exit_proof"] = proof
                continue

            group_members = [row for row in processes if row["pgid"] == pgid] if pgid else []
            project_references = [row for row in processes if row["references_project"]]
            proof.update({
                "inspection_complete": True,
                "live_process_count": len(group_members),
                "project_reference_count": len(project_references),
            })
            if pgid is not None:
                reused_leader = next(
                    (row for row in processes if row["pid"] == pgid and row["reused_leader_pid"]),
                    None,
                )
                if reused_leader is not None:
                    proof.update(status="blocked", reason="leader_pid_reused")
                elif group_members:
                    proof.update(status="blocked", reason="process_group_live_or_reused")
                elif project_references:
                    proof.update(status="blocked", reason="project_process_reference")
                else:
                    identity = item.get("host_identity")
                    try:
                        membership = self._descendant_membership_projection(
                            runtime_name, name, identity,
                        ) if isinstance(identity, P.WorkerProcessIdentity) else {}
                    except Exception:
                        membership = {}
                    if (
                        isinstance(membership, dict)
                        and membership.get("status") == "empty"
                        and membership.get("inspection_complete") is True
                    ):
                        proof.update(
                            status="verified_dead", reason=None,
                            descendant_membership_verified=True,
                        )
                    else:
                        proof.update(
                            status="unknown",
                            reason="descendant_membership_unavailable",
                        )
            elif project_references:
                proof.update(status="blocked", reason="project_process_reference")
            else:
                proof.update(
                    status="verified_dead", reason=None,
                    descendant_membership_verified=True,
                )
            worker["process_exit_proof"] = proof
        return projection

    def force_stop_project(
        self, runtime_name: str, *, worker: str | None = None, term_timeout: float = 5.0,
    ) -> dict[str, Any]:
        targets = self._target_worker_dirs(runtime_name, worker)
        managed_targets: list[tuple[Path, S.WorkerBoundaryStatus]] = []
        unmanaged_targets: list[Path] = []
        for worker_dir in targets:
            try:
                boundary = self._boundary_status(worker_dir)
            except S.SystemdBoundaryError as exc:
                raise RuntimeSafetyError(
                    f"worker {worker_dir.name} boundary inspection failed: {exc}"
                ) from exc
            if boundary is not None:
                if boundary.state == "active" or boundary.state == "orphaned":
                    managed_targets.append((worker_dir, boundary))
                elif boundary.state == "absent":
                    if self._project_processes(worker_dir):
                        raise RuntimeSafetyError(
                            f"worker {worker_dir.name} has unmanaged project processes; reclaim required"
                        )
                    managed_targets.append((worker_dir, boundary))
                else:
                    raise RuntimeSafetyError(
                        f"worker {worker_dir.name} boundary is {boundary.state}"
                    )
            else:
                unmanaged_targets.append(worker_dir)

        rows: list[dict[str, Any]] = []
        # Validate and stop every managed boundary through the exact pinned
        # slice. No PID, process group, or command-line signal path is involved.
        for worker_dir, boundary in managed_targets:
            if boundary.state == "absent":
                rows.append({
                    "worker": worker_dir.name, "outcome": "not-running",
                    "signals_sent": [], "boundary": "absent",
                })
                continue
            try:
                outcome = S.stop_worker_boundary(
                    L.WorkerLayout(worker_dir), timeout=term_timeout, force=True,
                )
            except S.SystemdBoundaryError as exc:
                raise RuntimeSafetyError(
                    f"worker {worker_dir.name} force stop failed closed: {exc}"
                ) from exc
            self._merge_worker_status(
                worker_dir, state="terminated", control_outcome="emergency_force_stop",
            )
            rows.append({
                "worker": worker_dir.name,
                "verified_boundary": {
                    "unit": boundary.unit, "slice": boundary.slice,
                    "invocation_id": boundary.invocation_id,
                    "reason": boundary.reason,
                },
                "signals_sent": ["systemd.slice.stop"],
                "descendants_verified": True,
                "outcome": "terminated" if outcome == "stopped" else outcome,
            })

        # Explicitly injected unmanaged/test seams retain the old identity gate.
        if not unmanaged_targets:
            return {"status": "force_stopped", "workers": rows}

        verified: list[tuple[Path, dict[str, Any]]] = []
        # Validate every target before the first destructive signal so a
        # multi-Worker request cannot partially execute and then fail safety.
        for worker_dir in unmanaged_targets:
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

        # Managed Workers are reconciled solely through the durable systemd
        # boundary. A populated orphan is safe only after an explicit reclaim;
        # an active invocation is never included in a stale reclaim plan.
        managed_rows: list[tuple[Path, S.WorkerBoundaryStatus]] = []
        unmanaged_dirs: list[Path] = []
        for worker_dir in worker_dirs:
            try:
                boundary = self._boundary_status(worker_dir)
            except S.SystemdBoundaryError as exc:
                raise RuntimeSafetyError(
                    f"worker {worker_dir.name} boundary inspection failed: {exc}"
                ) from exc
            if boundary is None:
                unmanaged_dirs.append(worker_dir)
            else:
                managed_rows.append((worker_dir, boundary))
        if managed_rows:
            if unmanaged_dirs:
                raise RuntimeSafetyError(
                    "cannot mix managed and unmanaged Workers in one reclaim"
                )
            plans: list[dict[str, Any]] = []
            safe = True
            for worker_dir, boundary in managed_rows:
                unmanaged_processes = (
                    self._project_processes(worker_dir)
                    if boundary.state == "absent" else []
                )
                worker_safe = (
                    boundary.state in {"absent", "orphaned"}
                    and not unmanaged_processes
                )
                safe = safe and worker_safe
                plans.append({
                    "worker": worker_dir.name,
                    "process_identity": "orphaned" if boundary.state == "orphaned" else "dead" if boundary.state == "absent" else "matched",
                    "boundary_state": boundary.state,
                    "boundary_reason": boundary.reason,
                    "pid": boundary.pid,
                    "persisted_identity": None,
                    "orphan_processes": unmanaged_processes,
                    "stale_artifacts": [
                        name for name in (L.PID_FILE, L.STOP_FILE, L.PAUSE_FILE)
                        if (worker_dir / name).exists()
                    ],
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
                raise RuntimeSafetyError("reclaim plan contains live Worker boundaries")
            for worker_dir, boundary in managed_rows:
                if boundary.state == "orphaned":
                    try:
                        outcome = S.stop_worker_boundary(
                            L.WorkerLayout(worker_dir), force=True,
                        )
                    except S.SystemdBoundaryError as exc:
                        raise RuntimeSafetyError(
                            f"orphan Worker reclaim failed closed: {exc}"
                        ) from exc
                    if outcome not in {"stopped", "not-managed"}:
                        raise RuntimeSafetyError(
                            f"orphan Worker reclaim did not stop cleanly: {outcome}"
                        )
                elif boundary.state != "absent":
                    raise RuntimeSafetyError(
                        f"Worker changed state during reclaim: {boundary.state}"
                    )
                for name in (L.PID_FILE, L.STOP_FILE, L.PAUSE_FILE, L.PROCESS_IDENTITY_FILE):
                    (worker_dir / name).unlink(missing_ok=True)
                self._merge_worker_status(
                    worker_dir, state="reclaimed", control_outcome="stale_reclaim",
                )
            remaining = self._project_processes(root)
            if worker is None and remaining:
                raise RuntimeSafetyError(
                    "project-wide reclaim could not prove zero Project processes"
                )
            cleared_locks = self._clear_provider_lock_artifacts(root) if not remaining else []
            return {
                "status": "reclaimed", "workers": plans,
                "cleared_lock_artifacts": cleared_locks,
                "remaining_project_processes": remaining,
            }

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
            boundary: S.WorkerBoundaryStatus | None = None
            boundary_error: str | None = None
            if worker_dir is not None:
                try:
                    boundary = self._boundary_status(worker_dir)
                except S.SystemdBoundaryError as exc:
                    boundary_error = str(exc)
            if boundary is not None:
                identity = (
                    "matched" if boundary.state == "active"
                    else "orphaned" if boundary.state == "orphaned"
                    else "dead"
                )
                worker["pid"] = boundary.pid
                worker["alive"] = boundary.state == "active"
                worker["identity_verified"] = boundary.state == "active"
                worker["boundary_state"] = boundary.state
                worker["boundary_reason"] = boundary.reason
                if (
                    boundary.state == "absent" and worker_dir is not None
                    and self._project_processes(worker_dir)
                ):
                    identity = "unmanaged"
                    worker["alive"] = False
                    worker["identity_verified"] = False
                    worker["boundary_state"] = "unmanaged"
                    worker["boundary_reason"] = "processes-outside-managed-boundary"
            elif boundary_error is not None:
                # A present ledger with an inspection error is not an unmanaged
                # process. Keep it visible and fail closed for destructive UI.
                identity = "unknown"
                worker["pid"] = None
                worker["alive"] = False
                worker["identity_verified"] = False
                worker["boundary_state"] = "error"
                worker["boundary_reason"] = boundary_error
            else:
                legacy_pid = (
                    P.read_pid(L.WorkerLayout(worker_dir))
                    if self._allow_legacy_process_test_seam and worker_dir is not None
                    else worker.get("pid")
                )
                worker["pid"] = legacy_pid
                identity = self._process_identity(worker_dir, legacy_pid)
                worker["alive"] = identity == "matched"
            worker["process_identity"] = identity
            if identity == "matched" and worker_dir is not None:
                try:
                    worker["host_process_group_recorded"] = self._capture_host_group_identity(
                        worker_dir, worker.get("pid"),
                    )
                except RuntimeSafetyError:
                    worker["host_process_group_recorded"] = False
            process_record = worker_dir / L.PROCESS_IDENTITY_FILE if worker_dir is not None else None
            worker["reclaim_candidate"] = bool(
                (boundary is not None and boundary.state == "orphaned")
                or identity == "unmanaged"
                or (
                    boundary is None and boundary_error is None
                    and identity in {"dead", "mismatch"}
                    and (
                        worker.get("pid") is not None
                        or (process_record is not None and process_record.is_file() and not process_record.is_symlink())
                    )
                )
            )
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
        """Return legacy identity only for an explicitly unmanaged Worker."""
        if worker_dir is None:
            return "unknown"
        wl = L.WorkerLayout(worker_dir)
        if S.ledger_path(wl).is_file():
            try:
                boundary = S.inspect_worker_boundary(wl)
            except S.SystemdBoundaryError:
                return "unknown"
            return (
                "matched" if boundary.state == "active"
                else "orphaned" if boundary.state == "orphaned"
                else "dead"
            )
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
        result = paper_write(project=str(self._project_dir(runtime_name)), paper_id=paper_id,
                             stop_workers=False, fact_ids=fact_ids, instructions=instructions)
        if stop_workers and result.get("status") == "ok":
            result["graceful_stop_requested"] = True
            result["graceful_stop"] = "host supervisor must execute the confirmed stop intent"
        return result

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
                kind = "target" if relative.name == "TARGET.md" else "verification-ledger" if relative.name.upper() in {"VERIFY_LEDGER.MD", "REFERENCE_LEDGER.MD"} else "report" if rel.startswith("report/") or rel.startswith("reports/") else "paper" if rel.startswith("paper/") or rel.startswith("papers/") else "output"
                rows.append({"path": rel, "name": relative.name, "size": size, "kind": kind, "content_type": "application/pdf" if lower.endswith(".pdf") else "text/plain" if lower.endswith((".md", ".txt", ".log")) else "text/latex" if lower.endswith((".tex", ".ltx")) else "application/octet-stream"})
        return {"files": rows}

    def artifact_bytes(self, runtime_name: str, relative: str, *, max_bytes: int = 2 * 1024 * 1024) -> tuple[bytes, str]:
        root = self._project_dir(runtime_name)
        relative_path = Path(relative)
        allowed = relative == "TARGET.md" or relative_path.parts[0] in {"report", "paper", "papers", "outputs", "reports"}
        if not allowed or not relative or relative_path.is_absolute() or "\\" in relative or any(part in {"", ".", ".."} for part in relative_path.parts):
            raise RuntimeOperationError("invalid artifact path")
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        dir_fd = os.open(root, directory_flags)
        opened_dirs = [dir_fd]
        try:
            for part in relative_path.parts[:-1]:
                dir_fd = os.open(part, directory_flags, dir_fd=dir_fd)
                opened_dirs.append(dir_fd)
            file_fd = os.open(relative_path.name, file_flags, dir_fd=dir_fd)
            try:
                info = os.fstat(file_fd)
                if not stat_module.S_ISREG(info.st_mode):
                    raise RuntimeOperationError("artifact not found")
                if info.st_size > max_bytes:
                    raise RuntimeOperationError("artifact too large")
                chunks = []
                remaining = max_bytes + 1
                while remaining > 0:
                    chunk = os.read(file_fd, min(65536, remaining))
                    if not chunk: break
                    chunks.append(chunk); remaining -= len(chunk)
                body = b"".join(chunks)
                if len(body) > max_bytes: raise RuntimeOperationError("artifact too large")
            finally:
                os.close(file_fd)
        except OSError as exc:
            raise RuntimeOperationError("artifact not found") from exc
        finally:
            for opened in reversed(opened_dirs):
                os.close(opened)
        suffix = relative_path.suffix.lower()
        return body, "application/pdf" if suffix == ".pdf" else "text/plain; charset=utf-8" if suffix in {".md", ".txt", ".log"} else "text/latex; charset=utf-8" if suffix in {".tex", ".ltx"} else "application/octet-stream"

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
        self._clear_host_group_identities(runtime_name)
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
