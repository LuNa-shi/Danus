"""Authenticated Web Console HTTP boundary (V1 first vertical slice)."""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ipaddress
import json
import os
import re
import shlex
import sqlite3
import secrets
import stat as stat_module
import threading
import time
import uuid
from urllib.parse import quote, urlsplit
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from danus import codex
from danus.execution import layout as L

from .config import ProviderModelCatalog, main_agent_metadata, strategy_metadata
from .beats import OrchestrationBeatCoordinator, orchestration_observation
from .runtime import DanusRuntimeAdapter, RuntimeErrorBase, RuntimeSafetyError, validate_runtime_name
from .files import (
    FileValidationError,
    control_staging_root,
    decode_upload_filename,
    file_type,
    fsync_directory,
    material_root,
    metadata,
    normalize_filename,
    promote_pending,
    staged_file_matches,
    staging_blob,
    stream_to_pending,
    validate_bytes,
)
from .main_agent import MainAgentError, MainAgentAdapter
from .observability import redact_text
from .security import (
    artifact_confirmation_capability,
    digest_token,
    new_token,
    project_lifecycle_capability,
    verify_password,
    verify_project_lifecycle_capability,
)
from .store import ConsoleStore


@dataclass
class AppSettings:
    database_path: Path
    password_hash: str
    cookie_name: str = "danus_console_session"
    cookie_secure: bool = True
    session_ttl_seconds: int = 12 * 3600
    allowed_origins: set[str] = field(default_factory=set)
    max_file_bytes: int = 25 * 1024 * 1024
    default_max_parallel_workers: int = 1
    max_parallel_workers_limit: int = 32
    model_catalog_ttl_seconds: float = 300.0
    model_catalog_timeout_seconds: float = 5.0
    lifecycle_base_url: str = "http://127.0.0.1:8080"
    lifecycle_hmac_secret: bytes | None = None
    deadline_poll_seconds: float = 0.25
    orchestration_poll_seconds: float = 30.0
    orchestration_consult_interval_seconds: float = 2 * 3600
    human_summary_interval_seconds: float = 3600.0
    artifact_confirmation_ttl_seconds: float = 20 * 60


def _error(status: int, detail: str) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=status)


def _public_main_agent_error(exc: MainAgentError) -> str:
    if exc.code in {"timeout", "turn_timeout_exhausted"} and not exc.safe_to_retry:
        return "Main Agent 执行超时；可能已有部分操作完成。请先检查执行记录，不要直接重试，以免重复操作。"
    if exc.retryable and not exc.safe_to_retry:
        return "上游中断发生在执行过程中；已保留会话。请先检查执行记录，再发送明确后续指令，避免重复操作。"
    messages = {
        "server_overloaded": "上游模型当前繁忙；自动重试后仍未完成，请稍后再试。",
        "rate_limit_exceeded": "上游请求频率受限；自动重试后仍未完成，请稍后再试。",
        "service_unavailable": "上游模型服务暂时不可用，请稍后再试。",
        "upstream_timeout": "上游模型响应超时，请稍后再试。",
        "request_timeout": "上游模型响应超时，请稍后再试。",
        "timeout": "上游模型响应超时，请稍后再试。",
    }
    if exc.code in messages:
        return messages[exc.code]
    if str(exc) == "main agent turn timed out":
        return "Main Agent 本次执行超时，请稍后重试。"
    return "Main Agent 未能完成本次回复；请稍后重试或联系管理员。"


def _redact_exact_value(value: Any, exact_secrets: tuple[str, ...]) -> Any:
    """Recursively redact exact per-turn capabilities at the HTTP boundary."""
    if isinstance(value, str):
        return redact_text(
            value, limit=max(16_384, len(value) + 1),
            exact_secrets=exact_secrets,
        )
    if isinstance(value, dict):
        return {
            _redact_exact_value(key, exact_secrets) if isinstance(key, str) else key:
            _redact_exact_value(item, exact_secrets)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_exact_value(item, exact_secrets) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_exact_value(item, exact_secrets) for item in value)
    return value


def _runtime_name(name: str) -> str:
    # Keep runtime names path-safe and stable; DB ids are opaque to clients.
    validate_runtime_name(name)
    return name


def _loopback_host(host: str | None) -> bool:
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


_PAPER_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
_FACT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}")
_CONTENT_ADDRESS_RE = re.compile(r"[0-9a-f]{64}")


def _artifact_payload(action: str, payload: Any) -> dict[str, Any]:
    """Validate and canonicalize the operator/broker artifact contract."""
    if not isinstance(payload, dict):
        raise ValueError("artifact payload must be an object")
    fields = {
        "finalize-suggest": {"action", "fact_ids"},
        "finalize": {"action", "fact_ids", "paper_id", "confirm", "confirmation_token"},
        "human-summary": {"action", "language", "confirm", "confirmation_token"},
        "write-paper": {
            "action", "paper_id", "fact_ids", "instructions", "stop_workers",
            "confirm", "confirmation_token",
        },
    }.get(action)
    if fields is None:
        raise ValueError("unsupported artifact action")
    if any(key not in fields for key in payload):
        raise ValueError("artifact payload contains unsupported fields")

    def has_control(value: str) -> bool:
        return any(ord(character) < 32 or ord(character) == 127 for character in value)

    def paper_id() -> str | None:
        value = payload.get("paper_id")
        if value is not None and (not isinstance(value, str) or not _PAPER_ID_RE.fullmatch(value)):
            raise ValueError("invalid paper_id")
        return value

    def fact_ids(*, required: bool) -> list[str]:
        value = payload.get("fact_ids")
        if value is None and not required:
            return []
        if (not isinstance(value, list) or isinstance(value, (str, bytes))
                or (required and not value) or len(value) > 128
                or any(not isinstance(fid, str) or not _FACT_ID_RE.fullmatch(fid) for fid in value)):
            qualifier = "non-empty " if required else ""
            raise ValueError(f"fact_ids must be a bounded {qualifier}list of strings")
        return list(value)

    if action == "finalize-suggest":
        if payload.get("fact_ids") not in (None, []):
            raise ValueError("finalize suggestion does not accept fact_ids")
        return {}
    if action == "finalize":
        return {"fact_ids": fact_ids(required=True), "paper_id": paper_id()}
    if action == "human-summary":
        language = payload.get("language")
        if language is not None and (
            not isinstance(language, str) or not language or len(language) > 80
            or has_control(language)
        ):
            raise ValueError("language must be non-empty text of at most 80 characters")
        return {"language": language}
    if action == "write-paper":
        stop_workers = payload.get("stop_workers")
        if not isinstance(stop_workers, bool):
            raise ValueError("stop_workers must be an explicit boolean")
        instructions = payload.get("instructions")
        if instructions is not None and (
            not isinstance(instructions, str) or not instructions.strip()
            or len(instructions) > 12000 or has_control(instructions)
        ):
            raise ValueError("instructions must be non-empty text of at most 12000 characters")
        return {
            "paper_id": paper_id(), "fact_ids": fact_ids(required=False),
            "instructions": instructions, "stop_workers": stop_workers,
        }
    raise ValueError("unsupported artifact action")


def _artifact_payload_digest(action: str, payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        {"action": action, "payload": payload}, ensure_ascii=False,
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _artifact_instruction(action: str, payload: dict[str, Any]) -> str:
    executable = "$DANUS_WEB_AGENT_BIN"
    if action == "finalize":
        parts = [executable, "finalize", "target"]
        for fact_id in payload["fact_ids"]:
            parts += ["--fact-id", shlex.quote(fact_id)]
        if payload["paper_id"] is not None:
            parts += ["--paper-id", shlex.quote(payload["paper_id"])]
    elif action == "human-summary":
        parts = [executable, "human-summary"]
        if payload["language"] is not None:
            parts += ["--language", shlex.quote(payload["language"])]
    elif action == "write-paper":
        parts = [executable, "write-paper"]
        if payload["paper_id"] is not None:
            parts += ["--paper-id", shlex.quote(payload["paper_id"])]
        for fact_id in payload["fact_ids"]:
            parts += ["--fact-id", shlex.quote(fact_id)]
        if payload["instructions"] is not None:
            parts += ["--instructions", shlex.quote(payload["instructions"])]
        parts.append("--stop-workers" if payload["stop_workers"] else "--keep-workers")
    else:
        raise ValueError("unsupported artifact action")
    command = " ".join(parts)
    return (
        "The operator explicitly confirmed this project-scoped artifact operation. "
        f"Run exactly `{command}` through the authenticated broker now, then report its result."
    )


def create_app(
    *,
    settings: AppSettings,
    runtime: Any | None = None,
    main_agent: Any | None = None,
    model_catalog: Any | None = None,
) -> FastAPI:
    active_beat_projects: set[str] = set()
    beat_execution_tasks: set[asyncio.Task[Any]] = set()
    beat_coordinator = OrchestrationBeatCoordinator(
        consult_interval_seconds=settings.orchestration_consult_interval_seconds,
        summary_interval_seconds=settings.human_summary_interval_seconds,
    )

    @contextlib.asynccontextmanager
    async def lifespan(application: FastAPI):
        await asyncio.to_thread(reconcile_external_materials)
        task = asyncio.create_task(deadline_supervisor_loop())
        beat_task = asyncio.create_task(orchestration_beat_loop())
        application.state.deadline_supervisor_task = task
        application.state.orchestration_beat_task = beat_task
        try:
            yield
        finally:
            task.cancel()
            beat_task.cancel()
            for running_beat in list(beat_execution_tasks):
                running_beat.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            with contextlib.suppress(asyncio.CancelledError):
                await beat_task
            if beat_execution_tasks:
                await asyncio.gather(*beat_execution_tasks, return_exceptions=True)

    app = FastAPI(title="Danus Web Console", version="0.1.0", lifespan=lifespan)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    lifecycle_base = settings.lifecycle_base_url.rstrip("/")
    parsed_lifecycle_base = urlsplit(lifecycle_base)
    if parsed_lifecycle_base.scheme not in {"http", "https"} or not _loopback_host(parsed_lifecycle_base.hostname):
        raise ValueError("lifecycle broker base URL must be loopback-only")
    lifecycle_hmac_secret = settings.lifecycle_hmac_secret or secrets.token_bytes(32)

    store = ConsoleStore(settings.database_path)
    runtime = runtime or DanusRuntimeAdapter()
    main_agent = main_agent or MainAgentAdapter()
    model_catalog = model_catalog or ProviderModelCatalog(
        ttl_seconds=settings.model_catalog_ttl_seconds,
        timeout_seconds=settings.model_catalog_timeout_seconds,
    )
    app.state.console_store = store
    app.state.main_agent_adapter = main_agent
    app.state.runtime_adapter = runtime
    main_agent_backend = getattr(main_agent, "backend", "codex")
    project_locks: dict[str, asyncio.Lock] = {}
    broker_windows: dict[str, dict[str, Any]] = {}
    locks_guard = threading.Lock()
    failed: dict[str, tuple[int, float]] = {}

    def lock_for(project_id: str) -> asyncio.Lock:
        with locks_guard:
            return project_locks.setdefault(project_id, asyncio.Lock())

    @contextlib.asynccontextmanager
    async def main_agent_broker_window(project_id: str):
        """Allow broker callbacks to share the outer serialized Agent turn."""
        with locks_guard:
            if project_id in broker_windows:
                raise RuntimeError("Project broker window is already active")
            window = {"active": 0, "closing": False}
            broker_windows[project_id] = window
        try:
            yield
        finally:
            with locks_guard:
                window["closing"] = True
            while True:
                with locks_guard:
                    if int(window["active"]) == 0:
                        broker_windows.pop(project_id, None)
                        break
                await asyncio.sleep(0)

    @contextlib.asynccontextmanager
    async def internal_broker_scope(project_id: str):
        """Serialize broker activity, with bounded re-entry from an Agent turn."""
        bypass = False
        with locks_guard:
            window = broker_windows.get(project_id)
            if window is not None and not bool(window["closing"]):
                window["active"] = int(window["active"]) + 1
                bypass = True
        if not bypass:
            async with lock_for(project_id):
                yield
            return
        try:
            yield
        finally:
            with locks_guard:
                window["active"] = max(0, int(window["active"]) - 1)

    @app.middleware("http")
    async def serialize_main_agent_turn(request: Request, call_next):
        """Hold the Project lock before a body or lifecycle mutation is consumed."""
        message_match = re.fullmatch(
            r"/api/projects/([0-9a-f]{32})/messages", request.url.path,
        )
        broker_match = re.fullmatch(
            r"/internal/api/projects/([0-9a-f]{32})/lifecycle", request.url.path,
        )
        if request.method != "POST" or (message_match is None and broker_match is None):
            return await call_next(request)
        project_id = (message_match or broker_match).group(1)
        # Avoid allocating unbounded locks for arbitrary unauthenticated IDs.
        if store.project(project_id) is None:
            return await call_next(request)
        if broker_match is not None:
            async with internal_broker_scope(project_id):
                request.state.project_broker_lock = project_id
                return await call_next(request)
        async with lock_for(project_id):
            request.state.project_turn_lock = project_id
            return await call_next(request)

    @contextlib.asynccontextmanager
    async def project_turn_scope(project_id: str, request: Request):
        if getattr(request.state, "project_turn_lock", None) == project_id:
            yield
            return
        async with lock_for(project_id):
            yield

    def material_blob(materials: Path, storage_name: str, *, require_regular: bool = True) -> Path:
        if not isinstance(storage_name, str) or not storage_name:
            raise FileValidationError("invalid stored material path")
        candidate = materials / storage_name
        if candidate.parent.resolve() != materials.resolve() or candidate.name != storage_name:
            raise FileValidationError("invalid stored material path")
        if require_regular:
            try:
                info = candidate.lstat()
            except FileNotFoundError as exc:
                raise FileValidationError("stored material is unavailable") from exc
            if candidate.is_symlink() or not stat_module.S_ISREG(info.st_mode):
                raise FileValidationError("stored material is not a regular file")
        return candidate

    def project_staging(project: dict[str, Any]) -> tuple[Path, Path]:
        context = Path(runtime.project_context_dir(project["runtime_name"]))
        materials = material_root(context)
        return materials, control_staging_root(context, materials)

    def promote_staged_conflict(
        incoming: dict[str, Any], materials: Path, staging: Path,
    ) -> tuple[Path, Path]:
        source = staging_blob(staging, incoming.get("staging_name"))
        if not staged_file_matches(
            source, str(incoming["sha256"]), int(incoming["size"]),
            require_private=True,
        ):
            raise FileValidationError("staged material integrity check failed")
        destination = material_blob(
            materials, str(incoming["storage_name"]), require_regular=False,
        )
        if destination.exists() or destination.is_symlink():
            if not staged_file_matches(
                destination, str(incoming["sha256"]), int(incoming["size"]),
            ):
                raise FileValidationError(
                    "existing material destination failed integrity verification",
                )
        os.replace(source, destination)
        os.chmod(destination, 0o600, follow_symlinks=False)
        fsync_directory(materials)
        fsync_directory(staging)
        return source, destination

    def rollback_staged_promotion(source: Path, destination: Path) -> bool:
        try:
            if source.exists() or source.is_symlink():
                return False
            if not destination.exists() or destination.is_symlink():
                return False
            os.replace(destination, source)
            os.chmod(source, 0o600, follow_symlinks=False)
            fsync_directory(source.parent)
            fsync_directory(destination.parent)
            return True
        except OSError:
            return False

    def erase_project_staging(project: dict[str, Any]) -> None:
        _materials, staging = project_staging(project)
        changed = False
        for candidate in staging.iterdir():
            info = candidate.lstat()
            if candidate.is_symlink() or stat_module.S_ISREG(info.st_mode):
                candidate.unlink()
                changed = True
                continue
            raise FileValidationError("Project staging contains an unsafe entry")
        if changed:
            fsync_directory(staging)
        staging.rmdir()
        fsync_directory(staging.parent)

    def purge_cleanup_job(job: dict[str, Any], project: dict[str, Any]) -> bool:
        try:
            materials = material_root(Path(runtime.project_context_dir(project["runtime_name"])))
            quarantine = material_blob(materials, str(job["quarantine_name"]), require_regular=False)
            original = material_blob(materials, str(job["original_storage_name"]), require_regular=False)
            quarantine_present = quarantine.exists() or quarantine.is_symlink()
            original_present = original.exists() or original.is_symlink()
            if quarantine_present and quarantine.is_symlink():
                quarantine.unlink()
                fsync_directory(materials)
                quarantine_present = False
            if original_present and original.is_symlink():
                original.unlink()
                fsync_directory(materials)
                original_present = False
            if quarantine_present and original_present:
                raise FileValidationError("cleanup has both original and quarantine blobs")
            if not quarantine_present and original_present:
                original_info = original.lstat()
                if not stat_module.S_ISREG(original_info.st_mode):
                    raise FileValidationError("cleanup source is not a regular file")
                os.replace(original, quarantine)
                quarantine_present = True
            if quarantine_present:
                info = quarantine.lstat()
                if not stat_module.S_ISREG(info.st_mode):
                    raise FileValidationError("cleanup target is not a regular file")
                quarantine.unlink()
            directory_fd = os.open(
                materials, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            store.complete_file_cleanup(str(job["id"]), completed_at=time.time())
            return True
        except (FileValidationError, OSError, RuntimeErrorBase) as exc:
            store.fail_file_cleanup(str(job["id"]), type(exc).__name__)
            return False

    def allocate_staging_placeholder(staging: Path) -> Path:
        flags = (
            os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        for _attempt in range(128):
            candidate = staging_blob(
                staging, f".staged-{secrets.token_hex(32)}",
                require_regular=False,
            )
            try:
                descriptor = os.open(candidate, flags, 0o600)
            except FileExistsError:
                continue
            try:
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            fsync_directory(staging)
            return candidate
        raise FileValidationError("could not allocate staged recovery locator")

    def unlink_regular_or_symlink(path: Path, *, label: str) -> bool:
        if not path.exists() and not path.is_symlink():
            return False
        info = path.lstat()
        if not (path.is_symlink() or stat_module.S_ISREG(info.st_mode)):
            raise FileValidationError(f"{label} is not a removable file")
        path.unlink()
        return True

    def reconcile_pending_staging(
        row: dict[str, Any], project: dict[str, Any],
    ) -> str:
        """Keep one pending conflict private across migration/crash windows."""
        materials, staging = project_staging(project)
        material = material_blob(
            materials, str(row["storage_name"]), require_regular=False,
        )
        staging_name = row.get("staging_name")
        try:
            staged = staging_blob(staging, staging_name, require_regular=False)
        except FileValidationError:
            staged = allocate_staging_placeholder(staging)
            if not store.set_pending_staging_name(
                str(row["id"]), str(row["project_id"]), staged.name,
            ):
                staged.unlink(missing_ok=True)
                fsync_directory(staging)
                raise sqlite3.IntegrityError("pending staging migration lost its DB row")
            staging_name = staged.name

        staged_present = staged.exists() or staged.is_symlink()
        material_present = material.exists() or material.is_symlink()
        staged_valid = (
            staged_present and not staged.is_symlink()
            and staged_file_matches(
                staged, str(row["sha256"]), int(row["size"]),
                require_private=True,
            )
        )
        material_valid = (
            material_present and not material.is_symlink()
            and staged_file_matches(material, str(row["sha256"]), int(row["size"]))
        )

        if material_valid and not staged_valid:
            # Covers legacy pending-in-materials and a crash after promotion but
            # before the DB transition. A preallocated empty placeholder may be
            # atomically overwritten here.
            if staged_present:
                info = staged.lstat()
                if staged.is_symlink() or not stat_module.S_ISREG(info.st_mode):
                    raise FileValidationError("staged recovery target is unsafe")
            os.replace(material, staged)
            os.chmod(staged, 0o600, follow_symlinks=False)
            fsync_directory(materials)
            fsync_directory(staging)
            return "recovered"

        if staged_valid:
            if material_present:
                unlink_regular_or_symlink(
                    material, label="public duplicate pending material",
                )
                fsync_directory(materials)
            return "private"

        # Neither location contains the authenticated pending bytes. Remove any
        # attacker-controlled/safe file entries before lifting maintenance.
        changed_staging = unlink_regular_or_symlink(
            staged, label="broken staged material",
        )
        changed_materials = unlink_regular_or_symlink(
            material, label="broken public pending material",
        )
        if changed_staging:
            fsync_directory(staging)
        if changed_materials:
            fsync_directory(materials)
        store.purge_broken_pending_conflict(
            str(row["conflict_id"]), str(row["project_id"]),
        )
        store.audit(
            "pending_file_reconcile", "purged_broken", str(row["project_id"]),
            details=json.dumps({
                "conflict_id": row["conflict_id"], "file_id": row["id"],
                "filename": row["logical_name"], "sha256": row["sha256"],
                "size": row["size"],
            }, sort_keys=True),
        )
        return "purged_broken"

    def reconcile_external_materials(project_id: str | None = None) -> dict[str, int]:
        """Idempotently hide legacy conflicts and finish destructive cleanups."""
        normalized = store.normalize_pending_conflict_files()
        projects = {
            str(project["id"]): project for project in store.projects()
            if project_id is None or str(project["id"]) == project_id
        }
        completed = failed_cleanup = tombstones = orphan_pending = 0
        orphan_materials = 0
        pending_private = pending_recovered = pending_broken = 0
        for row in store.pending_conflict_files(project_id):
            project = projects.get(str(row["project_id"]))
            if project is None:
                continue
            try:
                outcome = reconcile_pending_staging(row, project)
                if outcome == "private":
                    pending_private += 1
                elif outcome == "recovered":
                    pending_recovered += 1
                else:
                    pending_broken += 1
            except (FileValidationError, OSError, RuntimeErrorBase, sqlite3.Error) as exc:
                failed_cleanup += 1
                store.audit(
                    "pending_file_reconcile", "failure", str(row["project_id"]),
                    details=json.dumps({
                        "conflict_id": row["conflict_id"], "file_id": row["id"],
                        "error_code": type(exc).__name__,
                    }, sort_keys=True),
                )
        for job in store.file_cleanup_jobs(project_id):
            project = projects.get(str(job["project_id"]))
            if project is None:
                continue
            if purge_cleanup_job(job, project):
                completed += 1
            else:
                failed_cleanup += 1
        for row in store.legacy_file_tombstones():
            if project_id is not None and str(row["project_id"]) != project_id:
                continue
            project = projects.get(str(row["project_id"]))
            if project is None:
                continue
            try:
                materials = material_root(Path(runtime.project_context_dir(project["runtime_name"])))
                blob = material_blob(materials, str(row["storage_name"]), require_regular=False)
                if blob.exists() or blob.is_symlink():
                    if blob.is_symlink():
                        blob.unlink()
                        fsync_directory(materials)
                    else:
                        info = blob.lstat()
                        if not stat_module.S_ISREG(info.st_mode):
                            raise FileValidationError("legacy cleanup target is not a regular file")
                        blob.unlink()
                        fsync_directory(materials)
                message_ids = store.file_message_ids(str(row["id"]), str(row["project_id"]))
                store.purge_legacy_file_tombstone(str(row["id"]), str(row["project_id"]))
                store.audit("legacy_file_cleanup", "success", str(row["project_id"]), details=json.dumps({
                    "file_id": row["id"], "filename": row["logical_name"],
                    "version": row["version"], "sha256": row["sha256"],
                    "detached_message_ids": message_ids,
                }, sort_keys=True))
                tombstones += 1
            except (FileValidationError, OSError, RuntimeErrorBase, sqlite3.Error) as exc:
                failed_cleanup += 1
                store.audit("legacy_file_cleanup", "failure", str(row["project_id"]), details=json.dumps({
                    "file_id": row["id"], "error_code": type(exc).__name__,
                }, sort_keys=True))
        for row in store.orphan_pending_files():
            if project_id is not None and str(row["project_id"]) != project_id:
                continue
            project = projects.get(str(row["project_id"]))
            if project is None:
                continue
            try:
                materials, staging = project_staging(project)
                staging_name = row.get("staging_name")
                if staging_name:
                    staged = staging_blob(
                        staging, staging_name, require_regular=False,
                    )
                    if unlink_regular_or_symlink(
                        staged, label="orphan staged material",
                    ):
                        fsync_directory(staging)
                blob = material_blob(materials, str(row["storage_name"]), require_regular=False)
                if unlink_regular_or_symlink(
                    blob, label="orphan pending material",
                ):
                    fsync_directory(materials)
                store.purge_orphan_pending_file(str(row["id"]), str(row["project_id"]))
                store.audit("legacy_file_cleanup", "orphan_pending", str(row["project_id"]), details=json.dumps({
                    "file_id": row["id"], "filename": row["logical_name"],
                    "version": row["version"], "sha256": row["sha256"],
                }, sort_keys=True))
                orphan_pending += 1
            except (FileValidationError, OSError, RuntimeErrorBase, sqlite3.Error) as exc:
                store.audit("legacy_file_cleanup", "failure", str(row["project_id"]), details=json.dumps({
                    "file_id": row["id"], "error_code": type(exc).__name__,
                }, sort_keys=True))
        # A crash can occur after rename but before the cleanup queue commit.
        # Such dotfiles are never addressable inputs; remove them on startup.
        for project in projects.values():
            try:
                materials = material_root(Path(runtime.project_context_dir(project["runtime_name"])))
                queued = {str(job["quarantine_name"]) for job in store.file_cleanup_jobs(str(project["id"]))}
                for candidate in materials.glob(".delete-*"):
                    if candidate.name in queued:
                        continue
                    info = candidate.lstat()
                    if candidate.is_symlink():
                        candidate.unlink()
                        fsync_directory(materials)
                        continue
                    if not stat_module.S_ISREG(info.st_mode):
                        continue
                    candidate.unlink()
                    fsync_directory(materials)
            except (FileValidationError, OSError, RuntimeErrorBase):
                failed_cleanup += 1

        # An ordinary first upload promotes bytes before inserting its DB row.
        # A crash in that narrow window leaves an unreferenced content-addressed
        # blob. Only strict 64-hex regular material names are eligible here;
        # reports/artifacts and unsafe entries are never inferred as upload
        # leftovers.
        for project in projects.values():
            try:
                project_id_value = str(project["id"])
                materials = material_root(Path(runtime.project_context_dir(project["runtime_name"])))
                referenced_names = store.file_storage_names(project_id_value)
                changed = False
                for candidate in materials.iterdir():
                    if (
                        _CONTENT_ADDRESS_RE.fullmatch(candidate.name) is None
                        or candidate.name in referenced_names
                    ):
                        continue
                    info = candidate.lstat()
                    if candidate.is_symlink() or not stat_module.S_ISREG(info.st_mode):
                        continue
                    candidate.unlink()
                    changed = True
                    orphan_materials += 1
                if changed:
                    fsync_directory(materials)
            except (FileValidationError, OSError, RuntimeErrorBase):
                failed_cleanup += 1

        # Private staging is a durable cache only for live pending-conflict DB
        # rows. Remove any unreferenced random files, plus project directories
        # whose DB Project disappeared before cleanup completed.
        referenced: dict[str, set[str]] = {}
        for row in store.pending_conflict_files(project_id):
            if isinstance(row.get("staging_name"), str):
                referenced.setdefault(str(row["project_id"]), set()).add(
                    str(row["staging_name"]),
                )
        known_staging: set[Path] = set()
        shared_roots: set[Path] = set()
        for project in projects.values():
            try:
                _materials, staging = project_staging(project)
                known_staging.add(staging)
                shared_roots.add(staging.parent)
                changed = False
                for candidate in staging.iterdir():
                    if candidate.name in referenced.get(str(project["id"]), set()):
                        continue
                    if unlink_regular_or_symlink(
                        candidate, label="orphan private staged material",
                    ):
                        changed = True
                if changed:
                    fsync_directory(staging)
            except (FileValidationError, OSError, RuntimeErrorBase):
                failed_cleanup += 1

        if project_id is None:
            adapter_root = (
                getattr(runtime, "agents_root", None)
                or getattr(runtime, "root", None)
            )
            if adapter_root is not None:
                shared_roots.add(
                    Path(adapter_root).resolve() / ".danus-web-control-staging",
                )
            for shared in shared_roots:
                try:
                    if not shared.exists():
                        continue
                    info = shared.lstat()
                    if shared.is_symlink() or not stat_module.S_ISDIR(info.st_mode):
                        raise FileValidationError("control staging parent is unsafe")
                    shared_changed = False
                    for directory in shared.iterdir():
                        if directory in known_staging:
                            continue
                        if directory.is_symlink():
                            directory.unlink()
                            shared_changed = True
                            continue
                        directory_info = directory.lstat()
                        if not stat_module.S_ISDIR(directory_info.st_mode):
                            raise FileValidationError("orphan staging entry is unsafe")
                        for candidate in directory.iterdir():
                            unlink_regular_or_symlink(
                                candidate, label="orphan Project staged material",
                            )
                        fsync_directory(directory)
                        directory.rmdir()
                        shared_changed = True
                    if shared_changed:
                        fsync_directory(shared)
                except (FileValidationError, OSError):
                    failed_cleanup += 1
        return {
            "normalized_pending": normalized, "completed": completed,
            "cleanup_pending": failed_cleanup, "legacy_tombstones": tombstones,
            "orphan_pending": orphan_pending,
            "orphan_materials": orphan_materials,
            "pending_private": pending_private,
            "pending_recovered": pending_recovered,
            "pending_broken": pending_broken,
        }

    def session(request: Request) -> dict[str, Any] | None:
        token = request.cookies.get(settings.cookie_name)
        if not token:
            return None
        return store.session(digest_token(token), time.time())

    def protected(request: Request) -> dict[str, Any] | None:
        current = session(request)
        if current is None:
            return None
        return current

    def csrf_ok(request: Request, current: dict[str, Any]) -> bool:
        origin = request.headers.get("origin")
        # State-changing browser requests must identify the trusted origin.
        # Deployments with no configured allowlist fail closed.
        if not settings.allowed_origins or origin not in settings.allowed_origins:
            return False
        supplied = request.headers.get("x-csrf-token")
        return bool(supplied) and secrets.compare_digest(digest_token(supplied), current["csrf_digest"])

    def auth_required(request: Request) -> dict[str, Any] | JSONResponse:
        current = protected(request)
        return current if current is not None else _error(401, "authentication required")

    def project_or_404(project_id: str) -> dict[str, Any] | JSONResponse:
        project = store.project(project_id)
        return project if project is not None else _error(404, "project not found")

    def bounded_parallel(value: Any | None, *, default: int | None = None) -> int:
        fallback = default if default is not None else settings.default_max_parallel_workers
        try:
            parsed = int(value if value is not None else fallback)
        except (TypeError, ValueError):
            raise ValueError("max_parallel_workers must be an integer")
        if value is None and parsed < 1:
            parsed = 1
        if parsed < 1 or parsed > settings.max_parallel_workers_limit:
            raise ValueError("max_parallel_workers out of range")
        return parsed

    def project_config(project: dict[str, Any]) -> dict[str, Any]:
        max_parallel = bounded_parallel(project.get("max_parallel_workers"), default=settings.default_max_parallel_workers)
        worker_model = project.get("worker_model") or project.get("model")
        return {
            "roles": project.get("roles") or "high:3,xhigh:4",
            "worker_model": worker_model,
            "model": worker_model,
            "max_parallel_workers": max_parallel,
        }

    def project_payload(project: dict[str, Any], *, workers: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        config = project_config(project)
        payload = {
            "id": project["id"],
            "name": project["name"],
            "problem": project["problem"],
            "runtime_name": project["runtime_name"],
            "roles": config["roles"],
            "worker_model": config["worker_model"],
            "model": config["model"],
            "max_parallel_workers": config["max_parallel_workers"],
            "initial_direction_confirmed": project.get("initial_direction_confirmed_at") is not None,
            "config": config,
        }
        if workers is not None:
            payload["workers"] = workers
        return payload

    def projection_with_project(project: dict[str, Any], projection: dict[str, Any]) -> dict[str, Any]:
        config = project_config(project)
        for key, value in (projection.get("config") or {}).items():
            if value is not None:
                config[key] = value
        workers = projection.get("workers", [])
        return {
            **projection,
            "config": config,
            "project": project_payload(project),
            "progress": worker_progress(workers),
        }

    def unassigned_workers(projection: dict[str, Any]) -> list[str]:
        workers = projection.get("workers", [])
        return [
            str(worker.get("worker") or "")
            for worker in workers
            if worker.get("assigned") is not True
        ]

    def latest_memory_entry(memory: dict[str, Any], kind: str) -> dict[str, Any] | None:
        for channel in memory.get("channels", []) or []:
            if str(channel.get("kind") or "").lower() == kind:
                entries = channel.get("entries") or []
                return entries[0] if entries else None
        return None

    def guidance_source(entry: dict[str, Any] | None, transport: str) -> str:
        evidence = str((entry or {}).get("evidence") or "").lower()
        markers = {
            source for source in ("offline-main-agent", "consult-derived")
            if f"guidance-source: {source}" in evidence
        }
        if len(markers) != 1:
            return "unknown" if not markers else "contract-mismatch"
        declared = next(iter(markers))
        expected = "offline-main-agent" if transport == "off" else "consult-derived"
        return declared if declared == expected else "contract-mismatch"

    def worker_is_live(worker: dict[str, Any]) -> bool:
        identity = worker.get("process_identity")
        if identity in {"matched", "mismatch", "dead", "unknown"}:
            return identity == "matched"
        # Injectable adapters used by deployments/tests predating #8 retain a
        # compatibility fallback. Production never trusts a raw numeric PID.
        return bool(worker.get("alive"))

    def replace_worker_roster_proof(
        project: dict[str, Any], projection: Any,
    ) -> tuple[str | None, list[dict[str, str]]]:
        """Validate the runtime-owned, full-process-group Worker exit proof.

        Destructive material mutation needs a terminal Worker state *and* a
        complete host projection. A dead leader alone is insufficient: an
        orphan descendant can still hold or traverse Project material.
        """
        if not isinstance(projection, dict):
            return "invalid_status_projection", []
        config = projection.get("config")
        workers = projection.get("workers")
        if not isinstance(config, dict) or not isinstance(workers, list):
            return "invalid_status_projection", []
        try:
            expected = [
                name for name, _role
                in L.parse_roles(project_config(project)["roles"])
            ]
        except (TypeError, ValueError):
            return "invalid_configured_roster", []
        if not expected or len(expected) != len(set(expected)):
            return "invalid_configured_roster", []

        configured = config.get("workers")
        if configured is not None:
            if not isinstance(configured, list):
                return "invalid_status_projection", []
            configured_names: list[str] = []
            for item in configured:
                name = item.get("worker") if isinstance(item, dict) else item
                if not isinstance(name, str) or not name or name in configured_names:
                    return "invalid_status_projection", []
                configured_names.append(name)
            if set(configured_names) != set(expected):
                return "roster_mismatch", []

        roster: dict[str, dict[str, Any]] = {}
        for worker in workers:
            if not isinstance(worker, dict):
                return "invalid_status_projection", []
            name = worker.get("worker")
            if not isinstance(name, str) or not name or name in roster:
                return "invalid_status_projection", []
            roster[name] = worker
        if set(roster) != set(expected):
            return "roster_mismatch", []

        blocked: list[dict[str, str]] = []
        terminal_states = {
            "created", "deadline", "error", "max_rounds", "reclaimed",
            "stopped", "terminated",
        }
        proof_reason = {
            "leader_pid_reused": "worker_process_identity_reused",
            "process_group_live_or_reused": "worker_process_group_live_or_reused",
            "project_process_reference": "worker_project_process_live",
            "process_inspection_failed": "worker_process_inspection_failed",
            "descendant_membership_unavailable": "worker_descendant_membership_unverified",
            "duplicate_host_process_group": "worker_process_identity_reused",
        }
        for name in expected:
            worker = roster[name]
            identity = worker.get("process_identity")
            if identity != "dead":
                reason = (
                    "worker_live" if identity == "matched"
                    else "worker_identity_mismatch" if identity == "mismatch"
                    else "worker_identity_unknown"
                )
                blocked.append({"worker": name, "reason": reason})
                continue
            if worker.get("alive") is not False or worker.get("raw_alive") is not False:
                blocked.append({"worker": name, "reason": "worker_status_inconsistent"})
                continue

            state = str(worker.get("state") or "").lower()
            if state not in terminal_states:
                blocked.append({"worker": name, "reason": "worker_state_unverified"})
                continue

            proof = worker.get("process_exit_proof")
            if not isinstance(proof, dict):
                blocked.append({"worker": name, "reason": "worker_process_group_unverified"})
                continue
            source = proof.get("source")
            pgid = proof.get("pgid")
            live_count = proof.get("live_process_count")
            reference_count = proof.get("project_reference_count")
            counts_valid = (
                isinstance(live_count, int) and not isinstance(live_count, bool)
                and live_count == 0
                and isinstance(reference_count, int) and not isinstance(reference_count, bool)
                and reference_count == 0
            )
            source_valid = (
                source == "never_started" and pgid is None and state == "created"
            ) or (
                source == "host_process_group"
                and isinstance(pgid, int) and not isinstance(pgid, bool) and pgid > 0
                and proof.get("descendant_membership_verified") is True
            )
            if (
                proof.get("status") == "verified_dead"
                and proof.get("inspection_complete") is True
                and counts_valid and source_valid
                and proof.get("reason") is None
            ):
                continue
            reason = proof_reason.get(
                str(proof.get("reason") or ""), "worker_process_group_unverified",
            )
            blocked.append({"worker": name, "reason": reason})
        return ("workers_not_stopped", blocked) if blocked else (None, [])

    async def project_worker_exit_proof(
        project: dict[str, Any], *, reconcile: bool = False,
    ) -> tuple[str | None, list[dict[str, str]], str | None]:
        try:
            projection_method = getattr(runtime, "worker_exit_projection", None)
            if not callable(projection_method):
                raise RuntimeSafetyError("runtime has no full Worker exit projection")
            projection = await asyncio.to_thread(
                projection_method, project["runtime_name"],
            )
        except Exception as exc:
            return "status_unavailable", [], type(exc).__name__
        if reconcile:
            reconcile_run(str(project["id"]), project, projection)
        reason, blocked = replace_worker_roster_proof(project, projection)
        return reason, blocked, None

    def project_maintenance_rejection(
        project_id: str, action: str,
    ) -> JSONResponse | None:
        reason = store.project_maintenance_reason(project_id)
        if reason is None:
            return None
        pending = reason in {"pending_file_conflict", "pending_file_reservation"}
        error_code = "pending_file_conflict" if pending else "file_cleanup_pending"
        store.audit(
            "file_conflict_gate", "rejected", project_id,
            details=json.dumps({
                "action": action, "error_code": error_code,
                "maintenance_reason": reason,
            }, sort_keys=True),
        )
        return JSONResponse({
            "detail": (
                "resolve or cancel the pending file conflict before continuing"
                if pending else
                "finish the pending file cleanup before continuing"
            ),
            "error_code": error_code,
            "status": "maintenance_required",
        }, status_code=409)

    def graceful_stop_request_failure(
        project: dict[str, Any], result: Any,
    ) -> str | None:
        """Require an explicit accepted stop result for every configured Worker."""
        if not isinstance(result, dict) or not isinstance(result.get("workers"), list):
            return "invalid_stop_response"
        try:
            expected = [
                name for name, _role in L.parse_roles(project_config(project)["roles"])
            ]
        except (TypeError, ValueError):
            return "invalid_configured_roster"
        if not expected or len(expected) != len(set(expected)):
            return "invalid_configured_roster"
        rows: dict[str, dict[str, Any]] = {}
        for row in result["workers"]:
            if not isinstance(row, dict):
                return "invalid_stop_response"
            worker = row.get("worker")
            if not isinstance(worker, str) or not worker or worker in rows:
                return "invalid_stop_response"
            rows[worker] = row
        if set(rows) != set(expected):
            return "stop_roster_mismatch"
        allowed = {"stopping (graceful)", "not-running"}
        if any(str(rows[name].get("result") or "") not in allowed for name in expected):
            return "worker_stop_refused"
        return None

    def worker_progress(workers: list[dict[str, Any]]) -> dict[str, int]:
        live = [worker for worker in workers if worker_is_live(worker)]
        stale = [
            worker for worker in workers
            if not worker_is_live(worker) and (
                worker.get("process_identity") == "mismatch"
                or str(worker.get("state") or "").lower() in {"running", "retrying"}
            )
        ]
        return {
            "expected_workers": len(workers),
            "live_workers": len(live),
            "stop_pending_workers": sum(bool(worker.get("stop_requested")) for worker in live),
            "stopped_workers": len(workers) - len(live) - len(stale),
            "stale_workers": len(stale),
        }

    def expected_worker_roster(
        project: dict[str, Any], projection: dict[str, Any],
    ) -> list[str]:
        configured = (projection.get("config") or {}).get("workers") or []
        roster: list[str] = []
        for worker in configured:
            name = worker.get("worker") if isinstance(worker, dict) else worker
            if isinstance(name, str) and name and name not in roster:
                roster.append(name)
        if roster:
            return roster
        try:
            return [name for name, _role in L.parse_roles(project_config(project)["roles"])]
        except (TypeError, ValueError):
            return []

    def lifecycle_result_failures(
        result: dict[str, Any], *, allowed: set[str],
    ) -> list[dict[str, Any]]:
        rows = result.get("workers", []) if isinstance(result, dict) else []
        return [
            row for row in rows
            if isinstance(row, dict) and "result" in row
            and str(row.get("result")) not in allowed
        ]

    def unresolved_raw_processes(projection: dict[str, Any]) -> list[str]:
        return [
            str(worker.get("worker") or "")
            for worker in projection.get("workers", [])
            if worker.get("raw_alive") is True and worker.get("alive") is not True
        ]

    def roster_state(
        project: dict[str, Any], projection: dict[str, Any],
        *, expected: list[str] | None = None,
    ) -> tuple[list[str], list[str], list[str]]:
        expected = expected if expected is not None else expected_worker_roster(project, projection)
        workers = {
            str(worker.get("worker")): worker
            for worker in projection.get("workers", [])
            if worker.get("worker")
        }
        alive = [name for name in expected if worker_is_live(workers.get(name, {}))]
        pending = [name for name in expected if name not in alive]
        return expected, alive, pending

    def enforce_expired_deadline(
        project_id: str, project: dict[str, Any], active: dict[str, Any],
        projection: dict[str, Any],
    ) -> dict[str, Any]:
        workers = projection.get("workers", [])
        if not any(
            worker.get("alive") is True or worker.get("raw_alive") is True
            for worker in workers
        ):
            store.update_run(
                active["id"], status="stopped", stopped_at=time.time(),
                outcome="deadline_enforced",
            )
            return projection
        try:
            enforcer = getattr(runtime, "enforce_deadline", runtime.stop_project)
            result = enforcer(project["runtime_name"])
            failures = lifecycle_result_failures(
                result, allowed={"killed", "not-running"},
            )
            if failures:
                raise RuntimeErrorBase(
                    "deadline force-stop refused: "
                    + ",".join(str(row.get("worker")) for row in failures)
                )
            projection = runtime.status_project(project["runtime_name"])
        except (RuntimeErrorBase, OSError) as exc:
            store.update_run(
                active["id"], status="stopping",
                outcome=f"deadline_force_failed: {exc}"[:200],
            )
            store.audit("run_deadline", "failure", project_id)
            return projection
        remaining = [
            worker for worker in projection.get("workers", [])
            if worker.get("alive") is True or worker.get("raw_alive") is True
        ]
        if remaining:
            store.update_run(
                active["id"], status="stopping",
                outcome="deadline_force_incomplete",
            )
            store.audit("run_deadline", "partial_failure", project_id)
        else:
            store.update_run(
                active["id"], status="stopped", stopped_at=time.time(),
                outcome="deadline_enforced",
            )
            store.audit("run_deadline", "success", project_id)
        return projection

    def reconcile_run(project_id: str, project: dict[str, Any], projection: dict[str, Any]) -> dict[str, Any]:
        active = store.active_run(project_id)
        if active is not None:
            workers = projection.get("workers", [])
            expected, alive, pending = roster_state(project, projection)
            if time.time() >= active["deadline"]:
                return enforce_expired_deadline(
                    project_id, project, active, projection,
                )
            if active["status"] == "stopping" and not any(worker_is_live(worker) for worker in workers):
                unresolved = unresolved_raw_processes(projection)
                if unresolved:
                    store.update_run(
                        active["id"], status="stopping",
                        outcome=("stop_blocked_identity:" + ",".join(unresolved))[:200],
                    )
                else:
                    store.update_run(active["id"], status="stopped", stopped_at=time.time(), outcome="graceful_stop")
            elif (
                active["status"] == "starting"
                and int(active.get("start_attempt_generation") or 0) > 0
                and active.get("start_attempt_outcome") == "partial_start"
                and expected
                and not pending
            ):
                generation = int(active["start_attempt_generation"])
                store.complete_start_attempt(
                    active["id"], generation,
                    attempt_outcome="started", status="running",
                    outcome=f"broker_start_reconciled:{generation}",
                )
            elif active["status"] == "running" and expected and pending:
                if alive:
                    outcome = "degraded_missing:" + ",".join(pending)
                    if active.get("outcome") != outcome:
                        store.update_run(active["id"], status="running", outcome=outcome[:200])
                        store.audit("run_roster", "degraded", project_id)
                else:
                    outcome = "worker_error" if any(worker.get("state") == "error" for worker in workers) else "workers_exited"
                    store.update_run(active["id"], status="stopped", stopped_at=time.time(), outcome=outcome)
            elif active["status"] == "running" and expected and not pending and str(active.get("outcome") or "").startswith("degraded_missing:"):
                store.update_run(active["id"], status="running", outcome="roster_recovered")
        return projection

    def lifecycle_url(project_id: str) -> str:
        return f"{lifecycle_base}/internal/api/projects/{quote(project_id, safe='')}/lifecycle"

    def lifecycle_token(project: dict[str, Any]) -> str:
        return project_lifecycle_capability(
            lifecycle_hmac_secret, project["id"], project["runtime_name"],
        )

    def artifact_confirmation_token(intent: dict[str, Any]) -> str:
        return artifact_confirmation_capability(
            lifecycle_hmac_secret, str(intent["id"]), str(intent["project_id"]),
            str(intent["action"]), str(intent["payload_digest"]),
        )

    async def execute_artifact_action(
        project: dict[str, Any], action: str, normalized: dict[str, Any],
        *, actor: str,
    ) -> dict[str, Any] | JSONResponse:
        project_id = str(project["id"])
        audit_details = json.dumps({
            "action": action, "actor": actor,
            "payload_digest": _artifact_payload_digest(action, normalized),
            "paper_id": normalized.get("paper_id"),
            "fact_count": len(normalized.get("fact_ids") or []),
            "stop_workers": normalized.get("stop_workers"),
        }, sort_keys=True)
        try:
            if action == "finalize-suggest":
                raw = await asyncio.to_thread(runtime.finalize_suggestions, project["runtime_name"])
            elif action == "finalize":
                raw = await asyncio.to_thread(
                    runtime.finalize_target, project["runtime_name"],
                    normalized["fact_ids"], normalized["paper_id"],
                )
            elif action == "human-summary":
                raw = await asyncio.to_thread(
                    runtime.write_human_summary, project["runtime_name"], normalized["language"],
                )
            elif action == "write-paper":
                raw = await asyncio.to_thread(
                    runtime.write_paper_artifact, project["runtime_name"],
                    paper_id=normalized["paper_id"],
                    stop_workers=normalized["stop_workers"],
                    fact_ids=normalized["fact_ids"],
                    instructions=normalized["instructions"],
                )
            else:
                return _error(400, "unsupported artifact action")
            if not isinstance(raw, dict):
                raise RuntimeError("artifact runtime returned an invalid response")
            result = {"status": "ok", "action": action, **raw}
            if result.get("status") != "ok":
                store.audit("artifact_action", "failure", project_id, details=audit_details)
                status_code = 409 if result.get("status") == "needs_target" else 502
                return JSONResponse(result, status_code=status_code)
            if action == "write-paper" and normalized["stop_workers"]:
                graceful_stop = await asyncio.to_thread(
                    runtime.stop_project, project["runtime_name"],
                )
                stop_failure = graceful_stop_request_failure(project, graceful_stop)
                if stop_failure is not None:
                    store.audit(
                        "artifact_action", "stop_incomplete", project_id,
                        details=json.dumps({
                            **json.loads(audit_details),
                            "error_code": stop_failure,
                        }, sort_keys=True),
                    )
                    return JSONResponse({
                        "status": "failed", "action": action,
                        "error_code": stop_failure,
                        "detail": "one or more Worker stops were not accepted",
                    }, status_code=502)
                result["graceful_stop"] = graceful_stop
            store.audit("artifact_action", "success", project_id, details=audit_details)
            return result
        except (RuntimeErrorBase, OSError, ValueError, RuntimeError) as exc:
            store.audit("artifact_action", "failure", project_id, details=json.dumps({
                **json.loads(audit_details), "error_code": type(exc).__name__,
            }, sort_keys=True))
            status_code = 409 if action in {"finalize", "finalize-suggest"} else 502
            return _error(status_code, "artifact operation failed")

    @app.post("/internal/api/projects/{project_id}/lifecycle")
    async def internal_project_lifecycle(project_id: str, request: Request):
        client_host = request.client.host if request.client is not None else None
        if not _loopback_host(client_host):
            return _error(403, "loopback access required")
        project = store.project(project_id)
        if project is None:
            return _error(404, "project not found")
        authorization = request.headers.get("authorization", "")
        prefix = "Bearer "
        supplied = authorization[len(prefix):] if authorization.startswith(prefix) else ""
        if not verify_project_lifecycle_capability(
            supplied, lifecycle_hmac_secret, project["id"], project["runtime_name"],
        ):
            return _error(403, "invalid lifecycle capability")
        try:
            payload = await request.json()
        except Exception:
            return _error(400, "invalid lifecycle request")
        action = payload.get("action") if isinstance(payload, dict) else None
        if action not in {"assign", "status", "start", "pause", "resume", "stop", "finalize-suggest", "finalize", "human-summary", "write-paper"}:
            return _error(400, "invalid lifecycle action")
        if payload.get("force") is True:
            return _error(403, "force stop is reserved for host safety controls")
        worker = payload.get("worker")
        if worker is not None:
            try:
                validate_runtime_name(str(worker))
            except ValueError:
                return _error(400, "invalid worker")
            worker = str(worker)

        if action in {"finalize-suggest", "finalize", "human-summary", "write-paper"}:
            try:
                normalized = _artifact_payload(action, payload)
            except ValueError as exc:
                return _error(400, str(exc))
            if action == "finalize-suggest":
                return await execute_artifact_action(
                    project, action, normalized, actor="main_agent_broker",
                )
            else:
                supplied_confirmation = payload.get("confirmation_token")
                try:
                    confirmation_digest = (
                        digest_token(supplied_confirmation)
                        if isinstance(supplied_confirmation, str)
                        and 0 < len(supplied_confirmation) <= 512 else ""
                    )
                except (UnicodeEncodeError, ValueError):
                    confirmation_digest = ""
                confirmation_status = "invalid"
                if confirmation_digest:
                    confirmation_status = store.consume_artifact_confirmation(
                        confirmation_digest, project_id, action,
                        _artifact_payload_digest(action, normalized), now=time.time(),
                    )
                if confirmation_status != "consumed":
                    store.audit("artifact_confirmation", "rejected", project_id, details=json.dumps({
                        "action": action, "error_code": confirmation_status,
                        "payload_digest": _artifact_payload_digest(action, normalized),
                    }, sort_keys=True))
                    return JSONResponse({
                        "status": "rejected", "action": action,
                        "error_code": confirmation_status,
                        "detail": "artifact confirmation was rejected",
                    }, status_code=410 if confirmation_status == "expired" else 409)
                store.audit("artifact_confirmation", "consumed", project_id, details=json.dumps({
                    "action": action, "payload_digest": _artifact_payload_digest(action, normalized),
                }, sort_keys=True))
            artifact_result = await execute_artifact_action(
                project, action, normalized, actor="main_agent_broker",
            )
            succeeded = isinstance(artifact_result, dict) and artifact_result.get("status") == "ok"
            outcome_code = "ok" if succeeded else "runtime_failed"
            if not store.complete_artifact_confirmation(
                confirmation_digest, succeeded=succeeded, outcome_code=outcome_code,
                completed_at=time.time(),
            ):
                store.audit("artifact_confirmation", "outcome_persist_failed", project_id, details=json.dumps({
                    "action": action, "payload_digest": _artifact_payload_digest(action, normalized),
                }, sort_keys=True))
                return JSONResponse({
                    "status": "failed", "action": action,
                    "error_code": "outcome_not_persisted",
                    "detail": "artifact outcome could not be persisted",
                }, status_code=500)
            store.audit("artifact_confirmation", "succeeded" if succeeded else "failed", project_id, details=json.dumps({
                "action": action, "outcome_code": outcome_code,
                "payload_digest": _artifact_payload_digest(action, normalized),
            }, sort_keys=True))
            return artifact_result
        if action == "status":
            try:
                return runtime.status_project(project["runtime_name"])
            except (RuntimeErrorBase, OSError):
                return _error(502, "project status unavailable")
        if action in {"start", "resume"}:
            maintenance = project_maintenance_rejection(
                project_id, f"lifecycle_{action}",
            )
            if maintenance is not None:
                return maintenance
        if action in {"assign", "start"} and project.get("initial_direction_confirmed_at") is None:
            return _error(409, "initial direction confirmation required before assignment or start")
        if action == "assign":
            task = payload.get("task")
            if worker is None or not isinstance(task, str) or not task.strip():
                return _error(400, "assign requires worker and non-empty task")
            try:
                result = runtime.assign_worker(project["runtime_name"], worker, task)
            except (RuntimeErrorBase, OSError) as exc:
                store.audit("worker_assign", "failure", project_id)
                return _error(409, str(exc)[:200] or "assignment failed")
            store.audit("worker_assign", "success", project_id)
            return {"status": "assigned", "worker": worker, "result": result}

        active = store.active_run(project_id)
        if active is None:
            return _error(409, "project has no active run intent")
        if action in {"pause", "resume"} and (
            active["status"] != "running" or time.time() >= active["deadline"]
        ):
            return _error(409, "project run is not resumable")
        if action == "start":
            if active["status"] != "starting":
                if active["status"] == "running":
                    projection = runtime.status_project(project["runtime_name"])
                    expected, alive, pending = roster_state(project, projection)
                    if expected and not pending:
                        return {"status": "running", "run_id": active["id"], "workers": alive}
                return _error(409, "project run is not awaiting start")
            if time.time() >= active["deadline"]:
                try:
                    runtime.stop_project(project["runtime_name"])
                except (RuntimeErrorBase, OSError) as exc:
                    store.update_run(active["id"], status="stopping", outcome=f"deadline_stop_failed: {exc}"[:200])
                else:
                    store.update_run(active["id"], status="stopping", outcome="deadline_stop_requested")
                return _error(409, "project run deadline reached")
            generation = store.begin_start_attempt(active["id"])
            if generation is None:
                return _error(409, "project run is not awaiting start")
            try:
                before = runtime.status_project(project["runtime_name"])
                expected = expected_worker_roster(project, before)
                runtime.start_project(project["runtime_name"])
                projection = runtime.status_project(project["runtime_name"])
            except (RuntimeErrorBase, OSError) as exc:
                store.complete_start_attempt(
                    active["id"], generation,
                    attempt_outcome="failed", status="starting",
                    outcome=f"start_failed: {exc}"[:200],
                )
                store.audit("run_start", "failure", project_id)
                return _error(502, "project workers could not be started")
            _after_expected, alive, pending = roster_state(
                project, projection, expected=expected,
            )
            if not expected or pending:
                outcome = "partial_start:" + ",".join(pending or ["unknown_roster"])
                store.complete_start_attempt(
                    active["id"], generation,
                    attempt_outcome="partial_start", status="starting",
                    outcome=outcome[:200],
                )
                store.audit("run_start", "partial_failure", project_id)
                return JSONResponse({
                    "detail": "project workers only partially started",
                    "status": "partial_start",
                    "run_id": active["id"],
                    "expected_workers": expected,
                    "alive_workers": alive,
                    "not_running_workers": pending,
                }, status_code=502)
            store.complete_start_attempt(
                active["id"], generation,
                attempt_outcome="started", status="running",
                outcome="main_agent_start",
            )
            store.audit("run_start", "success", project_id)
            return {"status": "running", "run_id": active["id"], "workers": alive}

        if action == "pause":
            try:
                result = runtime.pause_project(project["runtime_name"], worker=worker)
            except (RuntimeErrorBase, OSError) as exc:
                store.audit("run_pause", "failure", project_id)
                return _error(409, str(exc)[:200] or "pause request failed")
            store.audit("run_pause", "success", project_id)
            return JSONResponse({**result, "run_id": active["id"]}, status_code=202)

        if action == "resume":
            try:
                result = runtime.resume_project(project["runtime_name"], worker=worker)
            except (RuntimeErrorBase, OSError) as exc:
                store.audit("run_resume", "failure", project_id)
                return _error(409, str(exc)[:200] or "resume request failed")
            store.audit("run_resume", "success", project_id)
            return JSONResponse({**result, "run_id": active["id"]}, status_code=202)

        try:
            result = runtime.stop_project(project["runtime_name"])
            failures = lifecycle_result_failures(
                result, allowed={"stopping (graceful)", "not-running"},
            )
            if failures:
                store.update_run(
                    active["id"], status="stopping",
                    outcome=("main_agent_stop_refused:" + ",".join(
                        str(row.get("worker")) for row in failures
                    ))[:200],
                )
                store.audit("run_stop", "failure", project_id)
                return JSONResponse({
                    "detail": "one or more Worker stops were refused",
                    "workers": failures,
                }, status_code=409)
        except (RuntimeErrorBase, OSError):
            store.update_run(active["id"], status="stopping", outcome="main_agent_stop_failed")
            store.audit("run_stop", "failure", project_id)
            return _error(502, "project stop could not be completed")
        store.update_run(active["id"], status="stopping", outcome="main_agent_stop_requested")
        store.audit("run_stop", "success", project_id)
        return JSONResponse({
            "status": "stop_requested", "run_id": active["id"],
        }, status_code=202)

    @app.post("/api/auth/login")
    async def login(request: Request):
        try:
            payload = await request.json()
        except Exception:
            return _error(401, "invalid credentials")
        password = payload.get("password") if isinstance(payload, dict) else None
        origin = request.headers.get("origin")
        if settings.allowed_origins and origin is not None and origin not in settings.allowed_origins:
            return _error(403, "origin not allowed")
        now = time.time()
        key = request.client.host if request.client else "unknown"
        count, until = failed.get(key, (0, 0.0))
        if until > now:
            return _error(429, "too many login attempts")
        if not isinstance(password, str) or not verify_password(password, settings.password_hash):
            count += 1
            failed[key] = (count, now + min(300.0, 2.0 ** min(count, 8)))
            store.audit("login", "failure", details=json.dumps({"source": "public"}))
            return _error(401, "invalid credentials")
        failed.pop(key, None)
        token, csrf = new_token(), new_token()
        now = time.time()
        store.add_session({
            "id": uuid.uuid4().hex, "token_digest": digest_token(token),
            "csrf_digest": digest_token(csrf), "created_at": now, "last_seen": now,
            "expires_at": now + settings.session_ttl_seconds,
        })
        store.audit("login", "success")
        response = JSONResponse({"authenticated": True, "csrf_token": csrf})
        response.set_cookie(settings.cookie_name, token, max_age=settings.session_ttl_seconds,
                            secure=settings.cookie_secure, httponly=True, samesite="strict", path="/")
        response.set_cookie(f"{settings.cookie_name}_csrf", csrf, max_age=settings.session_ttl_seconds,
                            secure=settings.cookie_secure, httponly=False, samesite="strict", path="/")
        return response

    @app.post("/api/auth/logout")
    async def logout(request: Request):
        current = session(request)
        if current is None:
            return _error(401, "authentication required")
        if not csrf_ok(request, current):
            return _error(403, "csrf validation failed")
        store.revoke_session(current["id"], time.time())
        store.audit("logout", "success")
        response = JSONResponse({"authenticated": False})
        response.delete_cookie(settings.cookie_name, path="/")
        response.delete_cookie(f"{settings.cookie_name}_csrf", path="/")
        return response

    @app.get("/api/auth/session")
    async def auth_session(request: Request):
        current = session(request)
        if current is None:
            return _error(401, "authentication required")
        token = request.cookies.get(f"{settings.cookie_name}_csrf")
        if not token or not secrets.compare_digest(digest_token(token), current["csrf_digest"]):
            token = new_token()
            store.rotate_csrf(current["id"], digest_token(token))
        response = JSONResponse({"authenticated": True, "expires_at": current["expires_at"], "csrf_token": token})
        response.set_cookie(f"{settings.cookie_name}_csrf", token, max_age=settings.session_ttl_seconds,
                            secure=settings.cookie_secure, httponly=False, samesite="strict", path="/")
        return response

    @app.get("/api/auth/me")
    async def me(request: Request):
        current = session(request)
        if current is None:
            return _error(401, "authentication required")
        return {"authenticated": True}

    @app.get("/api/config")
    async def config_projection(request: Request):
        if isinstance((auth := auth_required(request)), JSONResponse):
            return auth
        default_worker_model = codex.model()
        catalog = model_catalog.snapshot(default_worker_model=default_worker_model)
        worker_models = catalog.get("models", [])
        main_meta = main_agent_metadata(main_agent)
        strategy_meta = strategy_metadata()
        return {
            "worker_models": worker_models,
            "models": worker_models,
            "default_worker_model": default_worker_model,
            "default_max_parallel_workers": bounded_parallel(None),
            "limits": {
                "default_max_parallel_workers": bounded_parallel(None),
                "max_parallel_workers": settings.max_parallel_workers_limit,
            },
            "main_agent": main_meta,
            "strategy": strategy_meta,
            "main_agent_backend": main_meta["backend"],
            "strategy_transport": strategy_meta["transport"],
            "model_catalog": {
                key: value
                for key, value in catalog.items()
                if key not in {"models"}
            },
        }

    @app.get("/api/projects")
    async def list_projects(request: Request):
        if isinstance((auth := auth_required(request)), JSONResponse):
            return auth
        rows = []
        try:
            projects = store.projects()
        except sqlite3.Error:
            return _error(503, "project storage unavailable")
        for project in projects:
            try:
                projection = runtime.status_project(project["runtime_name"])
            except RuntimeErrorBase:
                projection = {"workers": [], "error": "runtime unavailable"}
            rows.append(project_payload(project, workers=projection.get("workers", [])))
        return rows

    @app.post("/api/projects")
    async def create_project(request: Request):
        current = auth_required(request)
        if isinstance(current, JSONResponse):
            return current
        if not csrf_ok(request, current):
            return _error(403, "csrf validation failed")
        try:
            payload = await request.json()
            name = _runtime_name(payload["name"])
            problem = payload["problem"]
            roles = payload.get("roles", "high:3,xhigh:4")
            worker_model = payload.get("worker_model", payload.get("model"))
            if worker_model is not None:
                worker_model = str(worker_model).strip() or None
            # Resolve "server default" now so project metadata and every Worker
            # ROLE.env retain the same concrete model for the lifetime of the
            # project, even if the server default changes later.
            worker_model = worker_model or codex.model()
            max_parallel_workers = bounded_parallel(payload.get("max_parallel_workers"))
            if not isinstance(problem, str) or not problem.strip():
                raise ValueError("problem must be non-empty")
            project_id = uuid.uuid4().hex
            result = runtime.create_project(
                name,
                problem,
                roles,
                worker_model,
                max_parallel_workers=max_parallel_workers,
            )
            try:
                store.add_project({
                    "id": project_id,
                    "name": name,
                    "runtime_name": name,
                    "problem": problem,
                    "roles": roles,
                    "worker_model": worker_model,
                    "max_parallel_workers": max_parallel_workers,
                    "created_at": time.time(),
                })
            except sqlite3.IntegrityError:
                try:
                    runtime.delete_project(name)
                except RuntimeErrorBase:
                    pass
                store.audit("project_create", "failure", details=json.dumps({"error": "project name already exists"}))
                return _error(409, "project name already exists")
            except Exception:
                try:
                    runtime.delete_project(name)
                except RuntimeErrorBase:
                    pass
                store.audit("project_create", "failure", details=json.dumps({"error": "metadata persistence failed"}))
                return _error(500, "project metadata could not be persisted")
            store.audit("project_create", "success", project_id)
            project = store.project(project_id)
            return JSONResponse(project_payload(project or {
                "id": project_id,
                "name": name,
                "runtime_name": name,
                "problem": problem,
                "roles": roles,
                "worker_model": worker_model,
                "max_parallel_workers": max_parallel_workers,
                "created_at": time.time(),
            }, workers=result.get("workers", [])), status_code=201)
        except (KeyError, TypeError, ValueError) as exc:
            return _error(400, str(exc))
        except RuntimeErrorBase as exc:
            store.audit("project_create", "failure", details=json.dumps({"error": str(exc)}))
            return _error(409, "project creation failed")

    @app.delete("/api/projects/{project_id}")
    async def delete_project(project_id: str, request: Request):
        current = auth_required(request)
        if isinstance(current, JSONResponse):
            return current
        if not csrf_ok(request, current):
            return _error(403, "csrf validation failed")
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse):
            return project
        payload = await request.json()
        if not isinstance(payload, dict) or payload.get("confirm_name") != project["name"]:
            return _error(400, "destructive confirmation does not match project name")
        async with lock_for(project_id):
            try:
                rejection_reason, blocked_workers, _status_error = (
                    await project_worker_exit_proof(project, reconcile=True)
                )
                if store.active_run(project_id) is not None or rejection_reason is not None:
                    store.audit(
                        "project_delete", "rejected_workers_not_stopped", project_id,
                        details=json.dumps({
                            "reason": rejection_reason or "active_run",
                            "blocked_workers": blocked_workers,
                        }, sort_keys=True),
                    )
                    return _error(409, "project must be stopped before deletion")
                # Staging is outside runtime.delete_project's Project tree. It
                # must be durably empty before the DB maintenance gate is
                # removed or the runtime directory disappears.
                erase_project_staging(project)
                result = runtime.delete_project(project["runtime_name"])
                store.delete_project(project_id)
                store.audit("project_delete", "success", project_id)
                return JSONResponse({"deleted": True, **result}, status_code=200)
            except (FileValidationError, OSError, RuntimeErrorBase):
                store.audit("project_delete", "failure", project_id)
                return _error(502, "project deletion failed")

    @app.get("/api/projects/{project_id}")
    async def get_project(project_id: str, request: Request):
        if isinstance((auth := auth_required(request)), JSONResponse):
            return auth
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse):
            return project
        return project_payload(project)

    @app.post("/api/projects/{project_id}/runs")
    async def start_run(project_id: str, request: Request):
        current = auth_required(request)
        if isinstance(current, JSONResponse):
            return current
        if not csrf_ok(request, current):
            return _error(403, "csrf validation failed")
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse):
            return project
        if project.get("initial_direction_confirmed_at") is None:
            return _error(409, "initial direction confirmation required before run start")
        try:
            payload = await request.json()
        except Exception:
            return _error(400, "duration_seconds must be an integer")
        duration = payload.get("duration_seconds") if isinstance(payload, dict) else None
        if isinstance(duration, bool) or not isinstance(duration, int):
            return _error(400, "duration_seconds must be an integer")
        if duration <= 0 or duration > 7 * 24 * 3600:
            return _error(400, "duration_seconds must be between 1 and 604800")
        async with lock_for(project_id):
            maintenance = project_maintenance_rejection(project_id, "run_start")
            if maintenance is not None:
                return maintenance
            try:
                status_projection = runtime.status_project(project["runtime_name"])
                reconcile_run(project_id, project, status_projection)
            except RuntimeErrorBase:
                # A run may only start after the control plane can prove all
                # workers have real Main Agent assignments.
                return _error(502, "runtime projection unavailable")
            active = store.active_run(project_id)
            if active is not None:
                return _error(409, "project already has an active run")
            workers = status_projection.get("workers", [])
            if not workers:
                return _error(409, "project has no workers")
            missing_assignments = [name for name in unassigned_workers(status_projection) if name]
            if missing_assignments:
                return JSONResponse(
                    {
                        "detail": "all workers must be assigned before starting a run",
                        "unassigned_workers": missing_assignments,
                    },
                    status_code=409,
                )
            started = time.time()
            deadline = started + duration
            run = {"id": uuid.uuid4().hex, "project_id": project_id, "duration_seconds": duration, "started_at": started, "deadline": deadline, "status": "starting"}
            # Persist the bounded operator intent before exposing it to the
            # Main Agent. Normal Worker spawning is brokered only when that
            # project-scoped Main Agent explicitly requests it.
            store.add_run(run)
            try:
                runtime.write_deadline(project["runtime_name"], deadline)
                beat_coordinator.request(project_id)
                store.audit("run_start", "intent_recorded", project_id)
                return JSONResponse({
                    "run_id": run["id"], "status": "start_requested",
                    "duration_seconds": duration, "started_at": started,
                    "deadline": deadline,
                }, status_code=202)
            except (RuntimeErrorBase, OSError) as exc:
                # A failed deadline write must not leave an active intent that
                # appears safe to start later.
                try:
                    runtime.clear_deadline(project["runtime_name"])
                except (AttributeError, RuntimeErrorBase):
                    pass
                store.update_run(run["id"], status="failed", stopped_at=time.time(), outcome=str(exc)[:200])
                store.audit("run_start", "failure", project_id)
                return _error(502, "project run could not be started")

    @app.get("/api/projects/{project_id}/runs/{run_id}")
    async def get_run(project_id: str, run_id: str, request: Request):
        if isinstance((auth := auth_required(request)), JSONResponse):
            return auth
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse):
            return project
        run = store.run(run_id)
        if run is None or run["project_id"] != project_id:
            return _error(404, "run not found")
        try:
            projection = reconcile_run(project_id, project, runtime.status_project(project["runtime_name"]))
            run = store.run(run_id) or run
        except RuntimeErrorBase:
            projection = {"workers": [], "error": "runtime unavailable"}
        workers = projection.get("workers", [])
        return {**run, **worker_progress(workers), "workers": workers}

    @app.post("/api/projects/{project_id}/runs/{run_id}/stop")
    async def stop_run(project_id: str, run_id: str, request: Request):
        current = auth_required(request)
        if isinstance(current, JSONResponse):
            return current
        if not csrf_ok(request, current):
            return _error(403, "csrf validation failed")
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse):
            return project
        run = store.run(run_id)
        if run is None or run["project_id"] != project_id:
            return _error(404, "run not found")
        async with lock_for(project_id):
            if run["status"] not in ("starting", "running", "stopping"):
                return JSONResponse({"run_id": run_id, "status": run["status"]}, status_code=200)
            active = store.active_run(project_id)
            if active is None or active["id"] != run_id:
                return _error(409, "run is not the active project run")
            store.update_run(run_id, status="stopping", outcome="operator_stop_intent")
            store.audit("run_stop", "intent_recorded", project_id)
            return JSONResponse({"run_id": run_id, "status": "stop_requested"}, status_code=202)

    @app.get("/api/projects/{project_id}/runtime")
    async def runtime_status(project_id: str, request: Request):
        if isinstance((auth := auth_required(request)), JSONResponse):
            return auth
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse):
            return project
        try:
            projection = reconcile_run(project_id, project, runtime.status_project(project["runtime_name"]))
            active = store.active_run(project_id)
            if active is not None:
                expected, alive, pending = roster_state(project, projection)
                progress = worker_progress(projection.get("workers", []))
                projection = {**projection, "run": {
                    "id": active["id"], "status": active["status"],
                    "duration_seconds": active["duration_seconds"],
                    "started_at": active["started_at"],
                    "deadline": active["deadline"], "outcome": active.get("outcome"),
                    "expected_worker_names": expected, "alive_worker_names": alive,
                    "alive_workers": alive, "not_running_workers": pending, **progress,
                }}

            return projection_with_project(project, projection)
        except RuntimeErrorBase:
            return _error(502, "runtime projection unavailable")

    @app.post("/api/projects/{project_id}/stop")
    async def stop_project(project_id: str, request: Request):
        current = auth_required(request)
        if isinstance(current, JSONResponse):
            return current
        if not csrf_ok(request, current):
            return _error(403, "csrf validation failed")
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse):
            return project
        async with lock_for(project_id):
            active = store.active_run(project_id)
            if active is None:
                return _error(409, "project has no active run intent")
            store.update_run(active["id"], status="stopping", outcome="operator_stop_intent")
            store.audit("run_stop", "intent_recorded", project_id)
            return JSONResponse({"status": "stop_requested"}, status_code=202)

    async def safety_control_context(project_id: str, request: Request) -> tuple[dict[str, Any], dict[str, Any]] | JSONResponse:
        current = auth_required(request)
        if isinstance(current, JSONResponse):
            return current
        if not csrf_ok(request, current):
            return _error(403, "csrf validation failed")
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse):
            return project
        try:
            payload = await request.json()
        except Exception:
            payload = {}
        if not isinstance(payload, dict):
            return _error(400, "invalid request body")
        payload["_actor_session_id"] = current.get("id")
        worker = payload.get("worker")
        if worker is not None:
            try:
                validate_runtime_name(str(worker))
            except ValueError:
                return _error(400, "invalid worker")
            payload["worker"] = str(worker)
        return project, payload

    @app.post("/api/projects/{project_id}/pause")
    async def pause_project_workers(project_id: str, request: Request):
        context = await safety_control_context(project_id, request)
        if isinstance(context, JSONResponse):
            return context
        project, payload = context
        async with lock_for(project_id):
            active = store.active_run(project_id)
            if active is None or active["status"] != "running" or time.time() >= active["deadline"]:
                return _error(409, "project run is not resumable")
            store.audit(
                "run_pause", "intent_recorded", project_id,
                details=json.dumps({
                    "actor": "operator_session", "session_id": payload.get("_actor_session_id"),
                    "worker": payload.get("worker"),
                }),
            )
            return JSONResponse({
                "status": "pause_intent", "worker": payload.get("worker"),
            }, status_code=202)

    @app.post("/api/projects/{project_id}/resume")
    async def resume_project_workers(project_id: str, request: Request):
        context = await safety_control_context(project_id, request)
        if isinstance(context, JSONResponse):
            return context
        project, payload = context
        async with lock_for(project_id):
            maintenance = project_maintenance_rejection(project_id, "run_resume")
            if maintenance is not None:
                return maintenance
            active = store.active_run(project_id)
            if active is None or active["status"] != "running" or time.time() >= active["deadline"]:
                return _error(409, "project run is not resumable")
            store.audit(
                "run_resume", "intent_recorded", project_id,
                details=json.dumps({
                    "actor": "operator_session", "session_id": payload.get("_actor_session_id"),
                    "worker": payload.get("worker"),
                }),
            )
            return JSONResponse({
                "status": "resume_intent", "worker": payload.get("worker"),
            }, status_code=202)

    @app.post("/api/projects/{project_id}/force-stop")
    async def force_stop_project_workers(project_id: str, request: Request):
        context = await safety_control_context(project_id, request)
        if isinstance(context, JSONResponse):
            return context
        project, payload = context
        if payload.get("confirm") != project["name"]:
            return _error(409, "project-name confirmation required")
        async with lock_for(project_id):
            try:
                result = runtime.force_stop_project(project["runtime_name"], worker=payload.get("worker"))
                projection = runtime.status_project(project["runtime_name"])
                active = store.active_run(project_id)
                if active is not None and not any(
                    worker_is_live(row) for row in projection.get("workers", [])
                ):
                    store.update_run(
                        active["id"], status="stopped", stopped_at=time.time(),
                        outcome="emergency_force_stop",
                    )
                store.audit(
                    "run_force_stop", "success", project_id,
                    details=json.dumps({
                        "actor": "operator_session",
                        "session_id": payload.get("_actor_session_id"),
                        "target_worker": payload.get("worker"),
                        "result": result.get("workers", []),
                    }),
                )
                return {**result, "progress": worker_progress(projection.get("workers", []))}
            except (RuntimeSafetyError, RuntimeErrorBase, OSError) as exc:
                store.audit(
                    "run_force_stop", "failure", project_id,
                    details=json.dumps({
                        "actor": "operator_session",
                        "session_id": payload.get("_actor_session_id"),
                        "target_worker": payload.get("worker"),
                        "error": str(exc)[:200],
                    }),
                )
                return _error(409, str(exc)[:200] or "force stop refused")

    @app.post("/api/projects/{project_id}/reclaim")
    async def reclaim_project_workers(project_id: str, request: Request):
        context = await safety_control_context(project_id, request)
        if isinstance(context, JSONResponse):
            return context
        project, payload = context
        execute = payload.get("execute") is True
        if execute and payload.get("confirm") != project["name"]:
            return _error(409, "project-name confirmation required")
        async with lock_for(project_id):
            try:
                result = runtime.reclaim_project(
                    project["runtime_name"], worker=payload.get("worker"), execute=execute,
                    confirmation_token=payload.get("confirmation_token"),
                )
                if execute and not result.get("remaining_project_processes"):
                    active = store.active_run(project_id)
                    if active is not None:
                        store.update_run(active["id"], status="stopped", stopped_at=time.time(), outcome="process_reclaimed")
                store.audit("process_reclaim", "success", project_id, details=json.dumps({
                    "actor": "operator_session", "session_id": payload.get("_actor_session_id"),
                    "execute": execute, "target_worker": payload.get("worker"),
                    "workers": result.get("workers", []),
                    "remaining_project_processes": result.get("remaining_project_processes", []),
                }))
                return result
            except (RuntimeSafetyError, RuntimeErrorBase, OSError) as exc:
                store.audit("process_reclaim", "failure", project_id, details=json.dumps({
                    "actor": "operator_session", "session_id": payload.get("_actor_session_id"),
                    "execute": execute, "target_worker": payload.get("worker"),
                    "error": str(exc)[:200],
                }))
                return _error(409, str(exc)[:200] or "reclaim refused")

    @app.get("/api/projects/{project_id}/files")
    async def list_files(project_id: str, request: Request):
        if isinstance((auth := auth_required(request)), JSONResponse):
            return auth
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse):
            return project
        return [metadata(row) for row in store.files(project_id)]

    @app.get("/api/projects/{project_id}/file-cleanups")
    async def file_cleanup_projection(project_id: str, request: Request):
        if isinstance((auth := auth_required(request)), JSONResponse):
            return auth
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse):
            return project
        jobs = store.file_cleanup_jobs(project_id)
        maintenance_reason = store.project_maintenance_reason(project_id)
        return {
            "status": "cleanup_pending" if maintenance_reason is not None else "ok",
            "maintenance_reason": maintenance_reason,
            "jobs": [{
                "id": row["id"], "reason": row["reason"],
                "created_at": row["created_at"], "last_error": row["last_error"],
            } for row in jobs],
        }

    @app.post("/api/projects/{project_id}/file-cleanups/retry")
    async def retry_file_cleanups(project_id: str, request: Request):
        current = auth_required(request)
        if isinstance(current, JSONResponse):
            return current
        if not csrf_ok(request, current):
            return _error(403, "csrf validation failed")
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse):
            return project
        async with lock_for(project_id):
            result = await asyncio.to_thread(reconcile_external_materials, project_id)
        pending_count = len(store.file_cleanup_jobs(project_id))
        maintenance_reason = store.project_maintenance_reason(project_id)
        cleanup_pending = maintenance_reason is not None
        store.audit("file_cleanup_retry", "pending" if cleanup_pending else "success", project_id, details=json.dumps({
            "pending_count": pending_count,
            "maintenance_reason": maintenance_reason,
            **result,
        }, sort_keys=True))
        return JSONResponse({
            "status": "cleanup_pending" if cleanup_pending else "ok",
            "committed": True, "cleanup_pending": cleanup_pending,
            "pending_count": pending_count,
            "maintenance_reason": maintenance_reason,
        }, status_code=202 if cleanup_pending else 200)

    @app.post("/api/projects/{project_id}/files")
    async def upload_file(project_id: str, request: Request):
        current = auth_required(request)
        if isinstance(current, JSONResponse):
            return current
        if not csrf_ok(request, current):
            return _error(403, "csrf validation failed")
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse):
            return project
        try:
            declared_name = decode_upload_filename(
                request.headers.get("x-danus-upload-filename", ""),
            )
            content_type, kind = file_type(declared_name)
        except FileValidationError as exc:
            return _error(400, str(exc))
        async with lock_for(project_id):
            pending: Path | None = None
            materials: Path | None = None
            staging: Path | None = None
            storage_name: str | None = None
            sha256 = ""
            ordinary_reserved = False
            try:
                unresolved = store.pending_conflict(project_id, declared_name)
                if unresolved is not None:
                    return JSONResponse({
                        "status": "conflict_pending", "conflict_id": unresolved["id"],
                        "detail": "resolve the existing file conflict first",
                    }, status_code=409)
                existing = store.current_file(project_id, declared_name)
                rejection_reason, blocked_workers, status_error = (
                    await project_worker_exit_proof(project)
                )
                if rejection_reason is not None:
                    is_conflict = existing is not None
                    error_code = (
                        "file_conflict_workers_not_stopped" if is_conflict
                        else "file_upload_workers_not_stopped"
                    )
                    details: dict[str, Any] = {
                        "filename": declared_name, "error_code": error_code,
                        "reason": rejection_reason,
                        "blocked_workers": blocked_workers,
                    }
                    if status_error is not None:
                        details["status_error"] = status_error
                    store.audit(
                        "file_upload",
                        (
                            "conflict_rejected_workers_not_stopped" if is_conflict
                            else "rejected_workers_not_stopped"
                        ),
                        project_id, details=json.dumps(details, sort_keys=True),
                    )
                    return JSONResponse({
                        "detail": (
                            "Uploading Project material requires every Worker to be "
                            "terminal and its complete process group exit verified"
                        ),
                        "error_code": error_code,
                        "status": (
                            "conflict_upload_blocked" if is_conflict
                            else "upload_blocked"
                        ),
                    }, status_code=409)

                # Parse/read the multipart body only after the same-name Worker
                # exit proof. The declared name is then bound to the multipart
                # filename so a caller cannot preflight one name and upload
                # another.
                try:
                    form = await request.form()
                except Exception:
                    return _error(400, "invalid multipart upload")
                upload = form.get("file")
                if (
                    upload is None or not hasattr(upload, "filename")
                    or not hasattr(upload, "file")
                ):
                    return _error(400, "file is required")
                logical_name = normalize_filename(upload.filename)
                if logical_name != declared_name:
                    return _error(400, "declared filename does not match multipart upload")

                materials, staging = project_staging(project)

                pending, sha256, size = stream_to_pending(
                    upload, staging, settings.max_file_bytes,
                )
                fsync_directory(staging)
                validate_bytes(kind, pending.read_bytes())
                existing_hash = store.file_by_hash(project_id, sha256)
                if existing_hash is None:
                    tombstone = store.file_tombstone_by_hash(project_id, sha256)
                    if tombstone is not None:
                        reconcile_external_materials(project_id)
                        tombstone = store.file_tombstone_by_hash(project_id, sha256)
                        if tombstone is not None:
                            pending.unlink(missing_ok=True)
                            fsync_directory(staging)
                            pending = None
                            return JSONResponse({
                                "status": "cleanup_pending",
                                "detail": "superseded file cleanup must finish before re-upload",
                            }, status_code=409)
                if existing_hash is not None:
                    pending.unlink(missing_ok=True)
                    fsync_directory(staging)
                    pending = None
                    if existing_hash.get("processing_status") != "available":
                        return JSONResponse({
                            "status": "conflict_pending",
                            "detail": "matching upload is awaiting conflict resolution",
                        }, status_code=409)
                    store.audit("file_upload", "reuse", project_id)
                    return JSONResponse(metadata(existing_hash), status_code=200)

                storage_name = sha256
                file_id = uuid.uuid4().hex
                version = store.next_version(project_id, logical_name)
                row = {
                    "id": file_id, "project_id": project_id,
                    "logical_name": logical_name, "content_type": content_type,
                    "kind": kind, "size": size, "sha256": sha256,
                    "storage_name": storage_name,
                    "staging_name": pending.name,
                    "version": version, "is_current": 0,
                    "processing_status": "pending",
                    "read_status": "not_read", "uploaded_at": time.time(),
                }
                if existing is not None:
                    conflict_id = uuid.uuid4().hex
                    conflict = {
                        "id": conflict_id, "project_id": project_id,
                        "logical_name": logical_name, "incoming_file_id": file_id,
                        "current_file_id": existing["id"], "created_at": time.time(),
                        "status": "pending",
                    }
                    store.add_file_conflict(row, conflict)
                    pending = None  # the DB now owns this private staged blob
                    store.audit("file_upload", "conflict", project_id)
                    return JSONResponse({
                        "conflict_id": conflict_id, "current": metadata(existing),
                        "incoming": metadata(row),
                        "choices": ["replace", "new_version", "cancel"],
                    }, status_code=409)

                reserved_path = pending
                reserved_name = pending.name
                store.add_file(row)
                ordinary_reserved = True
                pending = None  # the DB reservation now owns either location
                storage_name, _stored = promote_pending(
                    reserved_path, materials, sha256, size,
                )
                row["storage_name"] = storage_name
                row = store.finalize_ordinary_file(
                    file_id, project_id, staging_name=reserved_name,
                )
                ordinary_reserved = False
                return JSONResponse(metadata(row), status_code=201)
            except FileValidationError as exc:
                if pending is not None:
                    pending.unlink(missing_ok=True)
                    if staging is not None:
                        with contextlib.suppress(OSError):
                            fsync_directory(staging)
                if ordinary_reserved:
                    with contextlib.suppress(Exception):
                        reconcile_external_materials(project_id)
                return _error(400, str(exc))
            except (OSError, sqlite3.IntegrityError) as exc:
                if pending is not None:
                    with contextlib.suppress(OSError):
                        pending.unlink(missing_ok=True)
                        if staging is not None:
                            fsync_directory(staging)
                # The durable pending row precedes promotion. Reconcile both
                # possible byte locations immediately; if that cleanup itself
                # fails, the reservation remains in the unified maintenance
                # predicate and startup/retry will finish it.
                if ordinary_reserved:
                    with contextlib.suppress(Exception):
                        reconcile_external_materials(project_id)
                store.audit(
                    "file_upload", "failure", project_id,
                    json.dumps({"error_code": type(exc).__name__}),
                )
                return _error(500, "file could not be persisted")

    @app.post("/api/projects/{project_id}/file-conflicts/{conflict_id}")
    async def resolve_file_conflict(project_id: str, conflict_id: str, request: Request):
        current = auth_required(request)
        if isinstance(current, JSONResponse):
            return current
        if not csrf_ok(request, current):
            return _error(403, "csrf validation failed")
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse):
            return project
        try:
            payload = await request.json()
        except Exception:
            return _error(400, "invalid file conflict resolution request")
        choice = payload.get("choice") if isinstance(payload, dict) else None
        if not isinstance(choice, str) or choice not in (
            "replace", "new_version", "cancel",
        ):
            return _error(400, "choice must be replace, new_version, or cancel")
        async with lock_for(project_id):
            conflict = store.conflict(conflict_id, project_id)
            if conflict is None or conflict["status"] != "pending":
                return _error(404, "file conflict not found")
            incoming = store.file(conflict["incoming_file_id"], project_id)
            existing = store.file(conflict["current_file_id"], project_id)
            if incoming is None or existing is None:
                return _error(409, "file conflict is no longer available")
            try:
                if choice == "replace":
                    # The orchestration beat holds this same Project lock. Keep
                    # the read-only exit proof and destructive transition in one
                    # critical section so no Worker activity can interleave.
                    rejection_reason, blocked_workers, status_error = (
                        await project_worker_exit_proof(project)
                    )
                    if rejection_reason is not None:
                        error_code = "replace_workers_not_stopped"
                        details: dict[str, Any] = {
                            "choice": "replace", "conflict_id": conflict_id,
                            "error_code": error_code, "reason": rejection_reason,
                            "blocked_workers": blocked_workers,
                        }
                        if status_error is not None:
                            details["status_error"] = status_error
                        store.audit(
                            "file_conflict", "replace_rejected_workers_not_stopped",
                            project_id, details=json.dumps(details, sort_keys=True),
                        )
                        return JSONResponse({
                            "detail": (
                                "Replace requires every Worker to be terminal and its "
                                "complete process group exit to be verified"
                            ),
                            "error_code": error_code,
                            "status": "replace_blocked",
                        }, status_code=409)
                materials, staging = project_staging(project)
                staging_name = incoming.get("staging_name")
                if choice == "cancel":
                    staged = staging_blob(
                        staging, staging_name, require_regular=False,
                    )
                    if staged.exists() or staged.is_symlink():
                        info = staged.lstat()
                        if not (
                            staged.is_symlink() or stat_module.S_ISREG(info.st_mode)
                        ):
                            raise FileValidationError(
                                "staged cancellation target is unsafe",
                            )
                        staged.unlink()
                        fsync_directory(staging)
                    # Byte erasure precedes the DB transition. If the DB commit
                    # fails, the pending maintenance gate remains in force and
                    # retry treats the already-missing staged file idempotently.
                    cancelled_at = time.time()
                    store.cancel_staged_conflict(
                        conflict_id, project_id, staging_name=str(staging_name),
                        cancelled_at=cancelled_at,
                    )
                    store.audit("file_conflict", "cancel", project_id, details=json.dumps({
                        "choice": "cancel", "file_id": incoming["id"],
                        "filename": incoming["logical_name"], "version": incoming["version"],
                        "sha256": incoming["sha256"], "size": incoming["size"],
                        "cleanup_pending": False,
                    }, sort_keys=True))
                    return JSONResponse({
                        "status": "cancelled", "committed": True,
                        "cleanup_pending": False,
                    }, status_code=200)
                if choice == "new_version":
                    source, destination = promote_staged_conflict(
                        incoming, materials, staging,
                    )
                    try:
                        resolved = store.resolve_new_version(
                            conflict_id, project_id,
                            staging_name=str(staging_name),
                        )
                    except Exception:
                        if not rollback_staged_promotion(source, destination):
                            store.audit(
                                "file_conflict", "promotion_rollback_failed", project_id,
                                details=json.dumps({
                                    "choice": "new_version", "conflict_id": conflict_id,
                                    "file_id": incoming["id"],
                                }, sort_keys=True),
                            )
                        raise
                    return JSONResponse(metadata(resolved), status_code=200)
                if choice == "replace":
                    material_blob(materials, str(existing["storage_name"]))
                    source, destination = promote_staged_conflict(
                        incoming, materials, staging,
                    )
                    cleanup = {
                        "id": uuid.uuid4().hex,
                        "quarantine_name": f".delete-{uuid.uuid4().hex}",
                        "original_storage_name": existing["storage_name"],
                        "created_at": time.time(),
                    }
                    try:
                        resolved = store.resolve_destructive_conflict(
                            conflict_id, project_id, choice="replace", cleanup=cleanup,
                            staging_name=str(staging_name),
                        )
                    except Exception:
                        if not rollback_staged_promotion(source, destination):
                            store.audit(
                                "file_conflict", "promotion_rollback_failed", project_id,
                                details=json.dumps({
                                    "choice": "replace", "conflict_id": conflict_id,
                                    "file_id": incoming["id"],
                                }, sort_keys=True),
                            )
                        raise
                    assert resolved is not None
                    replaced_file = resolved.pop("replaced_file")
                    detached_message_ids = resolved.pop("detached_message_ids")
                    conversation_reset = bool(resolved.pop("conversation_reset"))
                    purged_message_ids = resolved.pop("purged_message_ids")
                    invalidated_intent_ids = resolved.pop(
                        "invalidated_artifact_intent_ids",
                    )
                    job = next(job for job in store.file_cleanup_jobs(project_id) if job["id"] == cleanup["id"])
                    cleaned = purge_cleanup_job(job, project)
                    outcome = "replace" if cleaned else "cleanup_pending"
                    store.audit("file_conflict", outcome, project_id, details=json.dumps({
                        "choice": "replace", "file_id": replaced_file["id"],
                        "filename": replaced_file["logical_name"],
                        "version": replaced_file["version"],
                        "sha256": replaced_file["sha256"], "size": replaced_file["size"],
                        "detached_message_ids": detached_message_ids,
                        "conversation_reset": conversation_reset,
                        "purged_message_ids": purged_message_ids,
                        "invalidated_artifact_intent_ids": invalidated_intent_ids,
                        "replacement_file_id": resolved["id"],
                        "cleanup_id": cleanup["id"], "cleanup_pending": not cleaned,
                    }, sort_keys=True))
                    return JSONResponse({
                        **metadata(resolved), "status": "replaced", "committed": True,
                        "cleanup_pending": not cleaned, "cleanup_id": cleanup["id"],
                        "conversation_reset": conversation_reset,
                        "purged_message_count": len(purged_message_ids),
                        "invalidated_artifact_intent_count": len(invalidated_intent_ids),
                    }, status_code=200 if cleaned else 202)
            except (FileValidationError, RuntimeErrorBase, OSError, sqlite3.IntegrityError) as exc:
                if isinstance(exc, sqlite3.IntegrityError):
                    error_code = "file_conflict_state_changed"
                    status_code = 409
                elif isinstance(exc, FileValidationError):
                    error_code = "file_conflict_integrity_failed"
                    status_code = 409
                else:
                    error_code = "file_conflict_storage_failed"
                    status_code = 502
                store.audit(
                    "file_conflict", "resolution_failure", project_id,
                    details=json.dumps({
                        "choice": choice, "conflict_id": conflict_id,
                        "error_code": error_code,
                        "exception_class": type(exc).__name__,
                    }, sort_keys=True),
                )
                return JSONResponse({
                    "detail": "file conflict could not be resolved",
                    "error_code": error_code,
                    "status": "resolution_failed",
                }, status_code=status_code)

    @app.get("/api/projects/{project_id}/workers")
    async def worker_projection(project_id: str, request: Request):
        if isinstance((auth := auth_required(request)), JSONResponse):
            return auth
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse):
            return project
        try:
            return projection_with_project(project, reconcile_run(project_id, project, runtime.status_project(project["runtime_name"])))
        except RuntimeErrorBase:
            return _error(502, "runtime projection unavailable")

    @app.get("/api/projects/{project_id}/logs")
    async def logs_projection(project_id: str, request: Request):
        if isinstance((auth := auth_required(request)), JSONResponse):
            return auth
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse):
            return project
        try:
            tail = max(1, min(int(request.query_params.get("tail", "200")), 1000))
            max_bytes = max(1024, min(int(request.query_params.get("max_bytes", str(64 * 1024))), 256 * 1024))
            worker = request.query_params.get("worker")
            if worker is not None:
                validate_runtime_name(worker)
            return runtime.logs_projection(
                project["runtime_name"], worker=worker, tail=tail, max_bytes=max_bytes,
            )
        except ValueError:
            return _error(400, "invalid log projection parameters")
        except RuntimeErrorBase:
            return _error(502, "logs projection unavailable")

    @app.get("/api/projects/{project_id}/fact-graph")
    async def fact_graph_projection(project_id: str, request: Request):
        if isinstance((auth := auth_required(request)), JSONResponse):
            return auth
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse):
            return project
        try:
            return runtime.fact_graph_projection(project["runtime_name"])
        except RuntimeErrorBase:
            return _error(502, "fact graph projection unavailable")

    @app.get("/api/projects/{project_id}/memory")
    async def memory_projection(project_id: str, request: Request):
        if isinstance((auth := auth_required(request)), JSONResponse):
            return auth
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse):
            return project
        try:
            return runtime.memory_projection(project["runtime_name"])
        except RuntimeErrorBase:
            return _error(502, "memory projection unavailable")

    @app.get("/api/projects/{project_id}/finalize/suggestions")
    async def finalize_suggestions(project_id: str, request: Request):
        if isinstance((auth := auth_required(request)), JSONResponse): return auth
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse): return project
        try: return runtime.finalize_suggestions(project["runtime_name"])
        except (RuntimeErrorBase, OSError): return _error(502, "finalize suggestions unavailable")

    @app.post("/api/projects/{project_id}/finalize")
    async def finalize_target(project_id: str, request: Request):
        current = auth_required(request)
        if isinstance(current, JSONResponse): return current
        if not csrf_ok(request, current): return _error(403, "csrf validation failed")
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse): return project
        return _error(410, "use the operator artifact action flow")

    @app.post("/api/projects/{project_id}/human-summary")
    async def human_summary_action(project_id: str, request: Request):
        current = auth_required(request)
        if isinstance(current, JSONResponse): return current
        if not csrf_ok(request, current): return _error(403, "csrf validation failed")
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse): return project
        return _error(410, "use the operator artifact action flow")

    @app.post("/api/projects/{project_id}/write-paper")
    async def write_paper_action(project_id: str, request: Request):
        current = auth_required(request)
        if isinstance(current, JSONResponse): return current
        if not csrf_ok(request, current): return _error(403, "csrf validation failed")
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse): return project
        return _error(410, "use the operator artifact action flow")

    @app.post("/api/projects/{project_id}/artifacts-actions")
    async def artifact_action_intent(project_id: str, request: Request):
        current = auth_required(request)
        if isinstance(current, JSONResponse): return current
        if not csrf_ok(request, current): return _error(403, "csrf validation failed")
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse): return project
        payload = await request.json()
        action = payload.get("action") if isinstance(payload, dict) else None
        if action not in {"finalize", "human-summary", "write-paper"}:
            return _error(400, "unsupported artifact action")
        if payload.get("confirm") != project["name"]:
            return _error(409, "project-name confirmation required")
        try:
            normalized = _artifact_payload(action, payload)
        except ValueError as exc:
            return _error(400, str(exc))
        now = time.time()
        expires_at = min(
            float(current["expires_at"]),
            now + max(60.0, min(3600.0, float(settings.artifact_confirmation_ttl_seconds))),
        )
        if expires_at <= now:
            return _error(401, "operator session expired")
        intent_id = uuid.uuid4().hex
        payload_digest = _artifact_payload_digest(action, normalized)
        token = artifact_confirmation_capability(
            lifecycle_hmac_secret, intent_id, project_id, action, payload_digest,
        )
        store.add_artifact_confirmation_intent({
            "id": intent_id, "token_digest": digest_token(token),
            "project_id": project_id, "action": action,
            "payload_json": json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            "payload_digest": payload_digest, "actor_session_id": current["id"],
            "created_at": now, "expires_at": expires_at,
        })
        store.audit("artifact_action_intent", "recorded", project_id, details=json.dumps({
            "intent_id": intent_id, "action": action, "payload_digest": payload_digest,
            "expires_at": expires_at,
        }, sort_keys=True))
        return {
            "status": "intent_recorded", "action": action,
            "intent_id": intent_id, "expires_at": expires_at,
            "instruction": _artifact_instruction(action, normalized),
        }

    @app.get("/api/projects/{project_id}/artifacts")
    async def artifacts_projection(project_id: str, request: Request):
        if isinstance((auth := auth_required(request)), JSONResponse): return auth
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse): return project
        try:
            if hasattr(runtime, "artifacts_projection"):
                return runtime.artifacts_projection(project["runtime_name"])
            return {"files": [*runtime.reports_projection(project["runtime_name"]).get("files", []), *runtime.outputs_projection(project["runtime_name"]).get("files", [])]}
        except RuntimeErrorBase: return _error(502, "artifact projection unavailable")

    @app.get("/api/projects/{project_id}/artifacts/{artifact_path:path}")
    async def artifact_download(project_id: str, artifact_path: str, request: Request):
        if isinstance((auth := auth_required(request)), JSONResponse): return auth
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse): return project
        try:
            projection = runtime.artifacts_projection(project["runtime_name"])
            allowed_paths = {str(row.get("path") or "") for row in projection.get("files", [])}
            if artifact_path not in allowed_paths:
                return _error(404, "artifact not found")
            body, content_type = runtime.artifact_bytes(project["runtime_name"], artifact_path)
            from fastapi.responses import Response
            safe_name = quote(Path(artifact_path).name, safe="._-")
            return Response(body, media_type=content_type, headers={"Content-Disposition": f"inline; filename*=UTF-8''{safe_name}"})
        except (RuntimeErrorBase, RuntimeError, OSError, ValueError): return _error(404, "artifact not found")

    @app.get("/api/projects/{project_id}/reports")
    async def reports_projection(project_id: str, request: Request):
        if isinstance((auth := auth_required(request)), JSONResponse):
            return auth
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse):
            return project
        try:
            return runtime.reports_projection(project["runtime_name"])
        except RuntimeErrorBase:
            return _error(502, "reports projection unavailable")

    @app.get("/api/projects/{project_id}/outputs")
    async def outputs_projection(project_id: str, request: Request):
        if isinstance((auth := auth_required(request)), JSONResponse):
            return auth
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse):
            return project
        try:
            return runtime.outputs_projection(project["runtime_name"])
        except RuntimeErrorBase:
            return _error(502, "outputs projection unavailable")

    @app.get("/api/projects/{project_id}/orchestration")
    async def orchestration_projection(project_id: str, request: Request):
        if isinstance((auth := auth_required(request)), JSONResponse):
            return auth
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse):
            return project
        try:
            status_projection = runtime.status_project(project["runtime_name"])
            memory = runtime.memory_projection(project["runtime_name"])
        except RuntimeErrorBase:
            return _error(502, "orchestration projection unavailable")
        workers = status_projection.get("workers", [])
        unassigned = [name for name in unassigned_workers(status_projection) if name]
        session_row = store.agent_session(project_id)
        session_projection = {
            "backend": (session_row or {}).get("backend") or main_agent_backend,
            "status": (session_row or {}).get("status") or "not_started",
            "session_id": (session_row or {}).get("session_id"),
            "session_id_present": bool((session_row or {}).get("session_id")),
            "updated_at": (session_row or {}).get("updated_at"),
        }
        active = store.active_run(project_id)
        run_projection = None
        if active is not None:
            run_projection = {
                "id": active["id"],
                "status": active["status"],
                "deadline": active["deadline"],
                **worker_progress(workers),
            }
        guidance = latest_memory_entry(memory, "master_guidance")
        guidance_transport = strategy_metadata()["transport"]
        return {
            "project": project_payload(project),
            "config": project_config(project),
            "main_agent": session_projection,
            "session": session_projection,
            "main_agent_status": session_projection["status"],
            "main_agent_backend": session_projection["backend"],
            "initial_direction_confirmed": project.get("initial_direction_confirmed_at") is not None,
            "orchestration_beat": store.orchestration_beat_state(project_id),
            "workers_total": len(workers),
            "assigned_workers": len(workers) - len(unassigned),
            "unassigned_workers": unassigned,
            "workers": [
                {
                    "worker": worker.get("worker"),
                    "task": worker.get("task", ""),
                    "assigned": worker.get("assigned") is True,
                }
                for worker in workers
            ],
            "master_guidance": guidance,
            "guidance": guidance,
            "guidance_source": guidance_source(guidance, guidance_transport),
            "guidance_transport": guidance_transport,
            "elaboration": latest_memory_entry(memory, "elaboration"),
            "run": run_projection,
        }

    @app.post("/api/projects/{project_id}/initial-direction/confirm")
    async def confirm_initial_direction(project_id: str, request: Request):
        current = auth_required(request)
        if isinstance(current, JSONResponse):
            return current
        if not csrf_ok(request, current):
            return _error(403, "csrf validation failed")
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse):
            return project
        try:
            payload = await request.json()
        except Exception:
            return _error(400, "invalid confirmation request")
        if not isinstance(payload, dict) or payload.get("confirm") != project["name"]:
            return _error(409, "project-name confirmation required")
        try:
            memory = runtime.memory_projection(project["runtime_name"])
        except RuntimeErrorBase:
            return _error(502, "guidance projection unavailable")
        guidance = latest_memory_entry(memory, "master_guidance")
        transport = strategy_metadata()["transport"]
        source = guidance_source(guidance, transport)
        if guidance is None:
            return _error(409, "initial guidance required before confirmation")
        if source not in {"offline-main-agent", "consult-derived"}:
            return _error(409, "guidance provenance does not match configured strategy transport")
        store.confirm_initial_direction(project_id, time.time())
        store.audit("initial_direction_confirm", "success", project_id)
        return {"status": "confirmed", "initial_direction_confirmed": True}

    @app.get("/api/projects/{project_id}/messages")
    async def list_messages(project_id: str, request: Request):
        if isinstance((auth := auth_required(request)), JSONResponse):
            return auth
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse):
            return project
        return store.messages(project_id)

    @app.get("/api/projects/{project_id}/main-agent-events")
    async def list_main_agent_events(project_id: str, request: Request, after: int = 0, limit: int = 1000):
        if isinstance((auth := auth_required(request)), JSONResponse):
            return auth
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse):
            return project
        events = store.main_agent_events(project_id, after_id=after, limit=limit)
        return {"events": events, "last_id": events[-1]["id"] if events else max(0, after)}

    @app.post("/api/projects/{project_id}/messages")
    async def send_message(project_id: str, request: Request):
        current = auth_required(request)
        if isinstance(current, JSONResponse):
            return current
        if not csrf_ok(request, current):
            return _error(403, "csrf validation failed")
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse):
            return project
        payload = await request.json()
        text = payload.get("text") if isinstance(payload, dict) else None
        attachment_ids = payload.get("attachment_ids", []) if isinstance(payload, dict) else []
        artifact_intent_id = payload.get("artifact_intent_id") if isinstance(payload, dict) else None
        if (not isinstance(text, str) or not text.strip() or not isinstance(attachment_ids, list)
                or len(attachment_ids) > 32
                or any(not isinstance(file_id, str) for file_id in attachment_ids)
                or len(set(attachment_ids)) != len(attachment_ids)):
            return _error(400, "text and attachment_ids are required")
        if artifact_intent_id is not None and (
            not isinstance(artifact_intent_id, str)
            or not re.fullmatch(r"[0-9a-f]{32}", artifact_intent_id)
        ):
            return _error(400, "invalid artifact_intent_id")
        maintenance = project_maintenance_rejection(
            project_id, "main_agent_message",
        )
        if maintenance is not None:
            return maintenance
        active_run = store.active_run(project_id)
        if active_run is not None and time.time() >= active_run["deadline"]:
            try:
                runtime.stop_project(project["runtime_name"])
            except RuntimeErrorBase as exc:
                store.update_run(active_run["id"], status="stopping", outcome=f"deadline_stop_failed: {exc}"[:200])
            else:
                store.update_run(active_run["id"], status="stopping", outcome="deadline_stop_requested")
            store.audit("message", "rejected_deadline", project_id)
            return _error(409, "project run deadline reached")
        attachments = []
        attachment_rows = []
        for file_id in attachment_ids:
            row = store.selectable_file(str(file_id), project_id)
            if row is None:
                return _error(404, "attachment not found")
            try:
                materials = material_root(Path(runtime.project_context_dir(project["runtime_name"])))
                blob_path = material_blob(materials, str(row["storage_name"]))
            except (FileValidationError, RuntimeErrorBase, OSError):
                return _error(409, "attachment blob is unavailable")
            attachment_rows.append(row)
            attachments.append(metadata(row) | {"path": str(blob_path)})
        # Validate every attachment before consuming the one-shot artifact
        # intent. A bad attachment must leave the confirmation pending so the
        # operator can correct the request without minting a second intent.
        turn_artifact_confirmation: str | None = None
        if artifact_intent_id is not None:
            intent_candidate = store.artifact_confirmation_intent(artifact_intent_id)
            try:
                if (
                    intent_candidate is None
                    or intent_candidate.get("project_id") != project_id
                    or intent_candidate.get("actor_session_id") != str(current["id"])
                    or intent_candidate.get("execution_status") != "pending"
                    or intent_candidate.get("dispatched_at") is not None
                ):
                    raise ValueError("artifact intent is not dispatchable")
                normalized_intent_payload = json.loads(str(intent_candidate["payload_json"]))
                normalized_intent_payload = _artifact_payload(
                    str(intent_candidate["action"]), normalized_intent_payload,
                )
                if _artifact_payload_digest(
                    str(intent_candidate["action"]), normalized_intent_payload,
                ) != intent_candidate["payload_digest"]:
                    raise ValueError("artifact intent payload digest mismatch")
                turn_artifact_confirmation = artifact_confirmation_token(intent_candidate)
                if digest_token(turn_artifact_confirmation) != intent_candidate["token_digest"]:
                    raise ValueError("artifact confirmation capability mismatch")
            except (ValueError, TypeError, json.JSONDecodeError, UnicodeError):
                store.audit("artifact_action_intent", "dispatch_failure", project_id, details=json.dumps({
                    "intent_id": artifact_intent_id,
                }, sort_keys=True))
                return _error(409, "artifact intent is invalid")
            intent = store.dispatch_artifact_confirmation_intent(
                artifact_intent_id, project_id, str(current["id"]), now=time.time(),
            )
            if intent is None:
                return _error(409, "artifact intent is invalid, expired, or already dispatched")
            # Never trust browser text to carry the confirmed parameters.
            text = _artifact_instruction(str(intent["action"]), normalized_intent_payload)
            store.audit("artifact_action_intent", "dispatched", project_id, details=json.dumps({
                "intent_id": artifact_intent_id, "action": intent["action"],
            }, sort_keys=True))
        message_id = uuid.uuid4().hex
        now = time.time()
        store.add_message({"id": message_id, "project_id": project_id, "role": "user", "text": text, "status": "submitted", "created_at": now, "error": None}, [row["id"] for row in attachment_rows])
        manifest = [metadata(row) for row in store.files(project_id)]
        turn_lifecycle_token = lifecycle_token(project)
        exact_turn_secrets = tuple(
            secret for secret in (
                turn_lifecycle_token, turn_artifact_confirmation,
            ) if secret
        )

        def record_main_agent_progress(event: dict[str, Any]) -> None:
            event_type = str(event.get("type") or "")
            allowed_types = {
                "session.started", "process.started", "turn.started", "agent.progress", "agent.message", "tool.started", "tool.completed",
                "turn.retry", "turn.completed", "turn.failed",
            }
            if event_type in allowed_types:
                safe_payload: dict[str, Any] = {}
                for key in ("tool", "detail", "status", "call_id", "error_code", "session_id", "process_id", "turn_id"):
                    value = event.get(key)
                    if value is not None:
                        safe_payload[key] = str(_redact_exact_value(
                            str(value), exact_turn_secrets,
                        ))[:4000 if key == "detail" else 200]
                for key in ("attempt", "max_attempts", "delay_seconds", "duration_seconds"):
                    value = event.get(key)
                    if isinstance(value, (int, float)):
                        safe_payload[key] = value
                active_event_run = store.active_run(project_id)
                safe_payload["main_agent_session_id"] = str(_redact_exact_value(
                    str(event.get("session_id") or session_id or ""),
                    exact_turn_secrets,
                ))[:200]
                safe_payload["run_id"] = str(active_event_run.get("id") if active_event_run else "")[:200]
                store.add_main_agent_event(
                    project_id=project_id, message_id=message_id,
                    event_type=event_type, payload=safe_payload,
                )

            if event.get("status") != "retrying":
                return
            attempt = max(1, int(event.get("attempt") or 1))
            max_attempts = max(attempt, int(event.get("max_attempts") or attempt))
            delay = max(0.0, float(event.get("delay_seconds") or 0.0))
            detail = (
                f"上游模型繁忙，正在自动续接（第 {attempt}/{max_attempts} 次尝试"
                f"，{delay:g} 秒后继续）"
            )
            store.update_message(message_id, status="retrying", error=detail[:200])
            progress_session_id = event.get("session_id")
            if progress_session_id:
                store.upsert_agent_session(
                    project_id, str(_redact_exact_value(
                        str(progress_session_id), exact_turn_secrets,
                    )), "active", time.time(),
                    backend=main_agent_backend,
                )

        async with project_turn_scope(project_id, request):
            session = store.agent_session(project_id) or {}
            session_id = session.get("session_id") if session.get("backend") == main_agent_backend else None
            store.upsert_agent_session(
                project_id, session_id, "active", time.time(), backend=main_agent_backend,
            )

            def invoke_main_agent():
                kwargs = dict(
                    context_dir=runtime.project_context_dir(project["runtime_name"]),
                    session_id=session_id,
                    message=text,
                    manifest=manifest,
                    project_state={"project_id": project_id, "name": project["name"], "problem": project["problem"]},
                    attachments=attachments,
                    on_progress=record_main_agent_progress,
                    lifecycle_url=lifecycle_url(project_id),
                    lifecycle_token=turn_lifecycle_token,
                )
                if turn_artifact_confirmation is not None:
                    kwargs["artifact_confirmation_token"] = turn_artifact_confirmation
                return main_agent.send(**kwargs)

            try:
                async with main_agent_broker_window(project_id):
                    raw_result = await asyncio.to_thread(invoke_main_agent)
                result = _redact_exact_value(raw_result, exact_turn_secrets)
                if not isinstance(result, dict):
                    raise RuntimeError("Main Agent returned an invalid response")
                artifact_outcome = None
                if artifact_intent_id is not None:
                    artifact_outcome = store.artifact_confirmation_intent(artifact_intent_id)
                    if artifact_outcome is None or artifact_outcome.get("execution_status") != "succeeded":
                        current_status = str((artifact_outcome or {}).get("execution_status") or "missing")
                        outcome_code = str((artifact_outcome or {}).get("outcome_code") or "")
                        if artifact_outcome is not None and current_status in {"pending", "dispatched", "running"}:
                            outcome_code = "not_executed" if current_status in {"pending", "dispatched"} else "execution_incomplete"
                            if current_status in {"pending", "dispatched"}:
                                store.fail_dispatched_artifact_intent(
                                    artifact_intent_id, project_id, outcome_code=outcome_code,
                                    completed_at=time.time(),
                                )
                                artifact_outcome = store.artifact_confirmation_intent(artifact_intent_id)
                                current_status = str((artifact_outcome or {}).get("execution_status") or "missing")
                        public_error = "已确认的产物操作未成功执行；请检查执行记录后重新确认。"
                        store.update_message(message_id, status="failed", error=public_error)
                        store.upsert_agent_session(
                            project_id, result.get("session_id"), "inactive", time.time(),
                            backend=main_agent_backend,
                        )
                        store.add_message({
                            "id": uuid.uuid4().hex, "project_id": project_id,
                            "role": "assistant", "text": "", "status": "failed",
                            "created_at": time.time(), "error": public_error,
                        })
                        store.audit("artifact_action_turn", "failure", project_id, details=json.dumps({
                            "intent_id": artifact_intent_id, "execution_status": current_status,
                            "outcome_code": outcome_code or "unknown",
                        }, sort_keys=True))
                        return JSONResponse({
                            "status": "artifact_failed", "detail": public_error,
                            "artifact_intent_id": artifact_intent_id,
                            "artifact_status": current_status,
                            "error_code": outcome_code or "artifact_not_succeeded",
                        }, status_code=409)
                if result.get("read_status") == "read":
                    for row in attachment_rows:
                        store.update_file_status(row["id"], read_status="read")
                store.update_message(message_id, status="completed")
                store.upsert_agent_session(
                    project_id, result["session_id"], "inactive", time.time(),
                    backend=main_agent_backend,
                )
                reply_id = uuid.uuid4().hex
                store.add_message({
                    "id": reply_id, "project_id": project_id,
                    "role": "assistant", "text": result["reply"], "status": "completed",
                    "created_at": time.time(), "error": None,
                })
                store.audit("message", "success", project_id)
                active_after_message = store.active_run(project_id)
                if active_after_message is not None:
                    try:
                        manual_status = runtime.status_project(project["runtime_name"])
                        manual_memory = runtime.memory_projection(project["runtime_name"])
                        manual_facts = runtime.fact_graph_projection(project["runtime_name"])
                        manual_state = beat_coordinator.settle(project_id, orchestration_observation(
                            run=active_after_message, status=manual_status, memory=manual_memory, facts=manual_facts,
                        ))
                        store.update_orchestration_beat_state(project_id, fingerprint=manual_state[0], status="manual_activation", reason="operator_message", last_beat_at=manual_state[1], last_consult_at=manual_state[2], last_summary_at=manual_state[3])
                    except (RuntimeErrorBase, OSError):
                        store.audit("orchestration_beat", "manual_settle_failure", project_id)
                return JSONResponse({
                    "message_id": message_id, "reply_id": reply_id, **result,
                    **({
                        "artifact_intent_id": artifact_intent_id,
                        "artifact_status": artifact_outcome["execution_status"],
                        "artifact_outcome_code": artifact_outcome["outcome_code"],
                    } if artifact_outcome is not None else {}),
                }, status_code=201)
            except Exception as exc:
                if artifact_intent_id is not None:
                    artifact_outcome = store.artifact_confirmation_intent(artifact_intent_id)
                    if artifact_outcome is not None and artifact_outcome.get("execution_status") in {"pending", "dispatched"}:
                        store.fail_dispatched_artifact_intent(
                            artifact_intent_id, project_id, outcome_code="main_agent_failed",
                            completed_at=time.time(),
                        )
                known_failure = isinstance(exc, MainAgentError)
                public_error = _public_main_agent_error(exc) if known_failure else "Main Agent 内部错误；请联系管理员。"
                error_code = (
                    _redact_exact_value(str(getattr(exc, "code", "")), exact_turn_secrets)
                    if known_failure and getattr(exc, "code", None) is not None else None
                )
                provider_retryable = bool(getattr(exc, "retryable", False)) if known_failure else False
                retryable = bool(getattr(exc, "safe_to_retry", False)) if known_failure else False
                attempts = max(1, int(getattr(exc, "attempts", 1))) if known_failure else 1
                store.update_message(message_id, status="failed", error=public_error)
                last_events = store.main_agent_events(project_id, limit=1)
                last_event = last_events[-1] if last_events else None
                if not last_event or last_event.get("message_id") != message_id or last_event.get("type") != "turn.failed":
                    store.add_main_agent_event(
                        project_id=project_id, message_id=message_id,
                        event_type="turn.failed",
                        payload={"status": "failed", "detail": public_error[:4000]},
                    )
                failed_session = store.agent_session(project_id) or {}
                failed_session_id = (
                    getattr(exc, "session_id", None)
                    or (failed_session.get("session_id") if failed_session.get("backend") == main_agent_backend else None)
                )
                if failed_session_id is not None:
                    failed_session_id = str(_redact_exact_value(
                        str(failed_session_id), exact_turn_secrets,
                    ))
                store.upsert_agent_session(
                    project_id, failed_session_id, "inactive", time.time(),
                    backend=main_agent_backend,
                )
                store.audit("message", "failure", project_id, details=json.dumps({
                    "error_code": error_code, "provider_retryable": provider_retryable,
                    "retryable": retryable, "attempts": attempts,
                }, sort_keys=True))
                store.add_message({
                    "id": uuid.uuid4().hex, "project_id": project_id,
                    "role": "assistant", "text": "", "status": "failed",
                    "created_at": time.time(), "error": public_error,
                })
                return JSONResponse({
                    "detail": public_error,
                    "error_code": error_code,
                    "provider_retryable": provider_retryable,
                    "retryable": retryable,
                    "attempts": attempts,
                }, status_code=502)


    from fastapi.staticfiles import StaticFiles
    app.mount("/static", StaticFiles(directory=Path(__file__).with_name("static")), name="static")
    @app.get("/health")
    async def health():
        return {"service": "danus-web-console", "status": "ok"}

    @app.get("/")
    async def index():
        from fastapi.responses import FileResponse
        return FileResponse(Path(__file__).with_name("static") / "index.html")

    async def execute_orchestration_beat(project: dict[str, Any]) -> None:
        project_id = project["id"]
        beat_id = None
        decision = None
        persisted = None
        try:
            async with lock_for(project_id):
                active = store.active_run(project_id)
                if active is None:
                    store.audit("orchestration_beat", "cancelled_inactive_run", project_id)
                    return
                persisted = store.orchestration_beat_state(project_id)
                maintenance_reason = store.project_maintenance_reason(project_id)
                if maintenance_reason is not None:
                    if not persisted or persisted.get("status") != "blocked_pending_file_conflict":
                        now = time.time()
                        store.update_orchestration_beat_state(
                            project_id,
                            fingerprint=str((persisted or {}).get("fingerprint") or maintenance_reason),
                            status="blocked_pending_file_conflict",
                            reason=maintenance_reason,
                            last_beat_at=float((persisted or {}).get("last_beat_at") or 0.0),
                            last_consult_at=float((persisted or {}).get("last_consult_at") or 0.0),
                            last_summary_at=float((persisted or {}).get("last_summary_at") or 0.0),
                        )
                        store.audit(
                            "orchestration_beat", "blocked_pending_file_conflict",
                            project_id, details=json.dumps({
                                "blocked_at": now,
                                "maintenance_reason": maintenance_reason,
                            }),
                        )
                    beat_coordinator.request(project_id)
                    return
                if persisted and persisted.get("status") in {"completed", "manual_activation", "cadence_due_no_change"}:
                    beat_coordinator.seed(
                        project_id, fingerprint=persisted["fingerprint"],
                        last_beat_at=persisted["last_beat_at"],
                        last_consult_at=persisted["last_consult_at"],
                        last_summary_at=persisted["last_summary_at"],
                    )
                projection = await asyncio.to_thread(runtime.status_project, project["runtime_name"])
                memory = await asyncio.to_thread(runtime.memory_projection, project["runtime_name"])
                facts = await asyncio.to_thread(runtime.fact_graph_projection, project["runtime_name"])
                observation = orchestration_observation(run=active, status=projection, memory=memory, facts=facts)
                decision = beat_coordinator.consider(project_id, observation)
                if not decision.due:
                    if decision.reason == "cadence_deferred_no_change":
                        last_consult, last_summary = beat_coordinator.defer_cadence(
                            project_id, consult_due=decision.consult_due, summary_due=decision.summary_due,
                        )
                        previous = persisted or {}
                        store.update_orchestration_beat_state(
                            project_id, fingerprint=decision.fingerprint,
                            status="cadence_due_no_change", reason=decision.reason,
                            last_beat_at=previous.get("last_beat_at", time.time()),
                            last_consult_at=last_consult, last_summary_at=last_summary,
                        )
                        store.audit("orchestration_beat", "cadence_due_no_change", project_id,
                                    details=json.dumps({"consult_due": decision.consult_due, "summary_due": decision.summary_due}))
                    return
                previous = persisted or {}
                now = time.time()
                store.update_orchestration_beat_state(
                    project_id, fingerprint=decision.fingerprint, status="scheduled", reason=decision.reason,
                    last_beat_at=previous.get("last_beat_at", 0.0),
                    last_consult_at=previous.get("last_consult_at", 0.0),
                    last_summary_at=previous.get("last_summary_at", 0.0),
                )
                store.audit("orchestration_beat", "scheduled", project_id,
                            details=json.dumps({"reason": decision.reason, "fingerprint": decision.fingerprint}))
                beat_id = uuid.uuid4().hex
                beat_message = (
                    f"[Host orchestration beat: {decision.reason}; consult_due={decision.consult_due}; summary_due={decision.summary_due}] "
                    "Inspect current Worker status, global memory, and Fact Graph. Act only on genuine new state: update provenance-marked "
                    "guidance when warranted, re-task Workers between rounds, and use the project lifecycle broker for normal lifecycle actions. "
                    "If verifier-accepted facts complete the Project target, request graceful stop and notify the operator. "
                    "If summary_due=true, produce the auditable human summary."
                )
                store.add_message({"id": beat_id, "project_id": project_id, "role": "system", "text": beat_message,
                                   "status": "submitted", "created_at": now, "error": None})
                session = store.agent_session(project_id) or {}
                session_id = session.get("session_id") if session.get("backend") == main_agent_backend else None
                store.upsert_agent_session(project_id, session_id, "active", time.time(), backend=main_agent_backend)
                beat_lifecycle_token = lifecycle_token(project)
                async with main_agent_broker_window(project_id):
                    raw_result = await asyncio.to_thread(lambda: main_agent.send(
                        context_dir=runtime.project_context_dir(project["runtime_name"]), session_id=session_id,
                        message=beat_message, manifest=[metadata(row) for row in store.files(project_id)],
                        project_state={"project_id": project_id, "name": project["name"], "problem": project["problem"]},
                        attachments=[], lifecycle_url=lifecycle_url(project_id), lifecycle_token=beat_lifecycle_token,
                    ))
                result = _redact_exact_value(
                    raw_result, (beat_lifecycle_token,),
                )
                if not isinstance(result, dict):
                    raise RuntimeError("Main Agent returned an invalid response")
                store.update_message(beat_id, status="completed")
                store.upsert_agent_session(project_id, result["session_id"], "inactive", time.time(), backend=main_agent_backend)
                store.add_message({"id": uuid.uuid4().hex, "project_id": project_id, "role": "assistant",
                                   "text": result["reply"], "status": "completed", "created_at": time.time(), "error": None})
                current_active = store.active_run(project_id)
                if current_active is None or current_active["id"] != active["id"]:
                    status = "completed_after_run_end" if current_active is None else "completed_after_run_change"
                    store.update_orchestration_beat_state(
                        project_id, fingerprint=decision.fingerprint, status=status, reason=decision.reason,
                        last_beat_at=time.time(), last_consult_at=(persisted or {}).get("last_consult_at", 0.0),
                        last_summary_at=(persisted or {}).get("last_summary_at", 0.0),
                    )
                    beat_coordinator.forget(project_id)
                    if current_active is not None:
                        beat_coordinator.request(project_id)
                    store.audit("orchestration_beat", status, project_id)
                    return
                settled_status = await asyncio.to_thread(runtime.status_project, project["runtime_name"])
                settled_memory = await asyncio.to_thread(runtime.memory_projection, project["runtime_name"])
                settled_facts = await asyncio.to_thread(runtime.fact_graph_projection, project["runtime_name"])
                completed = beat_coordinator.complete(project_id, orchestration_observation(
                    run=current_active, status=settled_status, memory=settled_memory, facts=settled_facts,
                ), decision)
                store.update_orchestration_beat_state(
                    project_id, fingerprint=completed[0], status="completed", reason=decision.reason,
                    last_beat_at=completed[1], last_consult_at=completed[2], last_summary_at=completed[3],
                )
                store.audit("orchestration_beat", "completed", project_id,
                            details=json.dumps({"reason": decision.reason, "fingerprint": completed[0]}))
        except Exception as exc:
            failures = beat_coordinator.record_failure(project_id)
            beat_coordinator.request(project_id)
            if beat_id is not None:
                store.update_message(beat_id, status="failed", error="Main Agent orchestration beat failed")
                session = store.agent_session(project_id) or {}
                store.upsert_agent_session(project_id, session.get("session_id"), "inactive", time.time(), backend=main_agent_backend)
            if decision is not None:
                previous = persisted or {}
                store.update_orchestration_beat_state(
                    project_id, fingerprint=decision.fingerprint, status="failed", reason=decision.reason,
                    last_beat_at=previous.get("last_beat_at", 0.0),
                    last_consult_at=previous.get("last_consult_at", 0.0),
                    last_summary_at=previous.get("last_summary_at", 0.0),
                )
            store.audit("orchestration_beat", "failure", project_id, details=json.dumps({
                "error_code": type(exc).__name__,
                "consecutive_failures": failures,
            }))
        finally:
            active_beat_projects.discard(project_id)

    async def orchestration_beat_loop() -> None:
        interval = max(0.25, float(settings.orchestration_poll_seconds))
        while True:
            await asyncio.sleep(interval)
            for project in store.projects():
                if store.active_run(project["id"]) is None or project["id"] in active_beat_projects or not beat_coordinator.retry_allowed(project["id"]):
                    continue
                active_beat_projects.add(project["id"])
                task = asyncio.create_task(execute_orchestration_beat(project))
                beat_execution_tasks.add(task)
                task.add_done_callback(beat_execution_tasks.discard)
    async def deadline_supervisor_loop() -> None:
        interval = max(0.05, float(settings.deadline_poll_seconds))
        while True:
            for project in store.projects():
                active = store.active_run(project["id"])
                if active is None or time.time() < active["deadline"]:
                    continue
                # Deadline enforcement is a host safety boundary and must not
                # wait behind a long Main Agent turn's orchestration lock.
                try:
                    await asyncio.to_thread(
                        lambda p=project: reconcile_run(
                            p["id"], p, runtime.status_project(p["runtime_name"]),
                        )
                    )
                except (RuntimeErrorBase, OSError):
                    store.audit("run_deadline", "projection_failure", project["id"])
            await asyncio.sleep(interval)

    app.state.execute_orchestration_beat = execute_orchestration_beat
    app.state.reconcile_external_materials = reconcile_external_materials
    return app
