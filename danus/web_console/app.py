"""Authenticated Web Console HTTP boundary (V1 first vertical slice)."""
from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import sqlite3
import secrets
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
from .runtime import DanusRuntimeAdapter, RuntimeErrorBase, validate_runtime_name
from .files import FileValidationError, file_type, material_root, metadata, normalize_filename, promote_pending, remove_blob, stream_to_pending, validate_bytes
from .main_agent import MainAgentError, MainAgentAdapter
from .security import (
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


def _error(status: int, detail: str) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=status)


def _public_main_agent_error(exc: MainAgentError) -> str:
    if exc.code == "timeout" and not exc.safe_to_retry:
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


def create_app(
    *,
    settings: AppSettings,
    runtime: Any | None = None,
    main_agent: Any | None = None,
    model_catalog: Any | None = None,
) -> FastAPI:
    @contextlib.asynccontextmanager
    async def lifespan(application: FastAPI):
        task = asyncio.create_task(deadline_supervisor_loop())
        application.state.deadline_supervisor_task = task
        try:
            yield
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

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
    locks_guard = threading.Lock()
    failed: dict[str, tuple[int, float]] = {}

    def lock_for(project_id: str) -> asyncio.Lock:
        with locks_guard:
            return project_locks.setdefault(project_id, asyncio.Lock())

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
        return {
            **projection,
            "config": config,
            "project": project_payload(project),
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
        alive = [name for name in expected if workers.get(name, {}).get("alive") is True]
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
            if active["status"] == "stopping" and not any(worker.get("alive") for worker in workers):
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
        if action not in {"assign", "status", "start", "stop"}:
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

        if action == "status":
            try:
                return runtime.status_project(project["runtime_name"])
            except (RuntimeErrorBase, OSError):
                return _error(502, "project status unavailable")
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
        for project in store.projects():
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
                projection = runtime.status_project(project["runtime_name"])
                reconcile_run(project_id, project, projection)
                if store.active_run(project_id) is not None or any(
                    worker.get("alive") for worker in projection.get("workers", [])
                ):
                    return _error(409, "project must be stopped before deletion")
                result = runtime.delete_project(project["runtime_name"])
                store.delete_project(project_id)
                store.audit("project_delete", "success", project_id)
                return JSONResponse({"deleted": True, **result}, status_code=200)
            except RuntimeErrorBase:
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
        try:
            payload = await request.json()
            duration = int(payload["duration_seconds"])
            if duration <= 0 or duration > 7 * 24 * 3600:
                raise ValueError("duration_seconds out of range")
        except (KeyError, TypeError, ValueError):
            return _error(400, "invalid duration_seconds")
        async with lock_for(project_id):
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
            started, deadline = time.time(), time.time() + duration
            run = {"id": uuid.uuid4().hex, "project_id": project_id, "duration_seconds": duration, "started_at": started, "deadline": deadline, "status": "starting"}
            # Persist the bounded operator intent before exposing it to the
            # Main Agent. Normal Worker spawning is brokered only when that
            # project-scoped Main Agent explicitly requests it.
            store.add_run(run)
            try:
                runtime.write_deadline(project["runtime_name"], deadline)
                store.audit("run_start", "intent_recorded", project_id)
                return JSONResponse({"run_id": run["id"], "status": "start_requested", "deadline": deadline}, status_code=202)
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
        return {**run, "workers": projection.get("workers", [])}

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
                projection = {**projection, "run": {
                    "id": active["id"], "status": active["status"],
                    "deadline": active["deadline"], "outcome": active.get("outcome"),
                    "expected_workers": expected, "alive_workers": alive,
                    "not_running_workers": pending,
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

    @app.get("/api/projects/{project_id}/files")
    async def list_files(project_id: str, request: Request):
        if isinstance((auth := auth_required(request)), JSONResponse):
            return auth
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse):
            return project
        return [metadata(row) for row in store.files(project_id)]

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
            form = await request.form()
        except Exception:
            return _error(400, "invalid multipart upload")
        upload = form.get("file")
        if upload is None or not hasattr(upload, "filename") or not hasattr(upload, "file"):
            return _error(400, "file is required")
        async with lock_for(project_id):
          pending = None
          try:
              logical_name = normalize_filename(upload.filename)
              content_type, kind = file_type(logical_name)
              materials = material_root(Path(runtime.project_context_dir(project["runtime_name"])))
              pending, sha256, size = stream_to_pending(upload, materials, settings.max_file_bytes)
              data = pending.read_bytes()
              validate_bytes(kind, data)
              storage_name, stored = promote_pending(pending, materials, sha256)
              existing_hash = store.file_by_hash(project_id, sha256)
              if existing_hash is None:
                  tombstone = store.file_tombstone_by_hash(project_id, sha256)
                  if tombstone is not None:
                      store.purge_file_tombstone(tombstone["id"], project_id)
                      tombstone = store.file_tombstone_by_hash(project_id, sha256)
                      if tombstone is not None:
                          # An attachment keeps the historical row and blob;
                          # restore it as a usable deduplicated file instead of
                          # violating UNIQUE(project_id, sha256).
                          store.update_file_status(tombstone["id"], processing_status="available")
                          existing_hash = store.file(tombstone["id"], project_id)
              if existing_hash is not None:
                  if stored:
                      remove_blob(materials, storage_name)
                  store.audit("file_upload", "reuse", project_id)
                  return JSONResponse(metadata(existing_hash), status_code=200)
              existing = store.current_file(project_id, logical_name)
              file_id = uuid.uuid4().hex
              version = store.next_version(project_id, logical_name)
              row = {"id": file_id, "project_id": project_id, "logical_name": logical_name, "content_type": content_type, "kind": kind, "size": size, "sha256": sha256, "storage_name": storage_name, "version": version, "is_current": 0 if existing else 1, "processing_status": "available", "read_status": "not_read", "uploaded_at": time.time()}
              store.add_file(row)
              if existing:
                  conflict_id = uuid.uuid4().hex
                  store.add_conflict({"id": conflict_id, "project_id": project_id, "logical_name": logical_name, "incoming_file_id": file_id, "current_file_id": existing["id"], "created_at": time.time(), "status": "pending"})
                  store.audit("file_upload", "conflict", project_id)
                  return JSONResponse({"conflict_id": conflict_id, "current": metadata(existing), "incoming": metadata(row), "choices": ["replace", "new_version", "cancel"]}, status_code=409)
              store.audit("file_upload", "success", project_id)
              return JSONResponse(metadata(row), status_code=201)
          except FileValidationError as exc:
              if pending is not None:
                  pending.unlink(missing_ok=True)
              return _error(400, str(exc))
          except (OSError, sqlite3.IntegrityError) as exc:
              # Best-effort cleanup for failures after blob promotion. A blob may
              # be shared by an existing content-addressed row, so only remove it
              # when this request created it and no row references it.
              try:
                  if "stored" in locals() and stored and "storage_name" in locals() and store.file_by_hash(project_id, sha256) is None:
                      remove_blob(materials, storage_name)
              except (OSError, FileValidationError):
                  pass
              store.audit("file_upload", "failure", project_id, json.dumps({"error": str(exc)[:200]}))
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
        payload = await request.json()
        choice = payload.get("choice") if isinstance(payload, dict) else None
        async with lock_for(project_id):
            conflict = store.conflict(conflict_id, project_id)
            if conflict is None or conflict["status"] != "pending":
                return _error(404, "file conflict not found")
            incoming = store.file(conflict["incoming_file_id"], project_id)
            existing = store.file(conflict["current_file_id"], project_id)
            if incoming is None or existing is None:
                return _error(409, "file conflict is no longer available")
            try:
                materials = material_root(Path(runtime.project_context_dir(project["runtime_name"])))
                incoming_blob = materials / incoming["storage_name"]
                if not incoming_blob.is_file():
                    return _error(409, "incoming file blob is unavailable")
                if choice == "cancel":
                    # Keep an attachment's historical file row; only discard
                    # the pending conflict blob and mark the incoming row.
                    remove_blob(materials, incoming["storage_name"])
                    store.update_conflict(conflict_id, "cancelled")
                    store.update_file_status(incoming["id"], processing_status="cancelled")
                    store.audit("file_conflict", "cancel", project_id)
                    return JSONResponse({"status": "cancelled"}, status_code=200)
                if choice == "new_version":
                    store.set_current(project_id, conflict["logical_name"], incoming["id"])
                    store.update_conflict(conflict_id, "new_version")
                    store.audit("file_conflict", "new_version", project_id)
                    return JSONResponse(metadata(store.file(incoming["id"], project_id)), status_code=200)
                if choice == "replace":
                    store.set_current(project_id, conflict["logical_name"], incoming["id"])
                    store.update_conflict(conflict_id, "replaced")
                    store.update_file_status(existing["id"], is_current=0, processing_status="replaced")
                    # Remove an unreferenced superseded blob only after the
                    # durable state transition. Attachments retain history.
                    if not store.messages(project_id) or not any(existing["id"] in m.get("attachment_ids", []) for m in store.messages(project_id)):
                        remove_blob(materials, existing["storage_name"])
                    store.audit("file_conflict", "replace", project_id)
                    return JSONResponse(metadata(store.file(incoming["id"], project_id)), status_code=200)
                return _error(400, "choice must be replace, new_version, or cancel")
            except (FileValidationError, RuntimeErrorBase, OSError, sqlite3.IntegrityError) as exc:
                return _error(409 if isinstance(exc, sqlite3.IntegrityError) else 502, "file conflict could not be resolved")

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
            return runtime.logs_projection(project["runtime_name"], worker=request.query_params.get("worker"), tail=tail)
        except (RuntimeErrorBase, ValueError):
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
            run_projection = {"id": active["id"], "status": active["status"], "deadline": active["deadline"]}
        return {
            "project": project_payload(project),
            "config": project_config(project),
            "main_agent": session_projection,
            "session": session_projection,
            "main_agent_status": session_projection["status"],
            "main_agent_backend": session_projection["backend"],
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
            "master_guidance": latest_memory_entry(memory, "master_guidance"),
            "guidance": latest_memory_entry(memory, "master_guidance"),
            "elaboration": latest_memory_entry(memory, "elaboration"),
            "run": run_projection,
        }

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
        if not isinstance(text, str) or not text.strip() or not isinstance(attachment_ids, list):
            return _error(400, "text and attachment_ids are required")
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
            row = store.file(str(file_id), project_id)
            if row is None:
                return _error(404, "attachment not found")
            attachment_rows.append(row)
            attachments.append(metadata(row) | {"path": str(material_root(Path(runtime.project_context_dir(project["runtime_name"]))) / row["storage_name"])})
        message_id = uuid.uuid4().hex
        now = time.time()
        store.add_message({"id": message_id, "project_id": project_id, "role": "user", "text": text, "status": "submitted", "created_at": now, "error": None}, [row["id"] for row in attachment_rows])
        manifest = [metadata(row) for row in store.files(project_id)]

        def record_main_agent_progress(event: dict[str, Any]) -> None:
            event_type = str(event.get("type") or "")
            allowed_types = {
                "turn.started", "agent.message", "tool.started", "tool.completed",
                "turn.retry", "turn.completed", "turn.failed",
            }
            if event_type in allowed_types:
                safe_payload: dict[str, Any] = {}
                for key in ("tool", "detail", "status"):
                    value = event.get(key)
                    if value is not None:
                        safe_payload[key] = str(value)[:4000 if key == "detail" else 200]
                for key in ("attempt", "max_attempts", "delay_seconds"):
                    value = event.get(key)
                    if isinstance(value, (int, float)):
                        safe_payload[key] = value
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
                    project_id, str(progress_session_id), "active", time.time(),
                    backend=main_agent_backend,
                )

        async with lock_for(project_id):
            session = store.agent_session(project_id) or {}
            session_id = session.get("session_id") if session.get("backend") == main_agent_backend else None
            store.upsert_agent_session(
                project_id, session_id, "active", time.time(), backend=main_agent_backend,
            )

            def invoke_main_agent():
                return main_agent.send(
                    context_dir=runtime.project_context_dir(project["runtime_name"]),
                    session_id=session_id,
                    message=text,
                    manifest=manifest,
                    project_state={"project_id": project_id, "name": project["name"], "problem": project["problem"]},
                    attachments=attachments,
                    on_progress=record_main_agent_progress,
                    lifecycle_url=lifecycle_url(project_id),
                    lifecycle_token=lifecycle_token(project),
                )

            try:
                result = await asyncio.to_thread(invoke_main_agent)
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
                return JSONResponse({
                    "message_id": message_id, "reply_id": reply_id, **result,
                }, status_code=201)
            except Exception as exc:
                known_failure = isinstance(exc, MainAgentError)
                public_error = _public_main_agent_error(exc) if known_failure else "Main Agent 内部错误；请联系管理员。"
                error_code = getattr(exc, "code", None) if known_failure else None
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

    return app
