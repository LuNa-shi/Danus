"""Authenticated Web Console HTTP boundary (V1 first vertical slice)."""
from __future__ import annotations

import json
import sqlite3
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .runtime import DanusRuntimeAdapter, RuntimeErrorBase, validate_runtime_name
from .files import FileValidationError, file_type, material_root, metadata, normalize_filename, promote_pending, remove_blob, stream_to_pending, validate_bytes
from .main_agent import MainAgentError, MainAgentAdapter
from .security import digest_token, new_token, verify_password
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


def _error(status: int, detail: str) -> JSONResponse:
    return JSONResponse({"detail": detail}, status_code=status)

def _runtime_name(name: str) -> str:
    # Keep runtime names path-safe and stable; DB ids are opaque to clients.
    validate_runtime_name(name)
    return name

def create_app(*, settings: AppSettings, runtime: Any | None = None, main_agent: Any | None = None) -> FastAPI:
    app = FastAPI(title="Danus Web Console", version="0.1.0")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    store = ConsoleStore(settings.database_path)
    runtime = runtime or DanusRuntimeAdapter()
    main_agent = main_agent or MainAgentAdapter()
    app.state.console_store = store
    app.state.main_agent_adapter = main_agent
    app.state.runtime_adapter = runtime
    project_locks: dict[str, threading.Lock] = {}
    locks_guard = threading.Lock()
    failed: dict[str, tuple[int, float]] = {}

    def lock_for(project_id: str) -> threading.Lock:
        with locks_guard:
            return project_locks.setdefault(project_id, threading.Lock())

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
        return response

    @app.get("/api/auth/session")
    async def auth_session(request: Request):
        current = session(request)
        if current is None:
            return _error(401, "authentication required")
        return {"authenticated": True, "expires_at": current["expires_at"]}

    @app.get("/api/auth/me")
    async def me(request: Request):
        current = session(request)
        if current is None:
            return _error(401, "authentication required")
        return {"authenticated": True}

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
            rows.append({"id": project["id"], "name": project["name"], "problem": project["problem"], "runtime_name": project["runtime_name"], "workers": projection.get("workers", [])})
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
            model = payload.get("model")
            if not isinstance(problem, str) or not problem.strip():
                raise ValueError("problem must be non-empty")
            project_id = uuid.uuid4().hex
            result = runtime.create_project(name, problem, roles, model)
            try:
                store.add_project({"id": project_id, "name": name, "runtime_name": name, "problem": problem, "created_at": time.time()})
            except sqlite3.IntegrityError:
                store.audit("project_create", "failure", details=json.dumps({"error": "project name already exists"}))
                return _error(409, "project name already exists")
            except Exception:
                store.audit("project_create", "failure", details=json.dumps({"error": "metadata persistence failed"}))
                return _error(500, "project metadata could not be persisted")
            store.audit("project_create", "success", project_id)
            return JSONResponse({"id": project_id, "name": name, "problem": problem, "runtime_name": name, "workers": result.get("workers", [])}, status_code=201)
        except (KeyError, TypeError, ValueError) as exc:
            return _error(400, str(exc))
        except RuntimeErrorBase as exc:
            store.audit("project_create", "failure", details=json.dumps({"error": str(exc)}))
            return _error(409, "project creation failed")

    @app.get("/api/projects/{project_id}")
    async def get_project(project_id: str, request: Request):
        if isinstance((auth := auth_required(request)), JSONResponse):
            return auth
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse):
            return project
        return {"id": project["id"], "name": project["name"], "problem": project["problem"], "runtime_name": project["runtime_name"]}

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
        with lock_for(project_id):
            active = store.active_run(project_id)
            if active is not None:
                if time.time() >= active["deadline"]:
                    store.update_run(active["id"], status="expired", stopped_at=time.time(), outcome="deadline")
                    try:
                        runtime.stop_project(project["runtime_name"])
                    except RuntimeErrorBase:
                        pass
                else:
                    return _error(409, "project already has an active run")
            started, deadline = time.time(), time.time() + duration
            run = {"id": uuid.uuid4().hex, "project_id": project_id, "duration_seconds": duration, "started_at": started, "deadline": deadline, "status": "starting"}
            try:
                runtime.write_deadline(project["runtime_name"], deadline)
                result = runtime.start_project(project["runtime_name"])
                store.add_run({**run, "status": "starting"})
                store.audit("run_start", "success", project_id)
                return JSONResponse({"run_id": run["id"], "status": "start_requested", "deadline": deadline}, status_code=202)
            except RuntimeErrorBase as exc:
                # A failed launch must not leave a deadline that can constrain
                # a later independent restart.
                try:
                    runtime.clear_deadline(project["runtime_name"])
                except (AttributeError, RuntimeErrorBase):
                    pass
                # Persist a failed control-plane outcome rather than claiming
                # that a deadline write/start request created a live run.
                store.add_run({**run, "status": "failed"})
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
            projection = runtime.status_project(project["runtime_name"])
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
        with lock_for(project_id):
            try:
                result = runtime.stop_project(project["runtime_name"])
                store.update_run(run_id, status="stopping", outcome="graceful_stop_requested")
                store.audit("run_stop", "success", project_id)
                return JSONResponse({"run_id": run_id, "status": "stop_requested"}, status_code=202)
            except RuntimeErrorBase:
                store.update_run(run_id, status="failed", stopped_at=time.time(), outcome="stop_failed")
                store.audit("run_stop", "failure", project_id)
                return _error(502, "project stop could not be completed")

    @app.get("/api/projects/{project_id}/runtime")
    async def runtime_status(project_id: str, request: Request):
        if isinstance((auth := auth_required(request)), JSONResponse):
            return auth
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse):
            return project
        try:
            projection = runtime.status_project(project["runtime_name"])
            active = store.active_run(project_id)
            if active is not None:
                projection = {**projection, "run": {"id": active["id"], "status": active["status"], "deadline": active["deadline"]}}
            return projection
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
        with lock_for(project_id):
            try:
                result = runtime.stop_project(project["runtime_name"])
                active = store.active_run(project_id)
                if active:
                    store.update_run(active["id"], status="stopping", outcome="graceful_stop_requested")
                store.audit("run_stop", "success", project_id)
                return JSONResponse({"status": "stop_requested"}, status_code=202)
            except RuntimeErrorBase:
                store.audit("run_stop", "failure", project_id)
                return _error(502, "project stop could not be completed")

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
        form = await request.form()
        upload = form.get("file")
        if upload is None or not hasattr(upload, "filename") or not hasattr(upload, "file"):
            return _error(400, "file is required")
        try:
            logical_name = normalize_filename(upload.filename)
            content_type, kind = file_type(logical_name)
            materials = material_root(Path(runtime.project_context_dir(project["runtime_name"])))
            pending, sha256, size = stream_to_pending(upload, materials, settings.max_file_bytes)
            data = pending.read_bytes()
            validate_bytes(kind, data)
            storage_name, stored = promote_pending(pending, materials, sha256)
            existing_hash = store.file_by_hash(project_id, sha256)
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
            return _error(400, str(exc))

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
        conflict = store.conflict(conflict_id, project_id)
        if conflict is None or conflict["status"] != "pending":
            return _error(404, "file conflict not found")
        payload = await request.json()
        choice = payload.get("choice") if isinstance(payload, dict) else None
        incoming = store.file(conflict["incoming_file_id"], project_id)
        existing = store.file(conflict["current_file_id"], project_id)
        if incoming is None or existing is None:
            return _error(409, "file conflict is no longer available")
        materials = material_root(Path(runtime.project_context_dir(project["runtime_name"])))
        incoming_blob = materials / incoming["storage_name"]
        if choice == "cancel":
            remove_blob(materials, incoming["storage_name"])
            store.update_conflict(conflict_id, "cancelled")
            store.delete_file(incoming["id"], project_id)
            store.audit("file_conflict", "cancel", project_id)
            return JSONResponse({"status": "cancelled"}, status_code=200)
        if choice == "new_version":
            store.set_current(project_id, conflict["logical_name"], incoming["id"])
            store.update_conflict(conflict_id, "new_version")
            store.audit("file_conflict", "new_version", project_id)
            return JSONResponse(metadata(store.file(incoming["id"], project_id)), status_code=200)
        if choice == "replace":
            remove_blob(materials, existing["storage_name"])
            store.set_current(project_id, conflict["logical_name"], incoming["id"])
            store.update_conflict(conflict_id, "replaced")
            store.update_file_status(existing["id"], is_current=0, processing_status="replaced")
            store.audit("file_conflict", "replace", project_id)
            return JSONResponse(metadata(store.file(incoming["id"], project_id)), status_code=200)
        return _error(400, "choice must be replace, new_version, or cancel")

    @app.get("/api/projects/{project_id}/messages")
    async def list_messages(project_id: str, request: Request):
        if isinstance((auth := auth_required(request)), JSONResponse):
            return auth
        project = project_or_404(project_id)
        if isinstance(project, JSONResponse):
            return project
        return store.messages(project_id)

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
        attachments = []
        for file_id in attachment_ids:
            row = store.file(str(file_id), project_id)
            if row is None:
                return _error(404, "attachment not found")
            attachments.append(metadata(row) | {"path": str(material_root(Path(runtime.project_context_dir(project["runtime_name"]))) / row["storage_name"])})
        message_id = uuid.uuid4().hex
        now = time.time()
        store.add_message({"id": message_id, "project_id": project_id, "role": "user", "text": text, "status": "submitted", "created_at": now, "error": None})
        store.upsert_agent_session(project_id, (store.agent_session(project_id) or {}).get("claude_session_id"), "active", now)
        try:
            manifest = [metadata(row) for row in store.files(project_id)]
            result = main_agent.send(context_dir=runtime.project_context_dir(project["runtime_name"]), session_id=(store.agent_session(project_id) or {}).get("claude_session_id"), message=text, manifest=manifest, project_state={"project_id": project_id, "name": project["name"], "problem": project["problem"]}, attachments=attachments)
            store.upsert_agent_session(project_id, result["session_id"], "inactive", time.time())
            reply_id = uuid.uuid4().hex
            store.add_message({"id": reply_id, "project_id": project_id, "role": "assistant", "text": result["reply"], "status": "completed", "created_at": time.time(), "error": None})
            store.audit("message", "success", project_id)
            return JSONResponse({"message_id": message_id, "reply_id": reply_id, **result}, status_code=201)
        except MainAgentError as exc:
            store.upsert_agent_session(project_id, (store.agent_session(project_id) or {}).get("claude_session_id"), "inactive", time.time())
            store.audit("message", "failure", project_id)
            store.add_message({"id": uuid.uuid4().hex, "project_id": project_id, "role": "assistant", "text": "", "status": "failed", "created_at": time.time(), "error": str(exc)[:200]})
            return _error(502, "main agent message failed")

    return app
