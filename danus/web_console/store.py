"""SQLite persistence owned by the Web Console control plane."""
from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Any


class ConsoleStore:
    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _initialize(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, runtime_name TEXT NOT NULL UNIQUE,
                    problem TEXT NOT NULL, created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS files (
                    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    logical_name TEXT NOT NULL, content_type TEXT NOT NULL, kind TEXT NOT NULL,
                    size INTEGER NOT NULL, sha256 TEXT NOT NULL, storage_name TEXT NOT NULL,
                    version INTEGER NOT NULL, is_current INTEGER NOT NULL,
                    processing_status TEXT NOT NULL, read_status TEXT NOT NULL,
                    uploaded_at REAL NOT NULL,
                    UNIQUE(project_id, logical_name, version),
                    UNIQUE(project_id, sha256)
                );
                CREATE TABLE IF NOT EXISTS file_conflicts (
                    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    logical_name TEXT NOT NULL, incoming_file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
                    current_file_id TEXT NOT NULL REFERENCES files(id), created_at REAL NOT NULL, status TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS main_agent_sessions (
                    project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
                    session_id TEXT, backend TEXT NOT NULL DEFAULT 'codex', status TEXT NOT NULL, updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    role TEXT NOT NULL, text TEXT NOT NULL, status TEXT NOT NULL, created_at REAL NOT NULL,
                    error TEXT
                );
                CREATE TABLE IF NOT EXISTS message_attachments (
                    message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                    file_id TEXT NOT NULL REFERENCES files(id), PRIMARY KEY(message_id, file_id)
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY, token_digest TEXT NOT NULL UNIQUE, csrf_digest TEXT NOT NULL,
                    created_at REAL NOT NULL, last_seen REAL NOT NULL, expires_at REAL NOT NULL, revoked_at REAL
                );
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    duration_seconds INTEGER NOT NULL, started_at REAL NOT NULL, deadline REAL NOT NULL,
                    status TEXT NOT NULL, stopped_at REAL, outcome TEXT
                );
                CREATE TABLE IF NOT EXISTS login_attempts (
                    key TEXT PRIMARY KEY, failures INTEGER NOT NULL, locked_until REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, project_id TEXT,
                    outcome TEXT NOT NULL, created_at REAL NOT NULL, details TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_runs_project_status ON runs(project_id, status);
                """
            )
            columns = {row[1] for row in conn.execute("PRAGMA table_info(main_agent_sessions)")}
            if "session_id" not in columns:
                conn.execute("ALTER TABLE main_agent_sessions ADD COLUMN session_id TEXT")
                conn.execute("ALTER TABLE main_agent_sessions ADD COLUMN backend TEXT NOT NULL DEFAULT 'codex'")
                if "claude_session_id" in columns:
                    conn.execute("UPDATE main_agent_sessions SET session_id=claude_session_id WHERE session_id IS NULL")

    @staticmethod
    def _dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
        return dict(row) if row is not None else None

    def add_project(self, project: dict[str, Any]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO projects(id,name,runtime_name,problem,created_at) VALUES(?,?,?,?,?)",
                (project["id"], project["name"], project["runtime_name"], project["problem"], project["created_at"]),
            )

    def project(self, project_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            return self._dict(conn.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone())

    def projects(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM projects ORDER BY created_at, id")]

    def delete_project(self, project_id: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM projects WHERE id=?", (project_id,))

    def has_active_run(self, project_id: str) -> bool:
        return self.active_run(project_id) is not None

    def add_file(self, file: dict[str, Any]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO files(id,project_id,logical_name,content_type,kind,size,sha256,storage_name,version,is_current,processing_status,read_status,uploaded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                tuple(file[k] for k in ("id", "project_id", "logical_name", "content_type", "kind", "size", "sha256", "storage_name", "version", "is_current", "processing_status", "read_status", "uploaded_at")),
            )

    def files(self, project_id: str, logical_name: str | None = None) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            if logical_name is None:
                rows = conn.execute("SELECT * FROM files WHERE project_id=? AND processing_status != 'cancelled' ORDER BY logical_name, version", (project_id,))
            else:
                rows = conn.execute("SELECT * FROM files WHERE project_id=? AND logical_name=? AND processing_status != 'cancelled' ORDER BY version", (project_id, logical_name))
            return [dict(row) for row in rows]

    def file(self, file_id: str, project_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            return self._dict(conn.execute("SELECT * FROM files WHERE id=? AND project_id=?", (file_id, project_id)).fetchone())

    def file_by_hash(self, project_id: str, sha256: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            return self._dict(conn.execute("SELECT * FROM files WHERE project_id=? AND sha256=? AND processing_status IN ('available','pending')", (project_id, sha256)).fetchone())

    def file_tombstone_by_hash(self, project_id: str, sha256: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            return self._dict(conn.execute("SELECT * FROM files WHERE project_id=? AND sha256=? AND processing_status IN ('cancelled','replaced')", (project_id, sha256)).fetchone())

    def purge_file_tombstone(self, file_id: str, project_id: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM files WHERE id=? AND project_id=? AND processing_status IN ('cancelled','replaced') AND NOT EXISTS (SELECT 1 FROM message_attachments WHERE file_id=files.id)", (file_id, project_id))

    def current_file(self, project_id: str, logical_name: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            return self._dict(conn.execute("SELECT * FROM files WHERE project_id=? AND logical_name=? AND is_current=1 AND processing_status != 'cancelled'", (project_id, logical_name)).fetchone())

    def next_version(self, project_id: str, logical_name: str) -> int:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT COALESCE(MAX(version),0)+1 AS v FROM files WHERE project_id=? AND logical_name=?", (project_id, logical_name)).fetchone()
            return int(row["v"])

    def set_current(self, project_id: str, logical_name: str, file_id: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("UPDATE files SET is_current=0 WHERE project_id=? AND logical_name=?", (project_id, logical_name))
            conn.execute("UPDATE files SET is_current=1 WHERE id=? AND project_id=?", (file_id, project_id))

    def add_conflict(self, conflict: dict[str, Any]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("INSERT INTO file_conflicts(id,project_id,logical_name,incoming_file_id,current_file_id,created_at,status) VALUES(?,?,?,?,?,?,?)", tuple(conflict[k] for k in ("id", "project_id", "logical_name", "incoming_file_id", "current_file_id", "created_at", "status")))

    def conflict(self, conflict_id: str, project_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            return self._dict(conn.execute("SELECT * FROM file_conflicts WHERE id=? AND project_id=?", (conflict_id, project_id)).fetchone())

    def update_conflict(self, conflict_id: str, status: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("UPDATE file_conflicts SET status=? WHERE id=?", (status, conflict_id))

    def delete_file(self, file_id: str, project_id: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM files WHERE id=? AND project_id=?", (file_id, project_id))

    def update_file_status(self, file_id: str, *, is_current: int | None = None, processing_status: str | None = None, read_status: str | None = None) -> None:
        fields = []
        values: list[Any] = []
        if is_current is not None:
            fields.append("is_current=?"); values.append(is_current)
        if processing_status is not None:
            fields.append("processing_status=?"); values.append(processing_status)
        if read_status is not None:
            fields.append("read_status=?"); values.append(read_status)
        if not fields:
            return
        values.append(file_id)
        with self._lock, self._connect() as conn:
            conn.execute(f"UPDATE files SET {', '.join(fields)} WHERE id=?", values)

    def agent_session(self, project_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            return self._dict(conn.execute("SELECT * FROM main_agent_sessions WHERE project_id=?", (project_id,)).fetchone())

    def upsert_agent_session(self, project_id: str, session_id: str | None, status: str, updated_at: float, *, backend: str = "codex") -> None:
        if backend not in {"codex", "claude"}:
            raise ValueError("invalid Main Agent backend")
        with self._lock, self._connect() as conn:
            conn.execute("INSERT INTO main_agent_sessions(project_id,session_id,backend,status,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(project_id) DO UPDATE SET session_id=excluded.session_id,backend=excluded.backend,status=excluded.status,updated_at=excluded.updated_at", (project_id, session_id, backend, status, updated_at))

    def update_message(self, message_id: str, *, status: str, error: str | None = None) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("UPDATE messages SET status=?, error=? WHERE id=?", (status, error, message_id))

    def add_message(self, message: dict[str, Any], attachment_ids: list[str] | None = None) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("INSERT INTO messages(id,project_id,role,text,status,created_at,error) VALUES(?,?,?,?,?,?,?)", tuple(message[k] for k in ("id", "project_id", "role", "text", "status", "created_at", "error")))
            for file_id in attachment_ids or []:
                conn.execute("INSERT INTO message_attachments(message_id,file_id) VALUES(?,?)", (message["id"], file_id))

    def messages(self, project_id: str) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = [dict(row) for row in conn.execute("SELECT * FROM messages WHERE project_id=? ORDER BY created_at,id", (project_id,))]
            for row in rows:
                row["attachment_ids"] = [r["file_id"] for r in conn.execute("SELECT file_id FROM message_attachments WHERE message_id=? ORDER BY file_id", (row["id"],))]
            return rows

    def add_session(self, session: dict[str, Any]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO sessions(id,token_digest,csrf_digest,created_at,last_seen,expires_at,revoked_at) VALUES(?,?,?,?,?,?,NULL)",
                tuple(session[k] for k in ("id", "token_digest", "csrf_digest", "created_at", "last_seen", "expires_at")),
            )

    def session(self, token_digest: str, now: float) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE token_digest=? AND revoked_at IS NULL AND expires_at>?",
                (token_digest, now),
            ).fetchone()
            if row is None:
                return None
            conn.execute("UPDATE sessions SET last_seen=? WHERE id=?", (now, row["id"]))
            return dict(row)

    def rotate_csrf(self, session_id: str, csrf_digest: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("UPDATE sessions SET csrf_digest=? WHERE id=? AND revoked_at IS NULL", (csrf_digest, session_id))

    def revoke_session(self, session_id: str, now: float) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("UPDATE sessions SET revoked_at=? WHERE id=?", (now, session_id))

    def add_run(self, run: dict[str, Any]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO runs(id,project_id,duration_seconds,started_at,deadline,status,stopped_at,outcome) VALUES(?,?,?,?,?,?,NULL,NULL)",
                tuple(run[k] for k in ("id", "project_id", "duration_seconds", "started_at", "deadline", "status")),
            )

    def active_run(self, project_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            return self._dict(conn.execute(
                "SELECT * FROM runs WHERE project_id=? AND status IN ('starting','running','stopping') ORDER BY started_at DESC LIMIT 1",
                (project_id,),
            ).fetchone())

    def run(self, run_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            return self._dict(conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone())

    def update_run(self, run_id: str, *, status: str, stopped_at: float | None = None, outcome: str | None = None) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("UPDATE runs SET status=?, stopped_at=?, outcome=? WHERE id=?", (status, stopped_at, outcome, run_id))

    def audit(self, action: str, outcome: str, project_id: str | None = None, details: str = "{}") -> None:
        with self._lock, self._connect() as conn:
            conn.execute("INSERT INTO audit_events(action,project_id,outcome,created_at,details) VALUES(?,?,?,?,?)", (action, project_id, outcome, time.time(), details))
