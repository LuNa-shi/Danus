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
