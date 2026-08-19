"""SQLite persistence owned by the Web Console control plane."""
from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
import threading
import time
from pathlib import Path
from typing import Any


class ConsoleStore:
    MAIN_AGENT_EVENT_RETENTION = 5000

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.RLock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            # Destructive Replace clears contaminated conversation text. Ask
            # SQLite to overwrite deleted cells instead of retaining recoverable
            # payload fragments on freelist pages.
            conn.execute("PRAGMA secure_delete = ON")
            with conn:
                yield conn
        finally:
            conn.close()

    def _initialize(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, runtime_name TEXT NOT NULL UNIQUE,
                    problem TEXT NOT NULL, roles TEXT NOT NULL DEFAULT 'high:3,xhigh:4',
                    worker_model TEXT, max_parallel_workers INTEGER NOT NULL DEFAULT 1,
                    initial_direction_confirmed_at REAL, created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS files (
                    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    logical_name TEXT NOT NULL, content_type TEXT NOT NULL, kind TEXT NOT NULL,
                    size INTEGER NOT NULL, sha256 TEXT NOT NULL, storage_name TEXT NOT NULL,
                    staging_name TEXT,
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
                CREATE TABLE IF NOT EXISTS main_agent_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                    event_type TEXT NOT NULL, payload TEXT NOT NULL, created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY, token_digest TEXT NOT NULL UNIQUE, csrf_digest TEXT NOT NULL,
                    created_at REAL NOT NULL, last_seen REAL NOT NULL, expires_at REAL NOT NULL, revoked_at REAL
                );
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    duration_seconds INTEGER NOT NULL, started_at REAL NOT NULL, deadline REAL NOT NULL,
                    status TEXT NOT NULL, stopped_at REAL, outcome TEXT,
                    start_attempt_generation INTEGER NOT NULL DEFAULT 0,
                    start_attempt_outcome TEXT
                );
                CREATE TABLE IF NOT EXISTS login_attempts (
                    key TEXT PRIMARY KEY, failures INTEGER NOT NULL, locked_until REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, project_id TEXT,
                    outcome TEXT NOT NULL, created_at REAL NOT NULL, details TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS orchestration_beat_state (
                    project_id TEXT PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
                    fingerprint TEXT NOT NULL, status TEXT NOT NULL, reason TEXT NOT NULL,
                    last_beat_at REAL NOT NULL, last_consult_at REAL NOT NULL,
                    last_summary_at REAL NOT NULL, updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS artifact_confirmation_intents (
                    id TEXT PRIMARY KEY,
                    token_digest TEXT NOT NULL UNIQUE,
                    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    action TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    payload_digest TEXT NOT NULL,
                    actor_session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    dispatched_at REAL,
                    consumed_at REAL,
                    execution_status TEXT NOT NULL DEFAULT 'pending',
                    completed_at REAL,
                    outcome_code TEXT
                );
                CREATE TABLE IF NOT EXISTS file_cleanup_queue (
                    id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    file_id TEXT NOT NULL,
                    quarantine_name TEXT NOT NULL,
                    original_storage_name TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    completed_at REAL,
                    last_error TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_runs_project_status ON runs(project_id, status);
                CREATE INDEX IF NOT EXISTS idx_main_agent_events_project_id ON main_agent_events(project_id, id);
                CREATE INDEX IF NOT EXISTS idx_artifact_confirmation_pending
                    ON artifact_confirmation_intents(project_id, expires_at, consumed_at);
                CREATE INDEX IF NOT EXISTS idx_file_cleanup_pending
                    ON file_cleanup_queue(project_id, completed_at);
                """
            )
            columns = {row[1] for row in conn.execute("PRAGMA table_info(main_agent_sessions)")}
            if "session_id" not in columns:
                conn.execute("ALTER TABLE main_agent_sessions ADD COLUMN session_id TEXT")
                conn.execute("ALTER TABLE main_agent_sessions ADD COLUMN backend TEXT NOT NULL DEFAULT 'codex'")
                if "claude_session_id" in columns:
                    conn.execute("UPDATE main_agent_sessions SET session_id=claude_session_id WHERE session_id IS NULL")
            project_columns = {row[1] for row in conn.execute("PRAGMA table_info(projects)")}
            if "roles" not in project_columns:
                conn.execute("ALTER TABLE projects ADD COLUMN roles TEXT NOT NULL DEFAULT 'high:3,xhigh:4'")
            if "worker_model" not in project_columns:
                conn.execute("ALTER TABLE projects ADD COLUMN worker_model TEXT")
            if "max_parallel_workers" not in project_columns:
                conn.execute("ALTER TABLE projects ADD COLUMN max_parallel_workers INTEGER NOT NULL DEFAULT 1")
            if "initial_direction_confirmed_at" not in project_columns:
                conn.execute("ALTER TABLE projects ADD COLUMN initial_direction_confirmed_at REAL")
            run_columns = {row[1] for row in conn.execute("PRAGMA table_info(runs)")}
            if "start_attempt_generation" not in run_columns:
                conn.execute(
                    "ALTER TABLE runs ADD COLUMN start_attempt_generation INTEGER NOT NULL DEFAULT 0"
                )
            if "start_attempt_outcome" not in run_columns:
                conn.execute("ALTER TABLE runs ADD COLUMN start_attempt_outcome TEXT")
            file_columns = {row[1] for row in conn.execute("PRAGMA table_info(files)")}
            if "staging_name" not in file_columns:
                conn.execute("ALTER TABLE files ADD COLUMN staging_name TEXT")

    @staticmethod
    def _dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
        return dict(row) if row is not None else None

    def add_project(self, project: dict[str, Any]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO projects(id,name,runtime_name,problem,roles,worker_model,max_parallel_workers,initial_direction_confirmed_at,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    project["id"], project["name"], project["runtime_name"], project["problem"],
                    project.get("roles") or "high:3,xhigh:4",
                    project.get("worker_model") or project.get("model"),
                    int(project.get("max_parallel_workers") or 1),
                    project.get("initial_direction_confirmed_at"),
                    project["created_at"],
                ),
            )

    def project(self, project_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            return self._dict(conn.execute("SELECT * FROM projects WHERE id=?", (project_id,)).fetchone())

    def confirm_initial_direction(self, project_id: str, confirmed_at: float) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE projects SET initial_direction_confirmed_at=COALESCE(initial_direction_confirmed_at, ?) WHERE id=?",
                (confirmed_at, project_id),
            )

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
                "INSERT INTO files(id,project_id,logical_name,content_type,kind,size,sha256,storage_name,staging_name,version,is_current,processing_status,read_status,uploaded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    *(file[k] for k in (
                        "id", "project_id", "logical_name", "content_type", "kind",
                        "size", "sha256", "storage_name",
                    )),
                    file.get("staging_name"),
                    *(file[k] for k in (
                        "version", "is_current", "processing_status", "read_status",
                        "uploaded_at",
                    )),
                ),
            )

    def add_file_conflict(self, file: dict[str, Any], conflict: dict[str, Any]) -> None:
        if not file.get("staging_name") or file.get("processing_status") != "pending":
            raise sqlite3.IntegrityError("pending conflict requires private staging")
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO files(id,project_id,logical_name,content_type,kind,size,sha256,storage_name,staging_name,version,is_current,processing_status,read_status,uploaded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    *(file[k] for k in (
                        "id", "project_id", "logical_name", "content_type", "kind",
                        "size", "sha256", "storage_name",
                    )),
                    file["staging_name"],
                    *(file[k] for k in (
                        "version", "is_current", "processing_status", "read_status",
                        "uploaded_at",
                    )),
                ),
            )
            conn.execute(
                "INSERT INTO file_conflicts(id,project_id,logical_name,incoming_file_id,current_file_id,created_at,status) VALUES(?,?,?,?,?,?,?)",
                tuple(conflict[key] for key in (
                    "id", "project_id", "logical_name", "incoming_file_id",
                    "current_file_id", "created_at", "status",
                )),
            )

    def files(self, project_id: str, logical_name: str | None = None) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            if logical_name is None:
                rows = conn.execute("SELECT * FROM files WHERE project_id=? AND processing_status='available' ORDER BY logical_name, version", (project_id,))
            else:
                rows = conn.execute("SELECT * FROM files WHERE project_id=? AND logical_name=? AND processing_status='available' ORDER BY version", (project_id, logical_name))
            return [dict(row) for row in rows]

    def file(self, file_id: str, project_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            return self._dict(conn.execute("SELECT * FROM files WHERE id=? AND project_id=?", (file_id, project_id)).fetchone())

    def selectable_file(self, file_id: str, project_id: str) -> dict[str, Any] | None:
        """Return only a durable external-material version eligible as input."""
        with self._lock, self._connect() as conn:
            return self._dict(conn.execute(
                "SELECT * FROM files WHERE id=? AND project_id=? AND processing_status='available'",
                (file_id, project_id),
            ).fetchone())

    def file_by_hash(self, project_id: str, sha256: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            return self._dict(conn.execute("SELECT * FROM files WHERE project_id=? AND sha256=? AND processing_status IN ('available','pending')", (project_id, sha256)).fetchone())

    def file_storage_names(self, project_id: str) -> set[str]:
        with self._lock, self._connect() as conn:
            return {
                str(row["storage_name"])
                for row in conn.execute(
                    "SELECT storage_name FROM files WHERE project_id=?",
                    (project_id,),
                )
            }

    def file_tombstone_by_hash(self, project_id: str, sha256: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            return self._dict(conn.execute("SELECT * FROM files WHERE project_id=? AND sha256=? AND processing_status IN ('cancelled','replaced','deleting')", (project_id, sha256)).fetchone())

    def purge_file_tombstone(self, file_id: str, project_id: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM files WHERE id=? AND project_id=? AND processing_status IN ('cancelled','replaced') AND NOT EXISTS (SELECT 1 FROM message_attachments WHERE file_id=files.id)", (file_id, project_id))

    def current_file(self, project_id: str, logical_name: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            return self._dict(conn.execute("SELECT * FROM files WHERE project_id=? AND logical_name=? AND is_current=1 AND processing_status='available'", (project_id, logical_name)).fetchone())

    def pending_conflict(self, project_id: str, logical_name: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            return self._dict(conn.execute(
                "SELECT * FROM file_conflicts WHERE project_id=? AND logical_name=? AND status='pending' ORDER BY created_at LIMIT 1",
                (project_id, logical_name),
            ).fetchone())

    def has_pending_file_conflicts(self, project_id: str) -> bool:
        with self._lock, self._connect() as conn:
            return conn.execute(
                "SELECT 1 FROM file_conflicts WHERE project_id=? AND status='pending' LIMIT 1",
                (project_id,),
            ).fetchone() is not None

    def project_maintenance_reason(self, project_id: str) -> str | None:
        """Return the durable condition that must block Project activity."""
        with self._lock, self._connect() as conn:
            if conn.execute(
                "SELECT 1 FROM file_conflicts WHERE project_id=? AND status='pending' LIMIT 1",
                (project_id,),
            ).fetchone() is not None:
                return "pending_file_conflict"
            if conn.execute(
                "SELECT 1 FROM files WHERE project_id=? AND processing_status='pending' LIMIT 1",
                (project_id,),
            ).fetchone() is not None:
                return "pending_file_reservation"
            if conn.execute(
                "SELECT 1 FROM file_cleanup_queue WHERE project_id=? AND completed_at IS NULL LIMIT 1",
                (project_id,),
            ).fetchone() is not None:
                return "file_cleanup_pending"
            if conn.execute(
                "SELECT 1 FROM files WHERE project_id=? "
                "AND processing_status IN ('deleting','cancelled','replaced') LIMIT 1",
                (project_id,),
            ).fetchone() is not None:
                return "file_cleanup_tombstone"
            return None

    def pending_conflict_files(self, project_id: str | None = None) -> list[dict[str, Any]]:
        query = (
            "SELECT f.*,c.id AS conflict_id,p.runtime_name FROM files f "
            "JOIN file_conflicts c ON c.incoming_file_id=f.id AND c.project_id=f.project_id "
            "JOIN projects p ON p.id=f.project_id WHERE c.status='pending'"
        )
        parameters: tuple[Any, ...] = ()
        if project_id is not None:
            query += " AND f.project_id=?"
            parameters = (project_id,)
        query += " ORDER BY f.project_id,f.uploaded_at,f.id"
        with self._lock, self._connect() as conn:
            return [dict(row) for row in conn.execute(query, parameters)]

    def set_pending_staging_name(
        self, file_id: str, project_id: str, staging_name: str | None,
    ) -> bool:
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                "UPDATE files SET staging_name=? WHERE id=? AND project_id=? "
                "AND processing_status='pending' AND EXISTS ("
                "SELECT 1 FROM file_conflicts c WHERE c.incoming_file_id=files.id "
                "AND c.project_id=files.project_id AND c.status='pending')",
                (staging_name, file_id, project_id),
            )
            return cursor.rowcount == 1

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

    def normalize_pending_conflict_files(self) -> int:
        """Hide incoming rows created by pre-migration conflict handling."""
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                "UPDATE files SET processing_status='pending',is_current=0 "
                "WHERE processing_status='available' AND id IN ("
                "SELECT incoming_file_id FROM file_conflicts WHERE status='pending')"
            )
            return int(cursor.rowcount)

    def file_message_ids(self, file_id: str, project_id: str) -> list[str]:
        with self._lock, self._connect() as conn:
            return [str(row["message_id"]) for row in conn.execute(
                "SELECT ma.message_id FROM message_attachments ma "
                "JOIN messages m ON m.id=ma.message_id "
                "WHERE ma.file_id=? AND m.project_id=? ORDER BY ma.message_id",
                (file_id, project_id),
            )]

    def resolve_new_version(
        self, conflict_id: str, project_id: str, *, staging_name: str,
    ) -> dict[str, Any]:
        with self._lock, self._connect() as conn:
            conflict = conn.execute(
                "SELECT * FROM file_conflicts WHERE id=? AND project_id=? AND status='pending'",
                (conflict_id, project_id),
            ).fetchone()
            if conflict is None:
                raise sqlite3.IntegrityError("file conflict is no longer pending")
            incoming = conn.execute(
                "SELECT * FROM files WHERE id=? AND project_id=? AND processing_status IN ('pending','available')",
                (conflict["incoming_file_id"], project_id),
            ).fetchone()
            if incoming is None:
                raise sqlite3.IntegrityError("incoming file is unavailable")
            if incoming["staging_name"] != staging_name:
                raise sqlite3.IntegrityError("incoming staging locator changed")
            conn.execute(
                "UPDATE files SET is_current=0 WHERE project_id=? AND logical_name=?",
                (project_id, conflict["logical_name"]),
            )
            conn.execute(
                "UPDATE files SET is_current=1,processing_status='available',staging_name=NULL WHERE id=? AND project_id=?",
                (incoming["id"], project_id),
            )
            conn.execute("UPDATE file_conflicts SET status='new_version' WHERE id=?", (conflict_id,))
            resolved = dict(conn.execute(
                "SELECT * FROM files WHERE id=?", (incoming["id"],),
            ).fetchone())
            conn.execute(
                "INSERT INTO audit_events(action,project_id,outcome,created_at,details) "
                "VALUES('file_conflict',?,'new_version',?,?)",
                (
                    project_id, time.time(), json.dumps({
                        "choice": "new_version", "file_id": resolved["id"],
                        "filename": resolved["logical_name"],
                        "version": resolved["version"], "sha256": resolved["sha256"],
                        "size": resolved["size"],
                    }, sort_keys=True),
                ),
            )
            return resolved

    def resolve_destructive_conflict(
        self, conflict_id: str, project_id: str, *, choice: str,
        cleanup: dict[str, Any], staging_name: str | None = None,
    ) -> dict[str, Any] | None:
        """Commit cancel/replace metadata changes and a durable cleanup job atomically."""
        if choice not in {"cancel", "replace"}:
            raise ValueError("invalid destructive conflict choice")
        with self._lock, self._connect() as conn:
            conflict = conn.execute(
                "SELECT * FROM file_conflicts WHERE id=? AND project_id=? AND status='pending'",
                (conflict_id, project_id),
            ).fetchone()
            if conflict is None:
                raise sqlite3.IntegrityError("file conflict is no longer pending")
            incoming = conn.execute(
                "SELECT * FROM files WHERE id=? AND project_id=?",
                (conflict["incoming_file_id"], project_id),
            ).fetchone()
            existing = conn.execute(
                "SELECT * FROM files WHERE id=? AND project_id=?",
                (conflict["current_file_id"], project_id),
            ).fetchone()
            if incoming is None or existing is None:
                raise sqlite3.IntegrityError("file conflict rows are unavailable")
            if choice == "replace" and incoming["staging_name"] != staging_name:
                raise sqlite3.IntegrityError("incoming staging locator changed")
            target = incoming if choice == "cancel" else existing
            if target["storage_name"] != cleanup["original_storage_name"]:
                raise sqlite3.IntegrityError("cleanup target does not match conflict")
            message_ids = [str(row["message_id"]) for row in conn.execute(
                "SELECT message_id FROM message_attachments WHERE file_id=? ORDER BY message_id",
                (target["id"],),
            )]
            conn.execute(
                "INSERT INTO file_cleanup_queue(id,project_id,file_id,quarantine_name,original_storage_name,reason,created_at,completed_at,last_error) "
                "VALUES(?,?,?,?,?,?,?,NULL,NULL)",
                (cleanup["id"], project_id, target["id"], cleanup["quarantine_name"], cleanup["original_storage_name"], choice, cleanup["created_at"]),
            )
            conn.execute(
                "INSERT INTO audit_events(action,project_id,outcome,created_at,details) VALUES(?,?,?,?,?)",
                (
                    "file_conflict", project_id, "committed", cleanup["created_at"],
                    json.dumps({
                        "choice": choice, "file_id": target["id"],
                        "filename": target["logical_name"], "version": target["version"],
                        "sha256": target["sha256"], "size": target["size"],
                        "detached_message_ids": message_ids,
                        "replacement_file_id": incoming["id"] if choice == "replace" else None,
                        "cleanup_id": cleanup["id"],
                    }, sort_keys=True),
                ),
            )

            if choice == "cancel":
                conn.execute("DELETE FROM message_attachments WHERE file_id=?", (incoming["id"],))
                conn.execute("DELETE FROM file_conflicts WHERE id=?", (conflict_id,))
                conn.execute(
                    "UPDATE files SET is_current=0,processing_status='deleting' WHERE id=? AND project_id=?",
                    (incoming["id"], project_id),
                )
                return None
            # Every Main-Agent turn receives the complete material manifest and
            # may inspect any available blob without explicitly attaching it to
            # a message.  Consequently there is no sound per-message test for
            # whether the old bytes contaminated the provider conversation.
            # Destructive Replace must always start a clean conversation.
            conversation_reset = True
            invalidated_intent_ids = [str(row["id"]) for row in conn.execute(
                "SELECT id FROM artifact_confirmation_intents WHERE project_id=? "
                "AND execution_status IN ('pending','dispatched','running') ORDER BY created_at,id",
                (project_id,),
            )]
            conn.execute(
                "UPDATE artifact_confirmation_intents SET execution_status='failed',"
                "completed_at=?,outcome_code='replaced_input_invalidated' "
                "WHERE project_id=? AND execution_status IN ('pending','dispatched','running')",
                (cleanup["created_at"], project_id),
            )
            purged_message_ids = [str(row["id"]) for row in conn.execute(
                "SELECT id FROM messages WHERE project_id=? ORDER BY created_at,id",
                (project_id,),
            )]
            conn.execute("DELETE FROM messages WHERE project_id=?", (project_id,))
            conn.execute(
                "UPDATE main_agent_sessions SET session_id=NULL,status='inactive',updated_at=? WHERE project_id=?",
                (cleanup["created_at"], project_id),
            )
            conn.execute(
                "INSERT INTO audit_events(action,project_id,outcome,created_at,details) VALUES(?,?,?,?,?)",
                (
                    "file_replace_conversation_purge", project_id, "success",
                    cleanup["created_at"], json.dumps({
                        "file_id": existing["id"], "filename": existing["logical_name"],
                        "version": existing["version"], "sha256": existing["sha256"],
                        "size": existing["size"], "detached_message_ids": message_ids,
                        "purged_message_ids": purged_message_ids,
                        "provider_session_reset": True,
                    }, sort_keys=True),
                ),
            )
            conn.execute("DELETE FROM message_attachments WHERE file_id=?", (existing["id"],))
            conn.execute("DELETE FROM file_conflicts WHERE id=?", (conflict_id,))
            conn.execute(
                "UPDATE files SET is_current=0,processing_status='deleting' WHERE id=? AND project_id=?",
                (existing["id"], project_id),
            )
            conn.execute(
                "UPDATE files SET is_current=0 WHERE project_id=? AND logical_name=?",
                (project_id, conflict["logical_name"]),
            )
            conn.execute(
                "UPDATE files SET is_current=1,processing_status='available',staging_name=NULL WHERE id=? AND project_id=?",
                (incoming["id"], project_id),
            )
            row = dict(conn.execute("SELECT * FROM files WHERE id=?", (incoming["id"],)).fetchone())
            row["replaced_file"] = dict(existing)
            row["detached_message_ids"] = message_ids
            row["conversation_reset"] = conversation_reset
            row["purged_message_ids"] = purged_message_ids
            row["invalidated_artifact_intent_ids"] = invalidated_intent_ids
            return row

    def finalize_ordinary_file(
        self, file_id: str, project_id: str, *, staging_name: str,
    ) -> dict[str, Any]:
        """Publish one pre-reserved ordinary upload after durable promotion."""
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                "UPDATE files SET is_current=1,processing_status='available',staging_name=NULL "
                "WHERE id=? AND project_id=? AND processing_status='pending' "
                "AND staging_name=? AND NOT EXISTS ("
                "SELECT 1 FROM file_conflicts c WHERE c.incoming_file_id=files.id "
                "AND c.project_id=files.project_id)",
                (file_id, project_id, staging_name),
            )
            if cursor.rowcount != 1:
                raise sqlite3.IntegrityError("ordinary upload reservation changed")
            row = conn.execute(
                "SELECT * FROM files WHERE id=? AND project_id=?",
                (file_id, project_id),
            ).fetchone()
            if row is None:
                raise sqlite3.IntegrityError("ordinary upload reservation disappeared")
            resolved = dict(row)
            conn.execute(
                "INSERT INTO audit_events(action,project_id,outcome,created_at,details) "
                "VALUES('file_upload',?,'success',?,?)",
                (
                    project_id, time.time(), json.dumps({
                        "file_id": resolved["id"],
                        "filename": resolved["logical_name"],
                        "version": resolved["version"], "sha256": resolved["sha256"],
                        "size": resolved["size"],
                    }, sort_keys=True),
                ),
            )
            return resolved

    def cancel_staged_conflict(
        self, conflict_id: str, project_id: str, *, staging_name: str,
        cancelled_at: float,
    ) -> dict[str, Any]:
        """Remove a conflict after its private staged bytes were erased."""
        with self._lock, self._connect() as conn:
            conflict = conn.execute(
                "SELECT * FROM file_conflicts WHERE id=? AND project_id=? AND status='pending'",
                (conflict_id, project_id),
            ).fetchone()
            if conflict is None:
                raise sqlite3.IntegrityError("file conflict is no longer pending")
            incoming = conn.execute(
                "SELECT * FROM files WHERE id=? AND project_id=? AND processing_status='pending'",
                (conflict["incoming_file_id"], project_id),
            ).fetchone()
            if incoming is None or incoming["staging_name"] != staging_name:
                raise sqlite3.IntegrityError("incoming staging locator changed")
            row = dict(incoming)
            conn.execute("DELETE FROM message_attachments WHERE file_id=?", (incoming["id"],))
            conn.execute("DELETE FROM file_conflicts WHERE id=?", (conflict_id,))
            conn.execute(
                "DELETE FROM files WHERE id=? AND project_id=? AND processing_status='pending'",
                (incoming["id"], project_id),
            )
            conn.execute(
                "INSERT INTO audit_events(action,project_id,outcome,created_at,details) VALUES(?,?,?,?,?)",
                (
                    "file_conflict", project_id, "committed", cancelled_at,
                    json.dumps({
                        "choice": "cancel", "file_id": incoming["id"],
                        "filename": incoming["logical_name"],
                        "version": incoming["version"], "sha256": incoming["sha256"],
                        "size": incoming["size"],
                    }, sort_keys=True),
                ),
            )
            return row

    def purge_broken_pending_conflict(self, conflict_id: str, project_id: str) -> None:
        with self._lock, self._connect() as conn:
            conflict = conn.execute(
                "SELECT incoming_file_id FROM file_conflicts "
                "WHERE id=? AND project_id=? AND status='pending'",
                (conflict_id, project_id),
            ).fetchone()
            if conflict is None:
                return
            conn.execute("DELETE FROM file_conflicts WHERE id=?", (conflict_id,))
            conn.execute("DELETE FROM message_attachments WHERE file_id=?", (conflict["incoming_file_id"],))
            conn.execute(
                "DELETE FROM files WHERE id=? AND project_id=? AND processing_status='pending'",
                (conflict["incoming_file_id"], project_id),
            )

    def file_cleanup_jobs(self, project_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            if project_id is None:
                rows = conn.execute("SELECT * FROM file_cleanup_queue WHERE completed_at IS NULL ORDER BY created_at,id")
            else:
                rows = conn.execute(
                    "SELECT * FROM file_cleanup_queue WHERE project_id=? AND completed_at IS NULL ORDER BY created_at,id",
                    (project_id,),
                )
            return [dict(row) for row in rows]

    def complete_file_cleanup(self, cleanup_id: str, *, completed_at: float) -> None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT file_id,project_id FROM file_cleanup_queue WHERE id=? AND completed_at IS NULL",
                (cleanup_id,),
            ).fetchone()
            if row is None:
                return
            conn.execute(
                "DELETE FROM files WHERE id=? AND project_id=? AND processing_status='deleting'",
                (row["file_id"], row["project_id"]),
            )
            conn.execute(
                "UPDATE file_cleanup_queue SET completed_at=?,last_error=NULL WHERE id=? AND completed_at IS NULL",
                (completed_at, cleanup_id),
            )

    def fail_file_cleanup(self, cleanup_id: str, error: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE file_cleanup_queue SET last_error=? WHERE id=? AND completed_at IS NULL",
                (str(error)[:200], cleanup_id),
            )

    def legacy_file_tombstones(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            return [dict(row) for row in conn.execute(
                "SELECT f.*,p.runtime_name FROM files f JOIN projects p ON p.id=f.project_id "
                "WHERE f.processing_status IN ('cancelled','replaced') ORDER BY f.project_id,f.uploaded_at,f.id"
            )]

    def orphan_pending_files(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            return [dict(row) for row in conn.execute(
                "SELECT f.*,p.runtime_name FROM files f JOIN projects p ON p.id=f.project_id "
                "WHERE f.processing_status='pending' AND NOT EXISTS ("
                "SELECT 1 FROM file_conflicts c WHERE c.incoming_file_id=f.id AND c.status='pending') "
                "ORDER BY f.project_id,f.uploaded_at,f.id"
            )]

    def purge_orphan_pending_file(self, file_id: str, project_id: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM message_attachments WHERE file_id=?", (file_id,))
            conn.execute(
                "DELETE FROM files WHERE id=? AND project_id=? AND processing_status='pending' "
                "AND NOT EXISTS (SELECT 1 FROM file_conflicts c WHERE c.incoming_file_id=files.id AND c.status='pending')",
                (file_id, project_id),
            )

    def purge_legacy_file_tombstone(self, file_id: str, project_id: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM message_attachments WHERE file_id=?", (file_id,))
            conn.execute(
                "DELETE FROM file_conflicts WHERE project_id=? AND (incoming_file_id=? OR current_file_id=?)",
                (project_id, file_id, file_id),
            )
            conn.execute(
                "DELETE FROM files WHERE id=? AND project_id=? AND processing_status IN ('cancelled','replaced')",
                (file_id, project_id),
            )

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

    def add_artifact_confirmation_intent(self, intent: dict[str, Any]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO artifact_confirmation_intents("
                "id,token_digest,project_id,action,payload_json,payload_digest,actor_session_id,created_at,expires_at,dispatched_at,consumed_at,execution_status,completed_at,outcome_code"
                ") VALUES(?,?,?,?,?,?,?,?,?,NULL,NULL,'pending',NULL,NULL)",
                tuple(intent[key] for key in (
                    "id", "token_digest", "project_id", "action", "payload_json", "payload_digest",
                    "actor_session_id", "created_at", "expires_at",
                )),
            )

    def dispatch_artifact_confirmation_intent(
        self, intent_id: str, project_id: str, actor_session_id: str, *, now: float,
    ) -> dict[str, Any] | None:
        """Bind a pending operator intent to exactly one Main-Agent turn."""
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                "UPDATE artifact_confirmation_intents SET dispatched_at=?,execution_status='dispatched' "
                "WHERE id=? AND project_id=? AND actor_session_id=? "
                "AND dispatched_at IS NULL AND consumed_at IS NULL AND execution_status='pending' AND expires_at>?",
                (now, intent_id, project_id, actor_session_id, now),
            )
            if cursor.rowcount != 1:
                return None
            return self._dict(conn.execute(
                "SELECT * FROM artifact_confirmation_intents WHERE id=?", (intent_id,),
            ).fetchone())

    def consume_artifact_confirmation(
        self, token_digest: str, project_id: str, action: str,
        payload_digest: str, *, now: float,
    ) -> str:
        """Atomically consume one dispatched, unexpired, payload-bound proof."""
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM artifact_confirmation_intents WHERE token_digest=?",
                (token_digest,),
            ).fetchone()
            if row is None or row["project_id"] != project_id:
                return "invalid"
            if row["action"] != action or row["payload_digest"] != payload_digest:
                return "mismatch"
            if row["consumed_at"] is not None:
                return "replay"
            session = conn.execute(
                "SELECT id,revoked_at,expires_at FROM sessions WHERE id=?",
                (row["actor_session_id"],),
            ).fetchone()
            if session is None or session["revoked_at"] is not None:
                return "invalid"
            if row["expires_at"] <= now or session["expires_at"] <= now:
                return "expired"
            if row["dispatched_at"] is None:
                return "invalid"
            cursor = conn.execute(
                "UPDATE artifact_confirmation_intents SET consumed_at=?,execution_status='running' "
                "WHERE token_digest=? AND project_id=? AND action=? AND payload_digest=? "
                "AND dispatched_at IS NOT NULL AND consumed_at IS NULL AND execution_status='dispatched' AND expires_at>? "
                "AND EXISTS (SELECT 1 FROM sessions s WHERE s.id=actor_session_id "
                "AND s.revoked_at IS NULL AND s.expires_at>?)",
                (now, token_digest, project_id, action, payload_digest, now, now),
            )
            return "consumed" if cursor.rowcount == 1 else "replay"

    def complete_artifact_confirmation(
        self, token_digest: str, *, succeeded: bool, outcome_code: str,
        completed_at: float,
    ) -> bool:
        status = "succeeded" if succeeded else "failed"
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                "UPDATE artifact_confirmation_intents SET execution_status=?,completed_at=?,outcome_code=? "
                "WHERE token_digest=? AND execution_status='running' AND consumed_at IS NOT NULL",
                (status, completed_at, str(outcome_code)[:80], token_digest),
            )
            return cursor.rowcount == 1

    def fail_dispatched_artifact_intent(
        self, intent_id: str, project_id: str, *, outcome_code: str,
        completed_at: float,
    ) -> bool:
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                "UPDATE artifact_confirmation_intents SET execution_status='failed',completed_at=?,outcome_code=? "
                "WHERE id=? AND project_id=? AND execution_status IN ('pending','dispatched')",
                (completed_at, str(outcome_code)[:80], intent_id, project_id),
            )
            return cursor.rowcount == 1

    def artifact_confirmation_intent(self, intent_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            return self._dict(conn.execute(
                "SELECT * FROM artifact_confirmation_intents WHERE id=?", (intent_id,),
            ).fetchone())

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

    def add_main_agent_event(self, *, project_id: str, message_id: str,
                             event_type: str, payload: dict[str, Any],
                             created_at: float | None = None) -> int:
        from .protocol import EventKind
        allowed = {kind.value for kind in EventKind}
        if event_type not in allowed:
            raise ValueError("unknown Main Agent event kind")
        if not isinstance(payload, dict) or len(payload) > 32:
            raise ValueError("invalid Main Agent event payload")
        payload = {str(key)[:80]: value for key, value in payload.items()}
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        if len(encoded) > 12000:
            raise ValueError("Main Agent event payload too large")
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO main_agent_events(project_id,message_id,event_type,payload,created_at) VALUES(?,?,?,?,?)",
                (project_id, message_id, event_type,
                 encoded,
                 created_at if created_at is not None else time.time()),
            )
            event_id = int(cursor.lastrowid)
            conn.execute(
                "DELETE FROM main_agent_events WHERE project_id=? AND id IN ("
                "SELECT id FROM main_agent_events WHERE project_id=? "
                "ORDER BY id DESC LIMIT -1 OFFSET ?)",
                (project_id, project_id, max(1, int(self.MAIN_AGENT_EVENT_RETENTION))),
            )
            return event_id

    def main_agent_events(self, project_id: str, *, after_id: int = 0,
                          limit: int = 1000) -> list[dict[str, Any]]:
        bounded_limit = max(1, min(1000, int(limit)))
        with self._lock, self._connect() as conn:
            if int(after_id) > 0:
                rows = conn.execute(
                    "SELECT id,message_id,event_type,payload,created_at "
                    "FROM main_agent_events WHERE project_id=? AND id>? ORDER BY id LIMIT ?",
                    (project_id, int(after_id), bounded_limit),
                ).fetchall()
            else:
                rows = list(reversed(conn.execute(
                    "SELECT id,message_id,event_type,payload,created_at "
                    "FROM main_agent_events WHERE project_id=? ORDER BY id DESC LIMIT ?",
                    (project_id, bounded_limit),
                ).fetchall()))
        events = []
        for row in rows:
            try:
                payload = json.loads(row["payload"])
            except (json.JSONDecodeError, TypeError):
                payload = {}
            events.append({
                "id": int(row["id"]), "message_id": row["message_id"],
                "type": row["event_type"], "created_at": row["created_at"],
                **(payload if isinstance(payload, dict) else {}),
            })
        return events

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

    def begin_start_attempt(self, run_id: str) -> int | None:
        """Atomically mark a Main Agent broker start attempt and return its generation."""
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                "UPDATE runs SET start_attempt_generation=start_attempt_generation+1, "
                "start_attempt_outcome='attempting' WHERE id=? AND status='starting'",
                (run_id,),
            )
            if cursor.rowcount != 1:
                return None
            row = conn.execute(
                "SELECT start_attempt_generation FROM runs WHERE id=?", (run_id,)
            ).fetchone()
            return int(row["start_attempt_generation"]) if row is not None else None

    def complete_start_attempt(
        self,
        run_id: str,
        generation: int,
        *,
        attempt_outcome: str,
        status: str,
        outcome: str,
    ) -> bool:
        """Persist one broker attempt result without overwriting a newer generation."""
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                "UPDATE runs SET start_attempt_outcome=?,status=?,outcome=? "
                "WHERE id=? AND start_attempt_generation=?",
                (attempt_outcome, status, outcome, run_id, int(generation)),
            )
            return cursor.rowcount == 1

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

    def orchestration_beat_state(self, project_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            return self._dict(conn.execute(
                "SELECT * FROM orchestration_beat_state WHERE project_id=?", (project_id,),
            ).fetchone())

    def update_orchestration_beat_state(
        self, project_id: str, *, fingerprint: str, status: str, reason: str,
        last_beat_at: float, last_consult_at: float, last_summary_at: float,
    ) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO orchestration_beat_state(project_id,fingerprint,status,reason,last_beat_at,last_consult_at,last_summary_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(project_id) DO UPDATE SET "
                "fingerprint=excluded.fingerprint,status=excluded.status,reason=excluded.reason,last_beat_at=excluded.last_beat_at,"
                "last_consult_at=excluded.last_consult_at,last_summary_at=excluded.last_summary_at,updated_at=excluded.updated_at",
                (project_id, fingerprint, status, reason, last_beat_at, last_consult_at, last_summary_at, time.time()),
            )

    def audit(self, action: str, outcome: str, project_id: str | None = None, details: str = "{}") -> None:
        with self._lock, self._connect() as conn:
            conn.execute("INSERT INTO audit_events(action,project_id,outcome,created_at,details) VALUES(?,?,?,?,?)", (action, project_id, outcome, time.time(), details))
