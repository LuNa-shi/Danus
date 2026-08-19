"""Persistence resource-boundary regression tests."""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

from danus.web_console.store import ConsoleStore


def test_repeated_project_reads_do_not_exhaust_file_descriptors(tmp_path: Path):
    script = r"""
import resource
import sys
from pathlib import Path
from danus.web_console.store import ConsoleStore
resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
store = ConsoleStore(Path(sys.argv[1]))
for _ in range(200):
    assert store.projects() == []
print("ok")
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path / "console.sqlite3")],
        text=True,
        capture_output=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"


def test_projects_remain_visible_after_store_restart(tmp_path: Path):
    database = tmp_path / "console.sqlite3"
    first = ConsoleStore(database)
    now = time.time()
    first.add_project({
        "id": "project-1", "name": "Persistent", "runtime_name": "Persistent",
        "problem": "keep this", "roles": "high:1", "worker_model": None,
        "max_parallel_workers": 1, "created_at": now,
    })
    first.add_message({
        "id": "message-1", "project_id": "project-1", "role": "user",
        "text": "persisted message", "status": "completed", "created_at": now,
        "error": None,
    })
    first.add_main_agent_event(
        project_id="project-1", message_id="message-1",
        event_type="agent.message", payload={"detail": "persisted event"},
        created_at=now,
    )
    first.add_run({
        "id": "run-1", "project_id": "project-1", "duration_seconds": 3600,
        "started_at": now, "deadline": now + 3600, "status": "running",
    })

    restarted = ConsoleStore(database)
    projects = restarted.projects()
    assert [(project["id"], project["name"], project["problem"]) for project in projects] == [
        ("project-1", "Persistent", "keep this"),
    ]
    assert restarted.messages("project-1")[0]["text"] == "persisted message"
    assert restarted.main_agent_events("project-1")[0]["detail"] == "persisted event"
    assert restarted.active_run("project-1")["id"] == "run-1"
