"""Persistence resource-boundary regression tests."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


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
