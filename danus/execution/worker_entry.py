"""Absolute, isolated-mode entrypoint for one trusted Worker outer loop."""

from __future__ import annotations

import sys
import json
import os
import time
from pathlib import Path

_TRUSTED_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_TRUSTED_ROOT))

from danus.execution.loop import main  # noqa: E402
from danus.secure_io import SecureIOError, read_private_bytes  # noqa: E402


def _load_environment(path: Path) -> None:
    try:
        raw = read_private_bytes(path, minimum=2, maximum=65536)
        value = json.loads(raw)
        if (
            not isinstance(value, dict)
            or not all(
                isinstance(key, str) and key and "=" not in key and "\0" not in key
                and isinstance(item, str) and "\0" not in item
                for key, item in value.items()
            )
        ):
            raise ValueError("invalid environment map")
        # Do not inherit the user manager's environment.  The environment file
        # was written by trusted orchestration from an exact allowlist.
        os.environ.clear()
        os.environ.update(value)
        path.unlink()
    except (OSError, SecureIOError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError("Worker host environment is unavailable or unsafe") from exc


def _wait_for_boundary_ledger(worker_dir: Path, *, timeout: float = 10.0) -> None:
    """Do not enter the model-controlled loop before host identity is durable.

    ``systemd-run --service-type=exec`` proves only that this Python image was
    executed.  The controller still needs a short window to pin the service and
    slice cgroups and atomically publish their invocation/inode identity.  The
    trusted entry therefore acts as the other half of that publication barrier.
    """

    configured = os.environ.get("DANUS_BOUNDARY_LEDGER", "")
    if not configured:
        raise RuntimeError("Worker boundary ledger locator is unavailable")
    ledger = Path(configured).absolute()
    expected_worker = str(worker_dir.resolve())
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            raw = read_private_bytes(ledger, minimum=2, maximum=16384)
        except FileNotFoundError:
            time.sleep(0.01)
            continue
        except (OSError, SecureIOError) as exc:
            raise RuntimeError("Worker boundary ledger is unavailable or unsafe") from exc
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("Worker boundary ledger is malformed") from exc
        process_argv = [
            str(Path(sys.executable).absolute()), "-I",
            str(Path(__file__).resolve()), *sys.argv[1:],
        ]
        if (
            not isinstance(value, dict)
            or value.get("schema") != 2
            or value.get("worker_dir") != expected_worker
            or value.get("main_pid") != os.getpid()
            or value.get("worker_argv") != process_argv
        ):
            raise RuntimeError("Worker boundary ledger does not attest this process")
        return
    raise RuntimeError("Worker boundary ledger publication timed out")


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] != "--environment-file":
        print("usage: Danus Worker entry requires its host environment and Worker locator", file=sys.stderr)
        raise SystemExit(2)
    try:
        _load_environment(Path(sys.argv[2]).absolute())
        _wait_for_boundary_ledger(Path(sys.argv[3]))
    except RuntimeError:
        print("Danus Worker host boundary failed closed", file=sys.stderr)
        raise SystemExit(126)
    raise SystemExit(main(sys.argv[3]))
