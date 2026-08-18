"""The per-worker autonomous outer loop — the round driver.

Launched detached by ``danus start`` (``python -m danus.execution <worker_dir>``).
Self-contained. Each round runs ONE ``codex exec`` session
whose internal control loop (worker.md + the worker skills) drives toward a full
verified result — a round is *continue solving from persisted memory*, NOT one
increment. The round ends when codex's session ends (its stopping rule, the
per-round hard timeout, or it bails); the loop then relaunches a fresh session
that resumes from memory. Stops on the ``.stop`` flag (graceful, at a round
boundary), the project deadline, or a round backstop.

Config:
  - codex binary resolved via the shared ``danus.codex`` launcher
    (``DANUS_CODEX_BIN`` / ``CODEX_BIN`` alias / PATH);
  - all config read at CALL time from env (matches core/gateway/verify).

Env (all optional; tests inject these):
  DANUS_CODEX_BIN            codex binary (default "codex")
  DANUS_ROUND_BEAT           seconds to sleep between rounds (default 5)
  DANUS_ROUND_HARD_TIMEOUT   per-round hard timeout, seconds (default 14400 = 4h)
  DANUS_MAX_ROUNDS           round backstop, 0 = unlimited (default 0)
  DANUS_MAX_CONSEC_FAILURES  bail after this many consecutive failed rounds (default 5)
  DANUS_MAX_PARALLEL_WORKERS fallback concurrent worker-round capacity per project
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from . import layout as L
from . import scaffold
from danus import codex

_FACT_ID_RE = re.compile(r'"?fact_id"?\s*[:=]\s*"?([0-9a-f]{16})"?')


# --- the per-round prompt (continuation semantics; see worker.md) ----------- #

def kickoff(project: str, worker: str) -> str:
    return (
        f"You are worker '{worker}' on project '{project}'. Continue solving the "
        f"problem (this is a continuation round, not a fresh start).\n"
        f"1. Read TASK.md — your current assignment (which direction/subgoal is yours).\n"
        f"2. Follow AGENTS.md (worker.md) exactly — your standing contract (the adaptive "
        f"control loop, memory discipline, the fact_submit gate). Drive toward a full "
        f"verified result.\n"
        f"3. Resume from state: gm_search relevant findings + dead ends, read the fact "
        f"graph and the latest master_guidance — DO NOT restart from zero; build on what "
        f"is already there.\n"
        f"4. Keep going: assess -> pick skills adaptively -> act -> persist, repeatedly. "
        f"An open problem is not a reason to stop. Do NOT finalize prematurely.\n"
        f"5. Persist as you go: rough progress to local memory; shareable findings via "
        f"gm_add; any verified result via fact_submit."
    )


# --- config (read at call time) -------------------------------------------- #

# codex binary + model/effort defaults are resolved via the shared danus.codex
# launcher (DANUS_CODEX_BIN / DANUS_CODEX_MODEL / DANUS_CODEX_EFFORT).


# --- small helpers --------------------------------------------------------- #

def _read_role(wl: L.WorkerLayout) -> dict:
    out = {"MODEL": codex.model(),
           "REASONING_EFFORT": "high", "ROLE": "high", "DANUS_AUTHOR": wl.name}
    rp = wl.role
    if rp.exists():
        for line in rp.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    return out


def write_status(wl: L.WorkerLayout, **fields) -> None:
    """Atomic status write (so `danus status` never reads a half-written file)."""
    path = wl.status
    cur = {}
    if path.exists():
        try:
            cur = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            cur = {}
    cur.update(fields)
    cur["worker"] = wl.name
    cur["pid"] = os.getpid()
    cur["updated_at"] = time.time()
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(cur, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _deadline_passed(project_dir: Path) -> bool:
    f = project_dir / L.DEADLINE_FILE
    if not f.exists():
        return False
    try:
        return time.time() >= float(f.read_text().strip())
    except (ValueError, OSError):
        return False


def _parse_last_fact_id(log_path: Path) -> Optional[str]:
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    ids = _FACT_ID_RE.findall(text)
    return ids[-1] if ids else None


def _positive_int(value: object) -> int | None:
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _project_max_parallel_workers(project_dir: Path) -> int | None:
    meta = project_dir / "project.json"
    if meta.is_file() and not meta.is_symlink():
        try:
            data = json.loads(meta.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            data = {}
        if isinstance(data, dict):
            configured = _positive_int(data.get("max_parallel_workers"))
            if configured is not None:
                return configured
    return _positive_int(os.environ.get("DANUS_MAX_PARALLEL_WORKERS"))


def _slot_paths(project_dir: Path, capacity: int) -> list[Path]:
    if capacity == 1:
        return [project_dir / ".worker-provider.lock"]
    lock_dir = project_dir / ".worker-provider.lock.d"
    lock_dir.mkdir(mode=0o700, exist_ok=True)
    if lock_dir.is_symlink() or not lock_dir.is_dir():
        raise OSError("worker slot lock path is not a directory")
    return [lock_dir / f"slot-{idx}.lock" for idx in range(capacity)]


def _try_acquire_slot(paths: list[Path]) -> object | None:
    for path in paths:
        lock = open(path, "a+")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return lock
        except BlockingIOError:
            lock.close()
    return None


def _acquire_worker_slot(wl: L.WorkerLayout) -> tuple[object | None, bool]:
    """Optionally wait for one of the project's expensive-provider slots."""
    capacity = _project_max_parallel_workers(wl.project_dir)
    if capacity is None:
        return None, True
    paths = _slot_paths(wl.project_dir, capacity)
    while True:
        lock = _try_acquire_slot(paths)
        if lock is not None:
            return lock, True
        write_status(
            wl, state="queued", queue_reason="waiting for API slot",
            queued_at=time.time(), slot_capacity=capacity,
        )
        if wl.stop.exists() or wl.pause.exists() or _deadline_passed(wl.project_dir):
            return None, False
        time.sleep(1)


def _release_worker_slot(lock: object | None) -> None:
    if lock is None:
        return
    fcntl.flock(lock, fcntl.LOCK_UN)  # type: ignore[arg-type]
    lock.close()  # type: ignore[attr-defined]


def _round_error(log_path: Path, rc: int) -> Optional[str]:
    """Return a compact operator-facing reason for a failed Codex round."""
    if rc in (0, 124):
        return None
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")[-65536:]
    except OSError:
        text = ""
    if "429 Too Many Requests" in text:
        return "API rate limited (429)"
    if "MCP startup failed" in text or "handshaking with MCP server failed" in text:
        return "Danus gateway unavailable"
    if "codex binary not found" in text or rc == 127:
        return "codex binary not found"
    for line in reversed(text.splitlines()):
        clean = line.strip()
        if clean.startswith("ERROR:"):
            return clean.removeprefix("ERROR:").strip()[:240]
    return f"Codex round exited with code {rc}"


# --- one round ------------------------------------------------------------- #

class _Child:
    """Holds the running codex subprocess so the SIGTERM handler can kill it."""
    proc: "subprocess.Popen | None" = None


def run_round(wl: L.WorkerLayout, role: dict, prompt: str, log_path: Path,
              hard_timeout: int) -> int:
    """Exec one ``codex exec`` continuation session. Returns codex's rc, 124 on
    hard-timeout (terminate → wait 10s → kill), or 127 if the codex binary is
    missing."""
    wdir = wl.dir
    codex_bin = codex.resolve_bin()
    cmd = codex.exec_cmd(
        codex_bin, role["MODEL"], role["REASONING_EFFORT"],
        "-C", str(wdir),
        # on an install without .git (tarball download), codex's
        # trusted-directory check refuses to run the worker round
        "--skip-git-repo-check",
        "--dangerously-bypass-approvals-and-sandbox",
        prompt,
    )
    with open(log_path, "w", encoding="utf-8") as logf:
        try:
            _Child.proc = subprocess.Popen(
                cmd, stdout=logf, stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL, cwd=str(wdir),
                env=codex.subprocess_env(codex_bin),
            )
        except FileNotFoundError:
            logf.write(f"[worker_loop] codex binary not found: {cmd[0]}\n")
            return 127
        try:
            return _Child.proc.wait(timeout=hard_timeout if hard_timeout > 0 else None)
        except subprocess.TimeoutExpired:
            _Child.proc.terminate()
            try:
                _Child.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                _Child.proc.kill()
            logf.write(f"\n[worker_loop] round hard-timeout after {hard_timeout}s\n")
            return 124
        finally:
            _Child.proc = None


# --- the loop -------------------------------------------------------------- #

def _cleanup_pid(wl: L.WorkerLayout) -> None:
    """Remove our own PID and host identity records on clean exit."""
    pf = wl.pid
    try:
        if pf.exists() and pf.read_text().strip() == str(os.getpid()):
            pf.unlink(missing_ok=True)
            wl.process_identity.unlink(missing_ok=True)
    except OSError:
        pass


def _wait_while_paused(wl: L.WorkerLayout) -> None:
    """Cooperatively wait at a round boundary while pause is requested."""
    wrote_status = False
    while wl.pause.exists():
        if wl.stop.exists() or _deadline_passed(wl.project_dir):
            return
        if not wrote_status:
            write_status(
                wl,
                state="paused",
                pause_requested=True,
                paused_at=time.time(),
                next_retry_at=None,
            )
            wrote_status = True
        time.sleep(0.2)
    if wrote_status:
        write_status(
            wl,
            state="idle",
            pause_requested=False,
            resumed_at=time.time(),
        )


def main(worker_dir: str) -> int:
    wdir = Path(worker_dir).resolve()
    if not wdir.is_dir():
        print(f"worker dir not found: {wdir}", file=sys.stderr)
        return 2
    wl = L.WorkerLayout(wdir)
    project_dir = wl.project_dir
    project = wl.project
    worker = wl.name
    role = _read_role(wl)

    # Pin the worker's gateway to THIS interpreter (sys.executable = the venv
    # python danus runs on), rewritten every start: a moved/rebuilt venv is
    # picked up, and a bare `python3` on codex's PATH can never resolve the
    # gateway to a different install.
    scaffold.write_codex_config(wl)

    beat = float(os.environ.get("DANUS_ROUND_BEAT", "5"))
    hard_timeout = int(os.environ.get("DANUS_ROUND_HARD_TIMEOUT", "14400"))
    max_rounds = int(os.environ.get("DANUS_MAX_ROUNDS", "0"))
    max_fail = int(os.environ.get("DANUS_MAX_CONSEC_FAILURES", "5"))
    wl.logs.mkdir(parents=True, exist_ok=True)
    prompt = kickoff(project, worker)

    def _on_term(signum, _frame):
        if _Child.proc is not None:
            _Child.proc.terminate()
        write_status(wl, state="terminated")
        _cleanup_pid(wl)
        sys.exit(0)

    signal.signal(signal.SIGTERM, _on_term)

    write_status(
        wl, state="running", round=0, started_at=time.time(),
        error=None, last_error=None, consecutive_failures=0,
        next_retry_at=None, last_rc=None,
    )
    rnd = 0
    consec_fail = 0
    try:
        while True:
            if wl.stop.exists():
                wl.stop.unlink(missing_ok=True)
                wl.pause.unlink(missing_ok=True)
                write_status(wl, state="stopped", pause_requested=False)
                break
            if _deadline_passed(project_dir):
                wl.pause.unlink(missing_ok=True)
                write_status(wl, state="deadline", pause_requested=False)
                break
            if wl.pause.exists():
                _wait_while_paused(wl)
                continue
            if max_rounds and rnd >= max_rounds:
                write_status(wl, state="max_rounds")
                break

            slot, can_run = _acquire_worker_slot(wl)
            if not can_run:
                continue
            rnd += 1
            log_path = wl.logs / f"round_{rnd}.log"
            write_status(
                wl, state="running", round=rnd, round_started_at=time.time(),
                queue_reason=None, queued_at=None,
            )
            try:
                rc = run_round(wl, role, prompt, log_path, hard_timeout)
            finally:
                _release_worker_slot(slot)
            last_error = _round_error(log_path, rc)
            consec_fail = consec_fail + 1 if rc not in (0, 124) else 0
            retry_delay = 0.0
            if last_error and beat > 0:
                retry_delay = min(300.0, beat * (2 ** max(0, consec_fail - 1)))
                if "429" in last_error:
                    retry_delay = max(30.0, retry_delay)
            write_status(
                wl, state="retrying" if last_error else "idle", round=rnd,
                last_round_at=time.time(),
                last_rc=rc, last_fact_id=_parse_last_fact_id(log_path),
                last_error=last_error, consecutive_failures=consec_fail,
                next_retry_at=time.time() + retry_delay if retry_delay else None,
            )

            if rc == 127:                    # codex missing — do not spin
                write_status(wl, state="error", error="codex binary not found")
                return 127
            if max_fail and consec_fail >= max_fail:
                write_status(wl, state="error", error=f"{consec_fail} consecutive failed rounds")
                return 1

            # A cooperative pause requested during the round must prevent the
            # next round immediately, before any retry/beat sleep elapses.
            if wl.pause.exists():
                continue
            delay = retry_delay or beat
            if delay > 0:
                time.sleep(delay)
    finally:
        _cleanup_pid(wl)
    return 0
