"""The per-worker autonomous outer loop — the round driver.

Launched by the validated transient Worker service created by ``danus start``.
Self-contained. Each round runs ONE ``codex exec`` session
whose internal control loop (worker.md + the worker skills) drives toward a full
verified result — a round is *continue solving from persisted memory*, NOT one
increment. The round ends when codex's session ends (its stopping rule, the
per-round hard timeout, or it bails); the loop then relaunches a fresh session
that resumes from memory. Stops on the ``.stop`` flag (graceful, at a round
boundary), the project deadline, or a round backstop.

Config:
  - the selected codex binary must resolve to the provisioned official runtime;
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

import base64
import codecs
import fcntl
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import BinaryIO, Iterable, Mapping, Optional, TextIO
from urllib.parse import quote_from_bytes

from . import layout as L
from . import scaffold
from . import security
from . import systemd_scope
from danus import codex
from danus.host_isolation import protect_host_process_secrets
from danus.secure_io import SecureIOError, read_private_bytes, secure_open_text

_FACT_ID_RE = re.compile(r'"?fact_id"?\s*[:=]\s*"?([0-9a-f]{16})"?')
_PROVIDER_LOG_SECRET_ENV = (
    "OPENAI_API_KEY",
    "DANUS_CODEX_API_KEY",
    "OPENAI_BASE_URL",
    "CODEX_API_BASE_URL",
    "OPENAI_CHATGPT_BASE_URL",
    "CODEX_CHATGPT_BASE_URL",
)
_AUTH_FILE_LIMIT = 1 << 20
_REDACTION_MARKER = b"[REDACTED]"


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
    return f"Codex round exited with code {rc}"


def _auth_string_values(value: object, *, token_context: bool = False) -> set[str]:
    """Return credential-like strings from one bounded ``auth.json`` value.

    Codex has changed the precise subscription-auth schema over time. Named
    token/key/secret containers are authoritative, while long strings are
    conservatively treated as credentials so a new token field cannot silently
    become loggable.
    """

    values: set[str] = set()
    if isinstance(value, str):
        if value and (token_context or len(value) >= 16):
            values.add(value)
    elif isinstance(value, list):
        for item in value:
            values.update(_auth_string_values(item, token_context=token_context))
    elif isinstance(value, dict):
        for key, item in value.items():
            normalized = str(key).casefold()
            sensitive = token_context or any(
                part in normalized
                for part in ("token", "secret", "credential", "password", "api_key")
            )
            values.update(_auth_string_values(item, token_context=sensitive))
    return values


def _provider_log_secrets(environment: Mapping[str, str]) -> set[str]:
    """Collect every known provider credential/endpoint before it can log."""

    values = {
        environment[name]
        for name in _PROVIDER_LOG_SECRET_ENV
        if environment.get(name)
    }
    home = environment.get("CODEX_HOME")
    if not home:
        raise security.WorkerSecurityError("Worker provider CODEX_HOME is unavailable")
    try:
        raw_auth = read_private_bytes(
            Path(home) / "auth.json", maximum=_AUTH_FILE_LIMIT,
        )
    except FileNotFoundError:
        return values
    except (OSError, SecureIOError) as exc:
        raise security.WorkerSecurityError(
            "Worker provider subscription auth is unavailable or unsafe"
        ) from exc
    try:
        auth = json.loads(raw_auth)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise security.WorkerSecurityError(
            "Worker provider subscription auth is malformed"
        ) from exc
    values.update(_auth_string_values(auth, token_context=not isinstance(auth, dict)))
    return values


def _lower_percent_escapes(value: bytes) -> bytes:
    return re.sub(
        rb"%[0-9A-F]{2}", lambda match: match.group(0).lower(), value,
    )


def _secret_variants(values: Iterable[str]) -> set[bytes]:
    """Expand raw secrets to common representations emitted by clients."""

    variants: set[bytes] = set()
    for value in values:
        raw = value.encode("utf-8")
        if not raw:
            continue
        variants.add(raw)
        for encoded in (base64.b64encode(raw), base64.urlsafe_b64encode(raw)):
            variants.add(encoded)
            variants.add(encoded.rstrip(b"="))
        variants.add(raw.hex().encode("ascii"))
        variants.add(raw.hex().upper().encode("ascii"))
        percent = quote_from_bytes(raw, safe="").encode("ascii")
        variants.add(percent)
        variants.add(_lower_percent_escapes(percent))
    return {variant for variant in variants if variant}


class _StreamingLogRedactor:
    """Bounded byte-stream redactor which preserves cross-chunk matches."""

    def __init__(self, values: Iterable[str]):
        patterns = sorted(_secret_variants(values), key=len, reverse=True)
        self._matcher = (
            re.compile(b"|".join(re.escape(pattern) for pattern in patterns))
            if patterns else None
        )
        self._overlap = max((len(pattern) for pattern in patterns), default=1) - 1
        self._buffer = b""
        self._marker = (
            b"" if any(pattern in _REDACTION_MARKER for pattern in patterns)
            else _REDACTION_MARKER
        )

    def feed(self, chunk: bytes, *, final: bool = False) -> bytes:
        self._buffer += chunk
        cutoff = len(self._buffer) if final else max(0, len(self._buffer) - self._overlap)
        if cutoff == 0:
            return b""
        if self._matcher is None:
            output, self._buffer = self._buffer[:cutoff], self._buffer[cutoff:]
            return output

        pieces: list[bytes] = []
        consumed = 0
        for match in self._matcher.finditer(self._buffer):
            if match.start() >= cutoff:
                break
            pieces.extend((self._buffer[consumed:match.start()], self._marker))
            consumed = match.end()
        if consumed < cutoff:
            pieces.append(self._buffer[consumed:cutoff])
            consumed = cutoff
        self._buffer = self._buffer[consumed:]
        return b"".join(pieces)


def _drain_provider_output(
    source: BinaryIO, destination: TextIO, redactor: _StreamingLogRedactor,
) -> None:
    """Copy provider output through the streaming secret boundary."""

    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    while True:
        try:
            chunk = source.read(65536)
        except (OSError, ValueError):
            break
        if not chunk:
            break
        rendered = decoder.decode(redactor.feed(chunk))
        if rendered:
            destination.write(rendered)
            destination.flush()
    try:
        rendered = decoder.decode(redactor.feed(b"", final=True), final=True)
        if rendered:
            destination.write(rendered)
            destination.flush()
    except (OSError, ValueError):
        pass


# --- one round ------------------------------------------------------------- #

class _Child:
    """Holds the running codex subprocess so the SIGTERM handler can kill it."""
    proc: "subprocess.Popen | None" = None
    gateway: "subprocess.Popen | None" = None


def _stop_round_children() -> None:
    """Best-effort stop/reap for both sides of the Worker trust boundary."""
    for attr in ("proc", "gateway"):
        process = getattr(_Child, attr)
        if process is None:
            continue
        try:
            if hasattr(process, "_stop_scope"):
                # ManagedProvider.wait() already proves its whole cgroup empty.
                # Re-running the proof after the transient unit is collected can
                # race cgroupfs teardown and turn a successful round into an
                # unhandled Worker crash. Only an actually live provider needs
                # the emergency stop path here.
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.process.kill()
                        process.process.wait(timeout=3)
            elif process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
        except (
            OSError, subprocess.SubprocessError,
            security.WorkerSecurityError, systemd_scope.SystemdBoundaryError,
        ):
            pass
        finally:
            closer = getattr(process, "close", None)
            if callable(closer):
                try:
                    closer()
                except (OSError, ValueError, systemd_scope.SystemdBoundaryError):
                    pass
            setattr(_Child, attr, None)


def run_round(wl: L.WorkerLayout, role: dict, prompt: str, log_path: Path,
              hard_timeout: int) -> int:
    """Exec one ``codex exec`` continuation session. Returns codex's rc, 124 on
    hard-timeout (terminate → wait 10s → kill), or 127 if the codex binary is
    missing."""
    wdir = wl.dir
    try:
        codex_bin = security.resolve_worker_codex_bin(codex.resolve_bin())
    except security.WorkerSecurityError as exc:
        log_path.write_text(f"[worker_loop] Worker security boundary unavailable: {exc}\n", encoding="utf-8")
        return 126
    gateway_log_path = log_path.with_name(log_path.stem + ".gateway.log")
    try:
        logf_context = secure_open_text(log_path)
        gateway_context = secure_open_text(gateway_log_path)
    except (OSError, SecureIOError):
        return 126
    with logf_context as logf, gateway_context as gateway_log:
        try:
            _Child.gateway = security.start_host_gateway(wl, gateway_log)
            # Regenerate host config each round, but the authoritative MCP
            # binding is the high-precedence one-shot socket CLI override below.
            scaffold.write_codex_config(wl)
            provider_cmd = codex.exec_cmd(
                codex_bin, role["MODEL"], role["REASONING_EFFORT"],
                *security.codex_security_args(wl, _Child.gateway.provider_socket_path),
                "-C", str(wdir), "--skip-git-repo-check", "-",
            )
            provider_cmd[1:1] = security.codex_global_security_args()
            provider_env = security.worker_provider_env(wl)
            provider_log_redactor = _StreamingLogRedactor(
                _provider_log_secrets(provider_env),
            )
            _Child.proc = systemd_scope.start_provider_scope(
                wl, codex_bin=codex_bin, provider_command=provider_cmd,
                provider_environment=provider_env, gateway=_Child.gateway,
                runtime_limit=hard_timeout,
            )
            security.record_provider_pid(wl, _Child.proc.pid)
        except FileNotFoundError:
            logf.write("[worker_loop] codex binary not found\n")
            _stop_round_children()
            return 127
        except (security.WorkerSecurityError, systemd_scope.SystemdBoundaryError):
            logf.write("[worker_loop] Worker security boundary unavailable\n")
            _stop_round_children()
            return 126
        assert _Child.proc.stdout is not None
        _Child.proc.send_prompt(prompt)

        def _drain_provider() -> None:
            if _Child.proc is not None:
                _drain_provider_output(
                    _Child.proc.stdout, logf, provider_log_redactor,
                )

        drain = threading.Thread(target=_drain_provider, daemon=True)
        drain.start()
        try:
            rc = _Child.proc.wait(timeout=hard_timeout if hard_timeout > 0 else None)
            drain.join(timeout=3)
            return rc
        except subprocess.TimeoutExpired:
            _Child.proc.terminate()
            try:
                _Child.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                _Child.proc.kill()
            drain.join(timeout=3)
            logf.write(f"\n[worker_loop] round hard-timeout after {hard_timeout}s\n")
            return 124
        finally:
            _stop_round_children()


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
    protect_host_process_secrets()
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
        if _Child.gateway is not None:
            _Child.gateway.terminate()
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
                try:
                    rc = run_round(wl, role, prompt, log_path, hard_timeout)
                except Exception as exc:
                    # A round boundary failure must become observable Worker
                    # state, never an unhandled outer-loop exit that leaves a
                    # persisted "running" status. Keep the detail structural so
                    # provider output/secrets cannot leak through status APIs.
                    try:
                        with secure_open_text(log_path, append=True) as logf:
                            logf.write(
                                "\n[worker_loop] round boundary exception: "
                                f"{type(exc).__name__}\n"
                            )
                    except (OSError, SecureIOError):
                        pass
                    rc = 126
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
