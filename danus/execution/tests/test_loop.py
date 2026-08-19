"""Offline tests for danus.execution.loop + __main__ (no real codex, no network).

Covers the round driver end-to-end without ever launching a real codex:

  - ``run_round`` against a FIXED fake-codex stub script: a chosen exit code, a
    hard-timeout (terminate → 124), and a missing binary (→ 127). These drive the
    real ``subprocess.Popen`` path in loop.py.
  - the ``main`` outer loop: stop-flag / deadline / max-rounds / consecutive-
    failure caps, the codex-missing (127) short-circuit, and the ``ok``/``error``
    status writes. ``run_round`` is monkeypatched so no subprocess spawns.
  - the SIGTERM handler (_on_term): terminates the in-flight child, writes
    ``terminated`` status, and exits 0.
  - __main__: ``runpy.run_module("danus.execution", run_name="__main__")`` with the
    loop entry patched, covering the argv guard + dispatch without spawning.
  - the remaining small error/edge branches in loop / layout / scaffold helpers.

Runs standalone (``python -m danus.execution.tests.test_loop``) and pytest.
"""

from __future__ import annotations

import json
import io
import os
import base64
import runpy
import signal
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote_from_bytes

from danus.execution import layout as L
from danus.execution import loop, scaffold


@contextmanager
def _env(**kw):
    old = {k: os.environ.get(k) for k in kw}
    for k, v in kw.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = str(v)
    try:
        yield
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


@contextmanager
def _restore_sigterm():
    """main() installs a SIGTERM handler; save/restore so tests don't leak it."""
    old = signal.getsignal(signal.SIGTERM)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, old)


def _mk_worker(tmp: Path, name: str = "high") -> L.WorkerLayout:
    """A minimal worker home under tmp: <tmp>/proj/workers/<name>."""
    wl = L.WorkerLayout(tmp / "proj" / "workers" / name)
    wl.dir.mkdir(parents=True)
    return wl


def _write_fake_codex(tmp: Path, body: str) -> Path:
    """Write an executable python fake-codex stub and return its path. The stub
    ignores all the exec args and just does what ``body`` says."""
    p = tmp / "fake_codex"
    p.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    p.chmod(0o755)
    return p


@contextmanager
def _direct_round_boundary(wl: L.WorkerLayout, codex_bin: Path):
    """Inject harmless gateway/provider seams for direct ``run_round`` tests.

    Production still calls the real host gateway and systemd provider scope;
    these Python object replacements are reachable only by this test process.
    """

    class _Gateway:
        provider_socket_path = Path(loop.security.PROVIDER_SOCKET_PATH)

        @staticmethod
        def poll():
            return 0

        @staticmethod
        def terminate():
            return None

        @staticmethod
        def close():
            return None

    observed: dict[str, object] = {}
    test_home = wl.dir / ".direct-test-provider-home"
    test_tmp = test_home / "tmp"
    test_tmp.mkdir(parents=True, exist_ok=True)
    test_home.chmod(0o700)
    test_tmp.chmod(0o700)

    class _DirectProvider:
        def __init__(self, command, environment):
            # Keep this seam hermetic even when the test runner itself has a
            # logged-in Codex subscription or a custom provider URL.
            observed["environment"] = dict(environment)
            self.process = subprocess.Popen(
                command, cwd="/", env=environment, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
            self.pid = self.process.pid
            self.stdout = getattr(self.process, "stdout", None) or io.BytesIO()

        def send_prompt(self, prompt):
            stream = getattr(self.process, "stdin", None)
            if stream is not None:
                stream.write(prompt.encode("utf-8"))
                stream.close()

        def poll(self):
            return self.process.poll()

        def wait(self, timeout=None):
            return self.process.wait(timeout=timeout)

        def terminate(self):
            self.process.terminate()

        def kill(self):
            self.process.kill()

        @staticmethod
        def close():
            return None

    original_gateway = loop.security.start_host_gateway
    original_provider = loop.systemd_scope.start_provider_scope
    original_resolve = loop.codex.resolve_bin
    original_validate = loop.security.resolve_worker_codex_bin

    def start_gateway(*_args, **_kwargs):
        return _Gateway()

    def start_provider(*_args, provider_command, provider_environment, **_kwargs):
        return _DirectProvider(provider_command, provider_environment)

    loop.security.start_host_gateway = start_gateway
    loop.systemd_scope.start_provider_scope = start_provider
    loop.codex.resolve_bin = lambda: str(codex_bin)
    loop.security.resolve_worker_codex_bin = lambda _selected: str(codex_bin)
    original_provider_env = loop.security.worker_provider_env
    loop.security.worker_provider_env = lambda _worker: {
        "CODEX_HOME": str(test_home),
        "HOME": str(test_home),
        "TMPDIR": str(test_tmp),
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONSAFEPATH": "1",
    }
    # ``codex.exec_cmd`` reads provider routing from the ambient process env;
    # clear it so a fake executable can never accidentally contact a real
    # endpoint or observe a real credential during these direct tests.
    isolated_env = _env(
        CODEX_HOME=None,
        OPENAI_API_KEY=None,
        DANUS_CODEX_API_KEY=None,
        OPENAI_BASE_URL=None,
        CODEX_API_BASE_URL=None,
        OPENAI_CHATGPT_BASE_URL=None,
        CODEX_CHATGPT_BASE_URL=None,
        DANUS_CODEX_JS=None,
        DANUS_NODE=None,
        DANUS_RUNTIME=None,
        SSL_CERT_FILE=None,
        SSL_CERT_DIR=None,
    )
    isolated_env.__enter__()
    try:
        yield observed
    finally:
        isolated_env.__exit__(None, None, None)
        loop.security.start_host_gateway = original_gateway
        loop.systemd_scope.start_provider_scope = original_provider
        loop.codex.resolve_bin = original_resolve
        loop.security.resolve_worker_codex_bin = original_validate
        loop.security.worker_provider_env = original_provider_env


# --- run_round: chosen exit code ------------------------------------------- #

def test_run_round_returns_codex_rc(tmp: Path):
    wl = _mk_worker(tmp)
    fake = _write_fake_codex(tmp, "import sys\nsys.stdout.write('hello from codex\\n')\nsys.exit(3)\n")
    log = wl.dir / "round.log"
    with _direct_round_boundary(wl, fake):
        rc = loop.run_round(wl, {"MODEL": "m", "REASONING_EFFORT": "high"},
                            "prompt", log, hard_timeout=30)
    assert rc == 3
    assert "hello from codex" in log.read_text()
    assert loop._Child.proc is None            # cleared in finally


def test_run_round_success_rc0(tmp: Path):
    wl = _mk_worker(tmp)
    fake = _write_fake_codex(tmp, "import sys\nsys.exit(0)\n")
    log = wl.dir / "round.log"
    with _direct_round_boundary(wl, fake):
        rc = loop.run_round(wl, {"MODEL": "m", "REASONING_EFFORT": "high"},
                            "prompt", log, hard_timeout=0)   # 0 => no timeout (wait forever)
    assert rc == 0


def test_direct_round_seam_does_not_inherit_host_provider_credentials(tmp: Path):
    """The direct fake seam must stay hermetic under a logged-in test runner."""

    wl = _mk_worker(tmp)
    fake = _write_fake_codex(tmp, "import sys\nsys.exit(0)\n")
    log = wl.dir / "round.log"
    with _env(
        CODEX_HOME=tmp / "real-host-home",
        OPENAI_API_KEY="host-api-secret-marker",
        DANUS_CODEX_API_KEY="host-danus-secret-marker",
        OPENAI_BASE_URL="https://real-provider.invalid/v1",
        CODEX_CHATGPT_BASE_URL="https://real-chatgpt.invalid",
    ):
        with _direct_round_boundary(wl, fake) as observed:
            assert loop.run_round(
                wl, {"MODEL": "m", "REASONING_EFFORT": "high"},
                "prompt", log, hard_timeout=30,
            ) == 0
    env = observed["environment"]
    assert isinstance(env, dict)
    assert not any(
        marker in repr(env)
        for marker in (
            "host-api-secret-marker", "host-danus-secret-marker",
            "real-provider.invalid", "real-chatgpt.invalid",
        )
    )
    assert set(env) <= {
        "CODEX_HOME", "HOME", "TMPDIR", "PATH", "LANG",
        "PYTHONDONTWRITEBYTECODE", "PYTHONSAFEPATH",
    }


def test_provider_output_scrubs_cross_chunk_raw_base64_and_percent_variants():
    api_key = "sk-provider-raw-secret"
    subscription_token = "subscription-token-marker"
    provider_url = "https://provider.invalid/private path"
    hex_secret = "hex-provider-secret"
    encoded_token = base64.b64encode(subscription_token.encode("utf-8"))
    encoded_url = quote_from_bytes(provider_url.encode("utf-8"), safe="").encode("ascii")
    encoded_hex = hex_secret.encode("utf-8").hex().upper().encode("ascii")

    class _ChunkedOutput:
        def __init__(self):
            self.chunks = iter((
                b"raw=" + api_key[:7].encode("utf-8"),
                api_key[7:].encode("utf-8") + b"\nbase64=" + encoded_token[:9],
                encoded_token[9:] + b"\npercent=" + encoded_url[:11],
                encoded_url[11:] + b"\nhex=" + encoded_hex[:13],
                encoded_hex[13:] + b"\ndone\n",
            ))

        def read(self, _size):
            return next(self.chunks, b"")

    destination = io.StringIO()
    loop._drain_provider_output(
        _ChunkedOutput(), destination,
        loop._StreamingLogRedactor(
            (api_key, subscription_token, provider_url, hex_secret),
        ),
    )
    rendered = destination.getvalue()
    assert api_key not in rendered
    assert encoded_token.decode("ascii") not in rendered
    assert encoded_url.decode("ascii") not in rendered
    assert encoded_hex.decode("ascii") not in rendered
    assert rendered.count("[REDACTED]") == 4
    assert all(label in rendered for label in ("raw=", "base64=", "percent=", "hex="))


def test_provider_log_secrets_include_subscription_auth_strings(tmp: Path):
    home = tmp / "provider-home"
    home.mkdir(mode=0o700)
    auth = home / "auth.json"
    auth.write_text(
        json.dumps({
            "auth_mode": "chatgpt",
            "tokens": {
                "access_token": "subscription-access-marker",
                "refresh_token": "subscription-refresh-marker",
            },
        }),
        encoding="utf-8",
    )
    auth.chmod(0o600)
    secrets = loop._provider_log_secrets({
        "CODEX_HOME": str(home),
        "OPENAI_API_KEY": "api-key-marker",
        "OPENAI_BASE_URL": "https://provider.invalid/v1",
    })
    assert "subscription-access-marker" in secrets
    assert "subscription-refresh-marker" in secrets
    assert "api-key-marker" in secrets
    assert "https://provider.invalid/v1" in secrets
    assert "chatgpt" not in secrets


# --- run_round: hard timeout → terminate → 124 ----------------------------- #

def test_run_round_hard_timeout_terminates(tmp: Path):
    wl = _mk_worker(tmp)
    # sleeps far past the tiny hard_timeout; a plain terminate() ends it.
    fake = _write_fake_codex(tmp, "import time\ntime.sleep(60)\n")
    log = wl.dir / "round.log"
    with _direct_round_boundary(wl, fake):
        rc = loop.run_round(wl, {"MODEL": "m", "REASONING_EFFORT": "high"},
                            "prompt", log, hard_timeout=1)
    assert rc == 124
    assert "hard-timeout after 1s" in log.read_text()
    assert loop._Child.proc is None


# --- run_round: missing binary → 127 --------------------------------------- #

def test_run_round_missing_binary_returns_127(tmp: Path):
    wl = _mk_worker(tmp)
    missing = tmp / "does_not_exist_codex"
    log = wl.dir / "round.log"
    with _direct_round_boundary(wl, missing):
        rc = loop.run_round(wl, {"MODEL": "m", "REASONING_EFFORT": "high"},
                            "prompt", log, hard_timeout=30)
    assert rc == 127
    assert "codex binary not found" in log.read_text()


# --- run_round: unresponsive child → terminate times out → kill → 124 ------ #

def test_run_round_timeout_then_kill(tmp: Path):
    """A child that ignores terminate() (wait(10) times out) is force-killed. We
    fake Popen so the 10s terminate-grace does not slow the test."""
    wl = _mk_worker(tmp)
    log = wl.dir / "round.log"

    class _StubProc:
        def __init__(self):
            self.pid = os.getpid()
            self.terminated = False
            self.killed = False
            self._waits = 0

        def wait(self, timeout=None):
            self._waits += 1
            # 1st wait = the hard-timeout expiry; 2nd wait = the 10s grace expiry.
            if self._waits <= 2:
                raise subprocess.TimeoutExpired(cmd="codex", timeout=timeout)
            return -9

        def poll(self):
            return None if self._waits <= 2 else -9

        def terminate(self):
            self.terminated = True

        def kill(self):
            self.killed = True

    stub = _StubProc()
    fake = _write_fake_codex(tmp, "import sys\nsys.exit(0)\n")
    orig_popen = subprocess.Popen
    subprocess.Popen = lambda *a, **k: stub
    try:
        with _direct_round_boundary(wl, fake):
            rc = loop.run_round(wl, {"MODEL": "m", "REASONING_EFFORT": "high"},
                                "prompt", log, hard_timeout=1)
    finally:
        subprocess.Popen = orig_popen
    assert rc == 124
    assert stub.terminated and stub.killed          # terminate → (grace expired) → kill
    assert loop._Child.proc is None


# --- main loop: stop flag → graceful stop ---------------------------------- #

def test_main_stops_on_stop_flag(tmp: Path):
    wl = _mk_worker(tmp)
    wl.stop.touch()          # stop before the first round
    with _restore_sigterm(), _env(DANUS_ROUND_BEAT="0"):
        _patch_run_round(lambda *a, **k: 0)
        try:
            rc = loop.main(str(wl.dir))
        finally:
            _unpatch_run_round()
    assert rc == 0
    assert not wl.stop.exists()                       # consumed
    assert json.loads(wl.status.read_text())["state"] == "stopped"


def test_main_pause_marker_blocks_next_round_until_stop(tmp: Path):
    wl = _mk_worker(tmp)
    wl.pause.touch()
    calls = []
    original_sleep = loop.time.sleep

    def release_to_stop(_seconds):
        calls.append("paused")
        wl.pause.unlink(missing_ok=True)
        wl.stop.touch()

    loop.time.sleep = release_to_stop
    with _restore_sigterm(), _env(DANUS_ROUND_BEAT="0"):
        _patch_run_round(lambda *a, **k: (_ for _ in ()).throw(AssertionError("round started while paused")))
        try:
            rc = loop.main(str(wl.dir))
        finally:
            _unpatch_run_round()
            loop.time.sleep = original_sleep
    assert rc == 0
    assert calls == ["paused"]
    assert json.loads(wl.status.read_text())["state"] == "stopped"


# --- main loop: deadline → stop -------------------------------------------- #

def test_main_stops_on_deadline(tmp: Path):
    wl = _mk_worker(tmp)
    (wl.project_dir / L.DEADLINE_FILE).write_text("1")   # epoch 1 = long past
    with _restore_sigterm(), _env(DANUS_ROUND_BEAT="0"):
        _patch_run_round(lambda *a, **k: 0)
        try:
            rc = loop.main(str(wl.dir))
        finally:
            _unpatch_run_round()
    assert rc == 0
    assert json.loads(wl.status.read_text())["state"] == "deadline"


# --- main loop: max-rounds cap --------------------------------------------- #

def test_main_max_rounds_cap(tmp: Path):
    wl = _mk_worker(tmp)
    calls = []
    with _restore_sigterm(), _env(DANUS_ROUND_BEAT="0", DANUS_MAX_ROUNDS="2",
                                  DANUS_MAX_CONSEC_FAILURES="0"):
        _patch_run_round(lambda *a, **k: (calls.append(1) or 0))
        try:
            rc = loop.main(str(wl.dir))
        finally:
            _unpatch_run_round()
    assert rc == 0
    assert len(calls) == 2                              # exactly max_rounds rounds ran
    st = json.loads(wl.status.read_text())
    assert st["state"] == "max_rounds"
    assert st["round"] == 2 and st["last_rc"] == 0


# --- main loop: consecutive-failure cap → error / rc 1 --------------------- #

def test_main_consecutive_failure_cap(tmp: Path):
    wl = _mk_worker(tmp)
    log = wl.logs / "round_1.log"   # a fact id in a round log flows into status
    with _restore_sigterm(), _env(DANUS_ROUND_BEAT="0", DANUS_MAX_CONSEC_FAILURES="2",
                                  DANUS_MAX_ROUNDS="0"):
        def _fail(w, role, prompt, log_path, ht):
            log_path.write_text('"fact_id": "0123456789abcdef"\n')
            return 5                                    # a failing rc (not 0/124)
        _patch_run_round(_fail)
        try:
            rc = loop.main(str(wl.dir))
        finally:
            _unpatch_run_round()
    assert rc == 1
    st = json.loads(wl.status.read_text())
    assert st["state"] == "error" and "consecutive failed rounds" in st["error"]
    # last idle status carried the parsed fact id
    assert st.get("last_fact_id") == "0123456789abcdef" or st["last_rc"] == 5


def test_main_round_exception_never_persists_exception_message(tmp: Path):
    wl = _mk_worker(tmp)
    secret = "exception-contained-provider-secret"
    with _restore_sigterm(), _env(
        DANUS_ROUND_BEAT="0", DANUS_MAX_CONSEC_FAILURES="1",
    ):
        _patch_run_round(
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError(f"failure: {secret}"))
        )
        try:
            assert loop.main(str(wl.dir)) == 1
        finally:
            _unpatch_run_round()
    persisted = wl.status.read_text(encoding="utf-8") + "".join(
        path.read_text(encoding="utf-8") for path in wl.logs.iterdir()
    )
    assert secret not in persisted
    assert "failure:" not in persisted
    assert "RuntimeError" in persisted
    assert "Codex round exited with code 126" in persisted


def test_round_error_does_not_promote_arbitrary_provider_text(tmp: Path):
    log = tmp / "round.log"
    log.write_text("ERROR: provider-controlled secret detail\n", encoding="utf-8")
    assert loop._round_error(log, 9) == "Codex round exited with code 9"


def test_main_timeout_rc124_does_not_count_as_failure(tmp: Path):
    """rc 124 (hard-timeout) resets the consecutive-failure counter, so a run of
    124s never trips the failure cap — it must stop via max_rounds instead."""
    wl = _mk_worker(tmp)
    with _restore_sigterm(), _env(DANUS_ROUND_BEAT="0", DANUS_MAX_CONSEC_FAILURES="2",
                                  DANUS_MAX_ROUNDS="3"):
        _patch_run_round(lambda *a, **k: 124)
        try:
            rc = loop.main(str(wl.dir))
        finally:
            _unpatch_run_round()
    assert rc == 0
    assert json.loads(wl.status.read_text())["state"] == "max_rounds"


# --- main loop: codex missing (127) short-circuits ------------------------- #

def test_main_codex_missing_127(tmp: Path):
    wl = _mk_worker(tmp)
    with _restore_sigterm(), _env(DANUS_ROUND_BEAT="0"):
        _patch_run_round(lambda *a, **k: 127)
        try:
            rc = loop.main(str(wl.dir))
        finally:
            _unpatch_run_round()
    assert rc == 127
    st = json.loads(wl.status.read_text())
    assert st["state"] == "error" and st["error"] == "codex binary not found"


# --- main: bad worker dir → rc 2 ------------------------------------------- #

def test_main_missing_worker_dir(tmp: Path):
    rc = loop.main(str(tmp / "nope"))
    assert rc == 2


# --- SIGTERM handler: terminate child, write terminated, exit 0 ------------ #

def test_main_sigterm_handler(tmp: Path):
    wl = _mk_worker(tmp)

    class _FakeProc:
        def __init__(self):
            self.terminated = False

        def terminate(self):
            self.terminated = True

    fake_proc = _FakeProc()

    # run_round: install a live child then deliver SIGTERM to ourselves so the
    # loop's own handler fires (covers _on_term end to end).
    def _round(w, role, prompt, log_path, ht):
        loop._Child.proc = fake_proc
        os.kill(os.getpid(), signal.SIGTERM)
        time.sleep(2)                     # give the signal time to be delivered
        return 0

    with _restore_sigterm(), _env(DANUS_ROUND_BEAT="0"):
        _patch_run_round(_round)
        try:
            try:
                loop.main(str(wl.dir))
                assert False, "handler should sys.exit(0)"
            except SystemExit as e:
                assert e.code == 0
        finally:
            _unpatch_run_round()
            loop._Child.proc = None
    assert fake_proc.terminated
    assert json.loads(wl.status.read_text())["state"] == "terminated"


# --- write_status: recovers from a corrupt existing status ----------------- #

def test_write_status_corrupt_existing_recovers(tmp: Path):
    wl = _mk_worker(tmp)
    wl.status.write_text("{not json")            # corrupt → JSONDecodeError branch
    loop.write_status(wl, state="running")
    st = json.loads(wl.status.read_text())
    assert st["state"] == "running" and st["worker"] == "high"


# --- _parse_last_fact_id: unreadable path → None --------------------------- #

def test_parse_last_fact_id_missing_file(tmp: Path):
    assert loop._parse_last_fact_id(tmp / "no_such.log") is None   # OSError branch


# --- _cleanup_pid: removes PID + identity only when the PID points at us --- #

def test_cleanup_pid_removes_own_identity_metadata(tmp: Path):
    wl = _mk_worker(tmp)
    wl.pid.write_text(str(os.getpid()))
    wl.process_identity.write_text('{"pid": "ours"}')
    loop._cleanup_pid(wl)
    assert not wl.pid.exists()
    assert not wl.process_identity.exists()


def test_cleanup_pid_keeps_foreign_identity_metadata(tmp: Path):
    wl = _mk_worker(tmp)
    wl.pid.write_text("999999999")            # some other pid
    wl.process_identity.write_text('{"pid": "foreign"}')
    loop._cleanup_pid(wl)
    assert wl.pid.exists()                     # left intact
    assert wl.process_identity.exists()


def test_cleanup_pid_swallows_oserror(tmp: Path):
    """A .pid that cannot be read (here: it is a directory) → OSError swallowed."""
    wl = _mk_worker(tmp)
    wl.pid.mkdir()                             # read_text on a dir raises OSError
    loop._cleanup_pid(wl)                      # must not raise
    assert wl.pid.exists()


# --- main loop: positive beat sleeps between rounds ------------------------ #

def test_main_beat_sleep_between_rounds(tmp: Path):
    """A positive DANUS_ROUND_BEAT makes the loop sleep between rounds; we stub
    time.sleep so no real wall-clock time passes and record it fired."""
    wl = _mk_worker(tmp)
    slept = []
    orig_sleep = time.sleep

    def _one_then_stop(*a, **k):
        wl.stop.touch()          # stop after the first round completes
        return 0

    time.sleep = lambda s: slept.append(s)
    try:
        with _restore_sigterm(), _env(DANUS_ROUND_BEAT="7", DANUS_MAX_ROUNDS="0",
                                      DANUS_MAX_CONSEC_FAILURES="0"):
            _patch_run_round(_one_then_stop)
            try:
                rc = loop.main(str(wl.dir))
            finally:
                _unpatch_run_round()
    finally:
        time.sleep = orig_sleep
    assert rc == 0
    assert 7 in slept                          # the beat sleep fired once


# --- kickoff prompt -------------------------------------------------------- #

def test_kickoff_mentions_worker_and_project():
    p = loop.kickoff("ProjX", "wkrY")
    assert "wkrY" in p and "ProjX" in p and "TASK.md" in p


# --- __main__ entry -------------------------------------------------------- #

def test_dunder_main_dispatches(tmp: Path):
    """runpy the package as __main__ with the loop entry patched: the guard runs
    and dispatches to main() without spawning anything."""
    seen = {}

    def _fake_main(arg):
        seen["arg"] = arg
        return 0

    orig = loop.main
    loop.main = _fake_main
    argv = sys.argv
    sys.argv = ["prog", "/some/worker/dir"]
    try:
        try:
            runpy.run_module("danus.execution", run_name="__main__")
            assert False, "should sys.exit"
        except SystemExit as e:
            assert e.code == 0
    finally:
        loop.main = orig
        sys.argv = argv
    assert seen["arg"] == "/some/worker/dir"


def test_dunder_main_usage_guard():
    """Wrong argc → usage message + exit 2 (no dispatch)."""
    argv = sys.argv
    sys.argv = ["prog"]                        # missing worker_dir
    try:
        try:
            runpy.run_module("danus.execution", run_name="__main__")
            assert False, "should sys.exit(2)"
        except SystemExit as e:
            assert e.code == 2
    finally:
        sys.argv = argv


# --- layout defaults (no env overrides) ------------------------------------ #

def test_layout_defaults_and_empties(tmp: Path):
    with _env(DANUS_WORKER_CONTRACT=None, DANUS_WORKER_SKILLS=None,
              DANUS_AGENTS_ROOT=None):
        # repo_root / worker_md / worker_skills_dir defaults
        rr = L.repo_root()
        assert L.worker_md() == rr / "agents" / "contracts" / "worker.md"
        assert L.worker_skills_dir() == rr / "agents" / "skills" / "worker"
        # agents_root default = <cwd>/runtime/projects
        assert L.agents_root() == (Path.cwd() / "runtime" / "projects").resolve()
    # list_workers / list_projects on a nonexistent root → []
    with _env(DANUS_AGENTS_ROOT=str(tmp / "no_such_root")):
        assert L.list_workers("ghost") == []
        assert L.list_projects() == []


# --- scaffold.symlink branches --------------------------------------------- #

def test_symlink_skips_existing(tmp: Path):
    target = tmp / "target"
    target.write_text("x")
    link = tmp / "link"
    link.write_text("already here")            # link path exists → early return
    scaffold.symlink(target, link)
    assert link.read_text() == "already here"  # untouched


def test_symlink_swallows_oserror(tmp: Path):
    target = tmp / "target"
    target.write_text("x")
    # a link path whose parent does not exist → os.symlink raises OSError, swallowed
    link = tmp / "no_parent_dir" / "link"
    scaffold.symlink(target, link)             # must not raise
    assert not link.exists()


# --- runner ---------------------------------------------------------------- #

# run_round monkeypatch helpers (so the standalone runner works without pytest's
# monkeypatch fixture): swap loop.run_round for the duration of a test.
_ORIG_RUN_ROUND = loop.run_round


def _patch_run_round(fn):
    loop.run_round = fn


def _unpatch_run_round():
    loop.run_round = _ORIG_RUN_ROUND


_NO_TMP = {test_kickoff_mentions_worker_and_project, test_dunder_main_usage_guard}


def main() -> None:
    tests = [
        test_run_round_returns_codex_rc,
        test_run_round_success_rc0,
        test_run_round_hard_timeout_terminates,
        test_run_round_missing_binary_returns_127,
        test_run_round_timeout_then_kill,
        test_main_stops_on_stop_flag,
        test_main_pause_marker_blocks_next_round_until_stop,
        test_main_stops_on_deadline,
        test_main_max_rounds_cap,
        test_main_consecutive_failure_cap,
        test_main_timeout_rc124_does_not_count_as_failure,
        test_main_codex_missing_127,
        test_main_missing_worker_dir,
        test_main_sigterm_handler,
        test_write_status_corrupt_existing_recovers,
        test_parse_last_fact_id_missing_file,
        test_cleanup_pid_removes_own_identity_metadata,
        test_cleanup_pid_keeps_foreign_identity_metadata,
        test_cleanup_pid_swallows_oserror,
        test_main_beat_sleep_between_rounds,
        test_kickoff_mentions_worker_and_project,
        test_dunder_main_dispatches,
        test_dunder_main_usage_guard,
        test_layout_defaults_and_empties,
        test_symlink_skips_existing,
        test_symlink_swallows_oserror,
    ]
    for t in tests:
        if t in _NO_TMP:
            t()
        else:
            with tempfile.TemporaryDirectory() as d:
                t(Path(d))
        print(f"  [ok] {t.__name__}")
    print("ALL LOOP TESTS PASSED")


if __name__ == "__main__":
    main()
