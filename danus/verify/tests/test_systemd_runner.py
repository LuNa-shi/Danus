"""Opt-in integration tests for the real verifier transient-service boundary.

Set ``DANUS_RUN_SYSTEMD_TESTS=1`` on a deployment host to exercise a real user
systemd manager and cgroup-v2 kernel.  The ordinary suite remains offline.
"""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import tempfile
import time

from fastapi import HTTPException
import pytest

from danus.verify import launcher
from danus.verify import systemd_runner as boundary


pytestmark = pytest.mark.skipif(
    os.environ.get("DANUS_RUN_SYSTEMD_TESTS") != "1",
    reason="real user-systemd verifier tests are opt-in",
)

_STATEMENT = "For every integer n, n equals itself under equality."
_PROOF = (
    "Equality is reflexive by definition: for every integer n, the ordered pair "
    "(n, n) represents the same value, hence n equals itself."
)


@contextmanager
def _env(**values):
    old = {name: os.environ.get(name) for name in values}
    try:
        for name, value in values.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        yield
    finally:
        for name, value in old.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _write_provider(root: Path, body: str) -> Path:
    path = root / "provider.py"
    path.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    path.chmod(0o755)
    return path


@contextmanager
def _case(body: str, *, timeout: str = "10"):
    with tempfile.TemporaryDirectory(dir=Path.cwd()) as raw:
        root = Path(raw)
        provider = _write_provider(root, body)
        agent = root / "agent"
        agent.mkdir()
        host_codex = root / "host-codex"
        host_codex.mkdir(mode=0o700)
        (host_codex / "auth.json").write_text(
            "{\"subscription\":true}", encoding="ascii",
        )
        (host_codex / "auth.json").chmod(0o600)
        with _env(
            DANUS_CODEX_BIN=None,
            CODEX_BIN=None,
            CODEX_HOME=str(host_codex),
            OPENAI_API_KEY=None,
            DANUS_CODEX_API_KEY=None,
            VERIFIER_RESULTS_DIR=str(root / "runs"),
            VERIFY_AGENT_HOME=str(agent),
            DANUS_VERIFY_PROVIDER_HOME=str(root / "provider-home"),
            CODEX_TIMEOUT_SECONDS=timeout,
            DANUS_VERIFY_CAPABILITY_SECRET_FILE=str(root / "KEY-SUPERSECRET"),
        ):
            yield root, provider


def _run(
    root: Path, provider: Path, run_id: str, *, runner=None,
    statement: str = _STATEMENT, proof: str = _PROOF,
):
    return launcher.run_codex_verification(
        run_id,
        statement,
        proof,
        runner=runner or boundary.SystemdTrustedVerifierRunner(),
        _test_provider_bin=str(provider),
    )


def _unit_names() -> set[str]:
    result = boundary._run_manager([
        boundary._safe_binary("systemctl"), "--user", "list-units", "--all",
        "--no-legend", "--plain", "danus-verifier-*.service",
    ], check=False)
    return {
        row.split(None, 1)[0]
        for row in result.stdout.splitlines()
        if row.startswith("danus-verifier-")
    }


def test_systemd_ready_pid_namespace_proc_and_dns(monkeypatch):
    host_pid = os.getpid()
    marker = "PROMPT-SUPERSECRET-SYSTEMD"
    body = (
        "import json, os, re, socket, sys, traceback\n"
        "from pathlib import Path\n"
        "prompt = sys.stdin.read()\n"
        "out = Path(re.search(r'this exact path:\\s*(\\S+)', prompt).group(1).rstrip('.'))\n"
        "try:\n"
        "    try:\n"
        "        pid1 = Path('/proc/1/cmdline').read_bytes().decode('utf-8', 'replace')\n"
        "        pid1_readable = True\n"
        "    except PermissionError:\n"
        "        pid1 = ''\n"
        "        pid1_readable = False\n"
        "    status = {'self_pid': os.getpid(), 'pid1': pid1, "
        "'pid1_readable': pid1_readable, "
        f"'host_visible': Path('/proc/{host_pid}').exists(), "
        "'resolver': Path('/etc/resolv.conf').read_text(), "
        "'hmac_visible': any('KEY-SUPERSECRET' in item for item in os.environ.values()), "
        f"'prompt_in_env': any({marker!r} in item for item in os.environ.values())}}\n"
        "    try:\n"
        "        status['dns'] = bool(socket.getaddrinfo('api.openai.com', 443))\n"
        "    except OSError:\n"
        "        status['dns'] = False\n"
        "    (out.parent / 'boundary-status.json').write_text(json.dumps(status))\n"
        f"    (out.parent / 'prompt-seen').write_text('yes' if {marker!r} in prompt else 'no')\n"
        "    out.write_text(json.dumps({'verification_report': "
        "{'critical_errors': [], 'gaps': []}, 'verdict': 'correct', "
        "'repair_hints': ''}))\n"
        "    print('provider-ok')\n"
        "except BaseException:\n"
        "    (out.parent / 'provider-error').write_text(traceback.format_exc())\n"
        "    raise\n"
    )
    with _case(body) as (root, provider):
        captured: dict[str, object] = {}
        original_pin = boundary._pin_service
        original_ready = boundary._validate_ready
        original_popen = boundary.subprocess.Popen

        def popen(*args, **kwargs):
            captured["controller_argv"] = args[0]
            return original_popen(*args, **kwargs)

        def pin(*args, **kwargs):
            result = original_pin(*args, **kwargs)
            captured["pinned"] = result
            captured["unit"] = result.unit
            return result

        def ready(pinned, value):
            # The provider cannot observe the candidate before this barrier.
            assert not (root / "runs" / "SYSTEMD" / "prompt-seen").exists()
            original_ready(pinned, value)
            captured["ready"] = value
            captured["unit_properties"] = boundary._show(
                pinned.unit,
                ("Description", "ExecStart", "Environment", "EnvironmentFiles"),
            )
            try:
                process_environment = (
                    Path("/proc") / str(pinned.main_pid) / "environ"
                ).read_bytes()
            except PermissionError:
                process_environment = b""
            captured["process_environment"] = process_environment

        monkeypatch.setattr(boundary.subprocess, "Popen", popen)
        monkeypatch.setattr(boundary, "_pin_service", pin)
        monkeypatch.setattr(boundary, "_validate_ready", ready)
        out = _run(root, provider, "SYSTEMD", statement=_STATEMENT + " " + marker)
        assert out["verdict"] == "correct"
        status = json.loads(
            (root / "runs" / "SYSTEMD" / "boundary-status.json").read_text(),
        )
        assert status["self_pid"] == 2
        # ProtectProc=ptraceable hides even PID 1's cmdline from the provider;
        # the trusted entry's READY attestation separately proves it is PID 1
        # in the private namespace.
        assert status["pid1_readable"] is False
        assert status["host_visible"] is False
        assert status["resolver"].strip()
        assert status["dns"] is True
        assert status["hmac_visible"] is False
        assert status["prompt_in_env"] is False
        assert (root / "runs" / "SYSTEMD" / "prompt-seen").read_text() == "yes"
        assert captured["ready"]["entry_pid"] == 1
        exposed = repr({
            "argv": captured["controller_argv"],
            "properties": captured["unit_properties"],
            "process_environment": captured["process_environment"],
        })
        assert marker not in exposed
        assert "KEY-SUPERSECRET" not in exposed
        unit = str(captured["unit"])
        journal = boundary._run_manager([
            boundary._safe_binary("journalctl"), "--user-unit", unit,
            "--no-pager", "-o", "cat",
        ], check=False).stdout
        assert marker not in journal
        assert "KEY-SUPERSECRET" not in journal


def test_systemd_timeout_kills_complete_cgroup():
    body = "import time; time.sleep(60)\n"
    with _case(body, timeout="1") as (root, provider):
        with pytest.raises(HTTPException) as caught:
            _run(root, provider, "SYSTEMD_TIMEOUT")
        assert caught.value.status_code == 504
        assert not any("SYSTEMD_TIMEOUT" in name for name in _unit_names())


def test_systemd_setsid_double_fork_cannot_survive_leader():
    body = (
        "import json, os, re, sys, time\n"
        "from pathlib import Path\n"
        "prompt = sys.stdin.read()\n"
        "out = Path(re.search(r'this exact path:\\s*(\\S+)', prompt).group(1).rstrip('.'))\n"
        "child = os.fork()\n"
        "if child == 0:\n"
        "    os.setsid()\n"
        "    grandchild = os.fork()\n"
        "    if grandchild > 0:\n"
        "        os._exit(0)\n"
        "    host_pid = int(next(line.split()[1] for line in "
        "Path('/proc/self/status').read_text().splitlines() if line.startswith('NSpid:')))\n"
        "    (out.parent / 'survivor.pid').write_text(str(host_pid))\n"
        "    time.sleep(60)\n"
        "(out.parent / 'leader-child.pid').write_text(str(child))\n"
        "out.write_text(json.dumps({'verification_report': "
        "{'critical_errors': [], 'gaps': []}, 'verdict': 'correct', "
        "'repair_hints': ''}))\n"
    )
    with _case(body) as (root, provider):
        out = _run(root, provider, "SYSTEMD_FORK")
        assert out["verdict"] == "correct"
        survivor = int(
            (root / "runs" / "SYSTEMD_FORK" / "survivor.pid").read_text(),
        )
        deadline = time.monotonic() + 3
        while Path("/proc", str(survivor)).exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not Path("/proc", str(survivor)).exists()


def test_systemd_startup_property_failure_cleans_unvalidated_unit(monkeypatch):
    body = "import time; time.sleep(60)\n"
    with _case(body) as (root, provider):
        monkeypatch.setattr(
            boundary,
            "_validate_properties",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                boundary._BoundaryError("deliberately invalid test property")
            ),
        )
        with pytest.raises(HTTPException) as caught:
            _run(root, provider, "SYSTEMD_BAD_PROPERTIES")
        assert caught.value.status_code == 503
        assert not any("SYSTEMD_BAD_PROPERTIES" in name for name in _unit_names())
