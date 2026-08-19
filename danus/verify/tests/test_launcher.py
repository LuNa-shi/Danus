"""Offline tests for launcher security, framing, and trusted-runner plumbing.

No real codex is ever launched. The subprocess path is exercised by pointing the
codex binary at tiny purpose-built stub scripts written into a temp dir (one per
failure mode) and asserting on the HTTPException status the launcher raises.

Covers:
  * build_codex_command: stdin sentinel, high-priority profile, no bypass/body argv.
  * minimal provider environment and exact outer isolation path contract.
  * _allocate_run_id: unique-dir retry on collision (FileExistsError branch).
  * _verification_path: found (each filename) and None-when-absent.
  * private hash-only logs, large stdin, fork cleanup, timeout/error mappings.

Runs standalone (``python -m danus.verify.tests.test_launcher``) and under pytest.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

from fastapi import HTTPException
import pytest

from danus import codex
from danus.verify import launcher
from danus.verify.tests.trusted_runner import DirectTrustedTestAdapter

_STMT = "For every integer n, n + 0 equals n."
_PROOF = "Zero is the additive identity; adding it changes nothing, so n + 0 = n."


@contextmanager
def _env(**kv):
    old = {k: os.environ.get(k) for k in kv}
    try:
        for k, v in kv.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        yield
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _write_stub(dirpath: Path, name: str, body: str) -> Path:
    dirpath.mkdir(parents=True, exist_ok=True)
    p = dirpath / name
    p.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
    p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return p


def _fake_official_runtime(root: Path) -> tuple[Path, Path]:
    package = root / "lib" / "node_modules" / "@openai" / "codex"
    entry = package / "bin" / "codex.js"
    entry.parent.mkdir(parents=True)
    entry.write_text("#!/usr/bin/env node\n", encoding="ascii")
    entry.chmod(0o755)
    (package / "package.json").write_text(json.dumps({
        "name": "@openai/codex", "version": "1.2.3",
        "bin": {"codex": "bin/codex.js"},
    }), encoding="utf-8")
    machine = os.uname().machine
    package_name, target, suffix = {
        "x86_64": ("codex-linux-x64", "x86_64-unknown-linux-musl", "linux-x64"),
        "aarch64": ("codex-linux-arm64", "aarch64-unknown-linux-musl", "linux-arm64"),
    }[machine]
    native_package = package / "node_modules" / "@openai" / package_name
    native_package.mkdir(parents=True)
    (native_package / "package.json").write_text(json.dumps({
        "name": "@openai/codex", "version": f"1.2.3-{suffix}", "os": ["linux"],
    }), encoding="utf-8")
    native_root = native_package / "vendor" / target
    native = native_root / "bin" / "codex"
    bwrap = native_root / "codex-resources" / "bwrap"
    native.parent.mkdir(parents=True)
    bwrap.parent.mkdir(parents=True)
    for path in (native, bwrap):
        path.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        path.chmod(0o755)
    return entry, native


# stub that writes a valid verification.json to the prompt's output path
_STUB_OK = """\
import re, sys, json
from pathlib import Path
prompt = sys.stdin.read()
out = Path(re.search(r'this exact path:\\s*(\\S+)', prompt).group(1).rstrip('.'))
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps({"verification_report": {"critical_errors": []},
                           "verdict": "correct", "repair_hints": ""}))
print("ok")
"""

# stub that exits nonzero and writes nothing
_STUB_FAIL = "import sys\nsys.stderr.write('boom\\n')\nsys.exit(7)\n"

# stub that exits 0 but writes NO output file
_STUB_NOOUT = "print('did nothing')\n"

# stub that writes invalid JSON
_STUB_BADJSON = """\
import re, sys
from pathlib import Path
prompt = sys.stdin.read()
out = Path(re.search(r'this exact path:\\s*(\\S+)', prompt).group(1).rstrip('.'))
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text("{ this is not json ")
"""

# stub that writes valid JSON that is NOT an object (a list)
_STUB_NONDICT = """\
import re, sys, json
from pathlib import Path
prompt = sys.stdin.read()
out = Path(re.search(r'this exact path:\\s*(\\S+)', prompt).group(1).rstrip('.'))
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(["not", "a", "dict"]))
"""

# stub that sleeps long enough to trip a 1s timeout
_STUB_SLOW = "import time\ntime.sleep(10)\n"

_STUB_FORK = """\
import json, os, re, sys, time
from pathlib import Path
prompt = sys.stdin.read()
out = Path(re.search(r'this exact path:\\s*(\\S+)', prompt).group(1).rstrip('.'))
out.parent.mkdir(parents=True, exist_ok=True)
child = os.fork()
if child == 0:
    time.sleep(60)
    os._exit(0)
(out.parent / 'fork-child.pid').write_text(str(child))
out.write_text(json.dumps({"verification_report": {"critical_errors": []},
                           "verdict": "correct", "repair_hints": ""}))
"""

_STUB_CWD = """\
import json, os, re, sys
from pathlib import Path
prompt = sys.stdin.read()
out = Path(re.search(r'this exact path:\\s*(\\S+)', prompt).group(1).rstrip('.'))
out.parent.mkdir(parents=True, exist_ok=True)
(out.parent / 'provider-cwd.txt').write_text(os.getcwd())
out.write_text(json.dumps({"verification_report": {"critical_errors": []},
                           "verdict": "correct", "repair_hints": ""}))
"""


@contextmanager
def _service(
    stub_body: str, *, timeout: str = "0", provider_key: str | None = "test-only-provider-key",
):
    """Point the launcher at a stub codex + isolated results/home dirs."""
    with tempfile.TemporaryDirectory() as tmp:
        tmpd = Path(tmp)
        stub = _write_stub(tmpd, "fake.py", stub_body)
        with _env(DANUS_CODEX_BIN=None, CODEX_BIN=None,
                  VERIFIER_RESULTS_DIR=str(tmpd / "runs"),
                  VERIFY_AGENT_HOME=str(tmpd / "home"),
                  DANUS_VERIFY_PROVIDER_HOME=str(tmpd / "provider-home"),
                  OPENAI_API_KEY=provider_key,
                  CODEX_TIMEOUT_SECONDS=timeout):
            (tmpd / "home").mkdir(exist_ok=True)
            adapter = DirectTrustedTestAdapter()
            adapter._test_provider_bin = str(stub)
            yield adapter


# --------------------------------------------------------------------------- #
# build_codex_command / config resolution                                     #
# --------------------------------------------------------------------------- #

def test_build_codex_command_shape():
    with tempfile.TemporaryDirectory() as tmp:
        provider = Path(tmp) / "codex"
        provider.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        provider.chmod(0o755)
        with _env(DANUS_CODEX_BIN=None,
                  VERIFY_AGENT_HOME=str(tmp),
                  DANUS_VERIFY_MODEL="m-test", DANUS_VERIFY_EFFORT="e-test",
                  DANUS_CODEX_MODEL=None, DANUS_CODEX_EFFORT=None):
            cmd = launcher.build_codex_command(
                "RID", _test_provider_bin=str(provider),
            )
    assert cmd[0] == str(provider) and cmd[1] == "exec"
    assert "--model" in cmd and cmd[cmd.index("--model") + 1] == "m-test"
    assert '--config' in cmd and 'model_reasoning_effort="e-test"' in cmd
    assert "-C" in cmd  # agent home
    # gateway injected via an absolute isolated-Python entry; that trusted entry
    # fixes the verifier role after clearing its inherited environment.
    assert "-c" in cmd
    assert any(
        'mcp_servers.danus=' in arg
        and 'args=["-I",' in arg
        and sys.executable in arg
        and str((launcher._HERE / "mcp_entry.py").resolve()) in arg
        for arg in cmd
    )
    assert "--dangerously-bypass-approvals-and-sandbox" not in cmd
    assert "--ignore-user-config" in cmd and "--strict-config" in cmd
    assert any('approval_policy="never"' == arg for arg in cmd)
    assert any('default_permissions="danus_verifier"' == arg for arg in cmd)
    # The complete prompt, especially the candidate statement/proof, is stdin
    # only.  A fixed sentinel is the final provider argument.
    assert cmd[-1] == "-"
    assert all(_STMT not in arg and _PROOF not in arg for arg in cmd)


def test_production_provider_rejects_arbitrary_owned_executable(tmp_path: Path):
    entry, _native = _fake_official_runtime(tmp_path / "official")
    arbitrary = _write_stub(tmp_path, "owned", "")
    with _env(DANUS_CODEX_JS=str(entry), DANUS_CODEX_BIN=str(arbitrary)):
        with pytest.raises(
            launcher.VerifierProviderConfigurationError,
            match="unsafe",
        ):
            launcher._provider_codex_bin()


def test_production_provider_rejects_repo_wrapper_alias(tmp_path: Path):
    entry, _native = _fake_official_runtime(tmp_path / "official")
    alias = tmp_path / "codex-alias"
    alias.symlink_to(launcher._REPO_ROOT / "bin" / "codex")
    with _env(DANUS_CODEX_JS=str(entry), DANUS_CODEX_BIN=str(alias)):
        with pytest.raises(launcher.VerifierProviderConfigurationError):
            launcher._provider_codex_bin()


def test_production_provider_rejects_spoofed_nurouter_marker(
    tmp_path: Path, monkeypatch,
):
    entry, _native = _fake_official_runtime(tmp_path / "official")
    fake_home = tmp_path / "home"
    launcher_path = _write_stub(fake_home / ".local" / "bin", "codex", "")
    marker = launcher_path.parent / ".nurouter-codex-launcher.json"
    marker.write_text(json.dumps({
        "schema_version": 2,
        "kind": "codex",
        "launcher_sha256": "0" * 64,
        "nurouter_home": str(fake_home / ".nurouter"),
    }), encoding="utf-8")
    marker.chmod(0o600)
    monkeypatch.setattr(
        launcher.pwd, "getpwuid", lambda _uid: SimpleNamespace(pw_dir=str(fake_home)),
    )
    with _env(DANUS_CODEX_JS=str(entry), DANUS_CODEX_BIN=str(launcher_path)):
        with pytest.raises(
            launcher.VerifierProviderConfigurationError,
            match="unsafe",
        ):
            launcher._provider_codex_bin()


def test_subprocess_env_prepends_dir_for_concrete_path():
    with tempfile.TemporaryDirectory() as tmp:
        binp = str(Path(tmp) / "codex")
        env = codex.subprocess_env(binp)
        assert env["PATH"].split(os.pathsep)[0] == str(Path(tmp).resolve())


def test_subprocess_env_no_cwd_injection_for_bare_name():
    before = os.environ.get("PATH", "")
    env = codex.subprocess_env("codex")
    # bare name has no dir component -> PATH must be untouched (no "." / cwd added)
    assert env["PATH"] == before


# --------------------------------------------------------------------------- #
# _allocate_run_id — collision retry                                          #
# --------------------------------------------------------------------------- #

def test_allocate_run_id_retries_on_collision():
    with tempfile.TemporaryDirectory() as tmp:
        with _env(VERIFIER_RESULTS_DIR=str(Path(tmp) / "runs")):
            base = launcher.generate_run_id(_STMT)
            root = launcher._results_root()
            root.mkdir(parents=True, exist_ok=True)
            # pre-create the base dir so the first mkdir raises FileExistsError,
            # forcing the numeric-suffix retry branch (lines 92-95).
            (root / base).mkdir()
            # generate_run_id is timestamp-based; freeze it so the retry collides
            # deterministically on `base`.
            orig = launcher.generate_run_id
            launcher.generate_run_id = lambda s: base  # type: ignore[assignment]
            try:
                rid = launcher._allocate_run_id(_STMT)
            finally:
                launcher.generate_run_id = orig  # type: ignore[assignment]
            assert rid == f"{base}_2"
            assert (root / rid).is_dir()


# --------------------------------------------------------------------------- #
# _verification_path                                                          #
# --------------------------------------------------------------------------- #

def test_verification_path_found_and_absent():
    with tempfile.TemporaryDirectory() as tmp:
        with _env(VERIFIER_RESULTS_DIR=str(Path(tmp) / "runs")):
            rid = "RID1"
            d = launcher._results_dir(rid)
            d.mkdir(parents=True)
            assert launcher._verification_path(rid) is None  # nothing yet
            (d / launcher.VERIFICATION_FILENAMES[1]).write_text("{}")
            # the alternate filename is also recognized
            assert launcher._verification_path(rid).name == launcher.VERIFICATION_FILENAMES[1]
            (d / launcher.VERIFICATION_FILENAMES[0]).write_text("{}")
            # primary filename takes precedence
            assert launcher._verification_path(rid).name == launcher.VERIFICATION_FILENAMES[0]


# --------------------------------------------------------------------------- #
# run_codex_verification — success + every error mapping                      #
# --------------------------------------------------------------------------- #

def _run(
    rid="RID", *, runner=None, statement=_STMT, proof=_PROOF,
    _test_provider_bin=None,
):
    test_provider = _test_provider_bin or getattr(
        runner, "_test_provider_bin", None,
    )
    return launcher.run_codex_verification(
        rid, statement, proof, runner=runner,
        _test_provider_bin=test_provider,
    )


def test_run_requires_a_trusted_supervisor():
    with _service(_STUB_OK) as test_adapter:
        try:
            _run(_test_provider_bin=test_adapter._test_provider_bin)
            assert False, "expected the missing production runner to fail closed"
        except HTTPException as exc:
            assert exc.status_code == 503
            assert exc.detail == "verifier security boundary unavailable"


def test_run_success_reads_back_payload():
    with _service(_STUB_OK) as runner:
        out = _run(runner=runner)
        assert out["verdict"] == "correct"
        assert out["verification_report"]["critical_errors"] == []
        assert runner.request.entry_argv[0] == sys.executable


def test_large_candidate_is_stdin_only_and_log_is_private_hash_metadata():
    marker = "CANDIDATE-BODY-MUST-NOT-LEAK"
    statement = marker + ("x" * (3 << 20))
    proof = marker + " proof"
    with _service(_STUB_OK) as runner:
        out = _run(
            rid="RID_LARGE", runner=runner, statement=statement, proof=proof,
        )
        assert out["verdict"] == "correct"
        assert marker.encode() in runner.request.prompt
        assert all(marker not in arg for arg in runner.request.provider_argv)
        log_path = launcher._results_dir("RID_LARGE") / "run.json"
        raw = log_path.read_bytes()
        assert marker.encode() not in raw
        record = json.loads(raw)
        assert set(record) == {
            "duration_ms", "input_sha256", "rc", "run_id", "schema",
            "stdout_bytes", "stdout_sha256",
        }
        assert record["run_id"] == "RID_LARGE" and record["rc"] == 0
        assert stat.S_IMODE(log_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(log_path.parent.stat().st_mode) == 0o700


def test_provider_environment_and_isolation_paths_are_exactly_minimal():
    forbidden = {
        "DANUS_WEB_PASSWORD_HASH": "web-secret-marker",
        "GH_TOKEN": "github-secret-marker",
        "CLOUDFLARE_API_TOKEN": "cloudflare-secret-marker",
        "DANUS_WEB_LIFECYCLE_CAPABILITY": "lifecycle-secret-marker",
        "DANUS_ARTIFACT_CAPABILITY": "artifact-secret-marker",
        "DANUS_VERIFY_CAPABILITY_SECRET_FILE": "hmac-path-secret-marker",
    }
    with _env(**forbidden):
        with _service(_STUB_OK) as runner:
            out = _run(rid="RID_ENV", runner=runner)
            assert out["verdict"] == "correct"
            request = runner.request
            assert set(request.provider_environment) <= (
                launcher._PROVIDER_ENV_ALLOWLIST
                | {
                    "CODEX_HOME", "HOME", "TMPDIR", "PATH", "LANG",
                    "PYTHONDONTWRITEBYTECODE", "PYTHONSAFEPATH",
                }
            )
            for name, marker in forbidden.items():
                assert name not in request.provider_environment
                assert marker not in "\0".join(request.provider_argv)
                assert marker.encode() not in request.prompt
            provider_home = request.provider_environment["CODEX_HOME"]
            assert provider_home == request.provider_environment["HOME"]
            assert provider_home in request.read_write_paths
            assert str(launcher._results_dir("RID_ENV")) in request.read_write_paths
            assert len(request.read_write_paths) == 2
            assert os.environ["CODEX_HOME"] not in request.read_write_paths
            assert any(
                "permissions.danus_verifier=" in arg
                and f'"{provider_home}"="deny"' in arg
                and '"/proc"="deny"' in arg
                and "network={enabled=false}" in arg
                for arg in request.provider_argv
            )


def test_subscription_auth_is_copied_to_an_isolated_provider_home():
    with tempfile.TemporaryDirectory() as tmp:
        host_home = Path(tmp) / "host-codex"
        host_home.mkdir(mode=0o700)
        host_auth = host_home / "auth.json"
        host_auth.write_text('{"tokens":"test-subscription-auth"}', encoding="utf-8")
        host_auth.chmod(0o600)
        with _env(
            CODEX_HOME=str(host_home),
            OPENAI_BASE_URL="https://provider.invalid/v1",
            OPENAI_CHATGPT_BASE_URL="https://chatgpt.invalid",
            DANUS_CODEX_API_KEY=None,
        ):
            with _service(_STUB_OK, provider_key=None) as runner:
                out = _run(rid="RID_AUTH", runner=runner)
                assert out["verdict"] == "correct"
                isolated = Path(runner.request.provider_environment["CODEX_HOME"])
                copied = isolated / "auth.json"
                assert isolated != host_home
                assert copied.read_bytes() == host_auth.read_bytes()
                assert stat.S_IMODE(isolated.stat().st_mode) == 0o700
                assert stat.S_IMODE(copied.stat().st_mode) == 0o600
                assert str(host_home) not in runner.request.provider_environment.values()


def test_run_timeout_504():
    with _service(_STUB_SLOW, timeout="1") as runner:
        try:
            _run(runner=runner)
            assert False, "expected 504"
        except HTTPException as e:
            assert e.status_code == 504 and "timed out" in e.detail


def test_clean_provider_exit_cannot_leave_a_forked_child():
    with _service(_STUB_FORK) as runner:
        out = _run(rid="RID_FORK", runner=runner)
        assert out["verdict"] == "correct"
        pid_path = launcher._results_dir("RID_FORK") / "fork-child.pid"
        child_pid = int(pid_path.read_text(encoding="ascii"))
        assert not Path("/proc", str(child_pid)).exists()


def test_provider_process_starts_at_root_not_a_worker_controlled_cwd():
    with _service(_STUB_CWD) as runner:
        out = _run(rid="RID_CWD", runner=runner)
        assert out["verdict"] == "correct"
        cwd = launcher._results_dir("RID_CWD") / "provider-cwd.txt"
        assert cwd.read_text(encoding="utf-8") == "/"


def test_run_nonzero_exit_500():
    with _service(_STUB_FAIL) as runner:
        try:
            _run(runner=runner)
            assert False, "expected 500"
        except HTTPException as e:
            assert e.status_code == 500
            assert e.detail == "verifier provider exited unsuccessfully"


def test_run_missing_output_500():
    with _service(_STUB_NOOUT) as runner:
        try:
            _run(runner=runner)
            assert False, "expected 500"
        except HTTPException as e:
            assert e.status_code == 500 and "was not found" in e.detail


def test_run_bad_json_500():
    with _service(_STUB_BADJSON) as runner:
        try:
            _run(runner=runner)
            assert False, "expected 500"
        except HTTPException as e:
            assert e.status_code == 500 and "not valid JSON" in e.detail


def test_run_non_dict_json_500():
    with _service(_STUB_NONDICT) as runner:
        try:
            _run(runner=runner)
            assert False, "expected 500"
        except HTTPException as e:
            assert e.status_code == 500 and "must be a JSON object" in e.detail


def test_ensure_agent_home_provisions_missing_home():
    # A fresh checkout has no verify agent home; ensure_agent_home builds it
    # (AGENTS.md = verifier contract, .agents/skills = verify skills) so the codex
    # -C dir exists. Regression for the live-found bug: service 500 on a missing home.
    with tempfile.TemporaryDirectory(prefix="verify_home_") as d:
        home = Path(d) / "agent"
        with _env(VERIFY_AGENT_HOME=str(home)):
            got = launcher.ensure_agent_home()
            assert got == home.resolve()
            agents_md = home / "AGENTS.md"
            skills = home / ".agents" / "skills"
            assert agents_md.exists(), "AGENTS.md must be provisioned"
            assert skills.exists(), ".agents/skills must be provisioned"
            # they point at the repo's canonical sources
            assert agents_md.resolve() == (launcher._REPO_ROOT / "agents" / "contracts" / "verifier.md").resolve()
            assert skills.resolve() == (launcher._REPO_ROOT / "agents" / "skills" / "verify").resolve()
            # idempotent: a second call is a no-op and still valid
            launcher.ensure_agent_home()
            assert agents_md.exists() and skills.exists()


@pytest.mark.parametrize(
    ("name", "resolver"),
    [
        ("VERIFY_AGENT_HOME", launcher._agent_home),
        ("DANUS_VERIFY_PROVIDER_HOME", launcher._provider_home_path),
        ("VERIFIER_RESULTS_DIR", launcher._results_root),
    ],
)
@pytest.mark.parametrize(
    "unsafe",
    [Path("/"), Path("/tmp"), Path.home(), launcher._REPO_ROOT],
)
def test_configured_verifier_directories_reject_broad_roots_without_chmod(
    name, resolver, unsafe,
):
    mode_before = stat.S_IMODE(unsafe.stat().st_mode)
    with _env(**{name: str(unsafe)}):
        with pytest.raises(
            launcher.VerifierProviderConfigurationError,
            match=r"^verifier .+ is unsafe$",
        ) as caught:
            resolver()
    assert str(unsafe) not in str(caught.value)
    assert stat.S_IMODE(unsafe.stat().st_mode) == mode_before


def test_configured_verifier_directories_accept_dedicated_temp_paths():
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        with _env(
            VERIFY_AGENT_HOME=str(root / "agent"),
            DANUS_VERIFY_PROVIDER_HOME=str(root / "provider"),
            VERIFIER_RESULTS_DIR=str(root / "results"),
        ):
            assert launcher._agent_home() == root / "agent"
            assert launcher._provider_home_path() == root / "provider"
            assert launcher._results_root() == root / "results"


def test_certificate_overrides_cannot_bind_a_broad_or_private_host_path():
    marker = str(Path.home())
    for name in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
        with pytest.raises(
            launcher.VerifierProviderConfigurationError,
            match=r"^verifier certificate configuration is unsafe$",
        ) as caught:
            launcher._validated_certificate_path(name, marker)
        assert marker not in str(caught.value)


def test_system_certificate_directory_is_accepted_when_present():
    candidates = [path for path in launcher._CERTIFICATE_ROOTS if path.is_dir()]
    if not candidates:
        pytest.skip("host has no supported system certificate directory")
    assert launcher._validated_certificate_path(
        "SSL_CERT_DIR", str(candidates[0]),
    ) == str(candidates[0].resolve())


def main() -> None:
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  [ok] {name}")
    print("ALL LAUNCHER TESTS PASSED")


if __name__ == "__main__":
    main()
