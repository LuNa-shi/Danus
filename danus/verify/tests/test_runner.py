from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import pytest

from danus.verify import runner, trusted_python, wire


def _request(tmp_path: Path) -> runner.VerifierRunRequest:
    return runner.VerifierRunRequest(
        run_id="RID",
        entry_argv=runner.trusted_entry_argv(),
        provider_argv=("/bin/true", "exec", "--ignore-user-config", "--strict-config", "-"),
        provider_environment={"PATH": "/usr/bin:/bin"},
        prompt=b"secret statement and proof",
        timeout_seconds=5,
        read_only_paths=("/usr",),
        read_write_paths=(str(tmp_path),),
    )


def test_runner_request_repr_never_discloses_prompt_or_environment(tmp_path: Path):
    request = _request(tmp_path)
    rendered = repr(request)
    assert "secret statement" not in rendered
    assert "provider_environment" not in rendered


def test_runner_rejects_missing_descendant_empty_proof(tmp_path: Path):
    class DirtyAdapter:
        def run(self, request):
            return runner.VerifierRunResult(
                returncode=0,
                duration_seconds=0.1,
                stdout_sha256=hashlib.sha256(b"").hexdigest(),
                stdout_bytes=0,
                descendants_empty=False,
            )

    with pytest.raises(
        runner.TrustedVerifierUnavailable,
        match="^verifier security boundary unavailable$",
    ):
        runner.run_with_trusted_supervisor(_request(tmp_path), adapter=DirtyAdapter())


def test_runner_redacts_untyped_adapter_errors(tmp_path: Path):
    marker = "provider-secret-must-not-reflect"

    class ExplodingAdapter:
        def run(self, request):
            raise RuntimeError(marker)

    with pytest.raises(runner.TrustedVerifierUnavailable) as caught:
        runner.run_with_trusted_supervisor(_request(tmp_path), adapter=ExplodingAdapter())
    assert str(caught.value) == "verifier security boundary unavailable"
    assert marker not in str(caught.value)


def test_framing_handles_large_prompt_and_rejects_truncation():
    prompt = b"P" * (3 << 20)
    frame = wire.encode_request(
        run_id="RID",
        provider_argv=("/bin/true", "exec", "-"),
        provider_environment={"PATH": "/usr/bin:/bin"},
        timeout_seconds=5,
        prompt=prompt,
    )
    header, decoded = wire.read_request(io.BytesIO(frame))
    assert header["run_id"] == "RID" and decoded == prompt
    with pytest.raises(wire.VerifierFrameError):
        wire.read_request(io.BytesIO(frame[:-1]))


def test_fixed_entry_rejects_bypass_without_reflecting_frame(tmp_path: Path):
    fake = tmp_path / "provider"
    fake.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    fake.chmod(0o700)
    frame = wire.encode_request(
        run_id="RID",
        provider_argv=(
            str(fake), "exec", "--ignore-user-config", "--strict-config",
            'approval_policy="never"', 'default_permissions="danus_verifier"',
            "--dangerously-bypass-approvals-and-sandbox", "-",
        ),
        provider_environment={"PATH": "/usr/bin:/bin"},
        timeout_seconds=5,
        prompt=b"candidate-secret-marker",
    )
    completed = subprocess.run(
        runner.trusted_entry_argv(), cwd=str(tmp_path),
        env={"PATH": os.defpath, "LANG": "C.UTF-8"},
        input=frame, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=10, check=False,
    )
    assert completed.returncode == 70
    assert completed.stdout == b"" and completed.stderr == b""


@pytest.mark.parametrize("injected", [
    'approval_policy="on-request"',
    'mcp_servers.evil={command="/bin/true"}',
])
def test_fixed_entry_rejects_duplicate_or_unknown_config(
    tmp_path: Path, injected: str,
):
    fake = tmp_path / "provider"
    fake.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    fake.chmod(0o700)
    # The minimal request helper lacks the full launcher's configs; use a real
    # launch command captured through its explicit private test seam.
    from danus.verify import launcher

    old = {
        name: os.environ.get(name)
        for name in (
            "DANUS_CODEX_BIN", "VERIFIER_RESULTS_DIR", "VERIFY_AGENT_HOME",
            "DANUS_VERIFY_PROVIDER_HOME", "OPENAI_API_KEY",
        )
    }
    try:
        os.environ.pop("DANUS_CODEX_BIN", None)
        os.environ["VERIFIER_RESULTS_DIR"] = str(tmp_path / "runs")
        os.environ["VERIFY_AGENT_HOME"] = str(tmp_path / "agent")
        os.environ["DANUS_VERIFY_PROVIDER_HOME"] = str(tmp_path / "provider-home")
        os.environ["OPENAI_API_KEY"] = "test-only-provider-key"
        (tmp_path / "agent").mkdir()
        (tmp_path / "runs" / "RID").mkdir(parents=True)
        command = launcher.build_codex_command(
            "RID", _test_provider_bin=str(fake),
        )
        environment = launcher._provider_environment(command)
    finally:
        for name, value in old.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    command[-1:-1] = ["--config", injected]
    frame = wire.encode_request(
        run_id="RID", provider_argv=command,
        provider_environment=environment, timeout_seconds=5,
        prompt=b"candidate-secret-marker",
    )
    process = subprocess.Popen(
        runner.trusted_entry_argv(), cwd="/",
        env={"PATH": os.defpath, "LANG": "C.UTF-8"},
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    assert process.stdin is not None and process.stdout is not None
    challenge = os.urandom(32)
    process.stdin.write(wire.encode_challenge(challenge))
    process.stdin.flush()
    wire.read_ready(process.stdout, challenge=challenge)
    process.stdin.write(frame)
    process.stdin.close()
    process.stdin = None
    stdout, stderr = process.communicate(timeout=10)
    assert process.returncode == 70
    assert stdout == b"" and stderr == b""


def test_isolated_mcp_entry_cannot_import_worker_cwd_shadow_module(tmp_path: Path):
    marker = tmp_path / "shadow-imported"
    (tmp_path / "danus.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n",
        encoding="utf-8",
    )
    entry = Path(__file__).resolve().parents[1] / "mcp_entry.py"
    completed = subprocess.run(
        (sys.executable, "-I", str(entry.resolve())),
        cwd=str(tmp_path),
        env={
            "PATH": os.defpath,
            "LANG": "C.UTF-8",
            "PYTHONPATH": str(tmp_path),
            "OPENAI_API_KEY": "must-be-scrubbed-before-import",
        },
        input=b"", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=10, check=False,
    )
    assert completed.returncode == 0
    assert not marker.exists()


def test_trusted_python_accepts_owned_intermediate_install_symlink(monkeypatch):
    with tempfile.TemporaryDirectory(dir=Path.cwd()) as raw_tmp:
        root = Path(raw_tmp)
        versioned = root / "python-3.11.15"
        (versioned / "bin").mkdir(parents=True)
        executable = versioned / "bin" / "python3.11"
        executable.write_bytes(b"test executable")
        executable.chmod(0o755)

        alias = root / "python-3.11"
        alias.symlink_to(versioned, target_is_directory=True)
        venv = root / "venv"
        (venv / "bin").mkdir(parents=True)
        lexical = venv / "bin" / "python"
        lexical.symlink_to(alias / "bin" / "python3.11")
        (venv / "pyvenv.cfg").write_text("home = test\n", encoding="utf-8")

        monkeypatch.setattr(trusted_python.sys, "executable", str(lexical))
        monkeypatch.setattr(trusted_python.sys, "prefix", str(venv))
        monkeypatch.setattr(trusted_python.sys, "base_prefix", str(versioned))

        assert trusted_python.trusted_python_executable() == str(lexical)
