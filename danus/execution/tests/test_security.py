"""Adversarial tests for the Worker provider and command trust boundaries."""

from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

from danus.execution import layout as L
from danus.execution import security, systemd_scope
from danus.gateway.fd_protocol import PROVIDER_SOCKET_PATH


@contextmanager
def _env(**values):
    old = {name: os.environ.get(name) for name in values}
    try:
        for name, value in values.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = str(value)
        yield
    finally:
        for name, value in old.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _worker(tmp: Path) -> L.WorkerLayout:
    wl = L.WorkerLayout(tmp / "projects" / "Project-A" / "workers" / "high")
    wl.dir.mkdir(parents=True)
    return wl


def _host_auth(tmp: Path, marker: bytes = b"private-subscription-marker") -> Path:
    home = tmp / "host-codex-home"
    home.mkdir(mode=0o700)
    auth = home / "auth.json"
    auth.write_bytes(marker)
    auth.chmod(0o600)
    return home


def _fake_official_package(
    root: Path, *, native_symlink: bool = False, bwrap_symlink: bool = False,
) -> tuple[Path, Path, Path]:
    """Build a metadata-shaped package for selector adversarial tests."""

    package = root / "lib" / "node_modules" / "@openai" / "codex"
    machine = os.uname().machine
    targets = {
        "x86_64": ("codex-linux-x64", "x86_64-unknown-linux-musl", "linux-x64", "x64"),
        "aarch64": (
            "codex-linux-arm64", "aarch64-unknown-linux-musl", "linux-arm64", "arm64",
        ),
    }
    package_name, target, version_suffix, cpu = targets[machine]
    native_package = package / "node_modules" / "@openai" / package_name
    vendor = native_package / "vendor" / target
    entry = package / "bin" / "codex.js"
    native = vendor / "bin" / "codex"
    bwrap = vendor / "codex-resources" / "bwrap"
    for path in (entry, native, bwrap):
        path.parent.mkdir(parents=True, exist_ok=True)
    entry.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    entry.chmod(0o755)
    (package / "package.json").write_text(json.dumps({
        "name": "@openai/codex", "version": "0.148.0",
        "bin": {"codex": "bin/codex.js"},
    }), encoding="utf-8")
    (native_package / "package.json").write_text(json.dumps({
        "name": "@openai/codex", "version": f"0.148.0-{version_suffix}",
        "os": ["linux"], "cpu": [cpu],
    }), encoding="utf-8")
    if native_symlink:
        evil = root / "evil-provider"
        evil.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
        evil.chmod(0o755)
        native.symlink_to(evil)
    else:
        native.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        native.chmod(0o755)
    if bwrap_symlink:
        evil_bwrap = root / "evil-bwrap"
        evil_bwrap.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
        evil_bwrap.chmod(0o755)
        bwrap.symlink_to(evil_bwrap)
    else:
        bwrap.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        bwrap.chmod(0o755)
    return entry, native, bwrap


def test_provider_environment_is_allowlisted_and_auth_is_project_external(tmp: Path):
    wl = _worker(tmp)
    host_home = _host_auth(tmp)
    sensitive = {
        "GITHUB_TOKEN": "github-secret-marker",
        "CLOUDFLARE_API_TOKEN": "cloudflare-secret-marker",
        "DANUS_WEB_PASSWORD": "web-secret-marker",
        "DANUS_VERIFY_CAPABILITY": "capability-secret-marker",
        "DATABASE_URL": "database-secret-marker",
    }
    with _env(
        CODEX_HOME=host_home,
        DANUS_RUNTIME=tmp / "runtime",
        OPENAI_API_KEY=None,
        DANUS_CODEX_API_KEY=None,
        **sensitive,
    ):
        provider_env = security.worker_provider_env(wl)
        args = security.codex_security_args(wl, Path(PROVIDER_SOCKET_PATH))
        isolated_home = security.provider_home(wl)

    assert set(sensitive).isdisjoint(provider_env)
    assert provider_env["CODEX_HOME"] == str(isolated_home)
    assert Path(provider_env["TMPDIR"]).parent == isolated_home
    assert isolated_home not in wl.project_dir.resolve().parents
    assert wl.project_dir.resolve() not in isolated_home.parents
    copied_auth = isolated_home / "auth.json"
    assert copied_auth.read_bytes() == (host_home / "auth.json").read_bytes()
    assert stat.S_IMODE(copied_auth.stat().st_mode) == 0o600
    assert stat.S_IMODE(isolated_home.stat().st_mode) == 0o700

    flat_args = "\0".join(args)
    assert security.codex_global_security_args() == ["--search"]
    assert "--ignore-user-config" in args and "--ignore-rules" in args
    assert "dangerously-bypass" not in flat_args and "sandbox_mode" not in flat_args
    assert str(isolated_home) in flat_args and PROVIDER_SOCKET_PATH in flat_args
    assert '"/proc"="deny"' in flat_args and "network={enabled=false" in flat_args
    for marker in sensitive.values():
        assert marker not in flat_args


def test_provider_state_and_model_tmp_refuse_symlinks(tmp: Path):
    wl = _worker(tmp)
    runtime = tmp / "runtime"
    runtime.mkdir()
    outside = tmp / "outside"
    outside.mkdir()
    (runtime / security.PROVIDER_STATE_DIR_NAME).symlink_to(outside, target_is_directory=True)
    with _env(DANUS_RUNTIME=runtime, CODEX_HOME=None):
        with pytest.raises(security.WorkerSecurityError, match="unavailable or unsafe"):
            security.provider_home(wl)

    model_outside = tmp / "model-outside"
    model_outside.mkdir()
    (wl.dir / security.MODEL_TMP_NAME).symlink_to(model_outside, target_is_directory=True)
    with pytest.raises(security.WorkerSecurityError, match="unavailable or unsafe"):
        security.model_tmp(wl)


def test_repo_launcher_resolves_to_provisioned_official_codex(tmp: Path):
    repo = Path(__file__).resolve().parents[3]
    node = repo / "runtime" / "node22" / "bin" / "node"
    entrypoint = repo / "runtime" / "codex-npm" / "lib" / "node_modules" / "@openai" / "codex" / "bin" / "codex.js"
    if not node.is_file() or not entrypoint.is_file():
        pytest.skip("provisioned Codex runtime is not present")
    with _env(DANUS_NODE=node, DANUS_CODEX_JS=entrypoint):
        resolved = security.resolve_worker_codex_bin(str(repo / "bin" / "codex"))
    native = Path(resolved).resolve()
    assert native.name == "codex"
    assert "@openai" in native.parts
    assert (native.parent.parent / "codex-resources" / "bwrap").is_file()


def test_arbitrary_provider_selector_cannot_bypass_official_codex(tmp: Path):
    """Host config may select only the provisioned upstream Codex runtime.

    An arbitrary executable would run before/without Codex's enforced inner
    permission profile and could read the provider auth mount/environment.
    The deterministic fake-provider seam therefore belongs in Python tests,
    never in ``DANUS_CODEX_BIN`` or another production environment setting.
    """
    repo = Path(__file__).resolve().parents[3]
    entrypoint = (
        repo / "runtime" / "codex-npm" / "lib" / "node_modules"
        / "@openai" / "codex" / "bin" / "codex.js"
    )
    if not entrypoint.is_file():
        pytest.skip("provisioned Codex runtime is not present")
    arbitrary = tmp / "codex"
    arbitrary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    arbitrary.chmod(0o700)

    with _env(DANUS_CODEX_JS=entrypoint, DANUS_CODEX_BIN=arbitrary):
        with pytest.raises(
            security.WorkerSecurityError,
            match="selector is not the validated upstream",
        ):
            security.resolve_worker_codex_bin(str(arbitrary))


def test_codex_selector_rejects_a_metadata_spoof_outside_trusted_install(tmp: Path):
    """A semver/name-shaped package in /tmp is not an official runtime."""

    entry, _native, _bwrap = _fake_official_package(tmp / "lookalike")
    with _env(DANUS_CODEX_JS=entry, DANUS_CODEX_BIN=entry):
        with pytest.raises(
            security.WorkerSecurityError,
            match="provisioned|install root",
        ):
            security.resolve_worker_codex_bin(str(entry))


def test_codex_selector_rejects_native_symlink_even_under_trusted_install(
    tmp: Path, monkeypatch,
):
    """The native executable and bwrap must be real package files, not links."""

    trusted = tmp / "trusted-codex"
    entry, _native, _bwrap = _fake_official_package(
        trusted, native_symlink=True,
    )
    monkeypatch.setattr(security, "_CODEX_INSTALL_ROOT", trusted)
    with _env(DANUS_CODEX_JS=entry, DANUS_CODEX_BIN=entry):
        with pytest.raises(security.WorkerSecurityError, match="symbolic link|identity"):
            security.resolve_worker_codex_bin(str(entry))


def test_codex_selector_rejects_bwrap_symlink_even_under_trusted_install(
    tmp: Path, monkeypatch,
):
    """A linked sandbox helper cannot inherit the provider credentials."""

    trusted = tmp / "trusted-codex"
    entry, _native, _bwrap = _fake_official_package(
        trusted, bwrap_symlink=True,
    )
    monkeypatch.setattr(security, "_CODEX_INSTALL_ROOT", trusted)
    with _env(DANUS_CODEX_JS=entry, DANUS_CODEX_BIN=entry):
        with pytest.raises(security.WorkerSecurityError, match="symbolic link|identity"):
            security.resolve_worker_codex_bin(str(entry))


def test_outer_provider_sink_revalidates_official_selector(tmp: Path, monkeypatch):
    """A caller cannot bypass the loop gate by invoking the outer sink directly."""

    trusted = tmp / "trusted-codex"
    entry, _native, _bwrap = _fake_official_package(trusted)
    monkeypatch.setattr(security, "_CODEX_INSTALL_ROOT", trusted)
    arbitrary = tmp / "arbitrary-provider"
    arbitrary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    arbitrary.chmod(0o755)
    wl = _worker(tmp / "worker")
    with _env(DANUS_CODEX_JS=entry):
        with pytest.raises(security.WorkerSecurityError, match="selector"):
            security.outer_sandbox_command(
                wl, str(arbitrary), [str(arbitrary)],
                ready_challenge=b"x" * 16, socket_dev=1, socket_ino=1,
            )


def test_provider_scope_sink_revalidates_before_manager_access(tmp: Path, monkeypatch):
    """The systemd scope entrypoint has the same deep selector invariant."""

    trusted = tmp / "trusted-codex"
    entry, _native, _bwrap = _fake_official_package(trusted)
    monkeypatch.setattr(security, "_CODEX_INSTALL_ROOT", trusted)
    arbitrary = tmp / "arbitrary-provider"
    arbitrary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    arbitrary.chmod(0o755)
    wl = _worker(tmp / "worker")
    gateway = type("Gateway", (), {})()
    with _env(DANUS_CODEX_JS=entry):
        with pytest.raises(security.WorkerSecurityError, match="selector"):
            systemd_scope.start_provider_scope(
                wl, codex_bin=str(arbitrary), provider_command=[str(arbitrary)],
                provider_environment={}, gateway=gateway, runtime_limit=30,
            )


def test_provider_launcher_fails_closed_outside_private_pid_namespace(tmp: Path):
    completed = subprocess.run(
        [
            sys.executable, str(Path(security.__file__).parent / "provider_launcher.py"),
            "--ready-challenge", "00" * 16,
            "--socket-dev", "1", "--socket-ino", "1",
            "--", "/usr/bin/true",
        ],
        cwd=tmp,
        env={"PATH": os.defpath, "PYTHONDONTWRITEBYTECODE": "1"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=20,
        check=False,
    )
    assert completed.returncode == 126
    assert "failed closed" in completed.stderr


def test_real_codex_profile_blocks_secrets_proc_network_and_gateway_socket(tmp: Path):
    """Run a deterministic command through Codex's real inner bubblewrap."""
    if sys.platform != "linux":
        pytest.skip("real Codex Linux sandbox prerequisites are unavailable")
    repo = Path(__file__).resolve().parents[3]
    node = repo / "runtime" / "node22" / "bin" / "node"
    entrypoint = repo / "runtime" / "codex-npm" / "lib" / "node_modules" / "@openai" / "codex" / "bin" / "codex.js"
    if not node.is_file() or not entrypoint.is_file():
        pytest.skip("provisioned Codex runtime is not present")

    wl = _worker(tmp)
    sibling = wl.project_dir.parent / "Project-B"
    sibling.mkdir()
    sibling_secret = sibling / "secret"
    sibling_secret.write_text("sibling-secret-marker", encoding="utf-8")
    materials = wl.project_dir / "materials"
    materials.mkdir()
    material = materials / "blob"
    material.write_text("immutable-material", encoding="utf-8")
    staging = wl.project_dir.parent / ".danus-web-control-staging"
    staging.mkdir()
    staged = staging / "pending"
    staged.write_text("control-only", encoding="utf-8")
    host_home = _host_auth(tmp, b"host-auth-secret-marker")
    with _env(
        CODEX_HOME=host_home,
        DANUS_RUNTIME=tmp / "runtime",
        DANUS_NODE=node,
        DANUS_CODEX_JS=entrypoint,
    ):
        isolated_home = security.provider_home(wl)
        profile = security.permission_profile_override(wl, Path(PROVIDER_SOCKET_PATH))
    isolated_auth = isolated_home / "auth.json"

    security.prepare_broker_dir(wl)
    gateway_path = Path(PROVIDER_SOCKET_PATH)
    if gateway_path.exists():
        pytest.skip("fixed provider gateway path is already in use")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(gateway_path))
    listener.listen(1)

    holder_env = {"PATH": os.defpath, "DANUS_HOLDER_SECRET": "proc-secret-marker"}
    holder = subprocess.Popen(
        ["/usr/bin/sleep", "20"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=holder_env,
    )
    workspace = security.model_workspace(wl)
    result_path = workspace / "inner-sandbox-result.json"
    probe = f"""
import json, socket
from pathlib import Path
result = {{}}
worker = Path({str(workspace)!r})
(worker / 'inner-write-ok').write_text('ok')
result['project_write'] = (worker / 'inner-write-ok').read_text() == 'ok'
result['material_read'] = Path({str(material)!r}).read_text() == 'immutable-material'
for name, path in {{
    'sibling_read': Path({str(sibling_secret)!r}),
    'host_auth_read': Path({str(host_home / 'auth.json')!r}),
    'isolated_auth_read': Path({str(isolated_auth)!r}),
    'proc_environ_read': Path('/proc/{holder.pid}/environ'),
    'staging_read': Path({str(staged)!r}),
}}.items():
    try:
        path.read_bytes()
        result[name] = True
    except OSError:
        result[name] = False
try:
    Path({str(material)!r}).write_text('poisoned')
    result['material_write'] = True
except OSError:
    result['material_write'] = False
for name, address in {{
    'tcp_8080': ('127.0.0.1', 8080),
    'tcp_8091': ('127.0.0.1', 8091),
    'tcp_external': ('1.1.1.1', 443),
}}.items():
    try:
        conn = socket.create_connection(address, timeout=0.5)
        conn.close()
        result[name] = True
    except OSError:
        result[name] = False
uds = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    uds.settimeout(0.5)
    uds.connect({PROVIDER_SOCKET_PATH!r})
    result['gateway_socket'] = True
except OSError:
    result['gateway_socket'] = False
finally:
    uds.close()
Path({str(result_path)!r}).write_text(json.dumps(result))
"""
    cli_home = tmp / "sandbox-cli-home"
    cli_home.mkdir(mode=0o700)
    command = [
        str(node), str(entrypoint), "sandbox",
        "-c", f"permissions.danus_worker={profile}",
        "-P", "danus_worker", "-C", str(wl.dir), "--",
        "/usr/bin/python3", "-c", probe,
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=wl.dir,
            env={
                "CODEX_HOME": str(cli_home),
                "HOME": str(wl.dir),
                "PATH": f"{node.parent}{os.pathsep}{os.defpath}",
                "TMPDIR": str(security.model_tmp(wl)),
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            check=False,
        )
    finally:
        holder.terminate()
        holder.wait(timeout=5)
        listener.close()
        gateway_path.unlink(missing_ok=True)
    assert completed.returncode == 0, completed.stderr[-2000:]
    result = json.loads(result_path.read_text(encoding="utf-8"))
    assert result == {
        "project_write": True,
        "material_read": True,
        "sibling_read": False,
        "host_auth_read": False,
        "isolated_auth_read": False,
        "proc_environ_read": False,
        "staging_read": False,
        "material_write": False,
        "tcp_8080": False,
        "tcp_8091": False,
        "tcp_external": False,
        "gateway_socket": False,
    }
