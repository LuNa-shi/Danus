"""Fixed isolated-Python entry for one verifier provider execution.

Production starts this absolute file as ``python -I ...`` with ``cwd=/`` inside
a dedicated transient service.  The candidate statement/proof, provider argv,
and credential environment arrive only through the private framed stdin pipe.
Provider stdout is discarded after hashing; only metadata is emitted.
"""

from __future__ import annotations

import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit


_HERE = Path(__file__).resolve().parent
_WIRE_PATH = (_HERE / "wire.py").resolve()
_CODEX_INSTALL_ROOT = _HERE.parents[1] / "runtime" / "codex-npm"
_CODEX_PACKAGE = _CODEX_INSTALL_ROOT / "lib" / "node_modules" / "@openai" / "codex"
_ENV_KEYS = {
    "CODEX_HOME", "HOME", "PATH", "LANG", "TMPDIR",
    "PYTHONDONTWRITEBYTECODE", "PYTHONSAFEPATH",
    "OPENAI_API_KEY", "DANUS_CODEX_API_KEY",
    "OPENAI_BASE_URL", "CODEX_API_BASE_URL",
    "OPENAI_CHATGPT_BASE_URL", "CODEX_CHATGPT_BASE_URL",
    "SSL_CERT_FILE", "SSL_CERT_DIR",
}
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_MAX_OUTPUT_BYTES = 16 << 20
_PR_SET_DUMPABLE = 4
_SHELL_SET_RE = re.compile(
    r'^shell_environment_policy\.set=\{PATH="/usr/local/bin:/usr/bin:/bin",'
    r'HOME=(?P<home>"(?:\\.|[^"\\])*"),LANG="C\.UTF-8",'
    r'TMPDIR=(?P<tmp>"(?:\\.|[^"\\])*")\}$'
)


def _reject_symlink_components(path: Path, label: str) -> None:
    if not path.is_absolute():
        raise ValueError(f"{label} must be absolute")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            if stat.S_ISLNK(current.lstat().st_mode):
                raise ValueError(f"{label} contains a symbolic link")
        except OSError as exc:
            raise ValueError(f"{label} is unavailable") from exc


def _safe_metadata(path: Path, label: str) -> dict[str, object]:
    _reject_symlink_components(path, label)
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.getuid()}
                or info.st_mode & 0o002 or info.st_size > (1 << 20)):
            raise ValueError(f"{label} is unsafe")
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
        try:
            value = json.loads(os.read(fd, (1 << 20) + 1))
        finally:
            os.close(fd)
    except ValueError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is unavailable") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} is unsafe")
    return value


def _official_native_binary() -> Path:
    """Derive the native CLI from the code-relative, fixed bootstrap root."""
    package = _CODEX_PACKAGE
    _reject_symlink_components(package, "Codex package")
    try:
        package_info = package.lstat()
        if (not stat.S_ISDIR(package_info.st_mode)
                or package_info.st_uid not in {0, os.getuid()}
                or package_info.st_mode & 0o002):
            raise ValueError("Codex package is unsafe")
    except OSError as exc:
        raise ValueError("Codex package is unavailable") from exc
    metadata = _safe_metadata(package / "package.json", "Codex package metadata")
    version = metadata.get("version")
    if (metadata.get("name") != "@openai/codex"
            or not isinstance(version, str)
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?", version)
            or metadata.get("bin") != {"codex": "bin/codex.js"}):
        raise ValueError("Codex package metadata is unsafe")
    targets = {
        "x86_64": ("codex-linux-x64", "x86_64-unknown-linux-musl", "linux-x64", "x64"),
        "aarch64": ("codex-linux-arm64", "aarch64-unknown-linux-musl", "linux-arm64", "arm64"),
    }
    try:
        package_name, target, suffix, cpu = targets[os.uname().machine]
    except KeyError as exc:
        raise ValueError("Codex native package is unsupported") from exc
    native_package = package / "node_modules" / "@openai" / package_name
    _reject_symlink_components(native_package, "Codex native package")
    native_metadata = _safe_metadata(native_package / "package.json", "Codex native metadata")
    if (native_metadata.get("name") != "@openai/codex"
            or native_metadata.get("version") != f"{version}-{suffix}"
            or native_metadata.get("os") != ["linux"]
            or native_metadata.get("cpu") != [cpu]):
        raise ValueError("Codex native metadata is unsafe")
    native_root = native_package / "vendor" / target
    entry = package / "bin" / "codex.js"
    bwrap = native_root / "codex-resources" / "bwrap"
    for path, label, executable in (
        (entry, "Codex entry", True), (native_root / "bin" / "codex", "Codex native", True),
        (bwrap, "Codex bubblewrap", True),
    ):
        _reject_symlink_components(path, label)
        try:
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.getuid()}
                    or info.st_mode & 0o002 or (executable and not info.st_mode & 0o111)):
                raise ValueError(f"{label} is unsafe")
        except OSError as exc:
            raise ValueError(f"{label} is unavailable") from exc
    return native_root / "bin" / "codex"


def _load_wire():
    spec = importlib.util.spec_from_file_location("_danus_verify_wire", _WIRE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("verifier wire protocol unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _nondumpable() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def _safe_provider_binary(value: str) -> str:
    if not value or not os.path.isabs(value):
        raise ValueError("provider binary must be absolute")
    path = Path(value)
    expected = _official_native_binary()
    if path != expected:
        raise ValueError("provider binary is not the official native Codex")
    return str(expected)


def _safe_endpoint(value: str) -> str:
    try:
        parsed = urlsplit(value)
        valid = (
            parsed.scheme in {"http", "https"}
            and bool(parsed.hostname)
            and parsed.username is None
            and parsed.password is None
            and not parsed.query
            and not parsed.fragment
            and not any(char.isspace() or ord(char) < 0x20 for char in value)
        )
        parsed.port
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("unsafe verifier provider route")
    return value


def _expected_routing_configs(environment: dict[str, str]) -> set[str]:
    base = environment.get("OPENAI_BASE_URL") or environment.get("CODEX_API_BASE_URL")
    chat = (
        environment.get("OPENAI_CHATGPT_BASE_URL")
        or environment.get("CODEX_CHATGPT_BASE_URL")
    )
    key_name = (
        "OPENAI_API_KEY" if environment.get("OPENAI_API_KEY")
        else "DANUS_CODEX_API_KEY" if environment.get("DANUS_CODEX_API_KEY")
        else None
    )
    if base:
        base = _safe_endpoint(base)
    if chat:
        chat = _safe_endpoint(chat)
    if base and key_name:
        provider = "danus_direct"
        details = f"model_providers.{provider}={{" + ",".join([
            f"name={json.dumps('Danus Direct API')}",
            f"base_url={json.dumps(base)}",
            f"env_key={json.dumps(key_name)}",
            f"wire_api={json.dumps('responses')}",
        ]) + "}"
        return {f'model_provider="{provider}"', details}
    if base and chat:
        provider = "danus_subscription"
        details = f"model_providers.{provider}={{" + ",".join([
            f"name={json.dumps('Danus Subscription Proxy')}",
            f"base_url={json.dumps(base)}",
            f"wire_api={json.dumps('responses')}",
            "requires_openai_auth=true",
            "supports_websockets=false",
        ]) + "}"
        return {
            'cli_auth_credentials_store="file"',
            f"chatgpt_base_url={json.dumps(chat)}",
            f'model_provider="{provider}"',
            details,
        }
    if base or chat:
        raise ValueError("unsafe verifier provider route")
    return set()


def _validate_provider_command(argv: list[str], environment: dict[str, str]) -> tuple[str, ...]:
    """Accept only the launcher's fixed command grammar and critical overrides."""
    argv[0] = _safe_provider_binary(argv[0])
    no_value = {
        "--ignore-user-config", "--ignore-rules", "--strict-config",
        "--skip-git-repo-check",
    }
    with_value = {"--config", "-c", "--model", "-C"}
    counts: dict[str, int] = {}
    configs: list[str] = []
    index = 2
    while index < len(argv) - 1:
        option = argv[index]
        counts[option] = counts.get(option, 0) + 1
        if option in no_value:
            index += 1
            continue
        if option not in with_value or index + 1 >= len(argv) - 1:
            raise ValueError("unsafe verifier provider command")
        value = argv[index + 1]
        if option in {"--config", "-c"}:
            configs.append(value)
        elif option == "-C" and not os.path.isabs(value):
            raise ValueError("unsafe verifier provider command")
        index += 2
    if (
        argv[1] != "exec"
        or argv[-1] != "-"
        or any(counts.get(flag) != 1 for flag in no_value | {"--model", "-C"})
    ):
        raise ValueError("unsafe verifier provider command")

    config_keys = [value.split("=", 1)[0] for value in configs]
    allowed_config_keys = {
        "approval_policy",
        "allow_login_shell",
        "chatgpt_base_url",
        "cli_auth_credentials_store",
        "default_permissions",
        "mcp_servers.danus",
        "model_provider",
        "model_providers.danus_direct",
        "model_providers.danus_subscription",
        "model_reasoning_effort",
        "permissions.danus_verifier",
        "shell_environment_policy.ignore_default_excludes",
        "shell_environment_policy.inherit",
        "shell_environment_policy.set",
    }
    if (
        any(key not in allowed_config_keys for key in config_keys)
        or len(config_keys) != len(set(config_keys))
    ):
        raise ValueError("unsafe verifier provider configuration")

    def exactly(value: str) -> bool:
        return configs.count(value) == 1

    profiles = [value for value in configs if value.startswith("permissions.danus_verifier=")]
    mcp_entries = [value for value in configs if value.startswith("mcp_servers.danus=")]
    shell_entries = [
        value for value in configs
        if value.startswith("shell_environment_policy.set=")
    ]
    effort_entries = [
        value for value in configs if value.startswith("model_reasoning_effort=")
    ]
    routing_keys = {
        "chatgpt_base_url", "cli_auth_credentials_store", "model_provider",
        "model_providers.danus_direct", "model_providers.danus_subscription",
    }
    routing = {
        value for value, key in zip(configs, config_keys) if key in routing_keys
    }
    expected_mcp = (
        "mcp_servers.danus={"
        f"command={json.dumps(sys.executable)},"
        f"args=[\"-I\",{json.dumps(str((_HERE / 'mcp_entry.py').resolve()))}],"
        "env={PYTHONDONTWRITEBYTECODE=\"1\",PYTHONSAFEPATH=\"1\"}}"
    )
    if (
        not exactly('approval_policy="never"')
        or not exactly("allow_login_shell=false")
        or not exactly('default_permissions="danus_verifier"')
        or not exactly('shell_environment_policy.inherit="none"')
        or not exactly("shell_environment_policy.ignore_default_excludes=false")
        or len([v for v in configs if v.startswith("shell_environment_policy.set=")]) != 1
        or len([v for v in configs if v.startswith("model_reasoning_effort=")]) != 1
        or len(profiles) != 1
        or '"/proc"="deny"' not in profiles[0]
        or f'"{environment["CODEX_HOME"]}"="deny"' not in profiles[0]
        or "network={enabled=false}" not in profiles[0]
        or mcp_entries != [expected_mcp]
        or routing != _expected_routing_configs(environment)
    ):
        raise ValueError("unsafe verifier provider command")
    shell_match = _SHELL_SET_RE.fullmatch(shell_entries[0])
    try:
        shell_home = json.loads(shell_match.group("home")) if shell_match else ""
        shell_tmp = json.loads(shell_match.group("tmp")) if shell_match else ""
    except json.JSONDecodeError as exc:
        raise ValueError("unsafe verifier provider command") from exc
    effort = effort_entries[0].removeprefix("model_reasoning_effort=")
    if (
        not isinstance(shell_home, str)
        or not os.path.isabs(shell_home)
        or shell_tmp != str(Path(shell_home) / "tmp")
        or not re.fullmatch(r'"[a-z][a-z0-9_-]{0,31}"', effort)
        or f'{json.dumps(shell_home)}="write"' not in profiles[0]
    ):
        raise ValueError("unsafe verifier provider command")
    return tuple(argv)


def _validated_request(header: dict[str, object], prompt: bytes):
    if set(header) != {
        "provider_argv", "provider_environment", "run_id", "schema", "timeout_seconds",
    } or header.get("schema") != 1:
        raise ValueError("invalid verifier request schema")
    run_id = header.get("run_id")
    argv = header.get("provider_argv")
    env = header.get("provider_environment")
    timeout = header.get("timeout_seconds")
    if not isinstance(run_id, str) or not _RUN_ID_RE.fullmatch(run_id):
        raise ValueError("invalid verifier run identity")
    if (
        not isinstance(argv, list)
        or len(argv) < 3
        or any(not isinstance(item, str) or not item or "\x00" in item for item in argv)
    ):
        raise ValueError("invalid verifier provider command")
    if not isinstance(env, dict) or not env:
        raise ValueError("invalid verifier provider environment")
    clean_env: dict[str, str] = {}
    for name, value in env.items():
        if (
            not isinstance(name, str)
            or not _ENV_NAME_RE.fullmatch(name)
            or name not in _ENV_KEYS
            or not isinstance(value, str)
            or "\x00" in value
            or len(value) > (1 << 20)
        ):
            raise ValueError("unsafe verifier provider environment")
        clean_env[name] = value
    required_environment = {
        "CODEX_HOME", "HOME", "TMPDIR", "PATH", "LANG",
        "PYTHONDONTWRITEBYTECODE", "PYTHONSAFEPATH",
    }
    if (
        not required_environment <= clean_env.keys()
        or clean_env["HOME"] != clean_env["CODEX_HOME"]
        or clean_env["TMPDIR"] != str(Path(clean_env["CODEX_HOME"]) / "tmp")
        or not os.path.isabs(clean_env["CODEX_HOME"])
        or clean_env["LANG"] != "C.UTF-8"
        or clean_env["PYTHONDONTWRITEBYTECODE"] != "1"
        or clean_env["PYTHONSAFEPATH"] != "1"
    ):
        raise ValueError("unsafe verifier provider environment")
    if not isinstance(prompt, bytes) or not prompt:
        raise ValueError("invalid verifier prompt")
    if timeout is not None and (
        isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0
    ):
        raise ValueError("invalid verifier timeout")
    return _validate_provider_command(argv, clean_env), clean_env, timeout


def _kill_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _process_group_empty(process: subprocess.Popen[bytes]) -> bool:
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def _run_provider(argv: tuple[str, ...], env: dict[str, str], prompt: bytes, timeout: int | None):
    before = time.monotonic()
    timed_out = False
    with tempfile.TemporaryFile(mode="w+b", dir=env["TMPDIR"]) as output:
        process = subprocess.Popen(
            argv,
            cwd="/",
            env=env,
            stdin=subprocess.PIPE,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            process.communicate(input=prompt, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_group(process)
            process.communicate()
        # A clean provider leader exit is not permission for forked helpers to
        # survive.  Stop the whole session/process-group and wait for the kernel
        # to report it empty.  The outer transient-service adapter independently
        # verifies the stronger cgroup-empty invariant (including setsid escapes).
        _kill_group(process)
        empty_deadline = time.monotonic() + 2.0
        while not _process_group_empty(process) and time.monotonic() < empty_deadline:
            time.sleep(0.01)
        process_group_empty = _process_group_empty(process)
        duration = time.monotonic() - before
        output.flush()
        output.seek(0)
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = output.read(65536)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return {
        "duration_seconds": duration,
        "returncode": int(process.returncode),
        "process_group_empty": process_group_empty,
        "schema": 1,
        "stdout_bytes": size,
        "stdout_sha256": digest.hexdigest(),
        "timed_out": timed_out,
    }


def main() -> int:
    try:
        os.chdir("/")
        os.umask(0o077)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        # Limit provider writes to the anonymous stdout sink.  The verifier JSON
        # itself is small and written through a separate filesystem descriptor.
        resource.setrlimit(resource.RLIMIT_FSIZE, (_MAX_OUTPUT_BYTES, _MAX_OUTPUT_BYTES))
        _nondumpable()
        # A user service otherwise inherits the user manager's complete
        # environment.  No inherited Web/GitHub/tunnel/HMAC/provider secret is
        # needed: the provider receives its own exact map in the private frame.
        os.environ.clear()
        os.environ.update({
            "PATH": "/usr/bin:/bin",
            "HOME": "/nonexistent",
            "LANG": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONSAFEPATH": "1",
        })
        wire = _load_wire()
        challenge = wire.read_challenge(sys.stdin.buffer)
        sys.stdout.buffer.write(wire.encode_ready(challenge))
        sys.stdout.buffer.flush()
        header, prompt = wire.read_request(sys.stdin.buffer)
        argv, env, timeout = _validated_request(header, prompt)
        metadata = _run_provider(argv, env, prompt, timeout)
        sys.stdout.buffer.write(wire.encode_result(metadata))
        sys.stdout.buffer.flush()
        return 0
    except BaseException:
        # Never reflect a frame, credential, path, prompt, or full command.
        return 70


if __name__ == "__main__":
    raise SystemExit(main())
