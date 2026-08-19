"""Cold-start codex launcher for the verify service.

Each /verify asks an injected trusted transient-service adapter to spawn one
fresh ``codex exec`` session. Candidate text is framed stdin, never argv. The
provider uses a high-priority permission profile and an absolute isolated-Python
MCP entry; it writes ``verification.json`` into one private run directory.

Config (env):
  DANUS_CODEX_BIN,
  DANUS_VERIFY_MODEL (default gpt-5.5),
  DANUS_VERIFY_EFFORT (default xhigh),
  CODEX_TIMEOUT_SECONDS (0 = no timeout),
  VERIFY_AGENT_HOME (the codex `-C` dir: AGENTS.md + .agents/skills + .codex),
  DANUS_VERIFY_PROVIDER_HOME (isolated provider CODEX_HOME),
  VERIFIER_RESULTS_DIR (run dirs; gitignored).
"""

from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import HTTPException

from danus import codex
from danus.secure_io import (
    SecureIOError,
    atomic_write_bytes,
    atomic_write_text,
    ensure_private_dir,
    read_private_bytes,
    secure_unlink,
)
from .runner import (
    TrustedVerifierRunner,
    TrustedVerifierTimeout,
    TrustedVerifierUnavailable,
    VerifierRunRequest,
    run_with_trusted_supervisor,
    trusted_entry_argv,
)
from .trusted_python import TrustedPythonError, trusted_python_executable

_HERE = Path(__file__).resolve().parent  # danus/verify/
_REPO_ROOT = _HERE.parent.parent         # repo root (danus/verify -> danus -> root)
VERIFICATION_FILENAMES = ("verification.json", "verificationt.json")
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_PROVIDER_ENV_ALLOWLIST = {
    "OPENAI_API_KEY",
    "DANUS_CODEX_API_KEY",
    "OPENAI_BASE_URL",
    "CODEX_API_BASE_URL",
    "OPENAI_CHATGPT_BASE_URL",
    "CODEX_CHATGPT_BASE_URL",
}
_CERTIFICATE_ROOTS = tuple(
    path for path in (
        Path("/etc/ssl"), Path("/etc/pki"),
        Path("/usr/share/ca-certificates"),
        Path("/usr/local/share/ca-certificates"),
    ) if path.exists()
)


class VerifierProviderConfigurationError(RuntimeError):
    """Provider auth/runtime configuration is absent, unsafe, or inconsistent."""


# --------------------------------------------------------------------------- #
# config resolution (env read at call time)                                   #
# --------------------------------------------------------------------------- #

def _configured_directory(name: str, default: Path, label: str) -> Path:
    """Resolve one dedicated verifier directory without accepting broad roots."""

    raw = os.environ.get(name)
    path = Path(raw).expanduser().absolute() if raw else default.absolute()
    normalized = Path(os.path.abspath(path))
    home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
    broad = {
        Path("/"), Path("/home"), Path("/root"), Path("/tmp"),
        Path("/var"), Path("/var/tmp"), Path("/run"), Path("/opt"),
        Path("/srv"), Path("/mnt"), Path("/media"), home,
        _REPO_ROOT, _REPO_ROOT / "runtime", _HERE, _HERE.parent,
        *_REPO_ROOT.parents,
    }
    sensitive = {
        home / ".ssh", home / ".gnupg", home / ".aws",
        home / ".config", home / ".local" / "share" / "keyrings",
        home / ".codex", home / ".nurouter",
    }
    host_codex = os.environ.get("CODEX_HOME")
    if host_codex:
        sensitive.add(Path(host_codex).expanduser().absolute())
    if (
        path != normalized
        or path in broad
        or any(path == root or path.is_relative_to(root) for root in sensitive)
    ):
        raise VerifierProviderConfigurationError(f"{label} is unsafe")
    return path


def _agent_home() -> Path:
    return _configured_directory(
        "VERIFY_AGENT_HOME", _HERE / "agent", "verifier agent home",
    )


def _provider_home_path() -> Path:
    runtime = os.environ.get("DANUS_RUNTIME")
    root = Path(runtime).expanduser().absolute() if runtime else _REPO_ROOT / "runtime"
    return _configured_directory(
        "DANUS_VERIFY_PROVIDER_HOME", root / "verifier-codex-state",
        "verifier provider home",
    )


def _prepare_provider_home() -> Path:
    """Provision a private verifier-only CODEX_HOME with no unrelated config."""
    home = _provider_home_path()
    try:
        ensure_private_dir(home)
        ensure_private_dir(home / "tmp")
        destination = home / "auth.json"
        if os.environ.get("OPENAI_API_KEY") or os.environ.get("DANUS_CODEX_API_KEY"):
            secure_unlink(destination, missing_ok=True)
            return home
        host_home = os.environ.get("CODEX_HOME")
        if not host_home:
            raise VerifierProviderConfigurationError(
                "verifier provider authentication is unavailable"
            )
        source = Path(host_home).expanduser().absolute() / "auth.json"
        auth = read_private_bytes(source, minimum=2, maximum=1 << 20)
        atomic_write_bytes(destination, auth, mode=0o600)
        return home
    except VerifierProviderConfigurationError:
        raise
    except (OSError, SecureIOError) as exc:
        raise VerifierProviderConfigurationError(
            "verifier provider authentication is unavailable or unsafe"
        ) from exc


def _validated_certificate_path(name: str, value: str) -> str:
    """Resolve only system CA material; never turn a CA override into a host bind."""

    path = Path(value).expanduser()
    try:
        if not path.is_absolute() or path != Path(os.path.abspath(path)):
            raise VerifierProviderConfigurationError(
                "verifier certificate configuration is unsafe"
            )
        resolved = path.resolve(strict=True)
        info = resolved.stat()
    except VerifierProviderConfigurationError:
        raise
    except OSError as exc:
        raise VerifierProviderConfigurationError(
            "verifier certificate configuration is unsafe"
        ) from exc
    expected_type = stat.S_ISREG if name == "SSL_CERT_FILE" else stat.S_ISDIR
    if (
        name not in {"SSL_CERT_FILE", "SSL_CERT_DIR"}
        or not expected_type(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o002
        or not any(
            resolved == root or resolved.is_relative_to(root)
            for root in _CERTIFICATE_ROOTS
        )
    ):
        raise VerifierProviderConfigurationError(
            "verifier certificate configuration is unsafe"
        )
    return str(resolved)


def _safe_executable(path: Path, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
        info = resolved.stat()
    except OSError as exc:
        raise VerifierProviderConfigurationError(f"{label} is unavailable") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid not in {0, os.getuid()}
        or info.st_mode & 0o002
    ):
        raise VerifierProviderConfigurationError(f"{label} is unsafe")
    return resolved


def _safe_real_file(path: Path, label: str, *, executable: bool = False) -> Path:
    try:
        info = path.lstat()
    except OSError as exc:
        raise VerifierProviderConfigurationError(f"{label} is unavailable") from exc
    if (
        not path.is_absolute()
        or stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_uid not in {0, os.getuid()}
        or info.st_mode & 0o002
        or (executable and not info.st_mode & 0o111)
    ):
        raise VerifierProviderConfigurationError(f"{label} is unsafe")
    return path


def _read_safe_json(path: Path, label: str) -> dict[str, object]:
    _safe_real_file(path, label)
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > (1 << 20):
                raise VerifierProviderConfigurationError(f"{label} is unsafe")
            raw = os.read(fd, (1 << 20) + 1)
        finally:
            os.close(fd)
        value = json.loads(raw)
    except VerifierProviderConfigurationError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerifierProviderConfigurationError(f"{label} is unavailable") from exc
    if not isinstance(value, dict):
        raise VerifierProviderConfigurationError(f"{label} is unsafe")
    return value


def _official_codex_runtime() -> tuple[Path, Path, Path]:
    """Return the pinned official native CLI, JS entry, and bundled bwrap."""

    raw = os.environ.get("DANUS_CODEX_JS")
    if not raw:
        raise VerifierProviderConfigurationError(
            "verifier upstream Codex runtime is unavailable"
        )
    entry = Path(raw).expanduser()
    if not entry.is_absolute() or entry != Path(os.path.abspath(entry)):
        raise VerifierProviderConfigurationError("verifier Codex entry is unsafe")
    _safe_real_file(entry, "verifier Codex entry", executable=True)
    package_root = entry.parent.parent
    if (
        entry.name != "codex.js"
        or entry.parent.name != "bin"
        or package_root.name != "codex"
        or package_root.parent.name != "@openai"
        or package_root.parent.parent.name != "node_modules"
    ):
        raise VerifierProviderConfigurationError("verifier Codex entry is unsafe")
    metadata = _read_safe_json(package_root / "package.json", "verifier Codex package")
    version = metadata.get("version")
    if (
        metadata.get("name") != "@openai/codex"
        or not isinstance(version, str)
        or not re.fullmatch(
            r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?", version,
        )
        or metadata.get("bin") != {"codex": "bin/codex.js"}
    ):
        raise VerifierProviderConfigurationError("verifier Codex package is unsafe")

    targets = {
        "x86_64": ("codex-linux-x64", "x86_64-unknown-linux-musl", "linux-x64"),
        "aarch64": ("codex-linux-arm64", "aarch64-unknown-linux-musl", "linux-arm64"),
    }
    try:
        package_name, target, version_suffix = targets[os.uname().machine]
    except KeyError as exc:
        raise VerifierProviderConfigurationError(
            "verifier Codex native package is unsupported"
        ) from exc
    native_package = package_root / "node_modules" / "@openai" / package_name
    native_metadata = _read_safe_json(
        native_package / "package.json", "verifier Codex native package",
    )
    if (
        native_metadata.get("name") != "@openai/codex"
        or native_metadata.get("version") != f"{version}-{version_suffix}"
        or native_metadata.get("os") != ["linux"]
    ):
        raise VerifierProviderConfigurationError(
            "verifier Codex native package is unsafe"
        )
    native_root = native_package / "vendor" / target
    native = _safe_real_file(
        native_root / "bin" / "codex", "verifier native Codex", executable=True,
    )
    bwrap = _safe_real_file(
        native_root / "codex-resources" / "bwrap",
        "verifier bundled bubblewrap", executable=True,
    )
    return native, entry, bwrap


def _sha256_real_file(path: Path, label: str) -> str:
    _safe_real_file(path, label, executable=True)
    digest = hashlib.sha256()
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        try:
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                digest.update(chunk)
        finally:
            os.close(fd)
    except OSError as exc:
        raise VerifierProviderConfigurationError(f"{label} is unavailable") from exc
    return digest.hexdigest()


def _validated_nurouter_launcher(candidate: Path) -> bool:
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    expected = home / ".local" / "bin" / "codex"
    if candidate != expected:
        return False
    marker = candidate.parent / ".nurouter-codex-launcher.json"
    value = _read_safe_json(marker, "host Codex launcher marker")
    if (
        value.get("schema_version") != 2
        or value.get("kind") != "codex"
        or value.get("nurouter_home") != str(home / ".nurouter")
        or value.get("launcher_sha256")
            != _sha256_real_file(candidate, "host Codex launcher")
    ):
        raise VerifierProviderConfigurationError("host Codex launcher is unsafe")
    return True


def _provider_codex_bin(test_binary: str | None = None) -> str:
    """Select only the validated official native CLI in production.

    Deterministic plumbing tests pass a binary through the explicit private
    argument; no environment variable or launcher marker can select an arbitrary
    production executable.
    """

    if test_binary is not None:
        return str(_safe_executable(Path(test_binary), "test verifier provider"))
    native, javascript, _bwrap = _official_codex_runtime()
    raw = codex.resolve_bin()
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute() or candidate != Path(os.path.abspath(candidate)):
        raise VerifierProviderConfigurationError("verifier Codex selector is unsafe")
    _safe_real_file(candidate, "verifier Codex selector", executable=True)
    repo_wrapper = _REPO_ROOT / "bin" / "codex"
    allowed = candidate in {repo_wrapper, javascript, native}
    if not allowed:
        allowed = _validated_nurouter_launcher(candidate)
    if not allowed:
        raise VerifierProviderConfigurationError("verifier Codex selector is unsafe")
    return str(native)


def _relink(link: Path, target: Path) -> None:
    """Point ``link`` (a symlink) at absolute ``target``, replacing a stale link."""
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(target)


def ensure_agent_home() -> Path:
    """Provision the verifier's codex ``-C`` home if absent, then return it.

    Unlike a worker home (assembled per project by ``danus new``), the verify
    agent home is a singleton with no scaffolder — so a fresh checkout has none and
    the codex ``-C`` dir would not exist. This builds it the same way a worker home
    is built: ``AGENTS.md`` (the verifier contract) + ``.agents/skills`` (the verify
    skills), symlinked to the repo's canonical sources so they stay in sync.
    Idempotent (a no-op once the links exist); skips silently if the canonical
    sources are absent (e.g. an installed package without the ``agents/`` tree),
    leaving the existing missing-home error to surface honestly."""
    home = _agent_home()
    contract = _REPO_ROOT / "agents" / "contracts" / "verifier.md"
    skills = _REPO_ROOT / "agents" / "skills" / "verify"
    agents_md = home / "AGENTS.md"
    skills_link = home / ".agents" / "skills"
    if agents_md.exists() and skills_link.exists():
        return home
    if not (contract.exists() and skills.exists()):
        return home  # nothing to link from — do not create broken links
    (home / ".agents").mkdir(parents=True, exist_ok=True)
    _relink(agents_md, contract)
    _relink(skills_link, skills)
    return home



def _results_root() -> Path:
    return _configured_directory(
        "VERIFIER_RESULTS_DIR", _HERE / "runs", "verifier results storage",
    )


def _model() -> str:
    return codex.model("DANUS_VERIFY_MODEL")


def _effort() -> str:
    return codex.effort("DANUS_VERIFY_EFFORT")


def _timeout() -> Optional[int]:
    return int(os.getenv("CODEX_TIMEOUT_SECONDS", "0")) or None


def _mcp_config_arg() -> str:
    """Inject the credential-scrubbing, read-only verifier MCP entry."""
    python = trusted_python_executable()
    entry = str((_HERE / "mcp_entry.py").resolve())
    return (
        "mcp_servers.danus={"
        f"command={json.dumps(python)},"
        f"args=[\"-I\",{json.dumps(entry)}],"
        "env={PYTHONDONTWRITEBYTECODE=\"1\",PYTHONSAFEPATH=\"1\"}}"
    )


def _toml(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _permission_profile_arg(run_id: str) -> str:
    """High-priority model-command policy for exactly one verifier run."""
    run_dir = _results_dir(run_id)
    filesystem = {
        ":minimal": "read",
        str(_agent_home()): "read",
        str(_REPO_ROOT / "agents"): "read",
        str(_REPO_ROOT / "danus"): "read",
        str(run_dir): "write",
        "/proc": "deny",
    }
    filesystem[str(_provider_home_path())] = "deny"
    python = Path(trusted_python_executable())
    filesystem[str(python.parent.parent)] = "read"
    javascript = os.environ.get("DANUS_CODEX_JS")
    if javascript:
        filesystem[str(Path(javascript).resolve(strict=False).parent.parent)] = "read"
    node = os.environ.get("DANUS_NODE")
    if node:
        filesystem[str(Path(node).resolve(strict=False).parent.parent)] = "read"
    fs = ",".join(
        f"{_toml(path)}={_toml(access)}" for path, access in filesystem.items()
    )
    return (
        "{description=\"Danus isolated verifier\","
        f"filesystem={{{fs}}},network={{enabled=false}}}}"
    )


# --------------------------------------------------------------------------- #
# run-dir allocation                                                          #
# --------------------------------------------------------------------------- #

def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def generate_run_id(statement: str) -> str:
    return f"{_utc_timestamp()}_{hashlib.sha256(statement.encode('utf-8')).hexdigest()[:12]}"


def _allocate_run_id(statement: str) -> str:
    """Claim a unique run dir atomically (mkdir exist_ok=False, retry with a
    numeric suffix) so concurrent verifiers sharing RESULTS_ROOT never clobber."""
    root = _results_root()
    try:
        ensure_private_dir(root)
    except (OSError, SecureIOError) as exc:
        raise RuntimeError("verifier results storage is unavailable") from exc
    base = generate_run_id(statement)
    run_id, suffix = base, 1
    for _ in range(10000):
        try:
            (root / run_id).mkdir(parents=False, exist_ok=False, mode=0o700)
            return run_id
        except FileExistsError:
            suffix += 1
            run_id = f"{base}_{suffix}"
    raise RuntimeError(f"could not allocate a unique run_id under {root} for base={base}")


def _results_dir(run_id: str) -> Path:
    return _results_root() / run_id


def _verification_path(run_id: str) -> Optional[Path]:
    for filename in VERIFICATION_FILENAMES:
        path = _results_dir(run_id) / filename
        if path.exists():
            return path
    return None


def build_prompt(run_id: str, statement: str, proof: str) -> str:
    output_path = _results_dir(run_id) / VERIFICATION_FILENAMES[0]
    return (
        f"Run_id: {run_id}. "
        f"Statement: {statement}. "
        f"Proof:\n{proof}\n\n"
        "Use AGENTS.md to verify the above proof for the statement. "
        f"Write the verification JSON to this exact path: {output_path}."
    )


def build_codex_command(
    run_id: str, *, _test_provider_bin: str | None = None,
) -> List[str]:
    if not _RUN_ID_RE.fullmatch(run_id):
        raise ValueError("invalid verifier run identity")
    run_dir = _results_dir(run_id)
    shell_env = (
        "{PATH=\"/usr/local/bin:/usr/bin:/bin\",HOME="
        + _toml(str(run_dir))
        + ",LANG=\"C.UTF-8\",TMPDIR="
        + _toml(str(run_dir / "tmp"))
        + "}"
    )
    return codex.exec_cmd(
        _provider_codex_bin(_test_provider_bin), _model(), _effort(),
        "--ignore-user-config",
        "--ignore-rules",
        "--strict-config",
        "--config", 'approval_policy="never"',
        "--config", "allow_login_shell=false",
        "--config", 'default_permissions="danus_verifier"',
        "--config", f"permissions.danus_verifier={_permission_profile_arg(run_id)}",
        "--config", 'shell_environment_policy.inherit="none"',
        "--config", "shell_environment_policy.ignore_default_excludes=false",
        "--config", f"shell_environment_policy.set={shell_env}",
        "-C", str(_agent_home()),
        # on an install without .git (tarball download), codex's
        # trusted-directory check refuses to run (exit 1 → /verify HTTP 500)
        "--skip-git-repo-check",
        "-c", _mcp_config_arg(),
        "-",
    )


def _provider_environment(command: List[str]) -> Dict[str, str]:
    """Build a complete minimal environment, never an inherited overlay."""
    env = {
        name: value
        for name in _PROVIDER_ENV_ALLOWLIST
        if (value := os.environ.get(name))
    }
    for name in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
        if value := os.environ.get(name):
            env[name] = _validated_certificate_path(name, value)
    home = str(_prepare_provider_home())
    env["CODEX_HOME"] = home
    env["HOME"] = home
    env["TMPDIR"] = str(Path(home) / "tmp")
    binary_dir = str(Path(command[0]).resolve(strict=False).parent)
    node = os.environ.get("DANUS_NODE")
    node_dir = str(Path(node).resolve(strict=False).parent) if node else ""
    path_parts = [
        part for part in (
            binary_dir, node_dir, "/usr/local/bin", "/usr/bin", "/bin",
        ) if part
    ]
    env.update({
        "PATH": os.pathsep.join(dict.fromkeys(path_parts)),
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONSAFEPATH": "1",
    })
    return env


def _provider_isolation_paths(
    command: List[str], environment: Dict[str, str], entry_argv: tuple[str, ...],
    run_dir: Path,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Describe the complete filesystem contract required by the host adapter."""
    lexical_python = Path(entry_argv[0]).absolute()
    # Do not bind the host /proc back into a PrivatePIDs service.  systemd
    # mounts a PID-namespace-specific procfs automatically; re-exposing the
    # host tree would make `/proc/1` systemd and defeat the namespace proof.
    read_only = [
        Path("/usr"), Path("/etc"), Path("/sys"),
        _REPO_ROOT / "danus", _REPO_ROOT / "agents", _agent_home(),
        Path(command[0]).resolve(strict=False),
        lexical_python.parent.parent,
        lexical_python.resolve(strict=False).parent.parent,
        Path(entry_argv[2]).resolve(strict=False),
    ]
    if lexical_python.is_symlink():
        target = Path(os.readlink(lexical_python))
        if not target.is_absolute():
            target = lexical_python.parent / target
        # With ProtectHome=tmpfs, binding only the lexical venv and final
        # resolved UV installation is insufficient: the venv symlink may point
        # through UV's unversioned installation alias.  Reopen that immediate
        # target root as part of the exact contract as well.
        read_only.append(Path(os.path.abspath(target)).parent.parent)
    for name in ("DANUS_CODEX_JS", "DANUS_NODE", "SSL_CERT_FILE", "SSL_CERT_DIR"):
        value = os.environ.get(name) if name.startswith("DANUS_") else environment.get(name)
        if value:
            path = Path(value).expanduser().resolve(strict=False)
            read_only.append(path.parent.parent if name in {"DANUS_CODEX_JS", "DANUS_NODE"} else path)
    resolver = Path("/etc/resolv.conf").resolve(strict=False)
    if resolver != Path("/etc/resolv.conf"):
        read_only.append(resolver)
    read_write = [
        run_dir,
        Path(environment["CODEX_HOME"]),
    ]

    def unique(paths: List[Path]) -> tuple[str, ...]:
        values: dict[str, None] = {}
        for path in paths:
            values[str(path.expanduser().absolute())] = None
        return tuple(values)

    return unique(read_only), unique(read_write)


def run_codex_verification(
    run_id: str,
    statement: str,
    proof: str,
    *,
    runner: TrustedVerifierRunner | None = None,
    _test_provider_bin: str | None = None,
) -> Dict[str, Any]:
    """Run one cold verifier through the trusted-supervisor seam and validate output."""
    if not _RUN_ID_RE.fullmatch(run_id):
        raise HTTPException(status_code=500, detail="invalid verifier run identity")
    results_dir = _results_dir(run_id)
    try:
        ensure_private_dir(_results_root())
        results_dir.mkdir(parents=False, exist_ok=True, mode=0o700)
        results_dir.chmod(0o700)
    except (OSError, SecureIOError) as exc:
        raise HTTPException(status_code=503, detail="verifier storage unavailable") from exc
    try:
        ensure_private_dir(results_dir / "tmp")
        ensure_agent_home()
        cmd = build_codex_command(run_id, _test_provider_bin=_test_provider_bin)
        prompt = build_prompt(run_id, statement, proof).encode("utf-8")
        entry_argv = trusted_entry_argv()
        provider_environment = _provider_environment(cmd)
        read_only_paths, read_write_paths = _provider_isolation_paths(
            cmd, provider_environment, entry_argv, results_dir,
        )
        timeout_seconds = _timeout()
    except (
        OSError,
        SecureIOError,
        TrustedPythonError,
        TrustedVerifierUnavailable,
        VerifierProviderConfigurationError,
        ValueError,
    ) as exc:
        raise HTTPException(
            status_code=503, detail="verifier provider configuration unavailable",
        ) from exc
    request = VerifierRunRequest(
        run_id=run_id,
        entry_argv=entry_argv,
        provider_argv=tuple(cmd),
        provider_environment=provider_environment,
        prompt=prompt,
        timeout_seconds=timeout_seconds,
        read_only_paths=read_only_paths,
        read_write_paths=read_write_paths,
    )
    try:
        completed = run_with_trusted_supervisor(request, adapter=runner)
    except TrustedVerifierTimeout as exc:
        raise HTTPException(status_code=504, detail="verifier provider timed out") from exc
    except TrustedVerifierUnavailable as exc:
        raise HTTPException(status_code=503, detail="verifier security boundary unavailable") from exc

    record = {
        "duration_ms": round(float(completed.duration_seconds) * 1000, 3),
        "input_sha256": hashlib.sha256(prompt).hexdigest(),
        "rc": completed.returncode,
        "run_id": run_id,
        "schema": 1,
        "stdout_bytes": completed.stdout_bytes,
        "stdout_sha256": completed.stdout_sha256,
    }
    try:
        atomic_write_text(
            results_dir / "run.json",
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
            mode=0o600,
        )
    except (OSError, SecureIOError) as exc:
        raise HTTPException(status_code=503, detail="verifier audit log unavailable") from exc

    if completed.returncode != 0:
        raise HTTPException(status_code=500, detail="verifier provider exited unsuccessfully")

    verification_path = _verification_path(run_id)
    if verification_path is None:
        raise HTTPException(status_code=500, detail="verification output was not found")
    try:
        payload = json.loads(
            read_private_bytes(verification_path, minimum=2, maximum=4 << 20)
        )
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail="verification output is not valid JSON") from exc
    except (OSError, SecureIOError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=500, detail="verification output is unavailable or unsafe") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=500, detail="verification output must be a JSON object")
    return payload
