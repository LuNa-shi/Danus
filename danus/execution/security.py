"""OS/process boundaries for untrusted Worker provider sessions.

There are deliberately two independent layers:

* a transient systemd service supplies a private PID/mount/cgroup view and
  re-opens only exact host paths needed by this Worker;
* a Codex 0.148 custom permission profile grants model-created commands only
  minimal system reads plus this Project, explicitly denying the isolated
  subscription home and the one-shot host-gateway socket directory.

The trusted service launcher retains only Landlock's signal/abstract-socket
scope.  It deliberately handles no filesystem rights because a filesystem
Landlock domain blocks Codex's inner bubblewrap mount setup.

The real MCP gateway runs outside both layers.  Codex receives only a
credential-free Unix-socket bridge; the verifier bearer stays in the trusted
host broker environment.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import pwd
import re
import select
import secrets
import stat
import struct
import subprocess
import sys
from pathlib import Path
from typing import Iterable

from danus.secure_io import (
    SecureIOError,
    atomic_write_bytes,
    atomic_write_text,
    ensure_private_dir,
)
from danus.gateway.fd_protocol import (
    BROKER_AUTHORIZED_MARKER,
    BROKER_READY_MARKER,
    PROVIDER_SOCKET_PATH,
)
from . import layout as L

BROKER_DIR_NAME = ".danus-broker"
BROKER_SOCKET_NAME = "gateway.sock"  # legacy fixed locator, cleaned but never reused
PROVIDER_PID_NAME = "provider.pid"
PROVIDER_STATE_DIR_NAME = "worker-codex-state"
MODEL_TMP_NAME = ".danus-tmp"
MODEL_WORKSPACE_NAME = "workspace"
_REPO_ROOT = Path(__file__).resolve().parents[2]
# ``DANUS_CODEX_JS`` is machine-derived by ``scripts/bootstrap.sh``.  It is
# deliberately *not* treated as a trust-root selector: accepting an arbitrary
# path here would let a project/user point the Worker at a look-alike package
# which receives the provider credentials.  Bootstrap installs the package at
# this fixed location, so the selector is anchored to it.
_CODEX_INSTALL_ROOT = _REPO_ROOT / "runtime" / "codex-npm"
_CODEX_PACKAGE_RELATIVE = Path("lib") / "node_modules" / "@openai" / "codex"
_BRIDGE_ENTRY = (_REPO_ROOT / "danus" / "gateway" / "bridge.py").resolve()
_BROKER_ENTRY = (_REPO_ROOT / "danus" / "gateway" / "broker.py").resolve()
_PROVIDER_ENTRY = (_REPO_ROOT / "danus" / "execution" / "provider_launcher.py").resolve()
_SAFE_SCOPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

# Values required by the Codex client itself.  Everything else in the service
# environment (Web password/cookies, GitHub tokens, Cloudflare credentials,
# database URLs, lifecycle capabilities, etc.) is omitted.
_PROVIDER_PASSTHROUGH = (
    "OPENAI_API_KEY",              # API deployments (subscription mode omits it)
    "DANUS_CODEX_API_KEY",
    "OPENAI_BASE_URL",
    "CODEX_API_BASE_URL",
    "OPENAI_CHATGPT_BASE_URL",
    "CODEX_CHATGPT_BASE_URL",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
)


class WorkerSecurityError(RuntimeError):
    """Fail-closed Worker isolation/configuration error."""


def broker_dir(wl: L.WorkerLayout) -> Path:
    del wl
    return Path("/run/user") / str(os.getuid()) / "danus-b"


def broker_socket(wl: L.WorkerLayout, nonce: str | None = None) -> Path:
    if nonce is None:
        return broker_dir(wl) / BROKER_SOCKET_NAME
    if not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise WorkerSecurityError("invalid Worker gateway nonce")
    path = broker_dir(wl) / f"b-{nonce}.sock"
    if len(os.fsencode(path)) > 107:
        raise WorkerSecurityError("Worker gateway locator exceeds AF_UNIX sun_path")
    return path


def provider_pid_file(wl: L.WorkerLayout) -> Path:
    return control_dir(wl) / PROVIDER_PID_NAME


def control_dir(wl: L.WorkerLayout) -> Path:
    """Project-external host control directory for exactly one Worker."""
    if not _SAFE_SCOPE.fullmatch(wl.project) or not _SAFE_SCOPE.fullmatch(wl.name):
        raise WorkerSecurityError("unsafe Project/Worker name for host control state")
    path = _runtime_root(wl) / "worker-control" / wl.project / wl.name
    project = wl.project_dir.resolve(strict=False)
    resolved = path.resolve(strict=False)
    if resolved == project or project in resolved.parents:
        raise WorkerSecurityError("Worker host control state must be outside the Project")
    return path


def _private_dir(path: Path, label: str) -> Path:
    """Create/validate a host-owned private directory without accepting links."""
    try:
        return ensure_private_dir(path)
    except (OSError, SecureIOError) as exc:
        raise WorkerSecurityError(f"{label} is unavailable or unsafe") from exc


def _runtime_root(wl: L.WorkerLayout) -> Path:
    configured = os.environ.get("DANUS_RUNTIME")
    # The normal layout is <runtime>/projects/<project>.  Deriving the parent
    # from the concrete Worker layout also keeps standalone/tests isolated.
    project_container = wl.project_dir.parent
    derived = project_container.parent if project_container.name == "projects" else project_container
    raw = Path(configured) if configured else derived
    return raw.expanduser().resolve(strict=False)


def provider_home(wl: L.WorkerLayout) -> Path:
    """Return a private, Project-external CODEX_HOME for this Worker.

    Subscription auth must be readable by the trusted Codex provider but never
    by a model-created command.  Keeping it outside the Project lets both the
    outer Landlock allowlist and the inner permission-profile deny be explicit.
    """
    if not _SAFE_SCOPE.fullmatch(wl.project) or not _SAFE_SCOPE.fullmatch(wl.name):
        raise WorkerSecurityError("unsafe Project/Worker name for provider state")
    state_root = _private_dir(
        _runtime_root(wl) / PROVIDER_STATE_DIR_NAME,
        "Worker provider state root",
    )
    project_state = _private_dir(state_root / wl.project, "Project provider state")
    home = _private_dir(project_state / wl.name, "Worker provider CODEX_HOME")
    project = wl.project_dir.resolve(strict=False)
    resolved_home = home.resolve(strict=False)
    if resolved_home == project or project in resolved_home.parents:
        raise WorkerSecurityError("Worker provider CODEX_HOME must be outside the Project")
    _sync_provider_auth(home)
    _private_dir(home / "tmp", "Worker provider temporary directory")
    return home


def model_tmp(wl: L.WorkerLayout) -> Path:
    """Private temporary directory available to model-created commands."""
    return _private_dir(wl.dir / MODEL_TMP_NAME, "Worker model temporary directory")


def model_workspace(wl: L.WorkerLayout) -> Path:
    """The only general-purpose model-writable research surface."""
    return _private_dir(wl.dir / MODEL_WORKSPACE_NAME, "Worker model workspace")


def shared_project_read_paths(wl: L.WorkerLayout) -> list[Path]:
    """Return explicit shared material paths, never the Project/workers tree.

    Landlock grants access *beneath* a rule, so allowing the Project root would
    also expose every sibling's private ``local_memory``.  Shared stores and
    host-published materials are instead admitted one child at a time.  Root
    regular files with public names cover uploaded problem statements and
    target metadata without granting directory traversal into ``workers``.
    """

    project = wl.project_dir
    allowed_directory_names = {
        "global_memory", "fact_graph", "materials", "sources", "references",
        "uploads", "papers",
    }
    paths: list[Path] = []
    try:
        children = list(project.iterdir())
    except OSError as exc:
        raise WorkerSecurityError("Project shared material inventory is unavailable") from exc
    for child in children:
        if child.name == "workers" or child.name.startswith(".danus-"):
            continue
        try:
            info = child.lstat()
        except OSError as exc:
            raise WorkerSecurityError("Project shared material inventory changed") from exc
        if stat.S_ISREG(info.st_mode) and not child.name.startswith("."):
            paths.append(child)
        elif stat.S_ISDIR(info.st_mode) and child.name in allowed_directory_names:
            paths.append(child)
    return sorted(paths, key=lambda path: str(path))


def prepare_broker_dir(wl: L.WorkerLayout) -> None:
    _private_dir(control_dir(wl), "Worker host control directory")
    path = _private_dir(broker_dir(wl), "Worker gateway broker directory")
    for stale in (provider_pid_file(wl),):
        if stale.is_symlink():
            raise WorkerSecurityError("refusing a symlink at a Worker gateway control path")
        if stale.exists():
            if stale == provider_pid_file(wl) and not stat.S_ISREG(stale.lstat().st_mode):
                raise WorkerSecurityError("refusing a non-file provider identity path")
            stale.unlink()


def _host_codex_auth() -> Path | None:
    home = os.environ.get("CODEX_HOME")
    if not home:
        return None
    auth = Path(home).resolve() / "auth.json"
    if not auth.exists():
        return None
    info = auth.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise WorkerSecurityError("CODEX_HOME/auth.json must be a regular non-symlink file")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise WorkerSecurityError("CODEX_HOME/auth.json must not be accessible by group/other")
    return auth


def _sync_provider_auth(home: Path) -> None:
    """Atomically mirror host subscription auth into the isolated provider home."""
    source = _host_codex_auth()
    destination = home / "auth.json"
    if source is None:
        # Do not silently retain a stale subscription credential when the host
        # has deliberately switched this service to API-key auth.
        destination.unlink(missing_ok=True)
        return

    source_flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        source_flags |= os.O_NOFOLLOW
    try:
        source_fd = os.open(source, source_flags)
    except OSError as exc:
        raise WorkerSecurityError("cannot open host Codex subscription auth") from exc
    try:
        source_info = os.fstat(source_fd)
        if not stat.S_ISREG(source_info.st_mode) or stat.S_IMODE(source_info.st_mode) & 0o077:
            raise WorkerSecurityError("host Codex subscription auth became unsafe")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(source_fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
            if sum(map(len, chunks)) > (1 << 20):
                raise WorkerSecurityError("host Codex subscription auth is unexpectedly large")
        atomic_write_bytes(destination, b"".join(chunks), mode=0o600)
    except (OSError, SecureIOError) as exc:
        raise WorkerSecurityError("cannot provision isolated Worker subscription auth") from exc
    finally:
        os.close(source_fd)


def worker_provider_env(wl: L.WorkerLayout) -> dict[str, str]:
    """Return the complete (not overlay) environment for the provider process."""
    env: dict[str, str] = {}
    for name in _PROVIDER_PASSTHROUGH:
        value = os.environ.get(name)
        if value:
            env[name] = value
    for name in ("LANG", "LC_ALL", "LC_CTYPE", "TZ"):
        value = os.environ.get(name)
        if value:
            env[name] = value
    home = provider_home(wl)
    env.update({
        "CODEX_HOME": str(home),
        "HOME": str(home),
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "TMPDIR": str(home / "tmp"),
        "PYTHONSAFEPATH": "1",
    })
    if _host_codex_auth() is None and not (
        env.get("OPENAI_API_KEY") or env.get("DANUS_CODEX_API_KEY")
    ):
        raise WorkerSecurityError(
            "Worker Codex has neither a private subscription auth.json nor an API credential"
        )
    return env


def _safe_executable(path: Path, label: str) -> Path:
    resolved = path.resolve(strict=False)
    if not resolved.is_file():
        raise WorkerSecurityError(f"{label} is missing: {resolved}")
    info = resolved.stat()
    if (
        info.st_uid not in (0, os.getuid())
        or info.st_mode & 0o002
        or not info.st_mode & 0o111
    ):
        raise WorkerSecurityError(f"{label} has unsafe ownership or world-write permission")
    return resolved


def _reject_symlink_components(path: Path, label: str) -> None:
    """Reject a path whose *file or any parent* is a symbolic link.

    Checking only the final component is insufficient for the Codex package:
    ``.../@openai`` or ``vendor`` can otherwise redirect an apparently valid
    package into an attacker-controlled tree.  This helper is intentionally
    separate from ``_safe_executable`` because the normal Danus virtualenv
    entry is allowed to be a lexical symlink; the upstream Codex runtime is
    not.
    """

    if not path.is_absolute():
        raise WorkerSecurityError(f"{label} must be an absolute path")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            info = current.lstat()
        except OSError as exc:
            raise WorkerSecurityError(f"{label} is unavailable") from exc
        if stat.S_ISLNK(info.st_mode):
            raise WorkerSecurityError(f"{label} contains a symbolic link")


def _safe_real_executable(path: Path, label: str) -> Path:
    """Validate one provisioned runtime executable without following links."""

    _reject_symlink_components(path, label)
    try:
        info = path.lstat()
    except OSError as exc:
        raise WorkerSecurityError(f"{label} is unavailable") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid not in {0, os.getuid()}
        or info.st_mode & 0o002
        or not info.st_mode & 0o111
    ):
        raise WorkerSecurityError(f"{label} has unsafe identity")
    return path


def _trusted_codex_package_root() -> Path:
    """Return the canonical package root and validate the install anchor."""

    root = _CODEX_INSTALL_ROOT
    _reject_symlink_components(root, "Worker Codex install root")
    try:
        info = root.lstat()
    except OSError as exc:
        raise WorkerSecurityError("Worker Codex install root is unavailable") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid not in {0, os.getuid()}
        or info.st_mode & 0o002
    ):
        raise WorkerSecurityError("Worker Codex install root has unsafe identity")
    package = root / _CODEX_PACKAGE_RELATIVE
    _reject_symlink_components(package, "Worker Codex package root")
    try:
        package_info = package.lstat()
    except OSError as exc:
        raise WorkerSecurityError("Worker Codex package root is unavailable") from exc
    if (
        not stat.S_ISDIR(package_info.st_mode)
        or package_info.st_uid not in {0, os.getuid()}
        or package_info.st_mode & 0o002
    ):
        raise WorkerSecurityError("Worker Codex package root has unsafe identity")
    return package


def _read_safe_json(path: Path, label: str) -> dict[str, object]:
    """Read one trusted package/launcher manifest without following a link."""

    try:
        raw_info = path.lstat()
        if (
            not path.is_absolute()
            or stat.S_ISLNK(raw_info.st_mode)
            or not stat.S_ISREG(raw_info.st_mode)
            or raw_info.st_uid not in {0, os.getuid()}
            or raw_info.st_mode & 0o002
            or raw_info.st_size > (1 << 20)
        ):
            raise WorkerSecurityError(f"{label} is unsafe")
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > (1 << 20):
                raise WorkerSecurityError(f"{label} is unsafe")
            raw = os.read(fd, (1 << 20) + 1)
        finally:
            os.close(fd)
        value = json.loads(raw)
    except WorkerSecurityError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkerSecurityError(f"{label} is unavailable") from exc
    if not isinstance(value, dict):
        raise WorkerSecurityError(f"{label} is unsafe")
    return value


def _sha256_safe_executable(path: Path, label: str) -> str:
    resolved = _safe_executable(path, label)
    digest = hashlib.sha256()
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(resolved, flags)
        try:
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                digest.update(chunk)
        finally:
            os.close(fd)
    except OSError as exc:
        raise WorkerSecurityError(f"{label} is unavailable") from exc
    return digest.hexdigest()


def _official_codex_runtime() -> tuple[Path, Path, Path]:
    """Resolve the provisioned upstream package to native Codex + bwrap.

    The JavaScript entry is used only as the package identity anchor.  Worker
    services execute the matching native binary directly, so no host launcher
    or user-controlled PATH lookup exists inside the provider boundary.
    """

    raw = os.environ.get("DANUS_CODEX_JS")
    if not raw:
        raise WorkerSecurityError("Worker upstream Codex runtime is unavailable")
    entrypoint = Path(raw).expanduser()
    if not entrypoint.is_absolute() or entrypoint != Path(os.path.abspath(entrypoint)):
        raise WorkerSecurityError("Worker Codex package entry is unsafe")
    package_root = _trusted_codex_package_root()
    expected_entrypoint = package_root / "bin" / "codex.js"
    # Compare lexical paths as well as canonical paths.  This rejects a
    # ``DANUS_CODEX_JS`` value outside the bootstrap install (including a
    # look-alike package under /tmp) and prevents parent-directory symlink
    # redirection.
    if entrypoint != expected_entrypoint:
        raise WorkerSecurityError("Worker Codex package entry is not provisioned")
    _safe_real_executable(entrypoint, "Worker @openai/codex entrypoint")
    if (
        entrypoint.name != "codex.js"
        or entrypoint.parent.name != "bin"
        or package_root.name != "codex"
        or package_root.parent.name != "@openai"
        or package_root.parent.parent.name != "node_modules"
    ):
        raise WorkerSecurityError("Worker Codex package entry is unsafe")
    metadata = _read_safe_json(package_root / "package.json", "Worker Codex package")
    version = metadata.get("version")
    if (
        metadata.get("name") != "@openai/codex"
        or not isinstance(version, str)
        or not re.fullmatch(
            r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?", version,
        )
        or metadata.get("bin") != {"codex": "bin/codex.js"}
    ):
        raise WorkerSecurityError("Worker Codex package metadata is unsafe")

    machine = os.uname().machine
    targets = {
        "x86_64": ("codex-linux-x64", "x86_64-unknown-linux-musl", "linux-x64"),
        "aarch64": ("codex-linux-arm64", "aarch64-unknown-linux-musl", "linux-arm64"),
    }
    try:
        package_name, target, version_suffix = targets[machine]
    except KeyError as exc:
        raise WorkerSecurityError("Worker Codex native package is unsupported on this host") from exc
    native_package = package_root / "node_modules" / "@openai" / package_name
    _reject_symlink_components(native_package, "Worker Codex native package")
    native_metadata = _read_safe_json(
        native_package / "package.json", "Worker Codex native package",
    )
    if (
        native_metadata.get("name") != "@openai/codex"
        or native_metadata.get("version") != f"{version}-{version_suffix}"
        or native_metadata.get("os") != ["linux"]
        or native_metadata.get("cpu") != [
            "x64" if machine == "x86_64" else "arm64"
        ]
    ):
        raise WorkerSecurityError("Worker Codex native package metadata is unsafe")
    native_root = native_package / "vendor" / target
    native = _safe_real_executable(
        native_root / "bin" / "codex", "Worker native Codex",
    )
    bwrap = _safe_real_executable(
        native_root / "codex-resources" / "bwrap", "Worker bundled bubblewrap",
    )
    return native, entrypoint, bwrap


def trusted_codex_runtime() -> tuple[Path, Path, Path]:
    """Return the bootstrap-pinned upstream Codex runtime triple.

    Verifier code uses the same fixed-root/package validation as Worker code;
    keeping this as the single public seam prevents a second selector from
    accidentally accepting a look-alike ``@openai/codex`` tree.
    """

    return _official_codex_runtime()


def _validated_nurouter_launcher(candidate: Path) -> bool:
    """Recognize the host launcher only as a selector, never execute it."""

    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    expected = home / ".local" / "bin" / "codex"
    if candidate != expected:
        return False
    marker = _read_safe_json(
        candidate.parent / ".nurouter-codex-launcher.json",
        "host Codex launcher marker",
    )
    if (
        marker.get("schema_version") != 2
        or marker.get("kind") != "codex"
        or marker.get("nurouter_home") != str(home / ".nurouter")
        or marker.get("launcher_sha256")
            != _sha256_safe_executable(candidate, "host Codex launcher")
    ):
        raise WorkerSecurityError("host Codex launcher identity is unsafe")
    return True


def trusted_venv_python() -> Path:
    """Return the lexical venv interpreter without discarding ``pyvenv.cfg``."""

    lexical = Path(sys.executable).absolute()
    resolved = _safe_executable(lexical, "Danus virtualenv Python")
    prefix = lexical.parent.parent
    config = prefix / "pyvenv.cfg"
    try:
        prefix_info = prefix.lstat()
        config_info = config.lstat()
    except OSError as exc:
        raise WorkerSecurityError("Danus must run from its provisioned virtualenv") from exc
    if (
        not stat.S_ISDIR(prefix_info.st_mode) or stat.S_ISLNK(prefix_info.st_mode)
        or prefix_info.st_uid not in {0, os.getuid()} or prefix_info.st_mode & 0o002
        or not stat.S_ISREG(config_info.st_mode) or stat.S_ISLNK(config_info.st_mode)
        or config_info.st_uid not in {0, os.getuid()} or config_info.st_mode & 0o002
        or not resolved.is_file()
    ):
        raise WorkerSecurityError("Danus virtualenv Python has unsafe ownership or layout")
    return lexical


def resolve_trusted_codex_bin(resolved_bin: str) -> str:
    """Return only the native binary anchored to the provisioned package.

    ``DANUS_CODEX_BIN`` remains a selector for operational compatibility, but
    cannot introduce an executable.  The repository wrapper, its exact JS
    entry, the matching native binary, and a hash-attested host launcher all
    select the same validated native CLI.  Deterministic fake providers are
    injected at the Python test seam instead of through production config.
    """

    native, entrypoint, _bwrap = _official_codex_runtime()
    candidate = Path(resolved_bin).expanduser()
    if not candidate.is_absolute() or candidate != Path(os.path.abspath(candidate)):
        raise WorkerSecurityError("Worker Codex selector is not the validated upstream CLI")
    try:
        info = candidate.lstat()
    except OSError as exc:
        raise WorkerSecurityError("Worker Codex selector is not the validated upstream CLI") from exc
    if stat.S_ISLNK(info.st_mode):
        raise WorkerSecurityError("Worker Codex selector is not the validated upstream CLI")
    _safe_executable(candidate, "Worker Codex selector")
    repo_wrapper = _REPO_ROOT / "bin" / "codex"
    if candidate not in {repo_wrapper, entrypoint, native} and not _validated_nurouter_launcher(candidate):
        raise WorkerSecurityError("Worker Codex selector is not the validated upstream CLI")
    return str(native)


def resolve_worker_codex_bin(resolved_bin: str) -> str:
    """Backwards-compatible Worker name for the shared trusted selector."""

    return resolve_trusted_codex_bin(resolved_bin)


def validated_worker_codex_bin(selected: str) -> str:
    """Deep-callable selector gate used by every provider launch boundary.

    The outer supervisor must not rely on the loop having called the selector
    first: a future caller (or a test seam accidentally left enabled) could
    otherwise pass an arbitrary executable directly to ``systemd-run``.
    """

    return resolve_trusted_codex_bin(selected)


def _codex_runtime_root(codex_bin: str) -> Path | None:
    binary = Path(codex_bin).resolve(strict=False)
    if binary.name != "codex" or binary.parent.name != "bin":
        return None
    root = binary.parent.parent
    resources = root / "codex-resources" / "bwrap"
    if not resources.is_file():
        return None
    _safe_executable(resources, "Worker bundled bubblewrap")
    return root


def host_gateway_env(wl: L.WorkerLayout) -> dict[str, str]:
    """Minimal trusted-sidecar env; signing key stays host-side."""
    verify_url = os.environ.get("DANUS_VERIFY_URL", "http://127.0.0.1:8091/verify")
    env = {
        "DANUS_PROJECT_DIR": str(wl.project_dir),
        "DANUS_AUTHOR": wl.name,
        "DANUS_ROLE": "worker",
        "DANUS_VERIFY_URL": verify_url,
        "DANUS_VERIFY_PROJECT": wl.project,
        "DANUS_VERIFY_WORKER": wl.name,
        "PATH": os.defpath,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONSAFEPATH": "1",
    }
    timeout = os.environ.get("DANUS_VERIFY_TIMEOUT")
    if timeout:
        env["DANUS_VERIFY_TIMEOUT"] = timeout
    secret_file = os.environ.get("DANUS_VERIFY_CAPABILITY_SECRET_FILE")
    if secret_file:
        env["DANUS_VERIFY_CAPABILITY_SECRET_FILE"] = secret_file
    runtime = os.environ.get("DANUS_RUNTIME")
    if runtime:
        env["DANUS_RUNTIME"] = runtime
    return env


@dataclass
class HostGateway:
    process: subprocess.Popen
    socket_path: Path
    socket_dev: int
    socket_ino: int
    control_fd: int
    provider_socket_path: Path = Path(PROVIDER_SOCKET_PATH)
    authorized: bool = False

    def poll(self):
        return self.process.poll()

    def terminate(self) -> None:
        self.process.terminate()

    def kill(self) -> None:
        self.process.kill()

    def wait(self, timeout=None):
        return self.process.wait(timeout=timeout)

    def authorize_provider(
        self, *, main_pid: int, cgroup: str, invocation_id: str,
        namespaces: dict[str, tuple[int, int]], launcher_argv: list[str],
        provider_argv: list[str],
    ) -> None:
        if self.authorized or self.process.stdin is None:
            raise WorkerSecurityError("Worker gateway was already authorized")
        argv = [
            str(Path(sys.executable).resolve()), "-I", str(_BRIDGE_ENTRY),
            "--socket", str(self.provider_socket_path),
        ]
        payload = json.dumps({
            "schema": 1, "main_pid": main_pid, "cgroup": cgroup,
            "invocation_id": invocation_id, "bridge_argv": argv,
            "launcher_argv": launcher_argv, "provider_argv": provider_argv,
            "namespaces": namespaces,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(payload) > 16384:
            raise WorkerSecurityError("Worker gateway authorization is unexpectedly large")
        try:
            self.process.stdin.write(struct.pack("!I", len(payload)) + payload)
            self.process.stdin.close()
        except (BrokenPipeError, OSError, ValueError) as exc:
            raise WorkerSecurityError("Worker gateway authorization channel failed") from exc
        readable, _, _ = select.select([self.control_fd], [], [], 10.0)
        marker = os.read(self.control_fd, 1) if readable else b""
        if marker != BROKER_AUTHORIZED_MARKER or self.process.poll() is not None:
            raise WorkerSecurityError("Worker gateway did not pin the provider identity")
        os.close(self.control_fd)
        self.control_fd = -1
        self.authorized = True

    def close(self) -> None:
        if self.process.stdin is not None and not self.process.stdin.closed:
            try:
                self.process.stdin.close()
            except (OSError, ValueError):
                pass
        if self.control_fd >= 0:
            try:
                os.close(self.control_fd)
            except OSError:
                pass
            self.control_fd = -1


def start_host_gateway(wl: L.WorkerLayout, log_handle) -> HostGateway:
    prepare_broker_dir(wl)
    socket_path = broker_socket(wl, secrets.token_hex(16))
    control_read, control_write = os.pipe2(os.O_CLOEXEC)
    os.set_inheritable(control_write, True)
    try:
        process = subprocess.Popen(
            [
                str(trusted_venv_python()), "-I", str(_BROKER_ENTRY),
                "--socket", str(socket_path),
                "--control-fd", str(control_write),
            ],
            stdin=subprocess.PIPE,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            env=host_gateway_env(wl),
            cwd="/",
            pass_fds=(control_write,),
        )
    except BaseException:
        os.close(control_read)
        os.close(control_write)
        raise
    os.close(control_write)
    readable, _, _ = select.select([control_read], [], [], 5.0)
    marker = os.read(control_read, 1) if readable else b""
    if marker != BROKER_READY_MARKER or process.poll() is not None:
        os.close(control_read)
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=3)
        raise WorkerSecurityError("host gateway broker exited before becoming ready")
    try:
        info = socket_path.lstat()
    except OSError as exc:
        process.terminate()
        process.wait(timeout=3)
        raise WorkerSecurityError("host gateway locator was not published") from exc
    if (
        not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        process.terminate()
        process.wait(timeout=3)
        raise WorkerSecurityError("host gateway locator has unsafe identity")
    return HostGateway(
        process=process, socket_path=socket_path,
        socket_dev=info.st_dev, socket_ino=info.st_ino,
        control_fd=control_read,
    )


def record_provider_pid(wl: L.WorkerLayout, pid: int) -> None:
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
        raise WorkerSecurityError("invalid provider process identity")
    try:
        atomic_write_text(provider_pid_file(wl), f"{pid}\n", mode=0o600)
    except (OSError, SecureIOError) as exc:
        raise WorkerSecurityError("cannot publish provider process identity") from exc


def _toml(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _validated_gateway_socket(wl: L.WorkerLayout, socket_path: Path) -> Path:
    path = socket_path.absolute()
    if path != Path(PROVIDER_SOCKET_PATH):
        raise WorkerSecurityError("Worker gateway locator is not the private service endpoint")
    return path


def permission_profile_override(wl: L.WorkerLayout, socket_path: Path) -> str:
    """TOML inline table for Codex 0.148's enforced Worker profile."""
    gateway_socket = _validated_gateway_socket(wl, socket_path)
    isolated_home = provider_home(wl)
    filesystem: dict[str, str] = {
        ":minimal": "read",
        str(wl.dir): "read",
        str(wl.local_memory): "write",
        str(model_workspace(wl)): "write",
        str(model_tmp(wl)): "write",
        str(_REPO_ROOT / "agents"): "read",
        str(broker_dir(wl)): "deny",
        str(gateway_socket): "deny",
        str(isolated_home): "deny",
        str(wl.project_dir.parent / ".danus-web-control-staging"): "deny",
        # ``inherit=none`` prevents direct environment inheritance.  These
        # rules also prevent reading credentials from a trusted ancestor's
        # procfs environment (including API-key deployments).
        "/proc": "deny",
    }
    for path in shared_project_read_paths(wl):
        filesystem[str(path)] = "read"
    # The Codex sandbox helper re-execs resources from its native vendor tree.
    # Admit that tree to the inner permission profile without admitting the
    # surrounding runtime or any sibling Project.
    js_value = os.environ.get("DANUS_CODEX_JS")
    if js_value:
        native = resolve_trusted_codex_bin(str(_REPO_ROOT / "bin" / "codex"))
        runtime_root = _codex_runtime_root(native)
        if runtime_root is None:
            raise WorkerSecurityError("unexpected native Codex runtime layout")
        filesystem[str(runtime_root)] = "read"
    fs = ",".join(f"{_toml(path)}={_toml(access)}" for path, access in filesystem.items())
    sockets = f"{{{_toml(str(gateway_socket))}=\"deny\"}}"
    return (
        "{description=\"Danus project-scoped Worker\","
        f"filesystem={{{fs}}},network={{enabled=false,unix_sockets={sockets}}}}}"
    )


def mcp_bridge_override(wl: L.WorkerLayout, socket_path: Path) -> str:
    gateway_socket = _validated_gateway_socket(wl, socket_path)
    python = str(Path(sys.executable).resolve(strict=False))
    args = ",".join(_toml(value) for value in (
        "-I", str(_BRIDGE_ENTRY), "--socket", str(gateway_socket),
    ))
    return (
        f"{{command={_toml(python)},args=[{args}],tool_timeout_sec=3600,"
        "env={PYTHONDONTWRITEBYTECODE=\"1\",PYTHONSAFEPATH=\"1\"}}"
    )


def codex_security_args(wl: L.WorkerLayout, socket_path: Path) -> list[str]:
    """High-precedence ``codex exec`` flags user config cannot weaken."""
    safe_shell_path = "/usr/local/bin:/usr/bin:/bin"
    temporary = model_tmp(wl)
    shell_set = (
        "{PATH=" + _toml(safe_shell_path) + ",HOME=" + _toml(str(model_workspace(wl)))
        + ",LANG=\"C.UTF-8\",TMPDIR=" + _toml(str(temporary)) + "}"
    )
    return [
        "--ignore-user-config",
        "--ignore-rules",
        "--strict-config",
        "--config", 'approval_policy="never"',
        "--config", "allow_login_shell=false",
        "--config", 'default_permissions="danus_worker"',
        "--config", f"permissions.danus_worker={permission_profile_override(wl, socket_path)}",
        "--config", 'shell_environment_policy.inherit="none"',
        "--config", "shell_environment_policy.ignore_default_excludes=false",
        "--config", f"shell_environment_policy.set={shell_set}",
        "--config", f"mcp_servers.danus={mcp_bridge_override(wl, socket_path)}",
    ]


def codex_global_security_args() -> list[str]:
    """Global CLI flags which must appear before the ``exec`` subcommand."""
    return ["--search"]


def _mount_source(path: Path, label: str) -> Path:
    try:
        raw_info = path.lstat()
        resolved = path.resolve(strict=True)
        info = resolved.stat()
    except OSError as exc:
        raise WorkerSecurityError(f"{label} is unavailable") from exc
    if stat.S_ISLNK(raw_info.st_mode) or not (
        stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)
    ):
        raise WorkerSecurityError(f"{label} is not a real file or directory")
    if info.st_mode & 0o002:
        raise WorkerSecurityError(f"{label} is world-writable")
    return resolved


def provider_read_only_paths(wl: L.WorkerLayout, codex_bin: str) -> list[Path]:
    """Exact host paths reopened in the provider's otherwise hidden view."""

    paths = [
        _mount_source(_REPO_ROOT / "danus", "Danus provider code"),
        _mount_source(_REPO_ROOT / "agents", "Danus Worker contracts"),
        _mount_source(wl.dir, "Worker directory"),
    ]
    paths.extend(
        _mount_source(path, "Project shared material")
        for path in shared_project_read_paths(wl)
    )
    python_root = Path(sys.base_prefix).resolve(strict=False)
    if str(python_root).startswith(("/home/", "/root/")):
        paths.append(_mount_source(python_root, "trusted Python runtime"))
    runtime_root = _codex_runtime_root(codex_bin)
    if runtime_root is not None:
        paths.append(_mount_source(runtime_root, "Worker native Codex runtime"))
    else:
        paths.append(_mount_source(Path(codex_bin), "Worker Codex binary"))
    return sorted({path for path in paths}, key=str)


def provider_writable_paths(wl: L.WorkerLayout) -> list[Path]:
    """Exact writable mounts for provider state and model-authored research."""

    local_memory = _private_dir(wl.local_memory, "Worker local memory")
    return sorted({
        local_memory, model_workspace(wl), model_tmp(wl), provider_home(wl),
    }, key=str)


def outer_sandbox_command(
    wl: L.WorkerLayout, codex_bin: str, command: Iterable[str], *,
    ready_challenge: bytes, socket_dev: int, socket_ino: int,
) -> list[str]:
    """Build the absolute trusted entry command for the systemd service."""

    # Revalidate at the boundary itself.  This is intentionally redundant with
    # ``loop.run_round``; the systemd launcher is the security-critical sink.
    validated = validated_worker_codex_bin(codex_bin)
    binary_candidate = Path(validated).resolve(strict=False)
    if not binary_candidate.is_file():
        raise WorkerSecurityError(f"codex binary not found: {binary_candidate}")
    binary = _safe_executable(binary_candidate, "Worker Codex binary")
    provider_command = list(command)
    if not provider_command:
        raise WorkerSecurityError("empty Worker Codex command")
    try:
        command_binary = Path(provider_command[0]).resolve(strict=False)
    except OSError as exc:
        raise WorkerSecurityError("invalid Worker Codex command") from exc
    if command_binary != binary:
        raise WorkerSecurityError("Worker Codex command does not match the validated binary")

    # Force mount inventory validation before asking systemd to start anything.
    provider_read_only_paths(wl, str(binary))
    provider_writable_paths(wl)
    launcher = str(Path(sys.executable).resolve())
    if len(ready_challenge) != 16:
        raise WorkerSecurityError("invalid provider READY challenge")
    if socket_dev < 0 or socket_ino <= 0:
        raise WorkerSecurityError("invalid provider gateway identity")
    return [
        launcher, "-I", str(_PROVIDER_ENTRY),
        "--ready-challenge", ready_challenge.hex(),
        "--socket-dev", str(socket_dev), "--socket-ino", str(socket_ino),
        "--", *provider_command,
    ]


__all__ = [
    "BROKER_DIR_NAME",
    "MODEL_TMP_NAME",
    "PROVIDER_STATE_DIR_NAME",
    "WorkerSecurityError",
    "broker_dir",
    "broker_socket",
    "codex_global_security_args",
    "codex_security_args",
    "host_gateway_env",
    "mcp_bridge_override",
    "outer_sandbox_command",
    "permission_profile_override",
    "prepare_broker_dir",
    "provider_pid_file",
    "provider_home",
    "provider_read_only_paths",
    "provider_writable_paths",
    "record_provider_pid",
    "resolve_trusted_codex_bin",
    "trusted_codex_runtime",
    "resolve_worker_codex_bin",
    "start_host_gateway",
    "trusted_venv_python",
    "validated_worker_codex_bin",
    "worker_provider_env",
]
