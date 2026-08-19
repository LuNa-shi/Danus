"""Project/Worker-scoped bearer capabilities for the local verifier.

The verifier is intentionally loopback-only, but loopback is not an
authorization boundary: an untrusted Worker command can also address
``127.0.0.1`` unless its command sandbox is perfect.  Every ``/verify`` request
therefore carries a signed capability bound to one Project and one Worker.

Only trusted host processes read the HMAC key.  The host-owned gateway broker
mints a fresh bearer for each verifier HTTP request; neither the Codex provider,
model-created commands, nor the credential-free MCP bridge receives the token
or HMAC key.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import time
import fcntl
from pathlib import Path

from danus.secure_io import (
    SecureIOError,
    ensure_private_dir,
    open_directory,
    publish_bytes_noreplace,
    read_private_bytes,
)

_SCOPE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_VERSION = 1
_MIN_KEY_BYTES = 32
_DEFAULT_TTL_SECONDS = 300
_MIN_TTL_SECONDS = 5
_MAX_TTL_SECONDS = 600
_CLOCK_SKEW_SECONDS = 30
_REPLAY_BUCKET_SECONDS = 60
_MAX_ACTIVE_BUCKETS = 16
_MAX_MARKERS_PER_BUCKET = 4096
_BUCKET_RE = re.compile(r"^expires-([0-9]{1,16})$")
_NONCE_RE = re.compile(r"^[0-9a-f]{64}$")


class CapabilityConfigurationError(RuntimeError):
    """The verifier capability key is absent, unsafe, or malformed."""


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("invalid base64url value")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _default_secret_path() -> Path:
    runtime = os.environ.get("DANUS_RUNTIME")
    if runtime:
        return Path(runtime).resolve() / "secrets" / "verify-capability.key"
    return Path(__file__).resolve().parents[2] / "runtime" / "secrets" / "verify-capability.key"


def secret_path() -> Path:
    configured = os.environ.get("DANUS_VERIFY_CAPABILITY_SECRET_FILE")
    # ``resolve`` would follow a final symlink before ``lstat`` can reject it.
    return Path(configured).expanduser().absolute() if configured else _default_secret_path()


def _validate_scope(project: str, worker: str) -> None:
    if not _SCOPE_RE.fullmatch(project):
        raise ValueError("invalid verifier capability project scope")
    if not _SCOPE_RE.fullmatch(worker):
        raise ValueError("invalid verifier capability worker scope")


def _read_key(path: Path) -> bytes:
    try:
        return read_private_bytes(path, minimum=_MIN_KEY_BYTES, maximum=4096)
    except (OSError, SecureIOError) as exc:
        # Never reflect the configured secret path: callers may surface this
        # message in a service log or HTTP error envelope.
        raise CapabilityConfigurationError("verifier capability key is unavailable or unsafe") from exc


def load_or_create_key() -> bytes:
    """Load/create the key without ever publishing an empty/partial file.

    A previous ``O_CREAT|O_EXCL`` implementation exposed the final pathname
    before the first writer had filled it.  A concurrent reader could therefore
    observe a zero-byte key and fail nondeterministically.  The new path writes
    and fsyncs a random private temporary, then uses an atomic no-replace hard
    link as the publication point; losers read the complete winning inode.
    """
    path = secret_path()
    try:
        ensure_private_dir(path.parent)
        key = secrets.token_bytes(48)
        publish_bytes_noreplace(path, key, mode=0o600)
        return _read_key(path)
    except CapabilityConfigurationError:
        raise
    except (OSError, SecureIOError) as exc:
        raise CapabilityConfigurationError("verifier capability key is unavailable or unsafe") from exc


def _token_ttl_seconds() -> int:
    raw = os.environ.get("DANUS_VERIFY_CAPABILITY_TTL_SECONDS")
    try:
        ttl = int(raw) if raw is not None else _DEFAULT_TTL_SECONDS
    except ValueError as exc:
        raise CapabilityConfigurationError(
            "verifier capability lifetime configuration is invalid"
        ) from exc
    if ttl < _MIN_TTL_SECONDS or ttl > _MAX_TTL_SECONDS:
        raise CapabilityConfigurationError(
            "verifier capability lifetime configuration is invalid"
        )
    return ttl


def mint_worker_capability(project: str, worker: str) -> str:
    """Mint a one-use bearer token for exactly ``project/worker``."""
    _validate_scope(project, worker)
    issued_at = int(time.time())
    payload = json.dumps(
        {
            "expires_at": issued_at + _token_ttl_seconds(),
            "issued_at": issued_at,
            "nonce": secrets.token_hex(32),
            "project": project,
            "v": _VERSION,
            "worker": worker,
        },
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")
    encoded = _b64encode(payload)
    signature = hmac.new(load_or_create_key(), encoded.encode("ascii"), hashlib.sha256).digest()
    return f"dv{_VERSION}.{encoded}.{_b64encode(signature)}"


def _open_lock(root_fd: int) -> int:
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(".lock", flags, 0o600, dir_fd=root_fd)
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        os.close(fd)
        raise CapabilityConfigurationError(
            "verifier capability replay state is unavailable or unsafe"
        )
    os.fchmod(fd, 0o600)
    return fd


def _remove_expired_bucket(root_fd: int, name: str) -> None:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    bucket_fd = os.open(name, flags, dir_fd=root_fd)
    try:
        for marker in os.listdir(bucket_fd):
            if not _NONCE_RE.fullmatch(marker):
                raise CapabilityConfigurationError(
                    "verifier capability replay state is unavailable or unsafe"
                )
            info = os.stat(marker, dir_fd=bucket_fd, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise CapabilityConfigurationError(
                    "verifier capability replay state is unavailable or unsafe"
                )
            os.unlink(marker, dir_fd=bucket_fd)
        os.fsync(bucket_fd)
    finally:
        os.close(bucket_fd)
    os.rmdir(name, dir_fd=root_fd)


def _consume_nonce(nonce: str, expires_at: int, now: int) -> bool:
    """Atomically consume one nonce in a TTL-bounded persistent replay ledger."""
    replay_dir = secret_path().parent / "verify-capability-replay"
    root_fd = -1
    lock_fd = -1
    bucket_fd = -1
    try:
        ensure_private_dir(replay_dir)
        root_fd = open_directory(replay_dir, private_final=True)
        lock_fd = _open_lock(root_fd)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)

        active: list[str] = []
        for name in os.listdir(root_fd):
            if name == ".lock":
                continue
            match = _BUCKET_RE.fullmatch(name)
            if not match:
                raise CapabilityConfigurationError(
                    "verifier capability replay state is unavailable or unsafe"
                )
            bucket_number = int(match.group(1))
            bucket_end = (bucket_number + 1) * _REPLAY_BUCKET_SECONDS
            if bucket_end <= now:
                _remove_expired_bucket(root_fd, name)
            else:
                active.append(name)
        target_number = expires_at // _REPLAY_BUCKET_SECONDS
        target = f"expires-{target_number}"
        if target not in active:
            try:
                os.mkdir(target, 0o700, dir_fd=root_fd)
            except FileExistsError:
                pass
            active.append(target)
        if len(set(active)) > _MAX_ACTIVE_BUCKETS:
            raise CapabilityConfigurationError(
                "verifier capability replay capacity is unavailable"
            )

        dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            dir_flags |= os.O_NOFOLLOW
        bucket_fd = os.open(target, dir_flags, dir_fd=root_fd)
        bucket_info = os.fstat(bucket_fd)
        if (
            not stat.S_ISDIR(bucket_info.st_mode)
            or bucket_info.st_uid != os.getuid()
            or stat.S_IMODE(bucket_info.st_mode) & 0o077
        ):
            raise CapabilityConfigurationError(
                "verifier capability replay state is unavailable or unsafe"
            )
        os.fchmod(bucket_fd, 0o700)
        entries = os.listdir(bucket_fd)
        for entry in entries:
            if not _NONCE_RE.fullmatch(entry):
                raise CapabilityConfigurationError(
                    "verifier capability replay state is unavailable or unsafe"
                )
            entry_info = os.stat(entry, dir_fd=bucket_fd, follow_symlinks=False)
            if (
                not stat.S_ISREG(entry_info.st_mode)
                or entry_info.st_uid != os.getuid()
                or stat.S_IMODE(entry_info.st_mode) & 0o077
            ):
                raise CapabilityConfigurationError(
                    "verifier capability replay state is unavailable or unsafe"
                )
        if len(entries) >= _MAX_MARKERS_PER_BUCKET and nonce not in entries:
            raise CapabilityConfigurationError(
                "verifier capability replay capacity is unavailable"
            )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(nonce, flags, 0o600, dir_fd=bucket_fd)
        except FileExistsError:
            return False
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise CapabilityConfigurationError(
                    "verifier capability replay state is unavailable or unsafe"
                )
            os.fchmod(fd, 0o600)
            os.write(fd, f"{expires_at}\n".encode("ascii"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(bucket_fd)
        os.fsync(root_fd)
        return True
    except CapabilityConfigurationError:
        raise
    except OSError as exc:
        raise CapabilityConfigurationError(
            "verifier capability replay state is unavailable or unsafe"
        ) from exc
    finally:
        if bucket_fd >= 0:
            os.close(bucket_fd)
        if lock_fd >= 0:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        if root_fd >= 0:
            os.close(root_fd)


def verify_worker_capability(token: str, project: str, worker: str) -> bool:
    """Verify and atomically consume an exactly Project/Worker-bound token."""
    try:
        _validate_scope(project, worker)
        prefix, encoded, supplied_signature = token.split(".", 2)
        if prefix != f"dv{_VERSION}" or len(token) > 1024:
            return False
        raw_payload = _b64decode(encoded)
        if _b64encode(raw_payload) != encoded:
            return False
        payload = json.loads(raw_payload)
        if not isinstance(payload, dict):
            return False
        nonce = payload.get("nonce")
        issued_at = payload.get("issued_at")
        expires_at = payload.get("expires_at")
        if (
            payload != {
                "expires_at": expires_at,
                "issued_at": issued_at,
                "nonce": nonce,
                "project": project,
                "v": _VERSION,
                "worker": worker,
            }
            or not isinstance(nonce, str)
            or not _NONCE_RE.fullmatch(nonce)
            or isinstance(issued_at, bool)
            or not isinstance(issued_at, int)
            or isinstance(expires_at, bool)
            or not isinstance(expires_at, int)
        ):
            return False
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("ascii")
        if canonical != raw_payload:
            return False
        now = int(time.time())
        if (
            expires_at <= issued_at
            or expires_at - issued_at > _MAX_TTL_SECONDS
            or issued_at > now + _CLOCK_SKEW_SECONDS
            or expires_at <= now
        ):
            return False
        expected = hmac.new(load_or_create_key(), encoded.encode("ascii"), hashlib.sha256).digest()
        supplied = _b64decode(supplied_signature)
        if _b64encode(supplied) != supplied_signature or len(supplied) != hashlib.sha256().digest_size:
            return False
        if not hmac.compare_digest(expected, supplied):
            return False
        return _consume_nonce(nonce, expires_at, now)
    except (
        ValueError, TypeError, binascii.Error, json.JSONDecodeError, UnicodeDecodeError,
    ):
        return False


__all__ = [
    "CapabilityConfigurationError",
    "load_or_create_key",
    "mint_worker_capability",
    "secret_path",
    "verify_worker_capability",
]
