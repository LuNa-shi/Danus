"""Small, symlink-safe host file primitives.

The Worker and verifier security boundaries keep their control state in
directories which an untrusted provider cannot modify.  These helpers are the
second line of defence: every path component is opened relative to a directory
descriptor with ``O_NOFOLLOW`` and every replacement is a fully-written,
fsynced, randomly-named file published atomically.

The functions deliberately accept :class:`~pathlib.Path` objects rather than
untrusted path fragments.  Callers remain responsible for deriving paths from
validated Project/Worker identifiers.
"""

from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path
from typing import BinaryIO, TextIO


class SecureIOError(RuntimeError):
    """A host control path failed a fail-closed safety check."""


_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
_FILE_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def _absolute_parts(path: Path) -> tuple[str, ...]:
    absolute = path.expanduser().absolute()
    if not absolute.is_absolute():  # pragma: no cover - ``absolute`` guarantees it
        raise SecureIOError("control path must be absolute")
    parts = absolute.parts[1:]
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise SecureIOError("control path contains an unsafe component")
    return parts


def open_directory(
    path: Path, *, create: bool = False, create_mode: int = 0o700,
    private_final: bool = False,
) -> int:
    """Open *path* without following any symlink in its ancestry.

    The returned descriptor is owned by the caller.  Missing components are
    created only when ``create`` is true.  ``private_final`` additionally
    requires the final directory to be owned by this uid and forces mode 0700.
    """

    parts = _absolute_parts(path)
    fd = os.open("/", _DIR_FLAGS)
    try:
        for part in parts:
            try:
                child = os.open(part, _DIR_FLAGS | _FILE_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(part, create_mode, dir_fd=fd)
                except FileExistsError:
                    # A concurrent creator won.  The no-follow open below is
                    # the authority on whether it created a safe directory.
                    pass
                child = os.open(part, _DIR_FLAGS | _FILE_NOFOLLOW, dir_fd=fd)
            info = os.fstat(child)
            if not stat.S_ISDIR(info.st_mode):
                os.close(child)
                raise SecureIOError("control path component is not a real directory")
            os.close(fd)
            fd = child
        if private_final:
            info = os.fstat(fd)
            if info.st_uid != os.getuid():
                raise SecureIOError("private control directory has unsafe ownership")
            os.fchmod(fd, 0o700)
        return fd
    except BaseException:
        os.close(fd)
        raise


def ensure_private_dir(path: Path) -> Path:
    """Create/validate an owned 0700 directory without following symlinks."""

    fd = open_directory(path, create=True, private_final=True)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return path.absolute()


def _target_info(parent_fd: int, name: str) -> os.stat_result | None:
    try:
        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode):
        raise SecureIOError("control file target is not a regular non-symlink file")
    if info.st_uid != os.getuid():
        raise SecureIOError("control file target has unsafe ownership")
    return info


def _write_temp(parent_fd: int, data: bytes, mode: int) -> str:
    for _ in range(128):
        name = f".danus-{secrets.token_hex(16)}.tmp"
        flags = (
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | _FILE_NOFOLLOW
        )
        try:
            fd = os.open(name, flags, mode, dir_fd=parent_fd)
        except FileExistsError:
            continue
        try:
            os.fchmod(fd, mode)
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:  # pragma: no cover - defensive kernel contract
                    raise OSError("short control-file write")
                view = view[written:]
            os.fsync(fd)
        except BaseException:
            os.close(fd)
            try:
                os.unlink(name, dir_fd=parent_fd)
            except OSError:
                pass
            raise
        os.close(fd)
        return name
    raise SecureIOError("could not allocate a private control-file temporary")


def atomic_write_bytes(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    """Atomically replace a regular file with private, fully-durable bytes."""

    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if stat.S_IMODE(mode) & 0o077:
        raise SecureIOError("control file mode must not grant group/other access")
    parent_fd = open_directory(path.parent, create=True)
    tmp = ""
    try:
        _target_info(parent_fd, path.name)
        tmp = _write_temp(parent_fd, data, stat.S_IMODE(mode))
        os.replace(
            tmp, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd,
        )
        tmp = ""
        os.fsync(parent_fd)
    finally:
        if tmp:
            try:
                os.unlink(tmp, dir_fd=parent_fd)
            except OSError:
                pass
        os.close(parent_fd)


def atomic_write_text(path: Path, text: str, *, mode: int = 0o600) -> None:
    atomic_write_bytes(path, text.encode("utf-8"), mode=mode)


def publish_bytes_noreplace(path: Path, data: bytes, *, mode: int = 0o600) -> bool:
    """Publish bytes exactly once without ever exposing a partial target.

    Returns ``True`` for the winning publisher and ``False`` when another
    process already published the target.  A hard-link publication is the
    portable Linux no-replace primitive: the random temporary and final name
    refer to the same already-fsynced inode, and ``link(2)`` is atomic.
    """

    parent_fd = open_directory(path.parent, create=True, private_final=True)
    tmp = ""
    try:
        if _target_info(parent_fd, path.name) is not None:
            return False
        tmp = _write_temp(parent_fd, data, stat.S_IMODE(mode))
        try:
            os.link(
                tmp, path.name,
                src_dir_fd=parent_fd, dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
            won = True
        except FileExistsError:
            won = False
        os.unlink(tmp, dir_fd=parent_fd)
        tmp = ""
        os.fsync(parent_fd)
        return won
    finally:
        if tmp:
            try:
                os.unlink(tmp, dir_fd=parent_fd)
            except OSError:
                pass
        os.close(parent_fd)


def read_private_bytes(path: Path, *, minimum: int = 0, maximum: int = 1 << 20) -> bytes:
    """Read one owned 0600-ish regular file through a no-follow descriptor."""

    parent_fd = open_directory(path.parent)
    fd = -1
    try:
        fd = os.open(
            path.name, os.O_RDONLY | os.O_CLOEXEC | _FILE_NOFOLLOW,
            dir_fd=parent_fd,
        )
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise SecureIOError("private control file has unsafe type, owner, or mode")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(fd, min(65536, maximum + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > maximum:
                raise SecureIOError("private control file exceeds its size limit")
        result = b"".join(chunks)
        if len(result) < minimum:
            raise SecureIOError("private control file is too short")
        return result
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(parent_fd)


def secure_open_text(
    path: Path, *, append: bool = False, mode: int = 0o600,
) -> TextIO:
    """Open a private host log/control file without following the final path."""

    parent_fd = open_directory(path.parent, create=True)
    try:
        existing = _target_info(parent_fd, path.name)
        flags = os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC | _FILE_NOFOLLOW
        flags |= os.O_APPEND if append else os.O_TRUNC
        fd = os.open(path.name, flags, mode, dir_fd=parent_fd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            os.close(fd)
            raise SecureIOError("host log target is unsafe")
        os.fchmod(fd, stat.S_IMODE(mode))
        return os.fdopen(fd, "a" if append else "w", encoding="utf-8")
    finally:
        os.close(parent_fd)


def secure_unlink(path: Path, *, missing_ok: bool = True) -> None:
    """Unlink one regular private file through its no-follow parent descriptor."""

    parent_fd = open_directory(path.parent)
    try:
        try:
            info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            if missing_ok:
                return
            raise
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise SecureIOError("refusing to unlink an unsafe control target")
        os.unlink(path.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


__all__ = [
    "SecureIOError",
    "atomic_write_bytes",
    "atomic_write_text",
    "ensure_private_dir",
    "open_directory",
    "publish_bytes_noreplace",
    "read_private_bytes",
    "secure_open_text",
    "secure_unlink",
]
