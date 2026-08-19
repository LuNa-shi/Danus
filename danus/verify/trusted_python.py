"""Validate while preserving the venv-facing Python executable path."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import sys

from danus.secure_io import SecureIOError, open_directory


class TrustedPythonError(RuntimeError):
    """The serving interpreter path is absent or has unsafe provenance."""


def _trusted_directory_owner(uid: int) -> bool:
    """Accept idmapped host-root ancestors without relaxing file checks.

    This deployment runs on an idmapped ZFS mount, where host-root-owned
    system directories appear as uid 65534 (``nobody``) in the container.
    These ancestors are immutable to the serving uid; executable and regular
    file payloads remain restricted to root or the serving uid.
    """

    return uid in {0, os.getuid(), 65534}


def _safe_regular(path: Path, label: str) -> None:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid not in {0, os.getuid()}
        or info.st_mode & 0o002
    ):
        raise TrustedPythonError(f"{label} is unsafe")


def _safe_directory(path: Path, label: str) -> None:
    fd = open_directory(path)
    try:
        info = os.fstat(fd)
        if not _trusted_directory_owner(info.st_uid) or info.st_mode & 0o002:
            raise TrustedPythonError(f"{label} is unsafe")
    finally:
        os.close(fd)


def _safe_directory_info(info: os.stat_result, label: str) -> None:
    if (
        not stat.S_ISDIR(info.st_mode)
        or not _trusted_directory_owner(info.st_uid)
        or info.st_mode & 0o002
    ):
        raise TrustedPythonError(f"{label} is unsafe")


def _resolve_safe_chain(path: Path) -> Path:
    """Resolve an owned, non-world-writable chain one component at a time.

    Python installations managed by uv have two legitimate symlinks in the
    executable path: the venv entry points at an unversioned installation name,
    and that name is itself a symlink to the versioned installation directory.
    Resolving only the final entry makes the intermediate directory look like an
    unsafe non-directory to ``open_directory``.  Instead, expand every symlink
    explicitly and then restart the no-follow walk from ``/``.
    """

    pending = list(Path(os.path.abspath(path)).parts[1:])
    current = Path("/")
    seen: set[tuple[int, int, int]] = set()
    symlinks = 0

    while pending:
        name = pending.pop(0)
        candidate = current / name
        info = candidate.lstat()
        if stat.S_ISLNK(info.st_mode):
            symlinks += 1
            marker = (info.st_dev, info.st_ino, info.st_ctime_ns)
            if (
                symlinks > 40
                or marker in seen
                or info.st_uid not in {0, os.getuid()}
            ):
                raise TrustedPythonError("verifier Python symlink chain is unsafe")
            seen.add(marker)

            target = Path(os.readlink(candidate))
            after = candidate.lstat()
            if (
                not stat.S_ISLNK(after.st_mode)
                or (after.st_dev, after.st_ino, after.st_ctime_ns) != marker
            ):
                raise TrustedPythonError("verifier Python symlink chain is unsafe")

            expanded = target if target.is_absolute() else current / target
            if pending:
                expanded = expanded.joinpath(*pending)
            pending = list(Path(os.path.abspath(expanded)).parts[1:])
            current = Path("/")
            continue

        if not pending:
            return candidate

        _safe_directory_info(info, "verifier Python parent")
        fd = open_directory(candidate)
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise TrustedPythonError("verifier Python symlink chain is unsafe")
        finally:
            os.close(fd)
        current = candidate

    raise TrustedPythonError("verifier Python symlink chain is unsafe")


def trusted_python_executable() -> str:
    """Return lexical ``sys.executable`` after validating its resolved target.

    Resolving the executable and then launching that resolved path discards a
    virtual environment's adjacent ``pyvenv.cfg``.  Keep the absolute lexical
    ``<venv>/bin/python`` for execution while validating both that entry and its
    final target.  The transient-service adapter separately pins the live
    ``/proc/<pid>/exe`` inode to the resolved target.
    """

    lexical = Path(sys.executable)
    if not lexical.is_absolute() or lexical != Path(os.path.abspath(lexical)):
        raise TrustedPythonError("verifier Python entry is unsafe")
    try:
        lexical_info = lexical.lstat()
        resolved = _resolve_safe_chain(lexical)
        if stat.S_ISLNK(lexical_info.st_mode):
            if lexical_info.st_uid not in {0, os.getuid()}:
                raise TrustedPythonError("verifier Python entry is unsafe")
        elif not stat.S_ISREG(lexical_info.st_mode):
            raise TrustedPythonError("verifier Python entry is unsafe")
        _safe_regular(resolved, "verifier Python target")

        prefix = Path(sys.prefix).absolute()
        _safe_directory(prefix, "verifier virtual environment")
        pyvenv = prefix / "pyvenv.cfg"
        if lexical.parent == prefix / "bin":
            _safe_regular(pyvenv, "verifier virtual environment")
        elif prefix != Path(sys.base_prefix).absolute():
            raise TrustedPythonError("verifier Python is outside its virtual environment")
    except (OSError, RuntimeError, SecureIOError) as exc:
        if isinstance(exc, TrustedPythonError):
            raise
        raise TrustedPythonError("verifier Python entry is unsafe") from exc
    return str(lexical)


__all__ = ["TrustedPythonError", "trusted_python_executable"]
