"""Fail-closed hardening for verifier processes that handle secret material."""

from __future__ import annotations

import ctypes
import os
import resource


_PR_GET_DUMPABLE = 3
_PR_SET_DUMPABLE = 4


class VerifierProcessSecurityError(RuntimeError):
    """The verifier process could not establish its secret-process policy."""


def _prctl(option: int, value: int = 0) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.prctl(option, value, 0, 0, 0)
    if result < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return int(result)


def harden_secret_process() -> None:
    """Disable ptrace/core-dump exposure or raise a redacted typed error."""

    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        _prctl(_PR_SET_DUMPABLE, 0)
        if _prctl(_PR_GET_DUMPABLE) != 0:
            raise OSError("kernel did not retain nondumpable state")
    except (OSError, ValueError) as exc:
        raise VerifierProcessSecurityError(
            "verifier process hardening unavailable"
        ) from exc


def process_is_dumpable() -> bool:
    """Return the kernel's current dumpability state for security tests/probes."""

    try:
        return _prctl(_PR_GET_DUMPABLE) != 0
    except OSError as exc:
        raise VerifierProcessSecurityError(
            "verifier process hardening unavailable"
        ) from exc


__all__ = [
    "VerifierProcessSecurityError",
    "harden_secret_process",
    "process_is_dumpable",
]
