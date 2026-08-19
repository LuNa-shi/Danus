"""Trusted-supervisor seam for verifier provider processes.

The verifier launcher owns prompt construction and output validation.  The
production adapter owns the OS process boundary: it starts the fixed trusted
entry in a dedicated transient service, streams the framed request over stdin,
and returns only redacted execution metadata after proving the service cgroup
is empty.  There is deliberately no direct-subprocess production fallback.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import os
from pathlib import Path
import re
import stat
import threading
from typing import Mapping, Protocol, runtime_checkable

from .trusted_python import TrustedPythonError, trusted_python_executable


class TrustedVerifierError(RuntimeError):
    """A typed, non-secret verifier-supervisor failure."""


class TrustedVerifierUnavailable(TrustedVerifierError):
    """No production supervisor is installed or it failed its safety checks."""


class TrustedVerifierTimeout(TrustedVerifierError):
    """The bounded provider run exceeded its deadline and was fully stopped."""


@dataclass(frozen=True, repr=False)
class VerifierRunRequest:
    """One semantic provider request; sensitive fields are intentionally no-repr.

    The adapter MUST put only :attr:`entry_argv` in transient-unit properties,
    use ``cwd=/``, and carry all other fields over a private framed stdin pipe.
    It MUST NOT place ``provider_argv``, ``provider_environment``, or ``prompt``
    in argv, environment properties, unit descriptions, or the journal.
    """

    run_id: str
    entry_argv: tuple[str, ...]
    provider_argv: tuple[str, ...]
    provider_environment: Mapping[str, str]
    prompt: bytes
    timeout_seconds: int | None
    read_only_paths: tuple[str, ...]
    read_write_paths: tuple[str, ...]
    cwd: str = "/"


@dataclass(frozen=True)
class VerifierRunResult:
    """Redacted result returned only after the complete process tree is empty."""

    returncode: int
    duration_seconds: float
    stdout_sha256: str
    stdout_bytes: int
    descendants_empty: bool


@runtime_checkable
class TrustedVerifierRunner(Protocol):
    """Port implemented by the production transient-service and test adapters."""

    def run(self, request: VerifierRunRequest) -> VerifierRunResult:
        """Run once or raise a typed error without reflecting request data."""


_HERE = Path(__file__).resolve().parent
_TRUSTED_ENTRY = (_HERE / "trusted_entry.py").resolve()
_RESULT_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_runner_lock = threading.Lock()
_production_runner: TrustedVerifierRunner | None = None


def trusted_entry_argv() -> tuple[str, ...]:
    """Return the sole command a production transient service may expose."""

    try:
        python = Path(trusted_python_executable())
        entry = _TRUSTED_ENTRY.resolve(strict=True)
    except (OSError, TrustedPythonError) as exc:
        raise TrustedVerifierUnavailable("verifier security boundary unavailable") from exc
    try:
        for path in (python, entry):
            info = path.stat()
            if (
                not path.is_absolute()
                or not stat.S_ISREG(info.st_mode)
                or info.st_uid not in {0, os.getuid()}
                or info.st_mode & 0o002
            ):
                raise TrustedVerifierUnavailable("verifier security boundary unavailable")
    except OSError as exc:
        raise TrustedVerifierUnavailable("verifier security boundary unavailable") from exc
    return (str(python), "-I", str(entry))


def install_production_runner(adapter: TrustedVerifierRunner) -> None:
    """Install the host adapter exactly once during trusted service bootstrap."""

    if not isinstance(adapter, TrustedVerifierRunner):
        raise TypeError("adapter does not implement TrustedVerifierRunner")
    global _production_runner
    with _runner_lock:
        if _production_runner is not None and _production_runner is not adapter:
            raise TrustedVerifierUnavailable("verifier security boundary unavailable")
        _production_runner = adapter


def clear_production_runner_for_testing() -> None:
    """Test-only reset; production bootstrap never calls this."""

    global _production_runner
    with _runner_lock:
        _production_runner = None


def run_with_trusted_supervisor(
    request: VerifierRunRequest,
    *,
    adapter: TrustedVerifierRunner | None = None,
) -> VerifierRunResult:
    """Cross the seam and enforce its result invariants in one place."""

    selected = adapter
    if selected is None:
        with _runner_lock:
            selected = _production_runner
    if selected is None:
        raise TrustedVerifierUnavailable("verifier security boundary unavailable")
    try:
        result = selected.run(request)
    except (TrustedVerifierTimeout, TrustedVerifierUnavailable):
        raise
    except TrustedVerifierError as exc:
        raise TrustedVerifierUnavailable("verifier security boundary unavailable") from exc
    except BaseException as exc:
        raise TrustedVerifierUnavailable("verifier security boundary unavailable") from exc
    if (
        not isinstance(result, VerifierRunResult)
        or isinstance(result.returncode, bool)
        or not isinstance(result.returncode, int)
        or not isinstance(result.duration_seconds, (int, float))
        or isinstance(result.duration_seconds, bool)
        or not math.isfinite(float(result.duration_seconds))
        or result.duration_seconds < 0
        or not _RESULT_HASH_RE.fullmatch(result.stdout_sha256)
        or isinstance(result.stdout_bytes, bool)
        or not isinstance(result.stdout_bytes, int)
        or result.stdout_bytes < 0
        or result.descendants_empty is not True
    ):
        raise TrustedVerifierUnavailable("verifier security boundary unavailable")
    return result


__all__ = [
    "TrustedVerifierError",
    "TrustedVerifierRunner",
    "TrustedVerifierTimeout",
    "TrustedVerifierUnavailable",
    "VerifierRunRequest",
    "VerifierRunResult",
    "clear_production_runner_for_testing",
    "install_production_runner",
    "run_with_trusted_supervisor",
    "trusted_entry_argv",
]
