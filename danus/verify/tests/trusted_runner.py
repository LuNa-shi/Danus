"""Python-only test adapter for the verifier runner seam.

This deliberately does not execute ``trusted_entry.py``: production's entry
rejects every provider except the bootstrap-pinned native Codex binary.  Tests
that need a deterministic fake run it directly through this explicit adapter.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import signal
import subprocess
import time

from danus.verify.runner import (
    TrustedVerifierTimeout,
    VerifierRunRequest,
    VerifierRunResult,
)


class DirectTrustedTestAdapter:
    """Run a fake provider directly; never selected by production bootstrap."""

    def run(self, request: VerifierRunRequest) -> VerifierRunResult:
        self.request = request
        assert request.entry_argv[1] == "-I"
        assert Path(request.entry_argv[0]).is_absolute()
        assert Path(request.entry_argv[2]).is_absolute()
        assert request.cwd == "/"
        before = time.monotonic()
        process = subprocess.Popen(
            request.provider_argv,
            cwd="/",
            env=dict(request.provider_environment),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            # Match the production trusted entry's private-file umask.  This
            # adapter is test-only, but its provider must still be unable to
            # create world-readable verification output that the secure reader
            # would correctly reject.
            preexec_fn=lambda: os.umask(0o077),
        )
        try:
            assert process.stdin is not None
            try:
                process.stdin.write(request.prompt)
                process.stdin.close()
                process.stdin = None
            except BrokenPipeError:
                process.stdin.close()
                process.stdin = None
            process.wait(timeout=request.timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise TrustedVerifierTimeout("verifier provider timed out") from exc
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        stdout, _ = process.communicate()
        digest = hashlib.sha256(stdout).hexdigest()
        return VerifierRunResult(
            returncode=int(process.returncode),
            duration_seconds=time.monotonic() - before,
            stdout_sha256=digest,
            stdout_bytes=len(stdout),
            descendants_empty=True,
        )


__all__ = ["DirectTrustedTestAdapter"]
