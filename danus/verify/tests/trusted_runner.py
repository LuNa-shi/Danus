"""Test adapter for the verifier runner seam (never used in production)."""

from __future__ import annotations

import os
from pathlib import Path
import secrets
import subprocess

from danus.verify import wire
from danus.verify.runner import (
    TrustedVerifierTimeout,
    VerifierRunRequest,
    VerifierRunResult,
)


class DirectTrustedTestAdapter:
    """Exercise the real fixed entry/framing without claiming cgroup security."""

    def run(self, request: VerifierRunRequest) -> VerifierRunResult:
        self.request = request
        assert request.entry_argv[1] == "-I"
        assert Path(request.entry_argv[0]).is_absolute()
        assert Path(request.entry_argv[2]).is_absolute()
        assert request.cwd == "/"
        frame = wire.encode_request(
            run_id=request.run_id,
            provider_argv=request.provider_argv,
            provider_environment=request.provider_environment,
            timeout_seconds=request.timeout_seconds,
            prompt=request.prompt,
        )
        outer_timeout = (request.timeout_seconds or 30) + 5
        process = subprocess.Popen(
            request.entry_argv,
            cwd="/",
            env={"PATH": os.defpath, "LANG": "C.UTF-8"},
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert process.stdin is not None and process.stdout is not None
        challenge = secrets.token_bytes(32)
        process.stdin.write(wire.encode_challenge(challenge))
        process.stdin.flush()
        ready = wire.read_ready(process.stdout, challenge=challenge)
        assert ready["executable"]
        process.stdin.write(frame)
        process.stdin.close()
        process.stdin = None
        stdout, stderr = process.communicate(timeout=outer_timeout)
        assert stderr == b""
        assert process.returncode == 0
        result = wire.read_result(stdout)
        if result["timed_out"]:
            raise TrustedVerifierTimeout("verifier provider timed out")
        return VerifierRunResult(
            returncode=int(result["returncode"]),
            duration_seconds=float(result["duration_seconds"]),
            stdout_sha256=str(result["stdout_sha256"]),
            stdout_bytes=int(result["stdout_bytes"]),
            descendants_empty=result["process_group_empty"] is True,
        )


__all__ = ["DirectTrustedTestAdapter"]
