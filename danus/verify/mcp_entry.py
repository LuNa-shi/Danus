"""Credential-scrubbing absolute entry for the verifier's read-only MCP."""

from __future__ import annotations

import ctypes
import os
from pathlib import Path
import resource


_PR_SET_DUMPABLE = 4
_EXPECTED_DANUS = Path(__file__).resolve().parents[1]


def _harden() -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def main() -> int:
    # Capture only non-credential certificate routing before destroying the
    # provider environment.  In particular API keys, CODEX_HOME, Web/GitHub/
    # tunnel variables, and verifier HMAC material never reach the MCP module.
    certificates = {
        name: value
        for name in ("SSL_CERT_FILE", "SSL_CERT_DIR")
        if (value := os.environ.get(name))
    }
    os.environ.clear()
    os.environ.update({
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONSAFEPATH": "1",
        **certificates,
    })
    os.chdir("/")
    os.umask(0o077)
    _harden()

    import danus
    from danus.gateway.server import build_app

    if Path(danus.__file__).resolve().parent != _EXPECTED_DANUS:
        raise RuntimeError("verifier MCP imported an untrusted Danus package")
    build_app(role="verifier").run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
