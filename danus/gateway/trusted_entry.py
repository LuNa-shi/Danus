"""Absolute, isolated-mode entrypoint for the host-owned MCP gateway."""

from __future__ import annotations

import sys
from pathlib import Path

_TRUSTED_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_TRUSTED_ROOT))

from danus.host_isolation import protect_host_process_secrets  # noqa: E402

# This process receives the verifier signing-key locator in its environment.
# Become nondumpable before importing the MCP/server stack or doing any other
# work that could lengthen the same-uid procfs exposure window.
protect_host_process_secrets()

from danus.gateway.server import build_app  # noqa: E402


def main() -> int:
    build_app().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
