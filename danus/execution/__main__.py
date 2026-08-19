"""Run one worker's outer loop: ``python -m danus.execution <worker_dir>``.

This is the absolute entry used by each managed transient Worker service.
"""

from __future__ import annotations

import sys

from .loop import main

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python -m danus.execution <worker_dir>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
