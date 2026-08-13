"""Narrow, project-scoped lifecycle broker for the Web Console Main Agent."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from danus.execution import layout as L
from danus.orchestration import cli


def _project() -> tuple[str, Path]:
    name = os.environ.get("DANUS_PROJECT_SCOPE", "")
    root = Path(os.environ.get("DANUS_AGENTS_ROOT", "")).resolve()
    pinned = Path(os.environ.get("DANUS_PROJECT_DIR", "")).resolve()
    if not name or not root.is_dir() or pinned != root / name or not pinned.is_dir():
        raise SystemExit("Main Agent project scope is not configured")
    return name, root


def main(argv: list[str] | None = None) -> int:
    name, root = _project()
    parser = argparse.ArgumentParser(prog="danus-web-agent")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    assign = sub.add_parser("assign")
    assign.add_argument("worker")
    assign.add_argument("--task", required=True)
    sub.add_parser("start")
    stop = sub.add_parser("stop")
    stop.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    target = name
    if args.command == "status":
        result = cli.do_status(target, root=root)
    elif args.command == "assign":
        result = cli.do_assign(f"{name}/{args.worker}", args.task, root=root)
    elif args.command == "start":
        result = cli.do_start(target, root=root)
    else:
        result = cli.do_stop(target, force=args.force, root=root)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
