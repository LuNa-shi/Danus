"""Narrow, project-scoped lifecycle broker for the Web Console Main Agent."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import urllib.error
import urllib.request


def _project() -> tuple[str, Path]:
    name = os.environ.get("DANUS_PROJECT_SCOPE", "")
    root = Path(os.environ.get("DANUS_AGENTS_ROOT", "")).resolve()
    pinned = Path(os.environ.get("DANUS_PROJECT_DIR", "")).resolve()
    if not name or not root.is_dir() or pinned != root / name or not pinned.is_dir():
        raise SystemExit("Main Agent project scope is not configured")
    return name, root


def _broker_post(
    action: str, *, worker: str | None = None, task: str | None = None,
    force: bool = False,
) -> dict:
    url = os.environ.get("DANUS_WEB_LIFECYCLE_URL", "")
    token = os.environ.get("DANUS_WEB_LIFECYCLE_TOKEN", "")
    if not url or not token:
        raise SystemExit("Main Agent lifecycle broker is not configured")
    payload = {"action": action}
    if worker is not None:
        payload["worker"] = worker
    if task is not None:
        payload["task"] = task
    if force:
        payload["force"] = True
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            body = json.loads(exc.read().decode("utf-8"))
            detail = str(body.get("detail") or "request rejected")
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
            detail = "request rejected"
        raise SystemExit(f"lifecycle broker rejected {action}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise SystemExit(f"lifecycle broker unavailable for {action}") from exc
    if not isinstance(result, dict):
        raise SystemExit("lifecycle broker returned an invalid response")
    return result


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
        result = _broker_post("status")
    elif args.command == "assign":
        result = _broker_post("assign", worker=args.worker, task=args.task)
    elif args.command == "start":
        result = _broker_post("start")
    else:
        result = _broker_post("stop", force=args.force)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
