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
    force: bool = False, extra: dict | None = None,
) -> dict:
    url = os.environ.get("DANUS_WEB_LIFECYCLE_URL", "")
    token = os.environ.get("DANUS_WEB_LIFECYCLE_TOKEN", "")
    if not url or not token:
        raise SystemExit("Main Agent lifecycle broker is not configured")
    payload = {"action": action, **(extra or {})}
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
    pause = sub.add_parser("pause")
    pause.add_argument("worker", nargs="?")
    resume = sub.add_parser("resume")
    resume.add_argument("worker", nargs="?")
    stop = sub.add_parser("stop")
    stop.add_argument("--force", action="store_true")
    finalize = sub.add_parser("finalize")
    finalize.add_argument("fact_ids", nargs="*")
    finalize.add_argument("--paper-id")
    finalize.add_argument("--operator-confirmed", action="store_true", required=True)
    summary = sub.add_parser("human-summary")
    summary.add_argument("--language")
    summary.add_argument("--operator-confirmed", action="store_true", required=True)
    paper = sub.add_parser("write-paper")
    paper.add_argument("--paper-id")
    paper.add_argument("--fact-id", action="append", dest="fact_ids")
    paper.add_argument("--instructions")
    paper.add_argument("--stop-workers", action="store_true")
    paper.add_argument("--operator-confirmed", action="store_true", required=True)
    args = parser.parse_args(argv)
    target = name
    if args.command == "status":
        result = _broker_post("status")
    elif args.command == "assign":
        result = _broker_post("assign", worker=args.worker, task=args.task)
    elif args.command == "start":
        result = _broker_post("start")
    elif args.command in {"pause", "resume"}:
        result = _broker_post(args.command, worker=args.worker)
    elif args.command == "finalize":
        result = _broker_post("finalize" if args.fact_ids else "finalize-suggest", extra={"fact_ids": args.fact_ids, "paper_id": args.paper_id, "operator_confirmed": args.operator_confirmed})
    elif args.command == "human-summary":
        result = _broker_post("human-summary", extra={"language": args.language, "operator_confirmed": args.operator_confirmed})
    elif args.command == "write-paper":
        result = _broker_post("write-paper", extra={"paper_id": args.paper_id, "fact_ids": args.fact_ids, "instructions": args.instructions, "stop_workers": args.stop_workers, "operator_confirmed": args.operator_confirmed})
    else:
        result = _broker_post("stop", force=args.force)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
