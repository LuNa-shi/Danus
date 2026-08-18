"""``danus`` — the main agent's control surface over codex workers.

    danus list   [--json]
    danus new    <project> [--roles high:3,xhigh:4] [--model M] [--max-parallel-workers N]
    danus assign <project>/<worker> (--task "…" | --file P | --stdin)
    danus finalize <project> [--paper <paper_id>] [<fact_id> ...]
    danus start  <project>[/<worker>]
    danus status <project>[/<worker>] [--json]
    danus stop   <project>[/<worker>] [--force]

This module is the verbs/UX only. The worker outer loop, the on-disk layout, and
the scaffolding they drive live in ``danus.execution`` (imported here as a
library). Reads/writes only files under the project dir — the loop is autonomous;
this CLI just assigns / starts / monitors / stops it.

Notes:
  - the layout + scaffolding + config template are imported from ``danus.execution``
    (no duplicated layout / config template);
  - the verbs are mode-agnostic and identical across deployments.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from danus.execution import layout as L
from danus.execution import processes as P
from danus.execution.scaffold import atomic_write, do_new, spawn_loop

def _reject_web_sandbox_control() -> None:
    if (
        os.environ.get("DANUS_ROLE") == "main"
        and os.environ.get("DANUS_WEB_LIFECYCLE_URL")
    ):
        raise SystemExit(
            "Web Main Agent control must use the project-scoped DANUS_WEB_AGENT_BIN broker"
        )

__all__ = [
    "do_new", "do_assign", "do_start", "do_status", "worker_status",
    "do_list", "do_stop", "do_finalize", "build_parser", "main",
]


# --------------------------------------------------------------------------- #
# execution-owned process helper compatibility aliases                        #
# --------------------------------------------------------------------------- #

_read_pid = P.read_pid
_alive = P.process_alive
_expected_worker_cmdline = P.expected_worker_cmdline
_capture_worker_identity = P.capture_worker_identity
_read_process_identity = P.read_worker_identity
_clear_process_identity = P.clear_worker_process_metadata
_worker_alive = P.worker_process_alive


def _read_status(wl: L.WorkerLayout) -> Dict:
    sp = wl.status
    if not sp.exists():
        return {}
    try:
        return json.loads(sp.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _read_worker_config(wl: L.WorkerLayout) -> Dict:
    """Expose persisted worker role settings to observability clients."""
    config: Dict[str, str] = {}
    try:
        if wl.role.exists():
            for line in wl.role.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    config[key.strip()] = value.strip()
    except OSError:
        pass
    try:
        project_meta = wl.project_dir / "project.json"
        if project_meta.exists():
            meta = json.loads(project_meta.read_text(encoding="utf-8"))
            config.setdefault("PROJECT_MODEL", str(meta.get("model") or ""))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        pass
    return config


def _task_assigned(text: str) -> bool:
    normalized = " ".join(text.strip().lower().split())
    if not normalized:
        return False
    return not (
        normalized.startswith("# task")
        and "(unassigned" in normalized
        and "danus assign" in normalized
    )


def _read_task_state(wl: L.WorkerLayout) -> Dict:
    try:
        if wl.task.is_symlink() or not wl.task.is_file():
            return {"task": "", "assigned": False}
        task = wl.task.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"task": "", "assigned": False}
    return {"task": task, "assigned": _task_assigned(task)}


# --------------------------------------------------------------------------- #
# assign                                                                       #
# --------------------------------------------------------------------------- #

def do_assign(target: str, task: str, root: Optional[Path] = None) -> Dict:
    """Overwrite (replace, NOT append) a worker's TASK.md, ensuring a trailing
    newline. Rejects a bare project, a nonexistent worker, and an empty task."""
    project, worker = L.resolve_target(target)
    if not worker:
        raise SystemExit("assign needs a specific worker: <project>/<worker>")
    wl = L.WorkerLayout(L.worker_dir(project, worker, root))
    if not wl.dir.is_dir():
        raise SystemExit(f"no such worker: {project}/{worker}")
    if not task.strip():
        raise SystemExit("refusing to assign an empty task")
    atomic_write(wl.task, task if task.endswith("\n") else task + "\n")
    return {"worker": f"{project}/{worker}", "task_file": str(wl.task)}


# --------------------------------------------------------------------------- #
# finalize                                                                     #
# --------------------------------------------------------------------------- #

def do_finalize(project: str, fact_ids: List[str],
                paper_id: Optional[str] = None) -> Dict:
    """Record the finalized target theorem(s) for a PAPER of a project in that
    paper's TARGET.md — the durable slot write-paper reads (never a guess). The
    default paper writes the LEGACY ``<project>/TARGET.md``; a non-default
    ``paper_id`` writes ``<project>/papers/<paper_id>/TARGET.md`` (its own
    workspace). One fact graph per project; per-paper targets.

    Resolves the project dir, VALIDATES every ``fact_id`` against that project's
    fact graph (refuses an id the graph does not have — you cannot record a
    phantom target), then writes the ids to the paper's TARGET.md.

    With NO ``fact_ids`` (suggestion mode): prints the candidate terminal facts
    (facts that are no other fact's predecessor — the ``assemble._terminal_facts``
    helper) as SUGGESTIONS and writes NOTHING (returns ``{"suggested": [...]}``).

    Rejections raise ``SystemExit`` (nonzero exit) with a clear message."""
    from danus.core import FactGraph
    from danus.write_paper import assemble

    pdir = L.project_dir(project)
    if not pdir.is_dir():
        raise SystemExit(f"no such project: {project}")
    fg = FactGraph(pdir)

    if not fact_ids:
        # suggestion mode: never auto-pick — just list candidate terminal facts.
        return {"project": project, "paper_id": paper_id,
                "suggested": assemble._terminal_facts(fg)}

    unknown = [fid for fid in fact_ids if not fg.exists(fid)]
    if unknown:
        raise SystemExit(
            f"cannot finalize: unknown fact id(s) in {project}: {', '.join(unknown)} "
            f"(a target must be a verified fact in the project's graph)"
        )
    # validate a non-default paper_id as a single safe path segment before writing.
    try:
        if not assemble._is_default_paper(paper_id):
            assemble._validate_paper_id(paper_id)  # type: ignore[arg-type]
    except ValueError as e:
        raise SystemExit(f"cannot finalize: {e}")
    # de-dup while preserving order
    seen: set = set()
    ids: List[str] = []
    for fid in fact_ids:
        if fid not in seen:
            seen.add(fid)
            ids.append(fid)
    path = assemble.write_target_fact_ids(pdir, ids, paper_id)
    return {"project": project, "paper_id": paper_id,
            "target_file": str(path), "target_fact_ids": ids}


# --------------------------------------------------------------------------- #
# start                                                                        #
# --------------------------------------------------------------------------- #

def _start_one(wl: L.WorkerLayout) -> str:
    """Return a lifecycle result while holding the Worker launch lock."""
    _reject_web_sandbox_control()
    wl.dir.mkdir(parents=True, exist_ok=True)
    wl.logs.mkdir(exist_ok=True)
    lock = open(wl.lock, "w")
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return "locked"
        if P.worker_process_alive(wl):
            # Migrate a legacy exact-command PID to the durable identity record.
            if P.read_worker_identity(wl) is None:
                pid = P.read_pid(wl)
                identity = P.capture_worker_identity(wl, pid) if pid is not None else None
                if identity is not None:
                    P.write_worker_identity(wl, identity)
            return "already-running"
        # A raw live PID with no matching Worker identity is stale (commonly a
        # namespace-local PID reused by an unrelated host process). Never let it
        # suppress a new launch.
        P.clear_worker_process_metadata(wl)
        wl.stop.unlink(missing_ok=True)  # clear a stale stop flag
        process = spawn_loop(wl.dir)
        pid = int(process.pid)
        atomic_write(wl.pid, str(pid))
        identity = None
        for _ in range(20):
            identity = P.capture_worker_identity(wl, pid)
            if identity is not None or not P.process_alive(pid):
                break
            time.sleep(0.01)
        if identity is None:
            # The direct Popen handle identifies this exact new child. Terminate
            # its whole start_new_session group, reap the leader, and verify the
            # group is gone before removing recoverable metadata.
            if P.terminate_spawned_worker(process):
                P.clear_worker_process_metadata(wl)
                return "start-failed"
            return "start-cleanup-failed"
        P.write_worker_identity(wl, identity)
        return "started"
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()


def do_start(target: str, stagger: float = 0.2, root: Optional[Path] = None) -> List[Dict]:
    _reject_web_sandbox_control()
    dirs = L.target_worker_dirs(target, root)
    if not dirs:
        raise SystemExit(f"no workers for target {target!r}")
    out = []
    for i, wdir in enumerate(dirs):
        if i and stagger:
            time.sleep(stagger)
        out.append({"worker": wdir.name, "result": _start_one(L.WorkerLayout(wdir))})
    return out


# --------------------------------------------------------------------------- #
# status                                                                       #
# --------------------------------------------------------------------------- #

def worker_status(wl: L.WorkerLayout) -> Dict:
    pid = _read_pid(wl)
    alive = _worker_alive(wl)
    st = _read_status(wl)
    persisted_state = st.get("state", "—")
    state = persisted_state
    if not alive and state in ("running", "retrying", "queued", "idle"):
        state = "stale"
    now = time.time()
    # While a round is active, age means time in the current round. A stale
    # last_round_at from a previous Run must not make a freshly restarted worker
    # look many minutes old.
    last = (st.get("round_started_at") if state == "running"
            else st.get("last_round_at") or st.get("round_started_at") or st.get("updated_at"))
    age = (now - last) if isinstance(last, (int, float)) else None

    if alive:
        # a round legitimately runs for hours; only flag truly stale running rounds
        rs = st.get("round_started_at")
        hard = int(os.environ.get("DANUS_ROUND_HARD_TIMEOUT", "14400"))
        if state == "running" and isinstance(rs, (int, float)) and (now - rs) > hard * 1.5:
            label = "stuck?"
        else:
            label = "working"
    else:
        label = state if state in ("stopped", "deadline", "max_rounds", "error",
                                   "terminated", "created") else "dead"
    config = _read_worker_config(wl)
    task_state = _read_task_state(wl)
    raw_alive = P.process_alive(pid)
    identity_status = "matched" if alive else "mismatch" if raw_alive else "dead"
    return {
        "worker": wl.name, "pid": pid, "alive": alive, "raw_alive": raw_alive,
        "process_identity": identity_status, "state": state,
        "persisted_state": persisted_state,
        "identity_verified": alive,
        "round": st.get("round", 0), "age_s": round(age, 1) if age is not None else None,
        "last_fact_id": st.get("last_fact_id"), "label": label,
        "task": task_state["task"],
        "assigned": task_state["assigned"],
        "last_rc": st.get("last_rc"),
        "last_error": st.get("last_error") or st.get("error"),
        "consecutive_failures": st.get("consecutive_failures", 0),
        "next_retry_at": st.get("next_retry_at"),
        "queue_reason": st.get("queue_reason"),
        "queued_at": st.get("queued_at"),
        "role": config.get("ROLE") or wl.name,
        "model": config.get("MODEL") or config.get("PROJECT_MODEL") or None,
        "reasoning_effort": config.get("REASONING_EFFORT") or config.get("ROLE") or None,
        "author": config.get("DANUS_AUTHOR") or wl.name,
    }


def do_status(target: str, root: Optional[Path] = None) -> List[Dict]:
    dirs = L.target_worker_dirs(target, root)
    if not dirs:
        raise SystemExit(f"no workers for target {target!r}")
    return [worker_status(L.WorkerLayout(d)) for d in dirs]


# --------------------------------------------------------------------------- #
# list                                                                         #
# --------------------------------------------------------------------------- #

def do_list(root: Optional[Path] = None) -> List[Dict]:
    """One row per project: roster + how many workers are live + model."""
    out: List[Dict] = []
    for project in L.list_projects(root):
        meta = {}
        mp = L.project_dir(project, root) / "project.json"
        if mp.exists():
            try:
                meta = json.loads(mp.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                meta = {}
        workers = L.list_workers(project, root)
        live = sum(1 for w in workers
                   if _worker_alive(L.WorkerLayout(L.worker_dir(project, w, root))))
        out.append({"project": project, "workers": len(workers), "live": live,
                    "model": meta.get("model", "—")})
    return out


def _fmt_list(rows: List[Dict]) -> str:
    head = f"{'PROJECT':<24}{'WORKERS':>8}{'LIVE':>6}  {'MODEL':<12}"
    lines = [head, "-" * len(head)]
    for r in rows:
        lines.append(f"{r['project']:<24}{r['workers']:>8}{r['live']:>6}  {str(r['model']):<12}")
    return "\n".join(lines) if rows else "(no projects under the agents root)"


def _fmt_status(rows: List[Dict]) -> str:
    head = f"{'WORKER':<14}{'LABEL':<12}{'STATE':<13}{'ROUND':>6}  {'AGE':>7}  {'LAST_FACT':<16}"
    lines = [head, "-" * len(head)]
    for r in rows:
        age = f"{r['age_s']:.0f}s" if r["age_s"] is not None else "—"
        lines.append(f"{r['worker']:<14}{r['label']:<12}{r['state']:<13}"
                     f"{r['round']:>6}  {age:>7}  {str(r['last_fact_id'] or '—'):<16}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# stop                                                                         #
# --------------------------------------------------------------------------- #

def _stop_one(wl: L.WorkerLayout, force: bool) -> str:
    _reject_web_sandbox_control()
    if force:
        return P.force_stop_worker(wl)
    pid = P.read_pid(wl)
    raw_alive = P.process_alive(pid)
    if not P.worker_process_alive(wl):
        # Retain live mismatched metadata for host reconciliation; clearing it
        # would hide an unresolved process and permit a false terminal outcome.
        if raw_alive:
            return "identity-mismatch"
        P.clear_worker_process_metadata(wl)
        return "not-running"
    wl.stop.touch()      # graceful: loop exits at round boundary
    return "stopping (graceful)"


def do_stop(target: str, force: bool = False, root: Optional[Path] = None) -> List[Dict]:
    _reject_web_sandbox_control()
    dirs = L.target_worker_dirs(target, root)
    if not dirs:
        raise SystemExit(f"no workers for target {target!r}")
    return [{"worker": d.name, "result": _stop_one(L.WorkerLayout(d), force)} for d in dirs]


# --------------------------------------------------------------------------- #
# argparse                                                                      #
# --------------------------------------------------------------------------- #

def _task_from_args(args) -> str:
    if args.task is not None:
        return args.task
    if args.file:
        return Path(args.file).read_text(encoding="utf-8")
    if args.stdin:
        return sys.stdin.read()
    raise SystemExit("assign needs one of --task, --file, or --stdin")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="danus", description="Control codex workers.")
    sub = p.add_subparsers(dest="cmd", required=True)

    li = sub.add_parser("list", help="list all projects + live worker counts")
    li.add_argument("--json", action="store_true")

    n = sub.add_parser("new", help="scaffold a project + worker dirs")
    n.add_argument("project")
    n.add_argument("--roles", default="high:3,xhigh:4", help="e.g. high:3,xhigh:4 (default)")
    n.add_argument("--model", default=None)
    n.add_argument("--max-parallel-workers", type=int, default=None,
                   help="project resource limit for concurrent worker rounds")

    a = sub.add_parser("assign", help="write a worker's per-round TASK.md")
    a.add_argument("target", help="<project>/<worker>")
    a.add_argument("--task", default=None)
    a.add_argument("--file", default=None)
    a.add_argument("--stdin", action="store_true")

    f = sub.add_parser("finalize", help="record the finalized target fact_id(s) in "
                                        "a paper's TARGET.md (write-paper reads this)")
    f.add_argument("project")
    f.add_argument("--paper", default=None,
                   help="the paper_id (multiple papers per project). Default / 'main' "
                        "→ legacy <project>/TARGET.md; else "
                        "<project>/papers/<paper_id>/TARGET.md")
    f.add_argument("fact_ids", nargs="*",
                   help="the target fact id(s); omit to print candidate terminal facts")

    s = sub.add_parser("start", help="launch worker loop(s)")
    s.add_argument("target", help="<project> or <project>/<worker>")

    st = sub.add_parser("status", help="liveness + progress")
    st.add_argument("target", help="<project> or <project>/<worker>")
    st.add_argument("--json", action="store_true")

    sp = sub.add_parser("stop", help="stop worker loop(s)")
    sp.add_argument("target", help="<project> or <project>/<worker>")
    sp.add_argument("--force", action="store_true", help="kill now (else finish current round)")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "list":
        rows = do_list()
        print(json.dumps(rows, ensure_ascii=False, indent=2) if args.json else _fmt_list(rows))
    elif args.cmd == "new":
        r = do_new(args.project, roles=args.roles, model=args.model,
                   max_parallel_workers=args.max_parallel_workers)
        print(f"created {args.project} with {len(r['workers'])} workers: "
              f"{', '.join(r['workers'])}\n  {r['project_dir']}")
    elif args.cmd == "assign":
        r = do_assign(args.target, _task_from_args(args))
        print(f"assigned {r['worker']} -> {r['task_file']}")
    elif args.cmd == "finalize":
        r = do_finalize(args.project, args.fact_ids, paper_id=args.paper)
        paper_note = f" (paper {args.paper})" if args.paper else ""
        paper_flag = f" --paper {args.paper}" if args.paper else ""
        if "suggested" in r:
            sug = r["suggested"]
            if sug:
                print(f"no fact_id given — candidate target facts for {r['project']}{paper_note} "
                      f"(terminal facts; nothing depends on them):")
                for fid in sug:
                    print(f"  {fid}")
                print(f"\nrun: danus finalize {r['project']}{paper_flag} <fact_id> [<fact_id> ...] to record")
            else:
                print(f"no candidate terminal facts in {r['project']} "
                      f"(is the fact graph empty?); nothing recorded")
        else:
            print(f"finalized target for {r['project']}{paper_note}: {', '.join(r['target_fact_ids'])}\n"
                  f"  wrote {r['target_file']}")
    elif args.cmd == "start":
        for r in do_start(args.target):
            print(f"{r['worker']}: {r['result']}")
    elif args.cmd == "status":
        rows = do_status(args.target)
        print(json.dumps(rows, ensure_ascii=False, indent=2) if args.json else _fmt_status(rows))
    elif args.cmd == "stop":
        for r in do_stop(args.target, force=args.force):
            print(f"{r['worker']}: {r['result']}")
    return 0
