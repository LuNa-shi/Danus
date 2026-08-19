#!/usr/bin/env python3
"""Danus gateway — the role-gated MCP server.

A thin MCP wrapper over ``danus.core`` (the truth stores) + one external
integration (``danus.integrations`` arXiv search). It exposes only the verbs an
LLM can't do reliably itself (content-addressed writes, cascade integrity, the
verifier-gated fact write, BM25) — reads / local memory / novelty judgment are
the agent's own file operations, deliberately NOT tools.

The permission model (which tools each role sees) lives in ``roles.py``. The
``fact_submit`` tool is the ONLY fact-write path: it runs the glossary-coverage
check, calls the verify service, writes the node IFF the verdict is ``correct``,
and ALWAYS traces the verdict to global memory (kind ``verification``) — accept,
reject, or accept-but-write-failed — so a verdict is never stored by nobody (the
verify service is stateless).

Config is read from the environment at CALL time (not import time) so the server
is testable and reconfigurable:
  DANUS_PROJECT_DIR   the project dir a worker is pinned to (fallback for main)
  DANUS_AGENTS_ROOT   root holding all projects (<root>/<project>); lets main
                      address any project by name via the ``project`` arg
  DANUS_AUTHOR        this agent's id, for attribution
  DANUS_ROLE          worker | main | verifier | all  (selects exposed tools;
                      unset falls back to the read-only verifier set — fail-closed)
  DANUS_VERIFY_URL    verify-service endpoint for fact_submit
  DANUS_VERIFY_CAPABILITY_SECRET_FILE  host-only signing key locator; a fresh
                      one-use bearer is minted for every verifier HTTP request
  DANUS_VERIFY_PROJECT / DANUS_VERIFY_WORKER  exact bearer scope
  DANUS_PROBLEM_ID    problem id stamped on written facts (default: project name)
  DANUS_PROJECT_SCOPE  optional single-project name enforced for main-agent sessions
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

from danus._mcp import FastMCP
from danus.core import FactGraph, GlobalMemory
from danus.integrations import search as _arxiv_search
from danus.verify.capability import mint_worker_capability

from .roles import tools_for

_PROJECT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class _RejectVerifierRedirects(urllib.request.HTTPRedirectHandler):
    """Keep a loopback verifier response from forwarding its bearer elsewhere."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Ignore ambient proxy configuration and reject every redirect.  The verifier
# bearer may travel only over the direct loopback connection validated below.
_VERIFY_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    _RejectVerifierRedirects(),
)


# --------------------------------------------------------------------------- #
# config resolution (env read at call time — testable / reconfigurable)       #
# --------------------------------------------------------------------------- #

def _author() -> str:
    return os.environ.get("DANUS_AUTHOR", "unknown")


def _role() -> str:
    # Fail-closed: an UNSET role gets the most-restrictive read-only set, same as
    # a mis-typed one (roles.tools_for). Dev use of the full set is explicit:
    # DANUS_ROLE=all.
    return os.environ.get("DANUS_ROLE", "verifier")


def _project(project: Optional[str] = None) -> Path:
    """Resolve the project dir to operate on.

    ``project`` (the main agent's per-call selector) wins: it names a project
    under ``DANUS_AGENTS_ROOT`` (``<root>/<project>``), so one session can touch
    several projects. With no ``project`` we fall back to ``DANUS_PROJECT_DIR``
    (a worker is always pinned this way). The name is validated to a single path
    segment — no ``/`` or ``..`` — so it can never escape the agents root."""
    agents_root = os.environ.get("DANUS_AGENTS_ROOT", "")
    project_dir = os.environ.get("DANUS_PROJECT_DIR", "")
    if project:
        scope = os.environ.get("DANUS_PROJECT_SCOPE", "")
        if scope and project != scope:
            raise RuntimeError("project is outside the Main Agent scope")
        if not agents_root:
            raise RuntimeError("DANUS_AGENTS_ROOT is not set; cannot resolve a project by name")
        if not _PROJECT_NAME_RE.match(project):
            raise RuntimeError(f"invalid project name: {project!r}")
        pdir = Path(agents_root) / project
        if not pdir.is_dir():
            raise RuntimeError(f"no such project: {project!r} (under {agents_root})")
        return pdir
    if not project_dir:
        raise RuntimeError("DANUS_PROJECT_DIR is not set and no project was given")
    return Path(project_dir)


def _gm(project: Optional[str] = None) -> GlobalMemory:
    return GlobalMemory(_project(project))


def _fg(project: Optional[str] = None) -> FactGraph:
    return FactGraph(_project(project))


def _verify_endpoint() -> str:
    """Return the one allowed local verifier endpoint or fail without reflection."""

    raw = os.environ.get("DANUS_VERIFY_URL", "")
    if not raw:
        raise RuntimeError("DANUS_VERIFY_URL is not set (verify service not wired yet)")
    try:
        parsed = urllib.parse.urlsplit(raw)
        port = parsed.port
    except ValueError:
        raise RuntimeError("verifier endpoint configuration is unsafe") from None
    host = parsed.hostname
    expected_netloc = "[::1]" if host == "::1" else host
    if port is not None:
        expected_netloc = f"{expected_netloc}:{port}"
    if (
        any(ord(char) <= 0x20 or ord(char) >= 0x7f for char in raw)
        or not raw.startswith("http://")
        or parsed.scheme != "http"
        or host not in {"127.0.0.1", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or port == 0
        or parsed.netloc != expected_netloc
        or parsed.path != "/verify"
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError("verifier endpoint configuration is unsafe")
    return raw


def _verify(statement: str, proof: str) -> Dict[str, Any]:
    """POST {statement, proof} to the verify service; return its JSON."""
    verify_url = _verify_endpoint()
    verify_project = os.environ.get("DANUS_VERIFY_PROJECT", "")
    verify_worker = os.environ.get("DANUS_VERIFY_WORKER", "")
    if not verify_project or not verify_worker:
        raise RuntimeError("verifier capability is not configured")
    # The gateway process is host-owned and pre-bound to one identity.  Refuse a
    # confused-deputy configuration before any HTTP request leaves the process.
    if verify_project != Path(_project()).name or verify_worker != _author():
        raise RuntimeError("verifier capability scope does not match this gateway")
    # Tokens are nonce-backed and consumed exactly once by the verifier.  Mint
    # at request time so sequential and concurrent fact submissions never reuse
    # a bearer.  The signing key remains in this nondumpable host process and is
    # never sent over the provider bridge.
    capability = mint_worker_capability(verify_project, verify_worker)
    try:
        timeout = int(os.environ.get("DANUS_VERIFY_TIMEOUT", "3600"))
    except ValueError:
        timeout = 3600
    data = json.dumps({"statement": statement, "proof": proof}).encode("utf-8")
    req = urllib.request.Request(
        verify_url,
        data=data,
        headers={
            "Authorization": f"Bearer {capability}",
            "Content-Type": "application/json",
            "X-Danus-Project": verify_project,
            "X-Danus-Worker": verify_worker,
        },
    )
    try:
        with _VERIFY_OPENER.open(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (OSError, urllib.error.URLError):
        raise RuntimeError("verify service request failed") from None


# --------------------------------------------------------------------------- #
# global memory                                                               #
# --------------------------------------------------------------------------- #

def gm_add(
    kind: str,
    claim: str,
    evidence: str = "",
    verifiable: Optional[bool] = None,
    glossary: Optional[Dict[str, str]] = None,
    links: Optional[Dict[str, Any]] = None,
    project: Optional[str] = None,
) -> Dict[str, Any]:
    """Publish a finding to shared global memory (claim + evidence). Verifiable
    kinds (conclusion/example/counterexample/proof_attempt) require explicit
    evidence; judgments (plan/direction/obstacle/master_guidance/elaboration) do
    not. Define your symbols in ``glossary`` and reuse project terminology.

    Main agent: pass ``project`` to target one of several projects by name;
    workers omit it (pinned to their own project)."""
    entry_id = _gm(project).append(
        kind, claim=claim, evidence=evidence, author=_author(),
        verifiable=verifiable, glossary=glossary, links=links,
    )
    return {"id": entry_id, "kind": kind}


def gm_search(query: str, kinds: Optional[List[str]] = None, limit_per_kind: int = 10,
              project: Optional[str] = None) -> Dict[str, Any]:
    """BM25 over shared global-memory findings. Use to reuse others' results,
    avoid duplicate work, and learn which paths already died. Main agent: pass
    ``project`` to search a specific project; workers omit it."""
    return _gm(project).search(query, kinds=kinds, limit_per_kind=limit_per_kind)


# --------------------------------------------------------------------------- #
# fact graph                                                                  #
# --------------------------------------------------------------------------- #

def fact_submit(
    statement: str,
    proof: str,
    predecessors: Optional[List[str]] = None,
    glossary_introduces: Optional[Dict[str, str]] = None,
    intuition: str = "",
    source_id: Optional[str] = None,
    external_refs: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """The only way to write a fact. Runs the glossary-coverage check, calls the
    verifier, and writes the node IFF accepted. On reject, returns repair hints
    and writes nothing. Cite the returned ``fact_id`` in downstream proofs.

    Once a verdict exists, the verification outcome is **always** recorded to
    global memory (kind ``verification``) — accept, reject, or accept-but-write-
    failed — so a verdict is never stored by nobody (the verifier is stateless;
    this worker tool persists it). ``source_id`` optionally links to the
    global-memory finding being promoted.

    When your proof cites an external (published) result, pass it in
    ``external_refs`` as a structured entry — e.g.
    ``{"key": "HL26", "authors": ["Han", "Liu"], "title": "...",
    "arxiv": "2603.03817", "year": 2026, "cited_for": "Theorem 1.2"}`` (ground it
    with ``search_arxiv_theorems``). This is captured on the fact so the paper
    pipeline can cite it without re-deriving; it is mutable metadata and does not
    affect the ``fact_id``."""
    fg = _fg()
    gm = _gm()
    problem_id = os.environ.get("DANUS_PROBLEM_ID", Path(_project()).name)

    # glossary coverage is advisory — never let a heuristic bug block submission
    try:
        undefined = fg.undefined_symbols(
            statement=statement, proof=proof, intuition=intuition,
            predecessors=predecessors, glossary_introduces=glossary_introduces,
        )
    except Exception:
        undefined = []

    # 1) Verify. If the verify service errors, no verdict exists yet: return a
    #    clean error so the worker retries. Nothing is lost.
    try:
        result = _verify(statement, proof)
    except Exception as e:
        return {"accepted": False, "verdict": "error", "error": str(e),
                "undefined_symbols": undefined}
    # A successful call that returned a non-dict body (e.g. a bare list) would make
    # the .get() below throw uncaught; treat it as a verify error (clean retry
    # envelope, no verdict to store) rather than leaking a stack trace to the worker.
    if not isinstance(result, dict):
        return {"accepted": False, "verdict": "error",
                "error": f"verify service returned a non-dict body ({type(result).__name__})",
                "undefined_symbols": undefined}
    verdict = result.get("verdict")
    accepted = verdict == "correct"

    # 2) Write the fact iff accepted. Catch write failures (e.g. a revoked
    #    predecessor) so they do NOT skip the trace below.
    fact_id = None
    write_error = None
    if accepted:
        try:
            fact_id = fg.add(
                problem_id=problem_id, author=_author(), statement=statement, proof=proof,
                predecessors=predecessors, glossary_introduces=glossary_introduces,
                intuition=intuition, external_refs=external_refs,
            )
        except Exception as e:
            write_error = str(e)

    # 3) ALWAYS record the verification outcome to global memory once a verdict exists.
    gm.append(
        "verification",
        claim=statement,
        evidence="verdict: correct" if accepted else (result.get("repair_hints") or "verdict: wrong"),
        author=_author(),
        verifiable=False,
        links={"source_id": source_id, "predecessors": predecessors or []},
        verdict=verdict,
        fact_id=fact_id,
        write_error=write_error,
        verification_report=result.get("verification_report"),
    )

    # 4) Return.
    if not accepted:
        return {
            "accepted": False,
            "verdict": verdict,
            "repair_hints": result.get("repair_hints"),
            "verification_report": result.get("verification_report"),
            "undefined_symbols": undefined,
        }
    if write_error:
        return {"accepted": True, "fact_id": None, "write_error": write_error,
                "undefined_symbols": undefined}
    return {"accepted": True, "fact_id": fact_id, "undefined_symbols": undefined}


def fact_search(query: str, limit: int = 10, project: Optional[str] = None) -> Dict[str, Any]:
    """BM25 search over the verified fact graph (statement + proof + glossary),
    the derived fact index rebuilt on demand from the fact files — the fact graph
    stays the single source of truth. Use it **before proving** to check whether a
    fact like yours already exists, and to find the verified facts that bear on
    your subgoal so you can cite their ``fact_id``. Returns ranked ``{fact_id,
    score, statement}``. Main agent: pass ``project`` to search a specific
    project's graph; workers omit it."""
    return {"query": query, "results": _fg(project).search(query, limit=limit)}


def fact_revoke(fact_id: str, reason: str, project: Optional[str] = None) -> Dict[str, Any]:
    """Cascade-revoke a wrong fact and everything that depends on it. Destructive;
    operator / main-agent only. Main agent: pass ``project`` to target the project
    that owns the fact."""
    revoked = _fg(project).revoke(fact_id, reason=reason)
    return {"revoked": revoked}


# --------------------------------------------------------------------------- #
# arXiv theorem search (external integration)                                 #
# --------------------------------------------------------------------------- #

def search_arxiv_theorems(query: str, num_results: int = 10) -> Dict[str, Any]:
    """Semantic search over arXiv theorem statements (Matlas). Returns
    **verbatim, as-published** theorem / lemma / definition statements — statement
    fidelity matters for math reasoning and citation checking. Phrase the query as
    a *complete mathematical statement* when possible. Returns ranked results,
    each with ``title``, the full ``theorem`` text, ``arxiv_id``, and the in-paper
    ``theorem_id``. External HTTP, no auth; on outage returns an ``error`` and
    empty ``results`` (retry / fall back to built-in web search)."""
    return _arxiv_search(query, num_results=num_results)


# --------------------------------------------------------------------------- #
# role-based registration                                                     #
# --------------------------------------------------------------------------- #

_TOOLS = {
    "gm_add": gm_add,
    "gm_search": gm_search,
    "fact_submit": fact_submit,
    "fact_search": fact_search,
    "fact_revoke": fact_revoke,
    "search_arxiv_theorems": search_arxiv_theorems,
}


def build_app(role: Optional[str] = None) -> FastMCP:
    """Build the stdio MCP app exposing exactly the tools ``role`` may use.
    ``role`` defaults to ``DANUS_ROLE`` (env); unset falls back to the read-only
    verifier set (fail-closed)."""
    app = FastMCP("danus-core")
    for name in tools_for(role if role is not None else _role()):
        app.tool(name=name)(_TOOLS[name])
    return app
