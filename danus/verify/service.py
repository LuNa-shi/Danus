"""Danus verify service — the sole write-gate's HTTP front.

    POST /verify {statement, proof} -> {verification_report, verdict, repair_hints}
    GET  /health                    -> {status: "ok", pid: <int>}

/verify runs the deterministic pre-checks (``prechecks.run_prechecks``) and, if
they pass, cold-starts a fresh codex verifier (``launcher.run_codex_verification``)
whose verdict the gateway's ``fact_submit`` uses to decide whether a claim becomes
a fact. The verifier is an LLM, NOT a formal proof assistant, with no human in the
loop by default — see the verifier contract (``agents/contracts/verifier.md``).
"""

from __future__ import annotations

import os
from typing import Annotated, Any, Dict, Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from .capability import CapabilityConfigurationError, verify_worker_capability
from .launcher import _allocate_run_id, run_codex_verification
from .prechecks import run_prechecks
from .process_security import harden_secret_process


# Importing the serving module handles HMAC material and provider credentials.
# Fail before binding a port if the kernel cannot make this process nondumpable.
harden_secret_process()


class VerifyRequest(BaseModel):
    statement: str = Field(..., min_length=1)
    proof: str = Field(..., min_length=1)


app = FastAPI(title="Danus verify service", version="0.1.0")


@app.get("/health")
async def health() -> Dict[str, Any]:
    # async on purpose: /health must not queue behind sync /verify threadpool
    # calls, so it responds in ~microseconds regardless of in-flight verifications.
    # `pid` self-identifies this instance: a health probe alone cannot tell OUR
    # verify from another deployment's verify holding the same port on a shared
    # host — callers match this pid against runtime/run/verify.pid to be sure.
    return {"status": "ok", "pid": os.getpid()}


def _authorize_worker(
    authorization: Optional[str], project: Optional[str], worker: Optional[str],
) -> None:
    """Fail closed unless this is an exactly scoped Worker capability."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="verifier capability required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization.removeprefix("Bearer ")
    try:
        valid = bool(
            token and project and worker
            and verify_worker_capability(token, project, worker)
        )
    except CapabilityConfigurationError as exc:
        raise HTTPException(
            status_code=503,
            detail="verifier authorization unavailable",
        ) from exc
    if not valid:
        # One generic response: callers cannot use the verifier as a scope/token
        # oracle, and no bearer material is reflected in logs or response bodies.
        raise HTTPException(status_code=403, detail="invalid verifier capability")


@app.post("/verify")
def verify(
    request: VerifyRequest,
    authorization: Annotated[Optional[str], Header(alias="Authorization")] = None,
    danus_project: Annotated[Optional[str], Header(alias="X-Danus-Project")] = None,
    danus_worker: Annotated[Optional[str], Header(alias="X-Danus-Worker")] = None,
) -> Dict[str, Any]:
    _authorize_worker(authorization, danus_project, danus_worker)
    rejected = run_prechecks(request.statement, request.proof)
    if rejected is not None:
        status_code, detail = rejected
        raise HTTPException(status_code=status_code, detail=detail)
    try:
        run_id = _allocate_run_id(request.statement)
    except Exception as exc:
        # Allocation errors may carry a configured host path.  Keep the HTTP
        # contract typed and redacted; no provider is started without a private
        # unique audit directory.
        raise HTTPException(
            status_code=503, detail="verifier storage unavailable",
        ) from exc
    return run_codex_verification(run_id=run_id, statement=request.statement, proof=request.proof)
