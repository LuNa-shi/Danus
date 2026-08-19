"""Offline HTTP-contract tests for danus.verify.service + __main__ entry.

Exercises the FastAPI app via TestClient with the launcher's codex-run
MONKEYPATCHED to a fake (no subprocess, no codex, no API spend), asserting the
POST /verify + GET /health contract and every error status mapping. The
``python -m danus.verify`` entrypoint is exercised via runpy with uvicorn.run
mocked so no server ever binds.

HTTP contract under test:
  POST /verify with one-use Project/Worker bearer
    {statement, proof} -> 200 {verification_report, verdict, repair_hints}
  * 401/403 on absent, malformed, cross-scope, expired, or replayed capability
  * 400 on a vacuous / precheck-failing input (before any codex run)
  * 422 on a schema-invalid body (missing/empty field — pydantic)
  * 504 on codex timeout, 500 on exit / missing-output / bad-json (launcher raises)
  GET /health -> 200 {status: "ok"}

Runs standalone (``python -m danus.verify.tests.test_service``) and under pytest.
"""

from __future__ import annotations

import os
import sys
import tempfile
import types
from contextlib import contextmanager
from pathlib import Path

from fastapi import HTTPException
from fastapi.testclient import TestClient

from danus.verify import capability, process_security, service

_STMT = "For every integer n, n + 0 equals n."
_PROOF = (
    "Zero is the additive identity of the integers, so adding zero to any integer n "
    "leaves the value unchanged. Hence n + 0 = n for every integer n, as required."
)

_CANNED_OK = {
    "verification_report": {"summary": "fake accept", "critical_errors": [], "gaps": []},
    "verdict": "correct",
    "repair_hints": "",
}


@contextmanager
def _fake_run(fn):
    """Replace the launcher's codex-run (imported into service) with a fake."""
    orig_run = service.run_codex_verification
    orig_alloc = service._allocate_run_id
    service.run_codex_verification = fn
    service._allocate_run_id = lambda statement: "RID-fake"
    try:
        yield
    finally:
        service.run_codex_verification = orig_run
        service._allocate_run_id = orig_alloc


def _client():
    return TestClient(service.app)


def _post(
    payload, *, project="Project-A", worker="worker-1", token=None,
    token_project=None, token_worker=None,
):
    """Authenticated request with an isolated test HMAC key."""
    old = os.environ.get("DANUS_VERIFY_CAPABILITY_SECRET_FILE")
    with tempfile.TemporaryDirectory() as tmp:
        os.environ["DANUS_VERIFY_CAPABILITY_SECRET_FILE"] = str(Path(tmp) / "verify.key")
        try:
            bearer = token if token is not None else capability.mint_worker_capability(
                token_project or project, token_worker or worker,
            )
            return _client().post(
                "/verify", json=payload,
                headers={
                    "Authorization": f"Bearer {bearer}",
                    "X-Danus-Project": project,
                    "X-Danus-Worker": worker,
                },
            )
        finally:
            if old is None:
                os.environ.pop("DANUS_VERIFY_CAPABILITY_SECRET_FILE", None)
            else:
                os.environ["DANUS_VERIFY_CAPABILITY_SECRET_FILE"] = old


# --------------------------------------------------------------------------- #
# /health                                                                     #
# --------------------------------------------------------------------------- #

def test_health_ok():
    resp = _client().get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    # /health self-identifies with the serving process pid (callers match it
    # against runtime/run/verify.pid to distinguish OUR verify from a foreign
    # deployment holding the same port on a shared host).
    assert isinstance(body["pid"], int) and body["pid"] > 0


def test_service_process_is_nondumpable():
    assert process_security.process_is_dumpable() is False


# --------------------------------------------------------------------------- #
# /verify — happy path                                                        #
# --------------------------------------------------------------------------- #

def test_verify_requires_bearer_before_codex_runs():
    with _fake_run(_must_not_run):
        resp = _client().post("/verify", json={"statement": _STMT, "proof": _PROOF})
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == "Bearer"


def test_verify_rejects_wrong_and_cross_scope_capabilities():
    with _fake_run(_must_not_run):
        wrong = _post({"statement": _STMT, "proof": _PROOF}, token="definitely-wrong")
        cross_project = _post(
            {"statement": _STMT, "proof": _PROOF},
            project="Project-B", token_project="Project-A",
        )
        cross_worker = _post(
            {"statement": _STMT, "proof": _PROOF},
            worker="worker-2", token_worker="worker-1",
        )
    assert wrong.status_code == 403
    assert cross_project.status_code == 403
    assert cross_worker.status_code == 403


def test_verify_consumes_each_bearer_exactly_once():
    with tempfile.TemporaryDirectory() as tmp:
        old = os.environ.get("DANUS_VERIFY_CAPABILITY_SECRET_FILE")
        os.environ["DANUS_VERIFY_CAPABILITY_SECRET_FILE"] = str(Path(tmp) / "verify.key")
        try:
            token = capability.mint_worker_capability("Project-A", "worker-1")
            headers = {
                "Authorization": f"Bearer {token}",
                "X-Danus-Project": "Project-A",
                "X-Danus-Worker": "worker-1",
            }
            with _fake_run(lambda run_id, statement, proof: _CANNED_OK):
                first = _client().post(
                    "/verify", json={"statement": _STMT, "proof": _PROOF}, headers=headers,
                )
                replay = _client().post(
                    "/verify", json={"statement": _STMT, "proof": _PROOF}, headers=headers,
                )
            assert first.status_code == 200
            assert replay.status_code == 403
            assert replay.json()["detail"] == "invalid verifier capability"
        finally:
            if old is None:
                os.environ.pop("DANUS_VERIFY_CAPABILITY_SECRET_FILE", None)
            else:
                os.environ["DANUS_VERIFY_CAPABILITY_SECRET_FILE"] = old


def test_verify_redacts_unsafe_capability_configuration():
    with tempfile.TemporaryDirectory() as tmp:
        weak = Path(tmp) / "weak.key"
        weak.write_text("short", encoding="ascii")
        weak.chmod(0o600)
        old = os.environ.get("DANUS_VERIFY_CAPABILITY_SECRET_FILE")
        try:
            os.environ["DANUS_VERIFY_CAPABILITY_SECRET_FILE"] = str(Path(tmp) / "good.key")
            structurally_valid = capability.mint_worker_capability("Project-A", "worker-1")
            os.environ["DANUS_VERIFY_CAPABILITY_SECRET_FILE"] = str(weak)
            with _fake_run(_must_not_run):
                response = _client().post(
                    "/verify",
                    json={"statement": _STMT, "proof": _PROOF},
                    headers={
                        "Authorization": f"Bearer {structurally_valid}",
                        "X-Danus-Project": "Project-A",
                        "X-Danus-Worker": "worker-1",
                    },
                )
            assert response.status_code == 503
            assert response.json()["detail"] == "verifier authorization unavailable"
            assert str(weak) not in response.text
        finally:
            if old is None:
                os.environ.pop("DANUS_VERIFY_CAPABILITY_SECRET_FILE", None)
            else:
                os.environ["DANUS_VERIFY_CAPABILITY_SECRET_FILE"] = old


def test_verify_redacts_run_storage_allocation_failure():
    marker = "/host/secret/results/path"

    def broken_allocator(_statement):
        raise RuntimeError(marker)

    original_allocator = service._allocate_run_id
    original_run = service.run_codex_verification
    service._allocate_run_id = broken_allocator
    service.run_codex_verification = _must_not_run
    try:
        response = _post({"statement": _STMT, "proof": _PROOF})
    finally:
        service._allocate_run_id = original_allocator
        service.run_codex_verification = original_run
    assert response.status_code == 503
    assert response.json()["detail"] == "verifier storage unavailable"
    assert marker not in response.text

def test_verify_accept_contract():
    def fake(run_id, statement, proof):
        assert run_id == "RID-fake"  # allocator was used
        return _CANNED_OK

    with _fake_run(fake):
        resp = _post({"statement": _STMT, "proof": _PROOF})
    assert resp.status_code == 200
    body = resp.json()
    assert body["verdict"] == "correct"
    assert body["verification_report"]["critical_errors"] == []
    assert "repair_hints" in body


def test_verify_reject_verdict_still_200():
    # a "wrong" verdict is a normal 200 response (the verdict is the payload).
    canned = dict(_CANNED_OK, verdict="wrong", repair_hints="fix the gap")
    with _fake_run(lambda run_id, statement, proof: canned):
        resp = _post({"statement": _STMT, "proof": _PROOF})
    assert resp.status_code == 200 and resp.json()["verdict"] == "wrong"


# --------------------------------------------------------------------------- #
# /verify — precheck rejections happen BEFORE any codex run (400)             #
# --------------------------------------------------------------------------- #

def _must_not_run(*a, **k):
    raise AssertionError("codex must not run when a precheck rejects")


def test_verify_vacuous_proof_400():
    with _fake_run(_must_not_run):
        resp = _post({"statement": _STMT, "proof": "QED"})
    assert resp.status_code == 400 and "vacuous proof" in resp.json()["detail"]


def test_verify_p1_precheck_400():
    bad = ("The result holds as declared in problem.md, which lists it as a verified "
           "building block, so we are done with the argument here.")
    with _fake_run(_must_not_run):
        resp = _post({"statement": _STMT, "proof": bad})
    assert resp.status_code == 400 and "[P1 on proof]" in resp.json()["detail"]


# --------------------------------------------------------------------------- #
# /verify — launcher error mappings surface as the raised status              #
# --------------------------------------------------------------------------- #

def _raiser(status, detail):
    def fn(run_id, statement, proof):
        raise HTTPException(status_code=status, detail=detail)
    return fn


def test_verify_timeout_504():
    with _fake_run(_raiser(504, "codex exec timed out after 900s")):
        resp = _post({"statement": _STMT, "proof": _PROOF})
    assert resp.status_code == 504 and "timed out" in resp.json()["detail"]


def test_verify_exit_500():
    with _fake_run(_raiser(500, "codex exec failed with exit code 7")):
        resp = _post({"statement": _STMT, "proof": _PROOF})
    assert resp.status_code == 500 and "exit code" in resp.json()["detail"]


def test_verify_missing_output_500():
    with _fake_run(_raiser(500, "verification output was not found")):
        resp = _post({"statement": _STMT, "proof": _PROOF})
    assert resp.status_code == 500 and "was not found" in resp.json()["detail"]


def test_verify_bad_json_500():
    with _fake_run(_raiser(500, "verification output ... is not valid JSON")):
        resp = _post({"statement": _STMT, "proof": _PROOF})
    assert resp.status_code == 500 and "not valid JSON" in resp.json()["detail"]


# --------------------------------------------------------------------------- #
# /verify — schema validation (pydantic, 422) before prechecks               #
# --------------------------------------------------------------------------- #

def test_verify_empty_field_422():
    with _fake_run(_must_not_run):
        resp = _post({"statement": "", "proof": _PROOF})
    assert resp.status_code == 422


def test_verify_missing_field_422():
    with _fake_run(_must_not_run):
        resp = _post({"statement": _STMT})
    assert resp.status_code == 422


# --------------------------------------------------------------------------- #
# `python -m danus.verify` entry — uvicorn mocked, no bind                    #
# --------------------------------------------------------------------------- #

def test_main_entry_runs_uvicorn(monkeypatch):
    import os
    import runpy

    calls = {}
    fake_uvicorn = types.ModuleType("uvicorn")

    def fake_run(app, host, port):  # noqa: ANN001
        calls["app"] = app
        calls["host"] = host
        calls["port"] = port

    fake_uvicorn.run = fake_run  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "uvicorn", fake_uvicorn)
    monkeypatch.setenv("VERIFY_HOST", "127.0.0.1")
    monkeypatch.setenv("VERIFY_PORT", "8199")
    monkeypatch.delenv("CODEX_TIMEOUT_SECONDS", raising=False)

    runpy.run_module("danus.verify", run_name="__main__")

    assert calls["host"] == "127.0.0.1" and calls["port"] == 8199
    assert calls["app"] is not None
    # the entrypoint sets a bounded default per-verification timeout
    assert os.environ.get("CODEX_TIMEOUT_SECONDS") == "900"


def main() -> None:
    import inspect

    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            if inspect.signature(fn).parameters:
                print(f"  [skip standalone] {name} (needs pytest fixture)")
                continue
            fn()
            print(f"  [ok] {name}")
    print("ALL SERVICE TESTS PASSED")


if __name__ == "__main__":
    main()
