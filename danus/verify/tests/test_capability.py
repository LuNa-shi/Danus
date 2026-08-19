from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import json
import os
import threading
from contextlib import contextmanager
from pathlib import Path

import pytest

from danus.verify import capability


@contextmanager
def _secret(path: Path):
    name = "DANUS_VERIFY_CAPABILITY_SECRET_FILE"
    old = os.environ.get(name)
    os.environ[name] = str(path)
    try:
        yield
    finally:
        if old is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = old


def test_capability_is_exactly_project_and_worker_scoped(tmp_path: Path):
    with _secret(tmp_path / "private" / "verify.key"):
        token = capability.mint_worker_capability("Project-A", "worker_1")
        assert capability.verify_worker_capability(token, "Project-A", "worker_1")
        assert not capability.verify_worker_capability(token, "Project-A", "worker_1")
        assert not capability.verify_worker_capability(token, "Project-B", "worker_1")
        assert not capability.verify_worker_capability(token, "Project-A", "worker_2")
        assert not capability.verify_worker_capability(token + "x", "Project-A", "worker_1")
        key = capability.secret_path()
        assert key.stat().st_mode & 0o077 == 0
        assert key.parent.stat().st_mode & 0o077 == 0


def test_capability_rejects_malformed_tokens_without_throwing(tmp_path: Path):
    with _secret(tmp_path / "verify.key"):
        capability.load_or_create_key()
        for token in ("", "not-a-token", "dv1.!!!!.!!!!", "x" * 2048):
            assert not capability.verify_worker_capability(token, "P", "w")


def test_cross_scope_attempt_does_not_consume_the_right_scope(tmp_path: Path):
    with _secret(tmp_path / "verify.key"):
        token = capability.mint_worker_capability("Project-A", "worker-1")
        assert not capability.verify_worker_capability(token, "Project-B", "worker-1")
        assert not capability.verify_worker_capability(token, "Project-A", "worker-2")
        assert capability.verify_worker_capability(token, "Project-A", "worker-1")


def test_capability_refuses_weak_or_symlinked_key(tmp_path: Path):
    weak = tmp_path / "weak.key"
    weak.write_bytes(b"short")
    weak.chmod(0o644)
    with _secret(weak), pytest.raises(capability.CapabilityConfigurationError):
        capability.load_or_create_key()

    target = tmp_path / "target.key"
    target.write_bytes(os.urandom(48))
    target.chmod(0o600)
    link = tmp_path / "link.key"
    link.symlink_to(target)
    with _secret(link), pytest.raises(capability.CapabilityConfigurationError):
        capability.load_or_create_key()


def test_concurrent_first_key_publish_never_exposes_partial_bytes(tmp_path: Path):
    with _secret(tmp_path / "private" / "verify.key"):
        barrier = threading.Barrier(32)

        def load():
            barrier.wait()
            return capability.load_or_create_key()

        with ThreadPoolExecutor(max_workers=32) as pool:
            keys = list(pool.map(lambda _: load(), range(32)))
        assert len(set(keys)) == 1
        assert len(keys[0]) == 48
        assert capability.secret_path().read_bytes() == keys[0]
        assert not list(capability.secret_path().parent.glob("*.tmp"))


def test_fresh_tokens_work_sequentially_and_concurrently_but_each_replay_fails(tmp_path: Path):
    with _secret(tmp_path / "verify.key"):
        sequential = [
            capability.mint_worker_capability("Project-A", "worker-1")
            for _ in range(2)
        ]
        assert all(
            capability.verify_worker_capability(token, "Project-A", "worker-1")
            for token in sequential
        )
        assert all(
            not capability.verify_worker_capability(token, "Project-A", "worker-1")
            for token in sequential
        )

        concurrent = [
            capability.mint_worker_capability("Project-A", "worker-1")
            for _ in range(2)
        ]
        with ThreadPoolExecutor(max_workers=2) as pool:
            accepted = list(pool.map(
                lambda token: capability.verify_worker_capability(
                    token, "Project-A", "worker-1",
                ),
                concurrent,
            ))
        assert accepted == [True, True]
        assert all(
            not capability.verify_worker_capability(token, "Project-A", "worker-1")
            for token in concurrent
        )


def test_concurrent_replay_race_has_exactly_one_winner(tmp_path: Path):
    with _secret(tmp_path / "verify.key"):
        token = capability.mint_worker_capability("Project-A", "worker-1")
        barrier = threading.Barrier(16)

        def consume():
            barrier.wait()
            return capability.verify_worker_capability(
                token, "Project-A", "worker-1",
            )

        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda _: consume(), range(16)))
        assert sum(results) == 1


def test_capability_expiry_and_replay_cleanup_are_bounded(tmp_path: Path, monkeypatch):
    now = 2_000_000_000
    monkeypatch.setattr(capability.time, "time", lambda: now)
    monkeypatch.setenv("DANUS_VERIFY_CAPABILITY_TTL_SECONDS", "60")
    with _secret(tmp_path / "verify.key"):
        old = capability.mint_worker_capability("Project-A", "worker-1")
        assert capability.verify_worker_capability(old, "Project-A", "worker-1")
        replay_root = capability.secret_path().parent / "verify-capability-replay"
        old_buckets = set(replay_root.glob("expires-*"))
        assert len(old_buckets) == 1

        now += 121
        assert not capability.verify_worker_capability(old, "Project-A", "worker-1")
        fresh = capability.mint_worker_capability("Project-A", "worker-1")
        assert capability.verify_worker_capability(fresh, "Project-A", "worker-1")
        assert not any(path.exists() for path in old_buckets)
        assert len(list(replay_root.glob("expires-*"))) <= capability._MAX_ACTIVE_BUCKETS


def test_noncanonical_signed_payload_is_rejected(tmp_path: Path):
    with _secret(tmp_path / "verify.key"):
        token = capability.mint_worker_capability("Project-A", "worker-1")
        _, encoded, _ = token.split(".")
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        payload = json.loads(raw)
        noncanonical = json.dumps(payload, indent=1).encode("ascii")
        changed = base64.urlsafe_b64encode(noncanonical).rstrip(b"=").decode("ascii")
        signature = hmac.new(
            capability.load_or_create_key(), changed.encode("ascii"), hashlib.sha256,
        ).digest()
        supplied = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
        assert not capability.verify_worker_capability(
            f"dv1.{changed}.{supplied}", "Project-A", "worker-1",
        )
