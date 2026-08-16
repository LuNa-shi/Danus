"""Offline tests for danus.codex — the single shared codex launcher.

Covers the four uniform pieces: binary resolution precedence (DANUS_CODEX_BIN
legacy alias, the <repo>/bin/codex wrapper, and shutil.which), model/effort
precedence (per-service overrides -> neutral DANUS_CODEX_* -> built-in default,
override names), subprocess_env (prepend the binary DIR to PATH only for a
concrete path; never inject the CWD for the bare "codex" fallback), and the
exec_cmd shape (quoted model_reasoning_effort + verbatim tail).

Zero network / API spend. Runs standalone
(``python -m danus.tests.test_codex``) and under pytest.
"""

from __future__ import annotations

import contextlib
import os
import stat
import tempfile
from pathlib import Path

from danus import codex


@contextlib.contextmanager
def env(**kv):
    """Temporarily set env vars (None deletes), restore after."""
    old = {k: os.environ.get(k) for k in kv}
    try:
        for k, v in kv.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        yield
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


# All env names the launcher consults — cleared as the baseline so ambient config
# never leaks into a precedence assertion.
_ALL = dict(
    DANUS_CODEX_BIN=None, CODEX_BIN=None,
    DANUS_CODEX_MODEL=None, DANUS_CODEX_EFFORT=None,
    OPENAI_BASE_URL=None, OPENAI_API_KEY=None,
    CODEX_API_BASE_URL=None, DANUS_CODEX_API_KEY=None,
    DANUS_VERIFY_MODEL=None, DANUS_VERIFY_EFFORT=None,
    DANUS_WRITE_PAPER_MODEL=None, DANUS_WRITE_PAPER_EFFORT=None,
    DANUS_HUMAN_SUMMARY_MODEL=None, DANUS_HUMAN_SUMMARY_EFFORT=None,
)


# --- resolve_bin precedence ------------------------------------------------- #

def test_resolve_bin_prefers_danus_codex_bin_over_alias():
    with env(**{**_ALL, "DANUS_CODEX_BIN": "/x/primary", "CODEX_BIN": "/x/alias"}):
        assert codex.resolve_bin() == "/x/primary"


def test_resolve_bin_uses_repo_wrapper_only_when_runtime_is_provisioned():
    import shutil
    real_root, real_which = codex._REPO_ROOT, shutil.which
    try:
        with tempfile.TemporaryDirectory() as d, env(**_ALL):
            root = Path(d)
            wrapper = root / "bin" / "codex"
            wrapper.parent.mkdir()
            wrapper.write_text("#!/bin/sh\n")
            (root / "runtime").mkdir()
            codex._REPO_ROOT = root
            shutil.which = lambda name: "/system/bin/codex"

            assert codex.resolve_bin() == "/system/bin/codex"

            (root / "runtime" / "runtime.env").write_text("DANUS_NODE=/runtime/node\n")
            assert codex.resolve_bin() == str(wrapper)
    finally:
        codex._REPO_ROOT, shutil.which = real_root, real_which


def test_resolve_bin_bare_when_nothing_available(monkeypatch=None):
    import shutil
    real_root, real_which = codex._REPO_ROOT, shutil.which
    try:
        with tempfile.TemporaryDirectory() as d, env(**_ALL):
            codex._REPO_ROOT = Path(d)
            shutil.which = lambda *a, **k: None  # type: ignore[assignment]
            assert codex.resolve_bin() == "codex"
    finally:
        codex._REPO_ROOT, shutil.which = real_root, real_which


# --- model / effort precedence ---------------------------------------------- #

def test_model_override_wins_then_neutral_then_default():
    with env(**{**_ALL, "DANUS_VERIFY_MODEL": "override-m", "DANUS_CODEX_MODEL": "neutral-m"}):
        assert codex.model("DANUS_VERIFY_MODEL") == "override-m"
    with env(**{**_ALL, "DANUS_CODEX_MODEL": "neutral-m"}):
        assert codex.model("DANUS_VERIFY_MODEL") == "neutral-m"
    with env(**_ALL):
        assert codex.model("DANUS_VERIFY_MODEL") == codex.DEFAULT_MODEL == "gpt-5.5"


def test_effort_override_wins_then_neutral_then_default():
    with env(**{**_ALL, "DANUS_VERIFY_EFFORT": "override-e", "DANUS_CODEX_EFFORT": "neutral-e"}):
        assert codex.effort("DANUS_VERIFY_EFFORT") == "override-e"
    with env(**{**_ALL, "DANUS_CODEX_EFFORT": "neutral-e"}):
        assert codex.effort("DANUS_VERIFY_EFFORT") == "neutral-e"
    with env(**_ALL):
        assert codex.effort("DANUS_VERIFY_EFFORT") == codex.DEFAULT_EFFORT == "xhigh"


def test_first_override_in_order_wins():
    with env(**{**_ALL, "DANUS_VERIFY_MODEL": "primary", "DANUS_WRITE_PAPER_MODEL": "other"}):
        # the first listed override name wins
        assert codex.model("DANUS_VERIFY_MODEL", "DANUS_WRITE_PAPER_MODEL") == "primary"


# --- subprocess_env --------------------------------------------------------- #

def test_subprocess_env_prepends_dir_for_concrete_path():
    with env(**{**_ALL, "PATH": "/usr/bin:/bin"}):
        out = codex.subprocess_env("/opt/codex/bin/codex")
        assert out["PATH"].split(os.pathsep)[0] == "/opt/codex/bin"
        assert "/usr/bin" in out["PATH"]


def test_subprocess_env_never_injects_cwd_for_bare_codex():
    with env(**{**_ALL, "PATH": "/usr/bin:/bin"}):
        out = codex.subprocess_env("codex")
        # the bare-name fallback has no dir component → PATH is untouched, and the
        # CWD ("" / ".") is NOT injected.
        assert out["PATH"] == "/usr/bin:/bin"
        assert "" not in out["PATH"].split(os.pathsep)
        assert "." not in out["PATH"].split(os.pathsep)


def test_subprocess_env_idempotent_when_dir_already_on_path():
    with env(**{**_ALL, "PATH": "/opt/codex/bin:/usr/bin"}):
        out = codex.subprocess_env("/opt/codex/bin/codex")
        # already present → not duplicated
        assert out["PATH"] == "/opt/codex/bin:/usr/bin"


# --- exec_cmd shape --------------------------------------------------------- #

def test_exec_cmd_shape_quoted_effort_and_verbatim_tail():
    with env(**_ALL):
        cmd = codex.exec_cmd("/x/codex", "the-model", "xhigh", "-C", "/home", "-")
    assert cmd == [
        "/x/codex", "exec",
        "--model", "the-model",
        "--config", 'model_reasoning_effort="xhigh"',
        "-C", "/home", "-",
    ]


def test_exec_cmd_empty_tail():
    with env(**_ALL):
        cmd = codex.exec_cmd("codex", "m", "e")
    assert cmd == ["codex", "exec", "--model", "m", "--config", 'model_reasoning_effort="e"']


def test_exec_cmd_builds_direct_provider_without_putting_key_in_argv():
    secret = "redacted-test-secret"
    with env(**{
        **_ALL,
        "OPENAI_BASE_URL": "https://provider.example/v1",
        "OPENAI_API_KEY": secret,
    }):
        cmd = codex.exec_cmd("codex", "gpt-5.5", "xhigh", "prompt")

    assert 'model_provider="danus_direct"' in cmd
    assert any(
        value.startswith("model_providers.danus_direct={")
        and 'base_url="https://provider.example/v1"' in value
        and 'env_key="OPENAI_API_KEY"' in value
        and 'wire_api="responses"' in value
        for value in cmd
    )
    assert not any(secret in value for value in cmd)


def test_exec_cmd_supports_codex_base_url_and_danus_key_pair():
    with env(**{
        **_ALL,
        "CODEX_API_BASE_URL": "https://codex-provider.example/v1",
        "DANUS_CODEX_API_KEY": "redacted-danus-secret",
    }):
        cmd = codex.exec_cmd("codex", "gpt-5.5", "high")

    assert any(
        'base_url="https://codex-provider.example/v1"' in value
        and 'env_key="DANUS_CODEX_API_KEY"' in value
        for value in cmd
    )
    assert not any("redacted-danus-secret" in value for value in cmd)


def main() -> None:
    tests = [
        test_resolve_bin_prefers_danus_codex_bin_over_alias,
        test_resolve_bin_uses_repo_wrapper_only_when_runtime_is_provisioned,
        test_resolve_bin_bare_when_nothing_available,
        test_model_override_wins_then_neutral_then_default,
        test_effort_override_wins_then_neutral_then_default,
        test_first_override_in_order_wins,
        test_subprocess_env_prepends_dir_for_concrete_path,
        test_subprocess_env_never_injects_cwd_for_bare_codex,
        test_subprocess_env_idempotent_when_dir_already_on_path,
        test_exec_cmd_shape_quoted_effort_and_verbatim_tail,
        test_exec_cmd_empty_tail,
        test_exec_cmd_builds_direct_provider_without_putting_key_in_argv,
        test_exec_cmd_supports_codex_base_url_and_danus_key_pair,
    ]
    for t in tests:
        t()
        print(f"  [ok] {t.__name__}")
    print("ALL CODEX LAUNCHER TESTS PASSED")


if __name__ == "__main__":
    main()
