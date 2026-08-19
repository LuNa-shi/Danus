from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
from typing import Iterator

import pytest


WRAPPER = Path(__file__).resolve().parents[3] / "bin" / "danus-web-agent"
LIFECYCLE_TOKEN = "lifecycle-capability-do-not-print"
CONFIRMATION_TOKEN = "artifact-confirmation-do-not-print"


class _BrokerHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        self.server.requests.append(  # type: ignore[attr-defined]
            {
                "path": self.path,
                "authorization": self.headers.get("Authorization"),
                "accept": self.headers.get("Accept"),
                "content_type": self.headers.get("Content-Type"),
                "raw": raw,
                "json": json.loads(raw),
            }
        )
        self.server.request_received.set()  # type: ignore[attr-defined]
        release = self.server.release_response  # type: ignore[attr-defined]
        if release is not None:
            release.wait(timeout=5)
        status = self.server.response_status  # type: ignore[attr-defined]
        body = self.server.response_body  # type: ignore[attr-defined]
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            pass

    def log_message(self, _format: str, *_args: object) -> None:
        pass


@contextmanager
def _broker(
    *, status: int = 200, body: bytes = b'{"status":"ok"}', block: bool = False,
) -> Iterator[ThreadingHTTPServer]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BrokerHandler)
    server.daemon_threads = True
    server.requests = []  # type: ignore[attr-defined]
    server.response_status = status  # type: ignore[attr-defined]
    server.response_body = body  # type: ignore[attr-defined]
    server.request_received = threading.Event()  # type: ignore[attr-defined]
    server.release_response = threading.Event() if block else None  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        release = server.release_response  # type: ignore[attr-defined]
        if release is not None:
            release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _env(server: ThreadingHTTPServer, *, confirmation: str | None = None) -> dict[str, str]:
    env = os.environ.copy()
    host, port = server.server_address
    env.update(
        {
            "DANUS_WEB_LIFECYCLE_URL": f"http://{host}:{port}/internal/project/lifecycle",
            "DANUS_WEB_LIFECYCLE_TOKEN": LIFECYCLE_TOKEN,
        }
    )
    if confirmation is None:
        env.pop("DANUS_WEB_ARTIFACT_CONFIRMATION_TOKEN", None)
    else:
        env["DANUS_WEB_ARTIFACT_CONFIRMATION_TOKEN"] = confirmation
    return env


def _run(
    server: ThreadingHTTPServer,
    args: list[str],
    *,
    confirmation: str | None = None,
    env_updates: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = _env(server, confirmation=confirmation)
    env.update(env_updates or {})
    return subprocess.run(
        [str(WRAPPER), *args],
        text=True,
        capture_output=True,
        env=env,
        timeout=8,
        check=False,
    )


def _assert_secrets_absent(result: subprocess.CompletedProcess[str]) -> None:
    combined = result.stdout + result.stderr
    assert LIFECYCLE_TOKEN not in combined
    assert CONFIRMATION_TOKEN not in combined


def test_help_lists_every_command_and_has_no_confirmation_cli_option() -> None:
    result = subprocess.run(
        [str(WRAPPER), "--help"], text=True, capture_output=True, timeout=5, check=False,
    )

    assert result.returncode == 0
    assert result.stderr == ""
    for command in (
        "status", "assign", "start", "pause", "resume", "stop",
        "finalize suggestion", "finalize target", "human-summary", "write-paper",
        "--stop-workers", "--keep-workers",
    ):
        assert command in result.stdout
    assert "--confirmation" not in result.stdout


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["status"], {"action": "status"}),
        (["start"], {"action": "start"}),
        (["stop"], {"action": "stop"}),
        (["pause", "worker_1"], {"action": "pause", "worker": "worker_1"}),
        (["resume"], {"action": "resume"}),
        (
            ["assign", "worker-2", "--task", "Prove the bounded claim."],
            {"action": "assign", "worker": "worker-2", "task": "Prove the bounded claim."},
        ),
    ],
)
def test_lifecycle_commands_send_exact_json(args: list[str], expected: dict[str, object]) -> None:
    with _broker() as server:
        result = _run(server, args)

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"status": "ok"}
    assert len(server.requests) == 1  # type: ignore[attr-defined]
    request = server.requests[0]  # type: ignore[attr-defined]
    assert request["path"] == "/internal/project/lifecycle"
    assert request["authorization"] == f"Bearer {LIFECYCLE_TOKEN}"
    assert request["accept"] == "application/json"
    assert request["content_type"] == "application/json"
    assert request["json"] == expected
    _assert_secrets_absent(result)


@pytest.mark.parametrize(
    ("args", "confirmation", "expected"),
    [
        (
            ["finalize", "suggestion"],
            None,
            {"action": "finalize-suggest", "fact_ids": []},
        ),
        (
            [
                "finalize", "target", "--fact-id", "deadbeef", "--paper-id", "paper_1",
                "--fact-id", "0123abcd",
            ],
            CONFIRMATION_TOKEN,
            {
                "action": "finalize", "fact_ids": ["deadbeef", "0123abcd"],
                "paper_id": "paper_1", "confirmation_token": CONFIRMATION_TOKEN,
            },
        ),
        (
            ["human-summary", "--language", "zh-CN"],
            CONFIRMATION_TOKEN,
            {
                "action": "human-summary", "language": "zh-CN",
                "confirmation_token": CONFIRMATION_TOKEN,
            },
        ),
        (
            [
                "write-paper", "--fact-id", "deadbeef", "--paper-id", "paper-2",
                "--instructions", "Keep the proof concise.", "--stop-workers",
            ],
            CONFIRMATION_TOKEN,
            {
                "action": "write-paper", "fact_ids": ["deadbeef"],
                "paper_id": "paper-2", "instructions": "Keep the proof concise.",
                "stop_workers": True, "confirmation_token": CONFIRMATION_TOKEN,
            },
        ),
        (
            ["write-paper", "--keep-workers"],
            CONFIRMATION_TOKEN,
            {
                "action": "write-paper", "fact_ids": [], "stop_workers": False,
                "confirmation_token": CONFIRMATION_TOKEN,
            },
        ),
    ],
)
def test_artifact_commands_send_exact_json(
    args: list[str], confirmation: str | None, expected: dict[str, object],
) -> None:
    with _broker() as server:
        result = _run(server, args, confirmation=confirmation)

    assert result.returncode == 0, result.stderr
    assert server.requests[0]["json"] == expected  # type: ignore[attr-defined]
    _assert_secrets_absent(result)


@pytest.mark.parametrize(
    ("args", "confirmation"),
    [
        (["finalize", "target", "--fact-id", "deadbeef"], None),
        (["finalize", "target"], CONFIRMATION_TOKEN),
        (
            ["finalize", "target", "--fact-id", "deadbeef", "--paper-id", "p1", "--paper-id", "p2"],
            CONFIRMATION_TOKEN,
        ),
        (["human-summary", "--language", "zh", "--language", "en"], CONFIRMATION_TOKEN),
        (["write-paper"], CONFIRMATION_TOKEN),
        (["write-paper", "--stop-workers", "--keep-workers"], CONFIRMATION_TOKEN),
        (["write-paper", "--keep-workers", "--instructions", "a", "--instructions", "b"], CONFIRMATION_TOKEN),
        (["write-paper", "--keep-workers", "--confirmation-token", "forbidden"], CONFIRMATION_TOKEN),
        (["assign", "../other-project", "--task", "escape"], None),
        (["pause", "worker", "unexpected"], None),
    ],
)
def test_invalid_arguments_fail_without_contacting_broker(
    args: list[str], confirmation: str | None,
) -> None:
    with _broker() as server:
        result = _run(server, args, confirmation=confirmation)

    assert result.returncode == 2
    assert server.requests == []  # type: ignore[attr-defined]
    _assert_secrets_absent(result)


def test_empty_and_overlong_confirmation_fail_without_contacting_broker() -> None:
    with _broker() as server:
        empty = _run(server, ["human-summary"], confirmation="")
        overlong = _run(server, ["write-paper", "--keep-workers"], confirmation="x" * 513)

    assert empty.returncode == overlong.returncode == 2
    assert server.requests == []  # type: ignore[attr-defined]
    assert "not configured or invalid" in empty.stderr
    assert "not configured or invalid" in overlong.stderr


def test_non_loopback_broker_url_is_rejected_before_curl() -> None:
    with _broker() as server:
        result = _run(
            server,
            ["human-summary"],
            confirmation=CONFIRMATION_TOKEN,
            env_updates={"DANUS_WEB_LIFECYCLE_URL": "http://example.com/internal/lifecycle"},
        )

    assert result.returncode == 2
    assert server.requests == []  # type: ignore[attr-defined]
    assert "loopback HTTP URL" in result.stderr
    _assert_secrets_absent(result)


def test_http_rejection_does_not_reflect_secrets() -> None:
    reflected = json.dumps(
        {"detail": f"bad {LIFECYCLE_TOKEN} and {CONFIRMATION_TOKEN}"}
    ).encode()
    with _broker(status=409, body=reflected) as server:
        result = _run(server, ["human-summary"], confirmation=CONFIRMATION_TOKEN)

    assert result.returncode == 1
    assert result.stdout == ""
    assert "HTTP 409" in result.stderr
    _assert_secrets_absent(result)


@pytest.mark.parametrize("body", [b"not-json", b"[]", b'"string"'])
def test_invalid_success_json_fails_safely(body: bytes) -> None:
    with _broker(body=body) as server:
        result = _run(server, ["status"])

    assert result.returncode == 1
    assert result.stdout == ""
    assert "invalid response" in result.stderr
    _assert_secrets_absent(result)


def test_success_response_that_reflects_a_secret_is_rejected() -> None:
    body = json.dumps({"status": "ok", "echo": CONFIRMATION_TOKEN}).encode()
    with _broker(body=body) as server:
        result = _run(server, ["write-paper", "--keep-workers"], confirmation=CONFIRMATION_TOKEN)

    assert result.returncode == 1
    assert result.stdout == ""
    assert "unsafe response" in result.stderr
    _assert_secrets_absent(result)


def test_curl_connection_error_fails_without_leaking_secrets() -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    env = os.environ.copy()
    env.update(
        {
            "DANUS_WEB_LIFECYCLE_URL": f"http://127.0.0.1:{port}/internal/lifecycle",
            "DANUS_WEB_LIFECYCLE_TOKEN": LIFECYCLE_TOKEN,
            "DANUS_WEB_ARTIFACT_CONFIRMATION_TOKEN": CONFIRMATION_TOKEN,
        }
    )

    result = subprocess.run(
        [str(WRAPPER), "human-summary"], text=True, capture_output=True,
        env=env, timeout=8, check=False,
    )

    assert result.returncode == 1
    assert "broker unavailable" in result.stderr
    _assert_secrets_absent(result)


def test_tokens_are_absent_from_curl_process_arguments() -> None:
    with _broker(block=True) as server:
        process = subprocess.Popen(
            [str(WRAPPER), "write-paper", "--keep-workers"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_env(server, confirmation=CONFIRMATION_TOKEN),
        )
        assert server.request_received.wait(timeout=5)  # type: ignore[attr-defined]

        host, port = server.server_address
        url_marker = f"http://{host}:{port}/internal/project/lifecycle".encode()
        matching_cmdlines: list[bytes] = []
        for cmdline_path in Path("/proc").glob("[0-9]*/cmdline"):
            try:
                cmdline = cmdline_path.read_bytes()
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                continue
            if url_marker in cmdline:
                matching_cmdlines.append(cmdline)

        assert matching_cmdlines, "curl process was not observable while the broker response was blocked"
        argv_bytes = b"\n".join(matching_cmdlines)
        assert LIFECYCLE_TOKEN.encode() not in argv_bytes
        assert CONFIRMATION_TOKEN.encode() not in argv_bytes

        server.release_response.set()  # type: ignore[attr-defined]
        stdout, stderr = process.communicate(timeout=5)

    assert process.returncode == 0, stderr
    assert json.loads(stdout) == {"status": "ok"}
    assert LIFECYCLE_TOKEN not in stdout + stderr
    assert CONFIRMATION_TOKEN not in stdout + stderr


def test_secure_temporary_files_are_removed(tmp_path: Path) -> None:
    with _broker() as server:
        result = _run(
            server, ["human-summary"], confirmation=CONFIRMATION_TOKEN,
            env_updates={"TMPDIR": str(tmp_path)},
        )

    assert result.returncode == 0, result.stderr
    assert list(tmp_path.iterdir()) == []
