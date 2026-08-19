"""Private framed-stdin protocol for the fixed verifier trusted entry.

Nothing sensitive is carried in argv or service-manager properties.  The
transient-service adapter writes one length-delimited header followed by the raw
prompt bytes, and reads back one metadata-only frame.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import struct
from typing import BinaryIO, Mapping, Sequence


_REQUEST_MAGIC = b"DVRQ\x00\x01\r\n"
_RESULT_MAGIC = b"DVRS\x00\x01\r\n"
_CHALLENGE_MAGIC = b"DVRC\x00\x01\r\n"
_READY_MAGIC = b"DVRD\x00\x01\r\n"
_REQUEST_PREFIX = struct.Struct("!8sIQ")
_RESULT_PREFIX = struct.Struct("!8sI")
_CHALLENGE = struct.Struct("!8s32s")
_READY = struct.Struct("!8s32s" + "QQ" * 5 + "Q")
_MAX_HEADER_BYTES = 1 << 20
_MAX_PROMPT_BYTES = 64 << 20
_MAX_RESULT_BYTES = 64 << 10
READY_FRAME_SIZE = _READY.size
_NAMESPACE_NAMES = ("pid", "mnt", "user", "cgroup")


class VerifierFrameError(ValueError):
    """A frame is malformed, oversized, truncated, or has unknown fields."""


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            raise VerifierFrameError("truncated verifier frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def encode_challenge(challenge: bytes) -> bytes:
    """Encode the non-secret startup challenge sent before a request frame."""

    if not isinstance(challenge, bytes) or len(challenge) != 32:
        raise VerifierFrameError("invalid verifier startup challenge")
    return _CHALLENGE.pack(_CHALLENGE_MAGIC, challenge)


def read_challenge(stream: BinaryIO) -> bytes:
    magic, challenge = _CHALLENGE.unpack(_read_exact(stream, _CHALLENGE.size))
    if magic != _CHALLENGE_MAGIC:
        raise VerifierFrameError("invalid verifier startup challenge")
    return challenge


def encode_ready(challenge: bytes) -> bytes:
    """Attest the trusted entry's executable and namespace identities."""

    if not isinstance(challenge, bytes) or len(challenge) != 32:
        raise VerifierFrameError("invalid verifier startup challenge")
    executable = Path("/proc/self/exe").stat()
    values: list[int] = [executable.st_dev, executable.st_ino]
    for name in _NAMESPACE_NAMES:
        info = (Path("/proc/self/ns") / name).stat()
        values.extend((info.st_dev, info.st_ino))
    return _READY.pack(_READY_MAGIC, challenge, *values, os.getpid())


def decode_ready(data: bytes, *, challenge: bytes) -> dict[str, object]:
    if not isinstance(data, bytes) or len(data) != READY_FRAME_SIZE:
        raise VerifierFrameError("invalid verifier startup attestation")
    unpacked = _READY.unpack(data)
    if unpacked[0] != _READY_MAGIC or unpacked[1] != challenge:
        raise VerifierFrameError("invalid verifier startup attestation")
    numbers = unpacked[2:]
    return {
        "entry_pid": numbers[10],
        "executable": (numbers[0], numbers[1]),
        "namespaces": {
            name: (numbers[index], numbers[index + 1])
            for name, index in zip(_NAMESPACE_NAMES, range(2, 10, 2))
        },
    }


def read_ready(stream: BinaryIO, *, challenge: bytes) -> dict[str, object]:
    return decode_ready(_read_exact(stream, READY_FRAME_SIZE), challenge=challenge)


def encode_request(
    *,
    run_id: str,
    provider_argv: Sequence[str],
    provider_environment: Mapping[str, str],
    timeout_seconds: int | None,
    prompt: bytes,
) -> bytes:
    if not isinstance(prompt, bytes) or len(prompt) > _MAX_PROMPT_BYTES:
        raise VerifierFrameError("invalid verifier prompt frame")
    header = json.dumps(
        {
            "provider_argv": list(provider_argv),
            "provider_environment": dict(provider_environment),
            "run_id": run_id,
            "schema": 1,
            "timeout_seconds": timeout_seconds,
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    if len(header) > _MAX_HEADER_BYTES:
        raise VerifierFrameError("verifier request header is too large")
    return _REQUEST_PREFIX.pack(_REQUEST_MAGIC, len(header), len(prompt)) + header + prompt


def read_request(stream: BinaryIO) -> tuple[dict[str, object], bytes]:
    magic, header_size, prompt_size = _REQUEST_PREFIX.unpack(
        _read_exact(stream, _REQUEST_PREFIX.size)
    )
    if (
        magic != _REQUEST_MAGIC
        or header_size > _MAX_HEADER_BYTES
        or prompt_size > _MAX_PROMPT_BYTES
    ):
        raise VerifierFrameError("invalid verifier request frame")
    try:
        header = json.loads(_read_exact(stream, header_size))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerifierFrameError("invalid verifier request header") from exc
    if not isinstance(header, dict):
        raise VerifierFrameError("invalid verifier request header")
    prompt = _read_exact(stream, prompt_size)
    if stream.read(1):
        raise VerifierFrameError("trailing verifier request data")
    return header, prompt


def encode_result(metadata: Mapping[str, object]) -> bytes:
    payload = json.dumps(
        dict(metadata), ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ).encode("ascii")
    if len(payload) > _MAX_RESULT_BYTES:
        raise VerifierFrameError("verifier result frame is too large")
    return _RESULT_PREFIX.pack(_RESULT_MAGIC, len(payload)) + payload


def read_result(data: bytes) -> dict[str, object]:
    stream = io.BytesIO(data)
    magic, payload_size = _RESULT_PREFIX.unpack(
        _read_exact(stream, _RESULT_PREFIX.size)
    )
    if magic != _RESULT_MAGIC or payload_size > _MAX_RESULT_BYTES:
        raise VerifierFrameError("invalid verifier result frame")
    try:
        payload = json.loads(_read_exact(stream, payload_size))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerifierFrameError("invalid verifier result payload") from exc
    if stream.read(1) or not isinstance(payload, dict):
        raise VerifierFrameError("invalid verifier result payload")
    return payload


__all__ = [
    "READY_FRAME_SIZE",
    "VerifierFrameError",
    "decode_ready",
    "encode_challenge",
    "encode_ready",
    "encode_request",
    "encode_result",
    "read_challenge",
    "read_ready",
    "read_request",
    "read_result",
]
