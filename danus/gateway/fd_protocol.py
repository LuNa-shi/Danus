"""Fixed wire values for the Worker provider/gateway handshakes."""

from __future__ import annotations

import struct
from collections.abc import Mapping


# The host accepts exactly one fixed-size attestation before it sends a prompt.
# A per-service challenge prevents stale output from satisfying the barrier;
# the socket identity binds the launcher's private mount view to the host-owned
# one-shot broker.  The flags are deliberately exact, not forward-compatible:
# every listed launcher self-check must have completed before READY is emitted.
_PROVIDER_READY_MAGIC = b"DANUS-PROVIDER-READY-V2"
_PROVIDER_NAMESPACE_ORDER = ("pid", "mnt", "user", "cgroup")
_PROVIDER_READY = struct.Struct("!23s16sQQQQQQQQQQI")
_PROVIDER_READY_FLAGS = 0xFF
PROVIDER_READY_SIZE = _PROVIDER_READY.size
PROVIDER_SOCKET_PATH = "/tmp/.danus-worker-mcp.sock"
BROKER_READY_MARKER = b"R"
BROKER_AUTHORIZED_MARKER = b"A"


def provider_ready_attestation(
    challenge: bytes, *, socket_dev: int, socket_ino: int,
    namespaces: Mapping[str, tuple[int, int]],
) -> bytes:
    if len(challenge) != 16:
        raise ValueError("provider READY challenge must be exactly 16 bytes")
    if (
        not isinstance(socket_dev, int) or isinstance(socket_dev, bool)
        or not isinstance(socket_ino, int) or isinstance(socket_ino, bool)
        or socket_dev < 0 or socket_dev >= 1 << 64
        or socket_ino <= 0 or socket_ino >= 1 << 64
    ):
        raise ValueError("provider READY socket identity is invalid")
    if set(namespaces) != set(_PROVIDER_NAMESPACE_ORDER):
        raise ValueError("provider READY namespace inventory is incomplete")
    namespace_values: list[int] = []
    for name in _PROVIDER_NAMESPACE_ORDER:
        identity = namespaces[name]
        if (
            not isinstance(identity, tuple) or len(identity) != 2
            or any(
                not isinstance(item, int) or isinstance(item, bool)
                or item <= 0 or item >= 1 << 64
                for item in identity
            )
        ):
            raise ValueError("provider READY namespace identity is invalid")
        namespace_values.extend(identity)
    return _PROVIDER_READY.pack(
        _PROVIDER_READY_MAGIC, challenge, socket_dev, socket_ino,
        *namespace_values, _PROVIDER_READY_FLAGS,
    )


def parse_provider_ready_attestation(
    value: bytes, *, challenge: bytes, socket_dev: int, socket_ino: int,
) -> dict[str, tuple[int, int]]:
    if len(value) != PROVIDER_READY_SIZE:
        raise ValueError("provider READY attestation has the wrong size")
    if len(challenge) != 16:
        raise ValueError("provider READY challenge must be exactly 16 bytes")
    unpacked = _PROVIDER_READY.unpack(value)
    magic, actual_challenge, actual_dev, actual_ino = unpacked[:4]
    namespace_values = unpacked[4:-1]
    flags = unpacked[-1]
    if magic != _PROVIDER_READY_MAGIC:
        raise ValueError("provider READY attestation has the wrong magic")
    if actual_challenge != challenge:
        raise ValueError("provider READY attestation challenge does not match")
    if actual_dev != socket_dev or actual_ino != socket_ino:
        raise ValueError("provider READY socket identity does not match")
    if flags != _PROVIDER_READY_FLAGS:
        raise ValueError("provider READY isolation flags are incomplete")
    namespaces = {
        name: (namespace_values[index], namespace_values[index + 1])
        for name, index in zip(_PROVIDER_NAMESPACE_ORDER, range(0, 8, 2))
    }
    # Reuse the exact range and inventory checks from the encoder rather than
    # accepting attacker-controlled zero/sentinel namespace values.
    provider_ready_attestation(
        challenge, socket_dev=socket_dev, socket_ino=socket_ino,
        namespaces=namespaces,
    )
    return namespaces


__all__ = [
    "BROKER_AUTHORIZED_MARKER", "BROKER_READY_MARKER",
    "PROVIDER_READY_SIZE", "PROVIDER_SOCKET_PATH", "provider_ready_attestation",
    "parse_provider_ready_attestation",
]
