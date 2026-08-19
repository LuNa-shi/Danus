"""Regression tests for the host/provider service boundary."""

from __future__ import annotations

import errno
import os
import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from danus.execution import layout as L
from danus.execution import security, systemd_scope
from danus.gateway import fd_protocol


def test_removed_provider_cgroup_fd_is_an_empty_proof_only_after_path_removal(
    monkeypatch,
) -> None:
    """cgroupfs reports ENODEV/ENXIO after systemd removes an empty scope."""

    def removed_fd(_fd: int, _offset: int, _whence: int) -> int:
        raise OSError(errno.ENODEV, "removed cgroup")

    monkeypatch.setattr(systemd_scope.os, "lseek", removed_fd)
    missing = "/danus-test-cgroup-that-does-not-exist"
    assert not Path("/sys/fs/cgroup" + missing).exists()
    assert systemd_scope._events_from_fd(99, missing) == {
        "populated": "0", "removed": "1",
    }

    with pytest.raises(systemd_scope.SystemdBoundaryError):
        systemd_scope._events_from_fd(99, "/")


@pytest.mark.parametrize("replacement", ["directory", "events"])
def test_cgroup_pin_rejects_same_path_inode_replacement(
    tmp_path: Path, monkeypatch, replacement: str,
) -> None:
    """Neither a directory nor cgroup.events name is durable authority."""

    cgroup_path = tmp_path / "provider.scope"
    cgroup_path.mkdir()
    events_path = cgroup_path / "cgroup.events"
    events_path.write_text("populated 1\n", encoding="ascii")
    monkeypatch.setattr(
        systemd_scope, "_cgroup_fs_path", lambda _cgroup: cgroup_path,
    )
    pin = systemd_scope._open_cgroup_pin("/provider.scope")
    assert pin is not None
    try:
        assert pin.path_matches()
        if replacement == "directory":
            cgroup_path.rename(tmp_path / "old-provider.scope")
            cgroup_path.mkdir()
            (cgroup_path / "cgroup.events").write_text(
                "populated 1\n", encoding="ascii",
            )
        else:
            replacement_path = cgroup_path / "replacement.events"
            replacement_path.write_text("populated 1\n", encoding="ascii")
            replacement_path.replace(events_path)

        with pytest.raises(systemd_scope.SystemdBoundaryError, match="replaced"):
            systemd_scope._events_from_pin(pin)
    finally:
        pin.close()


def test_cgroup_pin_close_is_idempotent(tmp_path: Path, monkeypatch) -> None:
    cgroup_path = tmp_path / "provider.scope"
    cgroup_path.mkdir()
    (cgroup_path / "cgroup.events").write_text("populated 0\n", encoding="ascii")
    monkeypatch.setattr(
        systemd_scope, "_cgroup_fs_path", lambda _cgroup: cgroup_path,
    )
    pin = systemd_scope._open_cgroup_pin("/provider.scope")
    assert pin is not None

    pin.close()
    pin.close()

    assert pin.dir_fd == -1
    assert pin.events_fd == -1


@pytest.mark.parametrize("reader", ["provider", "worker"])
def test_cgroup_pin_rechecks_identity_after_events_read(
    tmp_path: Path, monkeypatch, reader: str,
) -> None:
    """A same-name cgroup replacement racing the read fails closed."""

    cgroup_path = tmp_path / "provider.scope"
    cgroup_path.mkdir()
    (cgroup_path / "cgroup.events").write_text("populated 0\n", encoding="ascii")
    monkeypatch.setattr(
        systemd_scope, "_cgroup_fs_path", lambda _cgroup: cgroup_path,
    )
    pin = systemd_scope._open_cgroup_pin("/provider.scope")
    assert pin is not None
    original_pread = systemd_scope.os.pread

    def replace_after_read(fd: int, count: int, offset: int) -> bytes:
        raw = original_pread(fd, count, offset)
        cgroup_path.rename(tmp_path / "old-provider.scope")
        cgroup_path.mkdir()
        (cgroup_path / "cgroup.events").write_text(
            "populated 1\n", encoding="ascii",
        )
        return raw

    monkeypatch.setattr(systemd_scope.os, "pread", replace_after_read)
    try:
        with pytest.raises(systemd_scope.SystemdBoundaryError, match="replaced"):
            if reader == "provider":
                systemd_scope._events_from_pin(pin)
            else:
                pin.populated()
    finally:
        pin.close()


def test_provider_ready_attestation_is_fixed_and_challenge_bound() -> None:
    challenge = bytes(range(16))
    namespaces = {
        "pid": (1, 2), "mnt": (3, 4), "user": (5, 6), "cgroup": (7, 8),
    }

    ready = fd_protocol.provider_ready_attestation(
        challenge, socket_dev=0x0102030405060708,
        socket_ino=0x1112131415161718,
        namespaces=namespaces,
    )

    assert len(ready) == fd_protocol.PROVIDER_READY_SIZE
    assert ready == (
        b"DANUS-PROVIDER-READY-V2"
        + challenge
        + struct.pack(
            "!QQQQQQQQQQI",
            0x0102030405060708, 0x1112131415161718,
            1, 2, 3, 4, 5, 6, 7, 8, 0xFF,
        )
    )
    assert fd_protocol.parse_provider_ready_attestation(
        ready, challenge=challenge, socket_dev=0x0102030405060708,
        socket_ino=0x1112131415161718,
    ) == namespaces
    with pytest.raises(ValueError, match="challenge"):
        fd_protocol.parse_provider_ready_attestation(
            ready, challenge=b"x" * 16, socket_dev=0x0102030405060708,
            socket_ino=0x1112131415161718,
        )


def test_worker_entry_uses_the_lexical_virtualenv_interpreter(
    tmp_path: Path, monkeypatch,
) -> None:
    """The Worker needs packages installed in the Danus virtualenv."""

    base = tmp_path / "python-base"
    base.write_bytes(Path(sys.executable).read_bytes())
    base.chmod(0o755)
    venv_bin = tmp_path / "venv" / "bin"
    venv_bin.mkdir(parents=True)
    lexical = venv_bin / "python"
    lexical.symlink_to(base)
    monkeypatch.setattr(systemd_scope.os.sys, "executable", str(lexical))
    worker = L.WorkerLayout(tmp_path / "Project-A" / "workers" / "high")

    assert systemd_scope.expected_worker_argv(worker)[0] == str(lexical)


def test_provider_proc_view_keeps_kernel_sysctls_for_nested_bubblewrap(
    tmp_path: Path, monkeypatch,
) -> None:
    """PrivatePIDs isolates processes without hiding /proc/sys from bwrap."""

    worker = L.WorkerLayout(tmp_path / "Project-A" / "workers" / "high")
    monkeypatch.setattr(
        security, "provider_read_only_paths", lambda _worker, _codex: [Path("/usr")],
    )
    monkeypatch.setattr(
        security, "provider_writable_paths", lambda _worker: [Path("/tmp")],
    )
    gateway = SimpleNamespace(
        socket_path=Path("/run/user/1000/danus-b/g.sock"),
        provider_socket_path=Path("/tmp/.danus-worker-mcp.sock"),
    )

    properties, _read_only, _writable = systemd_scope._provider_service_properties(
        worker, "/usr/bin/true", gateway, 60,
    )

    assert "PrivatePIDs=yes" in properties
    assert "ProcSubset=all" in properties
    assert "ProcSubset=pid" not in properties


def test_provider_run_view_is_empty_except_resolver_and_private_socket(
    tmp_path: Path, monkeypatch,
) -> None:
    """DNS remains usable without exposing either host D-Bus endpoint."""

    worker = L.WorkerLayout(tmp_path / "Project-A" / "workers" / "high")
    resolver = tmp_path / "stub-resolv.conf"
    resolver.write_text("nameserver 127.0.0.53\n", encoding="ascii")
    monkeypatch.setattr(systemd_scope, "_RESOLVER_PATH", resolver)
    monkeypatch.setattr(
        security, "provider_read_only_paths", lambda _worker, _codex: [Path("/usr")],
    )
    monkeypatch.setattr(
        security, "provider_writable_paths", lambda _worker: [Path("/tmp")],
    )
    gateway = SimpleNamespace(
        socket_path=Path("/run/user/1000/danus-b/g.sock"),
        provider_socket_path=Path("/tmp/.danus-worker-mcp.sock"),
    )

    properties, read_only, _writable = systemd_scope._provider_service_properties(
        worker, "/usr/bin/true", gateway, 60,
    )

    assert "TemporaryFileSystem=/run:ro" in properties
    assert "InaccessiblePaths=/run" not in properties
    assert "InaccessiblePaths=/sys/fs/cgroup" in properties
    assert str(resolver) in read_only
    exposed_destinations = {
        item.split(":", 1)[-1] if ":" in item else item for item in read_only
    }
    assert not any(
        item.startswith("/run/user") or item.startswith("/run/dbus")
        for item in exposed_destinations
    )
