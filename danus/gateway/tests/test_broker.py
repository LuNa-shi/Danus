"""Real transient-service test for the one-shot host MCP broker."""

from __future__ import annotations

import json
import os
import secrets
import socket
import stat
import struct
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

import pytest

from danus.execution import layout as L
from danus.execution import security, systemd_scope
from danus.gateway.fd_protocol import (
    PROVIDER_READY_SIZE,
    PROVIDER_SOCKET_PATH,
    parse_provider_ready_attestation,
)


@pytest.fixture
def short_tmp():
    with tempfile.TemporaryDirectory(prefix="db-") as directory:
        yield Path(directory)


@contextmanager
def _env(**values):
    old = {name: os.environ.get(name) for name in values}
    try:
        os.environ.update({name: str(value) for name, value in values.items()})
        yield
    finally:
        for name, value in old.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def test_broker_rejects_direct_peer_then_relays_real_mcp_once(short_tmp: Path):
    """Provider pidfd ACK precedes prompt and only the attested bridge consumes UDS."""

    if not Path("/run/systemd/resolve/stub-resolv.conf").is_file():
        pytest.skip("systemd-resolved provider prerequisite is unavailable")
    try:
        manager_env = systemd_scope.manager_env()
    except systemd_scope.SystemdBoundaryError:
        pytest.skip("systemd user manager is unavailable")

    repo = Path(__file__).resolve().parents[3]
    wl = L.WorkerLayout(short_tmp / "projects" / "P" / "workers" / "high")
    wl.dir.mkdir(parents=True)
    launcher = (repo / "danus/execution/provider_launcher.py").resolve()
    bridge = (repo / "danus/gateway/bridge.py").resolve()
    provider_python = Path(sys.executable).resolve()
    python_root = Path(sys.base_prefix).resolve()
    unit = f"danus-provider-{'a' * 20}-{secrets.token_hex(8)}.service"
    broker = None
    service = None
    rogue = None

    with _env(
        DANUS_RUNTIME=short_tmp,
        DANUS_VERIFY_CAPABILITY_SECRET_FILE=short_tmp / "verify.key",
        DANUS_VERIFY_URL="http://127.0.0.1:9/verify",
    ), open(short_tmp / "broker.log", "w+", encoding="utf-8") as broker_log:
        try:
            broker = security.start_host_gateway(wl, broker_log)
            socket_path = broker.socket_path
            socket_info = socket_path.stat()
            assert stat.S_IMODE(socket_info.st_mode) == 0o600
            challenge = secrets.token_bytes(16)
            provider_argv = [
                str(provider_python), "-I", str(bridge),
                "--socket", PROVIDER_SOCKET_PATH,
            ]
            launcher_argv = [
                str(provider_python), "-I", str(launcher),
                "--ready-challenge", challenge.hex(),
                "--socket-dev", str(socket_info.st_dev),
                "--socket-ino", str(socket_info.st_ino), "--", *provider_argv,
            ]
            properties = [
                "KillMode=control-group", "SendSIGKILL=yes", "TimeoutStopSec=5s",
                "RuntimeMaxSec=60", "PrivatePIDs=yes", "ProtectProc=ptraceable",
                "ProcSubset=all", "ProtectSystem=strict", "ProtectHome=tmpfs",
                "PrivateTmp=yes", "PrivateDevices=yes", "ProtectControlGroups=strict",
                "NoNewPrivileges=yes", "ProtectKernelTunables=yes",
                "ProtectKernelModules=yes", "ProtectKernelLogs=yes", "ProtectClock=yes",
                "LockPersonality=yes", "RestrictRealtime=yes", "RestrictSUIDSGID=yes",
                "UMask=0077", "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
                "TemporaryFileSystem=/run:ro", "InaccessiblePaths=/sys/fs/cgroup",
                "BindReadOnlyPaths=/run/systemd/resolve/stub-resolv.conf",
                f"BindReadOnlyPaths={socket_path}:{PROVIDER_SOCKET_PATH}",
                f"BindReadOnlyPaths={repo / 'danus'}",
            ]
            if str(python_root).startswith(("/home/", "/root/")):
                properties.append(f"BindReadOnlyPaths={python_root}")
            args = [
                "/usr/bin/systemd-run", "--user", "--quiet", "--wait", "--pipe",
                "--collect", "--service-type=exec", f"--unit={unit}",
                "--property=WorkingDirectory=/",
                *(f"--property={item}" for item in properties), "--", *launcher_argv,
            ]
            service = subprocess.Popen(
                args, cwd="/", env=manager_env, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
            assert service.stdin is not None and service.stdout is not None
            environment = b'{"LANG":"C.UTF-8","PATH":"/usr/bin:/bin"}'
            service.stdin.write(struct.pack("!I", len(environment)) + environment)
            service.stdin.flush()
            namespaces = parse_provider_ready_attestation(
                service.stdout.read(PROVIDER_READY_SIZE), challenge=challenge,
                socket_dev=socket_info.st_dev, socket_ino=socket_info.st_ino,
            )
            shown = subprocess.run(
                [
                    "/usr/bin/systemctl", "--user", "show", unit,
                    "--property=MainPID", "--property=ControlGroup",
                    "--property=InvocationID", "--no-pager",
                ], env=manager_env, text=True, capture_output=True, check=True,
            )
            identity = dict(
                line.split("=", 1) for line in shown.stdout.splitlines() if "=" in line
            )

            rogue = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            rogue.settimeout(2)
            rogue.connect(str(socket_path))
            rogue.sendall(b"not-the-attested-bridge\n")
            broker.authorize_provider(
                main_pid=int(identity["MainPID"]), cgroup=identity["ControlGroup"],
                invocation_id=identity["InvocationID"], namespaces=namespaces,
                launcher_argv=launcher_argv, provider_argv=provider_argv,
            )

            initialize = {
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "broker-test", "version": "1"},
                },
            }
            payload = (json.dumps(initialize, separators=(",", ":")) + "\n").encode()
            service.stdin.write(struct.pack("!I", len(payload)) + payload)
            service.stdin.close()
            output = service.stdout.read().decode("utf-8", errors="replace")
            assert service.wait(timeout=30) == 0, output[-2000:]
            service = None
            assert '"id":1' in output and "serverInfo" in output
            assert broker.wait(timeout=30) == 0
            broker.close()
            broker = None
            assert not socket_path.exists()
            replay = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            with pytest.raises(OSError):
                replay.connect(str(socket_path))
            replay.close()
            try:
                assert rogue.recv(1) == b""
            except OSError:
                pass
        finally:
            if rogue is not None:
                rogue.close()
            if service is not None and service.poll() is None:
                service.terminate()
                service.wait(timeout=5)
            if broker is not None:
                if broker.poll() is None:
                    broker.terminate()
                    broker.wait(timeout=5)
                broker.close()
            subprocess.run(
                ["/usr/bin/systemctl", "--user", "stop", unit], env=manager_env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
