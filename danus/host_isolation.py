"""Small Linux isolation primitives used around provider/client processes.

Codex 0.148 uses bubblewrap for its own command permission profiles.  A Landlock
*filesystem* domain prevents that inner bubblewrap from changing mount
propagation and therefore cannot be the provider filesystem boundary.  The host
uses a systemd mount/PID namespace for files and procfs instead.  Landlock is
retained only for ABI-6 signal and abstract-AF_UNIX scoping; a scoped-only
ruleset composes with nested bubblewrap without handling filesystem operations.

This module intentionally has no Danus execution/Web imports so the same
primitive can secure both Worker and Web Main-Agent provider processes.
"""

from __future__ import annotations

import ctypes
import errno
import os
import platform
import stat
import socket
from pathlib import Path
from typing import Iterable

# Linux UAPI (include/uapi/linux/landlock.h).  The three Landlock syscalls use
# these numbers on the supported 64-bit Linux architectures.
_SYS_CREATE_RULESET = 444
_SYS_ADD_RULE = 445
_SYS_RESTRICT_SELF = 446
_CREATE_RULESET_VERSION = 1
_RULE_PATH_BENEATH = 1
_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_SECCOMP = 22
_PR_SET_DUMPABLE = 4
_PR_GET_DUMPABLE = 3
_SECCOMP_MODE_FILTER = 2

_BPF_LD = 0x00
_BPF_W = 0x00
_BPF_ABS = 0x20
_BPF_JMP = 0x05
_BPF_JEQ = 0x10
_BPF_JSET = 0x40
_BPF_K = 0x00
_BPF_RET = 0x06
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_SECCOMP_RET_ERRNO = 0x00050000
_SECCOMP_RET_ALLOW = 0x7FFF0000
_AUDIT_ARCH_X86_64 = 0xC000003E
_AUDIT_ARCH_AARCH64 = 0xC00000B7

_EXECUTE = 1 << 0
_WRITE_FILE = 1 << 1
_READ_FILE = 1 << 2
_READ_DIR = 1 << 3
_REMOVE_DIR = 1 << 4
_REMOVE_FILE = 1 << 5
_MAKE_CHAR = 1 << 6
_MAKE_DIR = 1 << 7
_MAKE_REG = 1 << 8
_MAKE_SOCK = 1 << 9
_MAKE_FIFO = 1 << 10
_MAKE_BLOCK = 1 << 11
_MAKE_SYM = 1 << 12
_REFER = 1 << 13
_TRUNCATE = 1 << 14
_IOCTL_DEV = 1 << 15

_READ = _EXECUTE | _READ_FILE | _READ_DIR


class _RulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
        ("scoped", ctypes.c_uint64),
    ]


class _PathBeneathAttr(ctypes.Structure):
    # The kernel reads the UAPI's first 12 bytes (u64 + s32).  ctypes may add
    # harmless trailing alignment padding; no structure size is passed to
    # landlock_add_rule(2).
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.POINTER(_SockFilter)),
    ]


class HostIsolationError(RuntimeError):
    pass


_LIBC = ctypes.CDLL(None, use_errno=True)
_LIBC.syscall.restype = ctypes.c_long
_LIBC.prctl.restype = ctypes.c_int


def protect_host_process_secrets() -> None:
    """Prevent same-uid untrusted processes from reading proc memory/environ."""

    if _LIBC.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        code = ctypes.get_errno()
        raise HostIsolationError(f"cannot protect host process credentials: {os.strerror(code)}")


def host_process_is_dumpable() -> bool:
    """Return the kernel dumpable bit for an attested trusted entry."""

    result = _LIBC.prctl(_PR_GET_DUMPABLE, 0, 0, 0, 0)
    if result < 0:
        code = ctypes.get_errno()
        raise HostIsolationError(f"cannot inspect process credential protection: {os.strerror(code)}")
    return result != 0


def allow_host_process_inspection() -> None:
    """Make a credential-free trusted bridge inspectable by its host broker."""

    if _LIBC.prctl(_PR_SET_DUMPABLE, 1, 0, 0, 0) != 0:
        code = ctypes.get_errno()
        raise HostIsolationError(f"cannot expose trusted bridge identity: {os.strerror(code)}")


def _syscall(number: int, *args) -> int:
    result = int(_LIBC.syscall(number, *args))
    if result < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return result


def abi_version() -> int:
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "aarch64"):
        raise HostIsolationError("Landlock Worker isolation requires 64-bit Linux")
    try:
        return _syscall(
            _SYS_CREATE_RULESET,
            ctypes.c_void_p(), ctypes.c_size_t(0), ctypes.c_uint32(_CREATE_RULESET_VERSION),
        )
    except OSError as exc:
        raise HostIsolationError(f"Landlock is unavailable: {exc}") from exc


def _handled_access(abi: int) -> int:
    access = (
        _EXECUTE | _WRITE_FILE | _READ_FILE | _READ_DIR | _REMOVE_DIR | _REMOVE_FILE
        | _MAKE_CHAR | _MAKE_DIR | _MAKE_REG | _MAKE_SOCK | _MAKE_FIFO | _MAKE_BLOCK
        | _MAKE_SYM
    )
    if abi >= 2:
        access |= _REFER
    if abi >= 3:
        access |= _TRUNCATE
    if abi >= 5:
        access |= _IOCTL_DEV
    return access


def _unique_existing(paths: Iterable[Path | str]) -> list[Path]:
    unique: dict[str, Path] = {}
    for raw in paths:
        path = Path(raw).resolve(strict=False)
        if not path.exists():
            raise HostIsolationError(f"required Landlock path is missing: {path}")
        unique[str(path)] = path
    return list(unique.values())


def restrict_current_process(
    *, read_only: Iterable[Path | str], read_write: Iterable[Path | str],
) -> None:
    """Irreversibly restrict this process and all descendants to the path set."""
    abi = abi_version()
    if abi < 6:
        raise HostIsolationError(
            "Landlock ABI 6+ is required for signal and abstract-socket scoping"
        )
    handled = _handled_access(abi)
    # A provider domain must not signal host/sibling processes or connect to an
    # abstract AF_UNIX control socket created outside this domain.  These scope
    # flags compose with the seccomp ban on creating pathname AF_UNIX sockets.
    ruleset_attr = _RulesetAttr(
        handled_access_fs=handled,
        handled_access_net=0,
        scoped=(1 << 0) | (1 << 1),
    )
    try:
        ruleset_fd = _syscall(
            _SYS_CREATE_RULESET,
            ctypes.byref(ruleset_attr), ctypes.sizeof(ruleset_attr), ctypes.c_uint32(0),
        )
    except OSError as exc:
        raise HostIsolationError(f"cannot create Landlock ruleset: {exc}") from exc

    try:
        entries = [(_READ, path) for path in _unique_existing(read_only)]
        entries.extend((handled, path) for path in _unique_existing(read_write))
        for allowed, path in entries:
            info = path.stat()
            if not stat.S_ISDIR(info.st_mode):
                # Directory-only access bits are invalid on a file rule.
                allowed &= _EXECUTE | _WRITE_FILE | _READ_FILE | _TRUNCATE | _IOCTL_DEV
            path_fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            try:
                attr = _PathBeneathAttr(
                    allowed_access=allowed & handled,
                    parent_fd=path_fd,
                )
                _syscall(
                    _SYS_ADD_RULE,
                    ruleset_fd, _RULE_PATH_BENEATH, ctypes.byref(attr), ctypes.c_uint32(0),
                )
            finally:
                os.close(path_fd)
        if _LIBC.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
        _syscall(_SYS_RESTRICT_SELF, ruleset_fd, ctypes.c_uint32(0))
    except OSError as exc:
        raise HostIsolationError(f"cannot enforce Landlock ruleset: {exc}") from exc
    finally:
        os.close(ruleset_fd)


def restrict_current_process_scope() -> None:
    """Scope signals and abstract Unix sockets without handling filesystem IO.

    The zero ``handled_access_fs`` value is security-critical.  Adding even a
    permissive filesystem rule here makes a descendant bubblewrap's
    ``mount(..., MS_SLAVE)`` fail with ``EPERM`` on the deployed kernel.
    Filesystem isolation belongs to the already-established systemd mount
    namespace, while these ABI-6 scope flags prevent reaching host/sibling
    processes through signal numbers or abstract socket names.
    """

    abi = abi_version()
    if abi < 6:
        raise HostIsolationError(
            "Landlock ABI 6+ is required for signal and abstract-socket scoping"
        )
    ruleset_attr = _RulesetAttr(
        handled_access_fs=0,
        handled_access_net=0,
        scoped=(1 << 0) | (1 << 1),
    )
    try:
        ruleset_fd = _syscall(
            _SYS_CREATE_RULESET,
            ctypes.byref(ruleset_attr), ctypes.sizeof(ruleset_attr), ctypes.c_uint32(0),
        )
    except OSError as exc:
        raise HostIsolationError(f"cannot create scoped Landlock ruleset: {exc}") from exc
    try:
        if _LIBC.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
        _syscall(_SYS_RESTRICT_SELF, ruleset_fd, ctypes.c_uint32(0))
    except OSError as exc:
        raise HostIsolationError(f"cannot enforce scoped Landlock ruleset: {exc}") from exc
    finally:
        os.close(ruleset_fd)


def restrict_unix_socket_creation(*, allow_pathname_unix: bool = False) -> None:
    """Restrict provider syscalls while retaining Codex/bubblewrap primitives.

    The Worker MCP bridge uses one host-created, already-connected AF_UNIX
    descriptor.  ``socket(AF_UNIX, ...)`` is normally denied, while local
    ``socketpair`` remains available to Codex and bubblewrap.  The transient
    service's trusted bridge mode may enable pathname AF_UNIX creation: its mount
    namespace exposes exactly one random broker socket, and scoped Landlock still
    blocks abstract sockets created outside the domain.  Native HTTP(S) and the exact
    NETLINK_ROUTE family used by bubblewrap's network namespace setup remain
    available.  ``clone3`` is intentionally *not* filtered: cgroupfs is absent
    from the provider mount namespace, so there is no cgroup fd with which to
    exercise ``CLONE_INTO_CGROUP`` and bubblewrap may use clone3 normally.
    """

    machine = platform.machine()
    if machine == "x86_64":
        audit_arch = _AUDIT_ARCH_X86_64
        numbers = {
            "socket": 41, "socketpair": 53, "ptrace": 101,
            "process_vm_readv": 310, "process_vm_writev": 311,
            "pidfd_getfd": 438, "kcmp": 312,
            "io_uring_setup": 425,
            "io_uring_enter": 426, "io_uring_register": 427,
        }
    elif machine == "aarch64":
        audit_arch = _AUDIT_ARCH_AARCH64
        numbers = {
            "socket": 198, "socketpair": 199, "ptrace": 117,
            "process_vm_readv": 270, "process_vm_writev": 271,
            "pidfd_getfd": 438, "kcmp": 272,
            "io_uring_setup": 425,
            "io_uring_enter": 426, "io_uring_register": 427,
        }
    else:
        raise HostIsolationError("AF_UNIX isolation requires a supported 64-bit Linux architecture")

    stmt = lambda code, k: _SockFilter(code=code, jt=0, jf=0, k=k)
    jump = lambda k, jt, jf: _SockFilter(
        code=_BPF_JMP | _BPF_JEQ | _BPF_K, jt=jt, jf=jf, k=k,
    )
    jump_set = lambda k, jt, jf: _SockFilter(
        code=_BPF_JMP | _BPF_JSET | _BPF_K, jt=jt, jf=jf, k=k,
    )
    ret_errno = _SockFilter(
        code=_BPF_RET | _BPF_K, jt=0, jf=0,
        k=_SECCOMP_RET_ERRNO | errno.EACCES,
    )
    ret_enosys = _SockFilter(
        code=_BPF_RET | _BPF_K, jt=0, jf=0,
        k=_SECCOMP_RET_ERRNO | errno.ENOSYS,
    )
    filters: list[_SockFilter] = [
        # struct seccomp_data: nr@0, arch@4, args[0]@16.
        stmt(_BPF_LD | _BPF_W | _BPF_ABS, 4),
        jump(audit_arch, 1, 0),
        stmt(_BPF_RET | _BPF_K, _SECCOMP_RET_KILL_PROCESS),
        stmt(_BPF_LD | _BPF_W | _BPF_ABS, 0),
    ]
    if machine == "x86_64":
        # x32 shares the x86_64 audit arch but ORs this bit into syscall nr.
        filters.extend([jump_set(0x40000000, 0, 1), ret_enosys])
    for name in ("ptrace", "process_vm_readv", "process_vm_writev", "pidfd_getfd", "kcmp"):
        filters.extend([jump(numbers[name], 0, 1), ret_errno])
    # io_uring can issue socket/connect operations without traversing their
    # ordinary syscall gates, so all three entrypoints are disabled.
    for name in ("io_uring_setup", "io_uring_enter", "io_uring_register"):
        filters.extend([jump(numbers[name], 0, 1), ret_enosys])
    # A fresh socket is allowed only for native HTTPS/DNS and NETLINK_ROUTE,
    # which bundled bubblewrap uses to configure its private loopback device.
    # In particular AF_UNIX, AF_PACKET, and control-plane families fail closed.
    socket_filter = [
        stmt(_BPF_LD | _BPF_W | _BPF_ABS, 16),
    ]
    if allow_pathname_unix:
        # Jump target is patched after the complete socket branch is assembled.
        socket_filter.append(jump(socket.AF_UNIX, 0, 0))
    socket_filter.extend([
        jump(socket.AF_INET, 0, 0),
        jump(socket.AF_INET6, 0, 0),
        jump(socket.AF_NETLINK, 1, 0),
        ret_errno,
        # struct seccomp_data args[2] (socket protocol) starts at byte 32.
        stmt(_BPF_LD | _BPF_W | _BPF_ABS, 32),
        jump(0, 1, 0),  # NETLINK_ROUTE
        ret_errno,
    ])
    final_allow_index = len(filters) + 1 + len(socket_filter)
    socket_jump_index = len(filters)
    filters.append(jump(numbers["socket"], 0, final_allow_index - socket_jump_index - 1))
    branch_start = len(filters)
    for index, instruction in enumerate(socket_filter):
        # AF_UNIX/INET/INET6 success jumps all target the final ALLOW.
        if instruction.code == (_BPF_JMP | _BPF_JEQ | _BPF_K) and instruction.k in {
            socket.AF_UNIX, socket.AF_INET, socket.AF_INET6,
        }:
            instruction.jt = final_allow_index - (branch_start + index) - 1
        filters.append(instruction)
    filters.append(stmt(_BPF_RET | _BPF_K, _SECCOMP_RET_ALLOW))
    array_type = _SockFilter * len(filters)
    array = array_type(*filters)
    program = _SockFprog(len=len(filters), filter=array)
    if _LIBC.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        code = ctypes.get_errno()
        raise HostIsolationError(f"cannot enable no-new-privileges: {os.strerror(code)}")
    if _LIBC.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.byref(program)) != 0:
        code = ctypes.get_errno()
        raise HostIsolationError(f"cannot enforce AF_UNIX isolation: {os.strerror(code)}")


__all__ = [
    "HostIsolationError", "abi_version", "restrict_current_process",
    "restrict_current_process_scope", "restrict_unix_socket_creation",
    "protect_host_process_secrets",
    "host_process_is_dumpable",
    "allow_host_process_inspection",
]
