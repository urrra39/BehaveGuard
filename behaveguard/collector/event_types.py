"""Python-side event model mirroring the C structs emitted by BehaveGuard eBPF programs.

This module is the single source of truth for the wire format shared between the
kernel-side eBPF programs (which write fixed-layout C structs into a ``BPF_MAP_TYPE_RINGBUF``)
and the userspace collector (which reads raw bytes back out and reconstructs typed events).

Two parallel representations are defined for every event family:

* ``*Raw`` ``ctypes.Structure`` subclasses describe the *exact* binary layout produced
  by the kernel. Their ``_fields_`` ordering, member types, and natural (default)
  alignment must match the corresponding C structs byte-for-byte. ``_pack_`` is
  intentionally left unset so that ``ctypes`` applies the platform's natural
  alignment rules, identical to how the C compiler lays out the kernel structs.
* ``@dataclass`` event classes (:class:`SyscallEvent`, :class:`NetworkEvent`,
  :class:`FileEvent`, :class:`ProcessEvent`) are the ergonomic, fully-decoded
  Python objects consumed by the rest of the pipeline (feature extraction,
  scoring, alerting). Each provides a ``from_raw`` classmethod that performs the
  decode from its ``*Raw`` counterpart.

Design constraints honoured here:

* Imports cleanly on CPython 3.9.13 while remaining correct for 3.10+. The
  ``from __future__ import annotations`` import makes every annotation a lazy
  string, so PEP 604 ``X | Y`` syntax never executes at runtime. The one place a
  union value is *evaluated* (the :data:`RawEvent` alias) uses
  :data:`typing.Union` explicitly.
* Standard library only: ``ctypes``, ``socket``, ``struct``, ``dataclasses``,
  ``enum``, ``typing``. No third-party dependencies.

The syscall table is the authoritative Linux **x86_64** ABI mapping (numbers
0..334, the classic table that predates the later io_uring/landlock additions),
exposed via :data:`SYSCALL_NAMES` and the :func:`syscall_name` lookup helper.
"""

from __future__ import annotations

import ctypes
import socket
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, List, Union

__all__ = [
    "TASK_COMM_LEN",
    "PATH_MAX_LEN",
    "EXE_PATH_LEN",
    "CMDLINE_LEN",
    "EventType",
    "FileOperation",
    "ProcessAction",
    "InjectionMethod",
    "ContainerAction",
    "AntiforensicAction",
    "SyscallEventRaw",
    "NetworkEventRaw",
    "FileEventRaw",
    "ProcessEventRaw",
    "InjectionEventRaw",
    "ContainerEscapeEventRaw",
    "LolbinEventRaw",
    "AntiforensicEventRaw",
    "DnsTunnelEventRaw",
    "SyscallEvent",
    "NetworkEvent",
    "FileEvent",
    "ProcessEvent",
    "InjectionEvent",
    "ContainerEscapeEvent",
    "LolbinEvent",
    "AntiforensicEvent",
    "DnsTunnelEvent",
    "RawEvent",
    "SYSCALL_NAMES",
    "syscall_name",
    "SENSITIVE_SYSCALLS",
    "SENSITIVE_PATHS",
]

# ---------------------------------------------------------------------------
# Layout constants (must match the ``#define`` values in the eBPF C sources).
# ---------------------------------------------------------------------------

#: Length of the ``comm`` (task command name) field, matching the kernel's
#: ``TASK_COMM_LEN``. The stored value is NUL-padded/truncated to this width.
TASK_COMM_LEN = 16

#: Maximum captured file path length for :class:`FileEventRaw`.
PATH_MAX_LEN = 256

#: Maximum captured executable path length for :class:`ProcessEventRaw`.
EXE_PATH_LEN = 256

#: Maximum captured command line length for :class:`ProcessEventRaw`.
CMDLINE_LEN = 256


# ---------------------------------------------------------------------------
# Enumerations.
# ---------------------------------------------------------------------------


class EventType(IntEnum):
    """Discriminator identifying which event family a decoded record belongs to.

    The numeric values are part of the contract with downstream consumers and
    must remain stable.
    """

    SYSCALL = 1
    NETWORK = 2
    FILE = 3
    PROCESS = 4
    # Advanced defense layers.
    INJECTION = 5
    CONTAINER_ESCAPE = 6
    LOLBIN = 7
    ANTIFORENSIC = 8
    DNS_TUNNEL = 9


class FileOperation(IntEnum):
    """File operation codes carried in :class:`FileEventRaw.operation`."""

    OPEN = 0
    READ = 1
    WRITE = 2
    UNLINK = 3


class ProcessAction(IntEnum):
    """Process lifecycle action codes carried in :class:`ProcessEventRaw.action`."""

    EXEC = 0
    FORK = 1
    EXIT = 2


class InjectionMethod(IntEnum):
    """Process-injection techniques carried in :class:`InjectionEventRaw.method`."""

    PTRACE = 0  # ptrace(PTRACE_ATTACH/POKETEXT...) via security_ptrace
    PROC_MEM = 1  # write to /proc/<pid>/mem
    PROCESS_VM_WRITEV = 2  # process_vm_writev() cross-process memory write


class ContainerAction(IntEnum):
    """Namespace/escape actions carried in :class:`ContainerEscapeEventRaw.action`."""

    SETNS = 0
    UNSHARE = 1
    PIVOT_ROOT = 2


class AntiforensicAction(IntEnum):
    """Anti-forensic actions carried in :class:`AntiforensicEventRaw.action`."""

    UNLINK = 0  # deletion of a log file
    TIMESTOMP = 1  # timestamp tampering (utimensat/utimes)
    TRUNCATE = 2  # truncation/clearing of a log file


# ---------------------------------------------------------------------------
# Raw ctypes structures (binary wire format from the eBPF ring buffer).
#
# IMPORTANT: ``_pack_`` is deliberately NOT set on any of these. The kernel C
# structs use natural alignment; matching that here means letting ctypes apply
# its default alignment as well. Field order and member types below mirror the
# C declarations exactly.
# ---------------------------------------------------------------------------


class SyscallEventRaw(ctypes.Structure):
    """Binary layout for a syscall entry/exit event.

    Fields:
        timestamp_ns: Monotonic kernel timestamp in nanoseconds.
        pid: Thread ID (kernel ``pid``).
        tgid: Thread group ID (POSIX process ID).
        uid: Real user ID of the calling task.
        comm: NUL-padded task command name (``TASK_COMM_LEN`` bytes).
        syscall_nr: x86_64 syscall number.
        ret: Raw syscall return value (unsigned; reinterpret as signed for use).
        args: First three syscall arguments.
    """

    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("tgid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
        ("syscall_nr", ctypes.c_uint64),
        ("ret", ctypes.c_uint64),
        ("args", ctypes.c_uint64 * 3),
    ]


class NetworkEventRaw(ctypes.Structure):
    """Binary layout for a network connection/transfer event.

    ``saddr``/``daddr`` are ``__be32`` values (network byte order) stored as
    host integers. ``sport``/``dport`` have already been converted to host byte
    order by the eBPF program. ``protocol`` follows the IP protocol numbers
    (6=TCP, 17=UDP); ``direction`` is 0 for outbound and 1 for inbound.

    Fields:
        timestamp_ns: Monotonic kernel timestamp in nanoseconds.
        pid: Process ID associated with the socket.
        uid: Real user ID of the owning task.
        comm: NUL-padded task command name (``TASK_COMM_LEN`` bytes).
        saddr: Source IPv4 address, network byte order (``__be32``).
        daddr: Destination IPv4 address, network byte order (``__be32``).
        sport: Source port in host byte order.
        dport: Destination port in host byte order.
        protocol: IP protocol number (6=TCP, 17=UDP).
        direction: 0=outbound, 1=inbound.
        bytes_count: Number of bytes transferred for this event.
    """

    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
        ("saddr", ctypes.c_uint32),
        ("daddr", ctypes.c_uint32),
        ("sport", ctypes.c_uint16),
        ("dport", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("direction", ctypes.c_uint8),
        ("bytes_count", ctypes.c_uint32),
    ]


class FileEventRaw(ctypes.Structure):
    """Binary layout for a file operation event.

    ``operation`` follows :class:`FileOperation` (0=open, 1=read, 2=write,
    3=unlink).

    Fields:
        timestamp_ns: Monotonic kernel timestamp in nanoseconds.
        ret: Signed syscall return value (e.g. fd, byte count, or ``-errno``).
        pid: Process ID performing the operation.
        uid: Real user ID of the owning task.
        flags: Open/operation flags as passed to the syscall.
        bytes_count: Bytes read/written where applicable.
        operation: Operation code (see :class:`FileOperation`).
        comm: NUL-padded task command name (``TASK_COMM_LEN`` bytes).
        path: NUL-padded file path (``PATH_MAX_LEN`` bytes).
    """

    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("ret", ctypes.c_int64),
        ("pid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("bytes_count", ctypes.c_uint32),
        ("operation", ctypes.c_uint32),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
        ("path", ctypes.c_char * PATH_MAX_LEN),
    ]


class ProcessEventRaw(ctypes.Structure):
    """Binary layout for a process lifecycle event.

    ``action`` follows :class:`ProcessAction` (0=exec, 1=fork, 2=exit).

    Fields:
        timestamp_ns: Monotonic kernel timestamp in nanoseconds.
        pid: Process ID of the subject task.
        ppid: Parent process ID.
        uid: Real user ID of the subject task.
        exit_code: Exit code (meaningful for exit actions; signed).
        action: Lifecycle action code (see :class:`ProcessAction`).
        comm: NUL-padded task command name (``TASK_COMM_LEN`` bytes).
        exe_path: NUL-padded executable path (``EXE_PATH_LEN`` bytes).
        cmdline: NUL-padded command line (``CMDLINE_LEN`` bytes).
    """

    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("exit_code", ctypes.c_int32),
        ("action", ctypes.c_uint32),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
        ("exe_path", ctypes.c_char * EXE_PATH_LEN),
        ("cmdline", ctypes.c_char * CMDLINE_LEN),
    ]


# --- Advanced defense-layer raw structures (must match the new .c programs) ---


class InjectionEventRaw(ctypes.Structure):
    """Binary layout for a process-injection event (40 bytes).

    Emitted by ``injection_monitor.c``. ``method`` follows :class:`InjectionMethod`.
    ``target_pid`` is the victim (0 when the hook cannot resolve it, e.g. a
    ``/proc/<pid>/mem`` write).
    """

    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("target_pid", ctypes.c_uint32),
        ("method", ctypes.c_uint32),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
    ]


class ContainerEscapeEventRaw(ctypes.Structure):
    """Binary layout for a container/namespace-escape event (40 bytes).

    Emitted by ``container_escape_monitor.c``. ``action`` follows
    :class:`ContainerAction`; ``flags`` carries the syscall flags (setns nstype /
    unshare flags; 0 for pivot_root).
    """

    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("action", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
    ]


class LolbinEventRaw(ctypes.Structure):
    """Binary layout for a Living-Off-The-Land-Binary execution event (40 bytes).

    Emitted by ``lolbin_monitor.c`` only when the exec'd ``comm`` matches the
    watchlist.
    """

    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("ppid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
    ]


class AntiforensicEventRaw(ctypes.Structure):
    """Binary layout for an anti-forensic event (296 bytes).

    Emitted by ``antiforensic_monitor.c`` for deletions/timestomps/truncations
    under ``/var/log``. ``action`` follows :class:`AntiforensicAction`.
    """

    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("action", ctypes.c_uint32),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
        ("path", ctypes.c_char * PATH_MAX_LEN),
    ]


class DnsTunnelEventRaw(ctypes.Structure):
    """Binary layout for a DNS-tunnel event (48 bytes).

    Emitted by ``dns_tunnel_monitor.c`` for oversized (> 100 byte) UDP/53 queries.
    ``daddr`` is a raw ``__be32``; ``dport`` is host order (always 53 here);
    ``payload_size`` is the sendmsg length.
    """

    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("daddr", ctypes.c_uint32),
        ("payload_size", ctypes.c_uint32),
        ("dport", ctypes.c_uint32),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
    ]


# ---------------------------------------------------------------------------
# Decoding helpers.
# ---------------------------------------------------------------------------


def _decode_cstr(raw_bytes: Any) -> str:
    """Decode a NUL-terminated C string field into a clean Python ``str``.

    Accepts either a ``bytes`` object or a ``ctypes`` character array (anything
    convertible to ``bytes``). The value is truncated at the first NUL byte,
    decoded as UTF-8 with ``errors="replace"`` so malformed bytes never raise,
    and surrounding whitespace is stripped.

    Args:
        raw_bytes: A ``bytes`` value or ctypes ``c_char`` array.

    Returns:
        The decoded, NUL-trimmed, whitespace-stripped string.
    """
    if isinstance(raw_bytes, (bytes, bytearray)):
        data = bytes(raw_bytes)
    else:
        # ctypes char arrays and similar buffer-like objects.
        data = bytes(raw_bytes)
    nul = data.find(b"\x00")
    if nul != -1:
        data = data[:nul]
    return data.decode("utf-8", errors="replace").strip()


def _to_signed64(value: int) -> int:
    """Reinterpret an unsigned 64-bit integer as signed two's complement.

    eBPF return values are commonly stored as ``c_uint64`` even though the
    semantic value (e.g. ``-errno``) is signed. This converts the unsigned bit
    pattern into the equivalent signed Python integer.

    Args:
        value: An integer holding an unsigned 64-bit bit pattern.

    Returns:
        The signed interpretation in the range [-2**63, 2**63 - 1].
    """
    value &= 0xFFFFFFFFFFFFFFFF
    if value >= 0x8000000000000000:
        value -= 0x10000000000000000
    return value


def _ipv4_to_str(addr: int) -> str:
    """Convert a network-order ``__be32`` (stored as a host int) to dotted-decimal.

    The address is already in network byte order; packing it little-endian with
    ``struct.pack("<I", ...)`` reproduces the original on-wire byte sequence that
    :func:`socket.inet_ntoa` expects.

    Args:
        addr: The ``__be32`` address value held in a host integer.

    Returns:
        The dotted-decimal IPv4 string, e.g. ``"192.168.1.1"``.
    """
    return socket.inet_ntoa(struct.pack("<I", addr & 0xFFFFFFFF))


def _protocol_to_str(protocol: int) -> str:
    """Map an IP protocol number to a short name.

    Args:
        protocol: IP protocol number.

    Returns:
        ``"TCP"`` for 6, ``"UDP"`` for 17, otherwise the decimal string.
    """
    if protocol == 6:
        return "TCP"
    if protocol == 17:
        return "UDP"
    return str(protocol)


def _direction_to_str(direction: int) -> str:
    """Map a direction code to a human-readable label.

    Args:
        direction: 0 for outbound, 1 for inbound.

    Returns:
        ``"outbound"`` for 0, ``"inbound"`` for 1, otherwise the decimal string.
    """
    if direction == 0:
        return "outbound"
    if direction == 1:
        return "inbound"
    return str(direction)


def _file_operation_to_str(operation: int) -> str:
    """Map a :class:`FileOperation` code to its lowercase name.

    Args:
        operation: Operation code (0=open, 1=read, 2=write, 3=unlink).

    Returns:
        The lowercase operation name, or ``"operation_<n>"`` if unrecognised.
    """
    try:
        return FileOperation(operation).name.lower()
    except ValueError:
        return "operation_{0}".format(operation)


def _process_action_to_str(action: int) -> str:
    """Map a :class:`ProcessAction` code to its lowercase name.

    Args:
        action: Action code (0=exec, 1=fork, 2=exit).

    Returns:
        The lowercase action name, or ``"action_<n>"`` if unrecognised.
    """
    try:
        return ProcessAction(action).name.lower()
    except ValueError:
        return "action_{0}".format(action)


def _injection_method_to_str(method: int) -> str:
    """Map an :class:`InjectionMethod` code to its lowercase name."""
    try:
        return InjectionMethod(method).name.lower()
    except ValueError:
        return "method_{0}".format(method)


def _container_action_to_str(action: int) -> str:
    """Map a :class:`ContainerAction` code to its lowercase name."""
    try:
        return ContainerAction(action).name.lower()
    except ValueError:
        return "action_{0}".format(action)


def _antiforensic_action_to_str(action: int) -> str:
    """Map an :class:`AntiforensicAction` code to its lowercase name."""
    try:
        return AntiforensicAction(action).name.lower()
    except ValueError:
        return "action_{0}".format(action)


# ---------------------------------------------------------------------------
# Decoded dataclasses.
# ---------------------------------------------------------------------------


@dataclass
class SyscallEvent:
    """A fully decoded syscall event.

    Attributes:
        timestamp_ns: Monotonic kernel timestamp in nanoseconds.
        pid: Thread ID.
        tgid: Thread group ID (POSIX process ID).
        uid: Real user ID.
        comm: Task command name.
        syscall_nr: x86_64 syscall number.
        syscall_name: Resolved syscall name for ``syscall_nr``.
        ret: Signed syscall return value.
        args: First three syscall arguments.
        event_type: Always :attr:`EventType.SYSCALL`.
    """

    timestamp_ns: int
    pid: int
    tgid: int
    uid: int
    comm: str
    syscall_nr: int
    syscall_name: str
    ret: int
    args: List[int]
    event_type: EventType = EventType.SYSCALL

    @classmethod
    def from_raw(cls, raw: SyscallEventRaw) -> "SyscallEvent":
        """Build a :class:`SyscallEvent` from its raw ctypes representation.

        Args:
            raw: A populated :class:`SyscallEventRaw` instance.

        Returns:
            The decoded :class:`SyscallEvent`.
        """
        return cls(
            timestamp_ns=int(raw.timestamp_ns),
            pid=int(raw.pid),
            tgid=int(raw.tgid),
            uid=int(raw.uid),
            comm=_decode_cstr(raw.comm),
            syscall_nr=int(raw.syscall_nr),
            syscall_name=syscall_name(int(raw.syscall_nr)),
            ret=_to_signed64(int(raw.ret)),
            args=[int(a) for a in raw.args],
        )


@dataclass
class NetworkEvent:
    """A fully decoded network event.

    Attributes:
        timestamp_ns: Monotonic kernel timestamp in nanoseconds.
        pid: Process ID associated with the socket.
        comm: Task command name.
        src_ip: Source IPv4 address in dotted-decimal form.
        dst_ip: Destination IPv4 address in dotted-decimal form.
        src_port: Source port (host byte order).
        dst_port: Destination port (host byte order).
        protocol: Protocol label (``"TCP"``/``"UDP"``/numeric string).
        bytes_count: Bytes transferred for this event.
        direction: ``"outbound"`` or ``"inbound"``.
        event_type: Always :attr:`EventType.NETWORK`.
    """

    timestamp_ns: int
    pid: int
    comm: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_count: int
    direction: str
    event_type: EventType = EventType.NETWORK

    @classmethod
    def from_raw(cls, raw: NetworkEventRaw) -> "NetworkEvent":
        """Build a :class:`NetworkEvent` from its raw ctypes representation.

        Args:
            raw: A populated :class:`NetworkEventRaw` instance.

        Returns:
            The decoded :class:`NetworkEvent`.
        """
        return cls(
            timestamp_ns=int(raw.timestamp_ns),
            pid=int(raw.pid),
            comm=_decode_cstr(raw.comm),
            src_ip=_ipv4_to_str(int(raw.saddr)),
            dst_ip=_ipv4_to_str(int(raw.daddr)),
            src_port=int(raw.sport),
            dst_port=int(raw.dport),
            protocol=_protocol_to_str(int(raw.protocol)),
            bytes_count=int(raw.bytes_count),
            direction=_direction_to_str(int(raw.direction)),
        )


@dataclass
class FileEvent:
    """A fully decoded file operation event.

    Attributes:
        timestamp_ns: Monotonic kernel timestamp in nanoseconds.
        pid: Process ID performing the operation.
        comm: Task command name.
        path: File path the operation targeted.
        operation: Operation label (``"open"``/``"read"``/``"write"``/``"unlink"``).
        flags: Open/operation flags.
        ret: Signed syscall return value.
        bytes_count: Bytes read/written where applicable.
        event_type: Always :attr:`EventType.FILE`.
    """

    timestamp_ns: int
    pid: int
    comm: str
    path: str
    operation: str
    flags: int
    ret: int
    bytes_count: int
    event_type: EventType = EventType.FILE

    @classmethod
    def from_raw(cls, raw: FileEventRaw) -> "FileEvent":
        """Build a :class:`FileEvent` from its raw ctypes representation.

        Args:
            raw: A populated :class:`FileEventRaw` instance.

        Returns:
            The decoded :class:`FileEvent`.
        """
        return cls(
            timestamp_ns=int(raw.timestamp_ns),
            pid=int(raw.pid),
            comm=_decode_cstr(raw.comm),
            path=_decode_cstr(raw.path),
            operation=_file_operation_to_str(int(raw.operation)),
            flags=int(raw.flags),
            ret=int(raw.ret),
            bytes_count=int(raw.bytes_count),
        )


@dataclass
class ProcessEvent:
    """A fully decoded process lifecycle event.

    Attributes:
        timestamp_ns: Monotonic kernel timestamp in nanoseconds.
        pid: Process ID of the subject task.
        ppid: Parent process ID.
        comm: Task command name.
        exe_path: Executable path.
        cmdline: Command line string.
        action: Action label (``"exec"``/``"fork"``/``"exit"``).
        exit_code: Exit code (meaningful for exit actions).
        event_type: Always :attr:`EventType.PROCESS`.
    """

    timestamp_ns: int
    pid: int
    ppid: int
    comm: str
    exe_path: str
    cmdline: str
    action: str
    exit_code: int
    event_type: EventType = EventType.PROCESS

    @classmethod
    def from_raw(cls, raw: ProcessEventRaw) -> "ProcessEvent":
        """Build a :class:`ProcessEvent` from its raw ctypes representation.

        Args:
            raw: A populated :class:`ProcessEventRaw` instance.

        Returns:
            The decoded :class:`ProcessEvent`.
        """
        return cls(
            timestamp_ns=int(raw.timestamp_ns),
            pid=int(raw.pid),
            ppid=int(raw.ppid),
            comm=_decode_cstr(raw.comm),
            exe_path=_decode_cstr(raw.exe_path),
            cmdline=_decode_cstr(raw.cmdline),
            action=_process_action_to_str(int(raw.action)),
            exit_code=int(raw.exit_code),
        )


@dataclass
class InjectionEvent:
    """A decoded process-injection event (one process writing another's memory)."""

    timestamp_ns: int
    pid: int
    uid: int
    comm: str
    target_pid: int
    method: str
    event_type: EventType = EventType.INJECTION

    @classmethod
    def from_raw(cls, raw: InjectionEventRaw) -> "InjectionEvent":
        return cls(
            timestamp_ns=int(raw.timestamp_ns),
            pid=int(raw.pid),
            uid=int(raw.uid),
            comm=_decode_cstr(raw.comm),
            target_pid=int(raw.target_pid),
            method=_injection_method_to_str(int(raw.method)),
        )


@dataclass
class ContainerEscapeEvent:
    """A decoded container/namespace-escape attempt (setns/unshare/pivot_root)."""

    timestamp_ns: int
    pid: int
    uid: int
    comm: str
    action: str
    flags: int
    event_type: EventType = EventType.CONTAINER_ESCAPE

    @classmethod
    def from_raw(cls, raw: ContainerEscapeEventRaw) -> "ContainerEscapeEvent":
        return cls(
            timestamp_ns=int(raw.timestamp_ns),
            pid=int(raw.pid),
            uid=int(raw.uid),
            comm=_decode_cstr(raw.comm),
            action=_container_action_to_str(int(raw.action)),
            flags=int(raw.flags),
        )


@dataclass
class LolbinEvent:
    """A decoded Living-Off-The-Land-Binary execution (watchlist match)."""

    timestamp_ns: int
    pid: int
    ppid: int
    uid: int
    comm: str
    event_type: EventType = EventType.LOLBIN

    @classmethod
    def from_raw(cls, raw: LolbinEventRaw) -> "LolbinEvent":
        return cls(
            timestamp_ns=int(raw.timestamp_ns),
            pid=int(raw.pid),
            ppid=int(raw.ppid),
            uid=int(raw.uid),
            comm=_decode_cstr(raw.comm),
        )


@dataclass
class AntiforensicEvent:
    """A decoded anti-forensic action against ``/var/log`` (delete/timestomp/truncate)."""

    timestamp_ns: int
    pid: int
    uid: int
    comm: str
    action: str
    path: str
    event_type: EventType = EventType.ANTIFORENSIC

    @classmethod
    def from_raw(cls, raw: AntiforensicEventRaw) -> "AntiforensicEvent":
        return cls(
            timestamp_ns=int(raw.timestamp_ns),
            pid=int(raw.pid),
            uid=int(raw.uid),
            comm=_decode_cstr(raw.comm),
            action=_antiforensic_action_to_str(int(raw.action)),
            path=_decode_cstr(raw.path),
        )


@dataclass
class DnsTunnelEvent:
    """A decoded suspected DNS-tunnel query (oversized UDP/53 payload)."""

    timestamp_ns: int
    pid: int
    uid: int
    comm: str
    dst_ip: str
    dst_port: int
    payload_size: int
    event_type: EventType = EventType.DNS_TUNNEL

    @classmethod
    def from_raw(cls, raw: DnsTunnelEventRaw) -> "DnsTunnelEvent":
        return cls(
            timestamp_ns=int(raw.timestamp_ns),
            pid=int(raw.pid),
            uid=int(raw.uid),
            comm=_decode_cstr(raw.comm),
            dst_ip=_ipv4_to_str(int(raw.daddr)),
            dst_port=int(raw.dport),
            payload_size=int(raw.payload_size),
        )


# ---------------------------------------------------------------------------
# Linux x86_64 syscall table (numbers 0..334).
#
# This is the authoritative classic x86_64 ABI mapping as defined in the kernel
# source ``arch/x86/entry/syscalls/syscall_64.tbl`` for the 64-bit ABI. Every
# number in the contiguous 0..334 range is listed with its real name.
# ---------------------------------------------------------------------------

SYSCALL_NAMES = {
    0: "read",
    1: "write",
    2: "open",
    3: "close",
    4: "stat",
    5: "fstat",
    6: "lstat",
    7: "poll",
    8: "lseek",
    9: "mmap",
    10: "mprotect",
    11: "munmap",
    12: "brk",
    13: "rt_sigaction",
    14: "rt_sigprocmask",
    15: "rt_sigreturn",
    16: "ioctl",
    17: "pread64",
    18: "pwrite64",
    19: "readv",
    20: "writev",
    21: "access",
    22: "pipe",
    23: "select",
    24: "sched_yield",
    25: "mremap",
    26: "msync",
    27: "mincore",
    28: "madvise",
    29: "shmget",
    30: "shmat",
    31: "shmctl",
    32: "dup",
    33: "dup2",
    34: "pause",
    35: "nanosleep",
    36: "getitimer",
    37: "alarm",
    38: "setitimer",
    39: "getpid",
    40: "sendfile",
    41: "socket",
    42: "connect",
    43: "accept",
    44: "sendto",
    45: "recvfrom",
    46: "sendmsg",
    47: "recvmsg",
    48: "shutdown",
    49: "bind",
    50: "listen",
    51: "getsockname",
    52: "getpeername",
    53: "socketpair",
    54: "setsockopt",
    55: "getsockopt",
    56: "clone",
    57: "fork",
    58: "vfork",
    59: "execve",
    60: "exit",
    61: "wait4",
    62: "kill",
    63: "uname",
    64: "semget",
    65: "semop",
    66: "semctl",
    67: "shmdt",
    68: "msgget",
    69: "msgsnd",
    70: "msgrcv",
    71: "msgctl",
    72: "fcntl",
    73: "flock",
    74: "fsync",
    75: "fdatasync",
    76: "truncate",
    77: "ftruncate",
    78: "getdents",
    79: "getcwd",
    80: "chdir",
    81: "fchdir",
    82: "rename",
    83: "mkdir",
    84: "rmdir",
    85: "creat",
    86: "link",
    87: "unlink",
    88: "symlink",
    89: "readlink",
    90: "chmod",
    91: "fchmod",
    92: "chown",
    93: "fchown",
    94: "lchown",
    95: "umask",
    96: "gettimeofday",
    97: "getrlimit",
    98: "getrusage",
    99: "sysinfo",
    100: "times",
    101: "ptrace",
    102: "getuid",
    103: "syslog",
    104: "getgid",
    105: "setuid",
    106: "setgid",
    107: "geteuid",
    108: "getegid",
    109: "setpgid",
    110: "getppid",
    111: "getpgrp",
    112: "setsid",
    113: "setreuid",
    114: "setregid",
    115: "getgroups",
    116: "setgroups",
    117: "setresuid",
    118: "getresuid",
    119: "setresgid",
    120: "getresgid",
    121: "getpgid",
    122: "setfsuid",
    123: "setfsgid",
    124: "getsid",
    125: "capget",
    126: "capset",
    127: "rt_sigpending",
    128: "rt_sigtimedwait",
    129: "rt_sigqueueinfo",
    130: "rt_sigsuspend",
    131: "sigaltstack",
    132: "utime",
    133: "mknod",
    134: "uselib",
    135: "personality",
    136: "ustat",
    137: "statfs",
    138: "fstatfs",
    139: "sysfs",
    140: "getpriority",
    141: "setpriority",
    142: "sched_setparam",
    143: "sched_getparam",
    144: "sched_setscheduler",
    145: "sched_getscheduler",
    146: "sched_get_priority_max",
    147: "sched_get_priority_min",
    148: "sched_rr_get_interval",
    149: "mlock",
    150: "munlock",
    151: "mlockall",
    152: "munlockall",
    153: "vhangup",
    154: "modify_ldt",
    155: "pivot_root",
    156: "_sysctl",
    157: "prctl",
    158: "arch_prctl",
    159: "adjtimex",
    160: "setrlimit",
    161: "chroot",
    162: "sync",
    163: "acct",
    164: "settimeofday",
    165: "mount",
    166: "umount2",
    167: "swapon",
    168: "swapoff",
    169: "reboot",
    170: "sethostname",
    171: "setdomainname",
    172: "iopl",
    173: "ioperm",
    174: "create_module",
    175: "init_module",
    176: "delete_module",
    177: "get_kernel_syms",
    178: "query_module",
    179: "quotactl",
    180: "nfsservctl",
    181: "getpmsg",
    182: "putpmsg",
    183: "afs_syscall",
    184: "tuxcall",
    185: "security",
    186: "gettid",
    187: "readahead",
    188: "setxattr",
    189: "lsetxattr",
    190: "fsetxattr",
    191: "getxattr",
    192: "lgetxattr",
    193: "fgetxattr",
    194: "listxattr",
    195: "llistxattr",
    196: "flistxattr",
    197: "removexattr",
    198: "lremovexattr",
    199: "fremovexattr",
    200: "tkill",
    201: "time",
    202: "futex",
    203: "sched_setaffinity",
    204: "sched_getaffinity",
    205: "set_thread_area",
    206: "io_setup",
    207: "io_destroy",
    208: "io_getevents",
    209: "io_submit",
    210: "io_cancel",
    211: "get_thread_area",
    212: "lookup_dcookie",
    213: "epoll_create",
    214: "epoll_ctl_old",
    215: "epoll_wait_old",
    216: "remap_file_pages",
    217: "getdents64",
    218: "set_tid_address",
    219: "restart_syscall",
    220: "semtimedop",
    221: "fadvise64",
    222: "timer_create",
    223: "timer_settime",
    224: "timer_gettime",
    225: "timer_getoverrun",
    226: "timer_delete",
    227: "clock_settime",
    228: "clock_gettime",
    229: "clock_getres",
    230: "clock_nanosleep",
    231: "exit_group",
    232: "epoll_wait",
    233: "epoll_ctl",
    234: "tgkill",
    235: "utimes",
    236: "vserver",
    237: "mbind",
    238: "set_mempolicy",
    239: "get_mempolicy",
    240: "mq_open",
    241: "mq_unlink",
    242: "mq_timedsend",
    243: "mq_timedreceive",
    244: "mq_notify",
    245: "mq_getsetattr",
    246: "kexec_load",
    247: "waitid",
    248: "add_key",
    249: "request_key",
    250: "keyctl",
    251: "ioprio_set",
    252: "ioprio_get",
    253: "inotify_init",
    254: "inotify_add_watch",
    255: "inotify_rm_watch",
    256: "migrate_pages",
    257: "openat",
    258: "mkdirat",
    259: "mknodat",
    260: "fchownat",
    261: "futimesat",
    262: "newfstatat",
    263: "unlinkat",
    264: "renameat",
    265: "linkat",
    266: "symlinkat",
    267: "readlinkat",
    268: "fchmodat",
    269: "faccessat",
    270: "pselect6",
    271: "ppoll",
    272: "unshare",
    273: "set_robust_list",
    274: "get_robust_list",
    275: "splice",
    276: "tee",
    277: "sync_file_range",
    278: "vmsplice",
    279: "move_pages",
    280: "utimensat",
    281: "epoll_pwait",
    282: "signalfd",
    283: "timerfd_create",
    284: "eventfd",
    285: "fallocate",
    286: "timerfd_settime",
    287: "timerfd_gettime",
    288: "accept4",
    289: "signalfd4",
    290: "eventfd2",
    291: "epoll_create1",
    292: "dup3",
    293: "pipe2",
    294: "inotify_init1",
    295: "preadv",
    296: "pwritev",
    297: "rt_tgsigqueueinfo",
    298: "perf_event_open",
    299: "recvmmsg",
    300: "fanotify_init",
    301: "fanotify_mark",
    302: "prlimit64",
    303: "name_to_handle_at",
    304: "open_by_handle_at",
    305: "clock_adjtime",
    306: "syncfs",
    307: "sendmmsg",
    308: "setns",
    309: "getcpu",
    310: "process_vm_readv",
    311: "process_vm_writev",
    312: "kcmp",
    313: "finit_module",
    314: "sched_setattr",
    315: "sched_getattr",
    316: "renameat2",
    317: "seccomp",
    318: "getrandom",
    319: "memfd_create",
    320: "kexec_file_load",
    321: "bpf",
    322: "execveat",
    323: "userfaultfd",
    324: "membarrier",
    325: "mlock2",
    326: "copy_file_range",
    327: "preadv2",
    328: "pwritev2",
    329: "pkey_mprotect",
    330: "pkey_alloc",
    331: "pkey_free",
    332: "statx",
    333: "io_pgetevents",
    334: "rseq",
}


def syscall_name(nr: int) -> str:
    """Resolve an x86_64 syscall number to its name.

    Args:
        nr: The syscall number.

    Returns:
        The canonical syscall name, or ``"syscall_<nr>"`` if the number is not
        present in :data:`SYSCALL_NAMES`.
    """
    return SYSCALL_NAMES.get(nr, "syscall_{0}".format(nr))


# ---------------------------------------------------------------------------
# Sensitivity heuristics consumed by feature extraction / scoring.
# ---------------------------------------------------------------------------

#: Syscalls considered security-sensitive (privilege changes, process control,
#: tracing, execution). Maps the syscall number to its name for quick lookup.
SENSITIVE_SYSCALLS = {
    105: "setuid",
    106: "setgid",
    157: "prctl",
    59: "execve",
    322: "execveat",
    62: "kill",
    101: "ptrace",
}

#: Filesystem paths (and glob-style patterns) whose access warrants elevated
#: scrutiny: credential stores, SSH key material, and direct memory devices.
SENSITIVE_PATHS = [
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/root/.ssh/",
    "/proc/*/mem",
    "/dev/mem",
    "/.ssh/id_rsa",
    "/.ssh/authorized_keys",
]


# ---------------------------------------------------------------------------
# Union alias.
#
# NOTE: this value is *evaluated* at import time, so it must use typing.Union
# rather than PEP 604 ``X | Y`` syntax to remain importable on Python 3.9.
# ---------------------------------------------------------------------------

#: Any decoded BehaveGuard event produced by a ``from_raw`` conversion.
RawEvent = Union[
    SyscallEvent,
    NetworkEvent,
    FileEvent,
    ProcessEvent,
    InjectionEvent,
    ContainerEscapeEvent,
    LolbinEvent,
    AntiforensicEvent,
    DnsTunnelEvent,
]
