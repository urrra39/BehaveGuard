"""Collector package: eBPF programs, raw event structs, and typed event models.

Only the pure-Python event types are re-exported here. The eBPF collector
(:mod:`behaveguard.collector.ebpf_collector`) is imported lazily by callers
because it depends on BCC, which is only available on a Linux host with the
kernel headers installed.
"""

from behaveguard.collector.event_types import (
    SENSITIVE_PATHS,
    SENSITIVE_SYSCALLS,
    SYSCALL_NAMES,
    AntiforensicEvent,
    ContainerEscapeEvent,
    DnsTunnelEvent,
    EventType,
    FileEvent,
    InjectionEvent,
    LolbinEvent,
    NetworkEvent,
    ProcessEvent,
    RawEvent,
    SyscallEvent,
    syscall_name,
)

__all__ = [
    "EventType",
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
    "SENSITIVE_SYSCALLS",
    "SENSITIVE_PATHS",
    "syscall_name",
]
