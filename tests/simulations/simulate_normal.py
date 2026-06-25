"""Benign baseline session for BehaveGuard tests.

``normal_session`` returns a list of raw events representing the ordinary
behaviour of a small web service: a handful of file reads/writes, a legitimate
read of a served HTML document, an outbound HTTPS connection to a public IP, and
a benign ``python3`` process. None of the attack signatures (shell spawn,
sensitive-file access, RFC1918 connection, injection, privilege escalation,
oversized DNS) appear here, so every defensive boolean stays at ``0`` when this
session is run through :meth:`FeatureExtractor.extract_vector`.

Pure standard library — no numpy/torch needed.
"""

from __future__ import annotations

from typing import List

from behaveguard.collector.event_types import (
    FileEvent,
    NetworkEvent,
    ProcessEvent,
    RawEvent,
    SyscallEvent,
)


def normal_session(base_ns: int = 1_000_000_000_000) -> List[RawEvent]:
    """Build a benign session.

    Args:
        base_ns: Monotonic nanosecond timestamp the session starts at. Each event
            is offset deterministically from this base so ordering is stable.

    Returns:
        A list of benign :class:`RawEvent` objects (syscalls, file ops, one
        outbound HTTPS connection, and one ``python3`` process).
    """
    pid = 4242
    comm = "python3"

    events: List[RawEvent] = [
        # A couple of ordinary read syscalls (read == 0) and writes (write == 1).
        SyscallEvent(
            timestamp_ns=base_ns + 1_000,
            pid=pid,
            tgid=pid,
            uid=1000,
            comm=comm,
            syscall_nr=0,
            syscall_name="read",
            ret=512,
            args=[3, 0, 512],
        ),
        SyscallEvent(
            timestamp_ns=base_ns + 2_000,
            pid=pid,
            tgid=pid,
            uid=1000,
            comm=comm,
            syscall_nr=1,
            syscall_name="write",
            ret=512,
            args=[1, 0, 512],
        ),
        SyscallEvent(
            timestamp_ns=base_ns + 3_000,
            pid=pid,
            tgid=pid,
            uid=1000,
            comm=comm,
            syscall_nr=0,
            syscall_name="read",
            ret=128,
            args=[3, 0, 128],
        ),
        # Open + read of a normal served document under the web root.
        FileEvent(
            timestamp_ns=base_ns + 4_000,
            pid=pid,
            comm=comm,
            path="/var/www/html/index.html",
            operation="open",
            flags=0,
            ret=4,
            bytes_count=0,
        ),
        FileEvent(
            timestamp_ns=base_ns + 5_000,
            pid=pid,
            comm=comm,
            path="/var/www/html/index.html",
            operation="read",
            flags=0,
            ret=2048,
            bytes_count=2048,
        ),
        # A benign write to a temp/cache file (still outside any system dir).
        FileEvent(
            timestamp_ns=base_ns + 6_000,
            pid=pid,
            comm=comm,
            path="/var/www/html/cache/page.tmp",
            operation="write",
            flags=0,
            ret=1024,
            bytes_count=1024,
        ),
        # Outbound HTTPS to a public IP on 443 — ordinary client traffic.
        NetworkEvent(
            timestamp_ns=base_ns + 7_000,
            pid=pid,
            comm=comm,
            src_ip="203.0.113.10",
            dst_ip="93.184.216.34",
            src_port=51000,
            dst_port=443,
            protocol="TCP",
            bytes_count=800,
            direction="outbound",
        ),
        # A benign python3 process exec (normal application startup).
        ProcessEvent(
            timestamp_ns=base_ns + 8_000,
            pid=pid,
            ppid=1,
            comm=comm,
            exe_path="/usr/bin/python3",
            cmdline="python3 /srv/app/server.py",
            action="exec",
            exit_code=0,
        ),
    ]
    return events
