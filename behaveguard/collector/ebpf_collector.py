"""eBPF collector: load the kernel programs and stream typed events.

:class:`EBPFCollector` compiles the four BCC programs under ``programs/`` (each
with ``-DOWN_PID=<self>`` so the detector never observes itself), subscribes to
their ring buffers via :class:`RingBufferReader`, parses each raw record into the
typed dataclasses from :mod:`behaveguard.collector.event_types`, and yields them
through an async generator.

``bcc`` is imported lazily inside :meth:`start`, so this module imports on any
platform; only actually starting collection requires a Linux host with BCC.
"""

from __future__ import annotations

import asyncio
import ctypes
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, AsyncGenerator, Dict, List, Tuple

from behaveguard.collector.event_types import (
    FileEvent,
    FileEventRaw,
    NetworkEvent,
    NetworkEventRaw,
    ProcessEvent,
    ProcessEventRaw,
    RawEvent,
    SyscallEvent,
    SyscallEventRaw,
)
from behaveguard.collector.ring_buffer import RingBufferReader

if TYPE_CHECKING:  # pragma: no cover - typing only
    from behaveguard.config.settings import Settings

logger = logging.getLogger("behaveguard.collector")

PROGRAMS_DIR = Path(__file__).resolve().parent / "programs"

# (source filename, ring-buffer table name, parser method name)
PROGRAM_SPECS: List[Tuple[str, str, str]] = [
    ("syscall_monitor.c", "syscall_events", "_parse_syscall_event"),
    ("network_monitor.c", "network_events", "_parse_network_event"),
    ("file_monitor.c", "file_events", "_parse_file_event"),
    ("process_monitor.c", "process_events", "_parse_process_event"),
]


class EBPFCollector:
    """Loads all eBPF programs and provides an async stream of raw events."""

    def __init__(self, config: "Settings") -> None:
        self.config = config
        self._queue: "asyncio.Queue[RawEvent]" = asyncio.Queue(maxsize=100_000)
        self._bpf_objects: Dict[str, Any] = {}
        self._reader: RingBufferReader | None = None
        self.running = False

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    async def start(self) -> None:
        """Compile, load, and attach every program, then begin polling."""
        try:
            from bcc import BPF  # type: ignore
        except ImportError as exc:  # pragma: no cover - platform dependent
            raise RuntimeError(
                "eBPF collection requires BCC (python3-bpfcc) on a Linux 5.15+ host"
            ) from exc

        own_pid = os.getpid()
        cflags = [f"-DOWN_PID={own_pid}"]

        for filename, _table, _parser in PROGRAM_SPECS:
            source = (PROGRAMS_DIR / filename).read_text(encoding="utf-8")
            logger.info("loading eBPF program %s", filename)
            self._bpf_objects[filename] = BPF(text=source, cflags=cflags)

        poll_ms = int(self.config.collection.poll_interval_ms)
        self._reader = RingBufferReader(self._bpf_objects, self._queue, poll_ms)
        for filename, table, parser_name in PROGRAM_SPECS:
            self._reader.register(filename, table, getattr(self, parser_name))

        await self._reader.start(asyncio.get_event_loop())
        self.running = True
        logger.info("eBPF collector started (own_pid=%d)", own_pid)

    async def stop(self) -> None:
        """Stop polling, detach all probes, and release kernel resources."""
        self.running = False
        if self._reader is not None:
            await self._reader.stop()
            self._reader = None
        for filename, bpf in self._bpf_objects.items():
            try:
                bpf.cleanup()
            except Exception:  # noqa: BLE001 - best-effort teardown
                logger.warning("cleanup failed for %s", filename)
        self._bpf_objects.clear()
        logger.info("eBPF collector stopped")

    async def events(self) -> AsyncGenerator[RawEvent, None]:
        """Yield events in real time until stopped and the queue is drained."""
        while self.running or not self._queue.empty():
            try:
                event = await asyncio.wait_for(self._queue.get(), timeout=0.5)
            except asyncio.TimeoutError:
                continue
            yield event

    @property
    def dropped_events(self) -> int:
        """Number of events dropped due to queue back-pressure."""
        return self._reader.dropped_events if self._reader else 0

    # ------------------------------------------------------------------ #
    # Parsers: raw ring-buffer bytes -> typed dataclasses
    # ------------------------------------------------------------------ #
    def _parse_syscall_event(self, ctx: Any, data: Any, size: int) -> SyscallEvent:
        raw = ctypes.cast(data, ctypes.POINTER(SyscallEventRaw)).contents
        return SyscallEvent.from_raw(raw)

    def _parse_network_event(self, ctx: Any, data: Any, size: int) -> NetworkEvent:
        raw = ctypes.cast(data, ctypes.POINTER(NetworkEventRaw)).contents
        return NetworkEvent.from_raw(raw)

    def _parse_file_event(self, ctx: Any, data: Any, size: int) -> FileEvent:
        raw = ctypes.cast(data, ctypes.POINTER(FileEventRaw)).contents
        return FileEvent.from_raw(raw)

    def _parse_process_event(self, ctx: Any, data: Any, size: int) -> ProcessEvent:
        raw = ctypes.cast(data, ctypes.POINTER(ProcessEventRaw)).contents
        return ProcessEvent.from_raw(raw)
