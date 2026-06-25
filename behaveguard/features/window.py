"""Sliding time windows over raw events.

Events carry ``timestamp_ns`` taken from ``bpf_ktime_get_ns()`` in the kernel,
which is CLOCK_MONOTONIC nanoseconds since boot — *not* the wall clock. Eviction
is therefore done relative to the most recent event's timestamp (or an explicit
``now_ns`` supplied by the caller) rather than ``time.time()``; this keeps the
window correct regardless of the clock source and makes it deterministically
testable from synthetic events.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional

from behaveguard.collector.event_types import RawEvent

NS_PER_SEC = 1_000_000_000


@dataclass
class TimeWindow:
    """A sliding window that retains only events newer than ``window_seconds``.

    The window's notion of "now" is the largest ``timestamp_ns`` it has observed,
    so feeding it a stream of monotonically increasing events evicts correctly
    without consulting the system clock.
    """

    window_seconds: int = 30
    _events: Deque[RawEvent] = field(default_factory=deque)
    _latest_ns: int = 0

    def add(self, event: RawEvent) -> None:
        """Append an event and evict anything that has aged out."""
        ts = int(event.timestamp_ns)
        if ts > self._latest_ns:
            self._latest_ns = ts
        self._events.append(event)
        self._evict_old()

    def get_events(self, now_ns: Optional[int] = None) -> List[RawEvent]:
        """Return the events currently inside the window.

        Args:
            now_ns: Optional explicit "now" (monotonic ns). When omitted the most
                recent event timestamp is used as the reference point.
        """
        self._evict_old(now_ns)
        return list(self._events)

    def _evict_old(self, now_ns: Optional[int] = None) -> None:
        """Drop events older than ``window_seconds`` relative to the reference."""
        reference = self._latest_ns if now_ns is None else int(now_ns)
        if reference <= 0:
            return
        cutoff_ns = reference - self.window_seconds * NS_PER_SEC
        while self._events and int(self._events[0].timestamp_ns) < cutoff_ns:
            self._events.popleft()

    @property
    def event_count(self) -> int:
        """Number of events currently retained."""
        return len(self._events)

    @property
    def duration_ms(self) -> float:
        """Span between the oldest and newest retained event, in milliseconds."""
        if len(self._events) < 2:
            return 0.0
        oldest = int(self._events[0].timestamp_ns)
        newest = int(self._events[-1].timestamp_ns)
        return max(0.0, (newest - oldest) / 1_000_000.0)


class PerProcessWindowManager:
    """Maintains one :class:`TimeWindow` per PID, auto-creating and reaping them."""

    def __init__(self, window_seconds: int = 30) -> None:
        self.window_seconds = window_seconds
        self._windows: Dict[int, TimeWindow] = {}

    def add_event(self, event: RawEvent) -> None:
        """Route an event to its PID's window, creating the window on first sight."""
        pid = int(event.pid)
        window = self._windows.get(pid)
        if window is None:
            window = TimeWindow(self.window_seconds)
            self._windows[pid] = window
        window.add(event)

    def get_window(self, pid: int) -> Optional[TimeWindow]:
        """Return the window for ``pid`` or ``None`` if none exists."""
        return self._windows.get(pid)

    def cleanup_dead_processes(self, active_pids: set[int]) -> None:
        """Drop windows for PIDs no longer present in ``active_pids``."""
        dead = [pid for pid in self._windows if pid not in active_pids]
        for pid in dead:
            del self._windows[pid]

    def get_all_pids(self) -> List[int]:
        """Return the PIDs that currently have a window."""
        return list(self._windows.keys())

    def prune_empty(self, now_ns: Optional[int] = None) -> None:
        """Evict aged events everywhere and forget windows that emptied out."""
        if now_ns is None:
            now_ns = time.monotonic_ns()
        empty = []
        for pid, window in self._windows.items():
            window.get_events(now_ns)
            if window.event_count == 0:
                empty.append(pid)
        for pid in empty:
            del self._windows[pid]
