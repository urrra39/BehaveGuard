"""Time-series storage for raw events.

Backed by SQLite via the standard-library ``sqlite3`` module. Because ``sqlite3``
is synchronous, every database operation runs inside :func:`asyncio.to_thread`
(each call opens, uses, and closes its own connection, which is thread-safe),
giving an ``async`` API without pulling in ``aiosqlite``. The configured
``influxdb`` backend is accepted but not yet implemented; SQLite is the default
and the only backend required for the core loop.

Events are stored with their key fields promoted to indexed columns plus a JSON
blob of the full dataclass, so queries can reconstruct the original typed events.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from dataclasses import fields
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List

from behaveguard.collector.event_types import (
    EventType,
    FileEvent,
    NetworkEvent,
    ProcessEvent,
    RawEvent,
    SyscallEvent,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from behaveguard.config.settings import Settings

_EVENT_CLASSES = {
    EventType.SYSCALL: SyscallEvent,
    EventType.NETWORK: NetworkEvent,
    EventType.FILE: FileEvent,
    EventType.PROCESS: ProcessEvent,
}


def _serialize(event: RawEvent) -> "tuple[int, int, int, str, str]":
    """Flatten an event into ``(ts_ns, event_type, pid, comm, json_blob)``."""
    data = {f.name: getattr(event, f.name) for f in fields(event)}
    event_type_int = int(data.pop("event_type"))
    return (
        int(event.timestamp_ns),
        event_type_int,
        int(getattr(event, "pid", 0)),
        str(getattr(event, "comm", "")),
        json.dumps(data),
    )


def _deserialize(event_type_int: int, data_json: str) -> RawEvent:
    """Rebuild a typed event from its stored type tag and JSON blob."""
    cls = _EVENT_CLASSES[EventType(event_type_int)]
    payload = json.loads(data_json)
    return cls(**payload)


class EventStore:
    """SQLite-backed, async-friendly store for raw behavioral events."""

    def __init__(self, config: "Settings") -> None:
        self.backend = config.storage.backend
        self.db_path = str(config.storage.sqlite_path)
        self.retention_days = int(config.storage.retention_days)
        self._initialized = False

    # ------------------------------------------------------------------ #
    # Connection / schema
    # ------------------------------------------------------------------ #
    def _connect(self) -> sqlite3.Connection:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        conn = self._connect()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts_ns       INTEGER NOT NULL,
                    event_type  INTEGER NOT NULL,
                    pid         INTEGER NOT NULL,
                    comm        TEXT    NOT NULL,
                    data        TEXT    NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_pid ON events(pid, ts_ns)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_comm ON events(comm, ts_ns)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts_ns)")
            conn.commit()
        finally:
            conn.close()

    async def initialize(self) -> None:
        """Create the schema if needed (idempotent)."""
        if self._initialized:
            return
        await asyncio.to_thread(self._init_db)
        self._initialized = True

    # ------------------------------------------------------------------ #
    # Writes
    # ------------------------------------------------------------------ #
    def _write_rows(self, events: List[RawEvent]) -> None:
        conn = self._connect()
        try:
            conn.executemany(
                "INSERT INTO events (ts_ns, event_type, pid, comm, data) VALUES (?, ?, ?, ?, ?)",
                [_serialize(e) for e in events],
            )
            conn.commit()
        finally:
            conn.close()

    async def write_event(self, event: RawEvent) -> None:
        """Persist a single event."""
        await self.initialize()
        await asyncio.to_thread(self._write_rows, [event])

    async def write_batch(self, events: List[RawEvent]) -> None:
        """Persist a batch of events in one transaction."""
        if not events:
            return
        await self.initialize()
        await asyncio.to_thread(self._write_rows, list(events))

    # ------------------------------------------------------------------ #
    # Queries
    # ------------------------------------------------------------------ #
    def _query(self, sql: str, params: tuple) -> List[RawEvent]:
        conn = self._connect()
        try:
            cursor = conn.execute(sql, params)
            return [_deserialize(row[0], row[1]) for row in cursor.fetchall()]
        finally:
            conn.close()

    async def query_by_pid(self, pid: int, from_ts: int, to_ts: int) -> List[RawEvent]:
        """Return events for ``pid`` with ``from_ts <= ts_ns <= to_ts`` (ordered)."""
        await self.initialize()
        sql = (
            "SELECT event_type, data FROM events "
            "WHERE pid = ? AND ts_ns BETWEEN ? AND ? ORDER BY ts_ns ASC"
        )
        return await asyncio.to_thread(self._query, sql, (int(pid), int(from_ts), int(to_ts)))

    async def query_by_process_name(
        self, name: str, from_ts: int, to_ts: int, limit: int = 10_000
    ) -> List[RawEvent]:
        """Return up to ``limit`` events for process ``name`` in a time range."""
        await self.initialize()
        sql = (
            "SELECT event_type, data FROM events "
            "WHERE comm = ? AND ts_ns BETWEEN ? AND ? ORDER BY ts_ns ASC LIMIT ?"
        )
        return await asyncio.to_thread(
            self._query, sql, (str(name), int(from_ts), int(to_ts), int(limit))
        )

    def _syscall_freq(self, pid: int, window_seconds: int) -> Dict[str, int]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT MAX(ts_ns) FROM events WHERE pid = ? AND event_type = ?",
                (int(pid), int(EventType.SYSCALL)),
            ).fetchone()
            latest = row[0] if row and row[0] is not None else None
            if latest is None:
                return {}
            cutoff = int(latest) - window_seconds * 1_000_000_000
            cursor = conn.execute(
                "SELECT data FROM events WHERE pid = ? AND event_type = ? AND ts_ns >= ?",
                (int(pid), int(EventType.SYSCALL), cutoff),
            )
            counts: Dict[str, int] = {}
            for (data_json,) in cursor.fetchall():
                name = json.loads(data_json).get("syscall_name", "unknown")
                counts[name] = counts.get(name, 0) + 1
            return counts
        finally:
            conn.close()

    async def get_syscall_frequency(self, pid: int, window_seconds: int = 60) -> Dict[str, int]:
        """Return ``{syscall_name: count}`` for ``pid`` over the last window."""
        await self.initialize()
        return await asyncio.to_thread(self._syscall_freq, int(pid), int(window_seconds))

    # ------------------------------------------------------------------ #
    # Retention
    # ------------------------------------------------------------------ #
    def _cleanup(self, cutoff_ns: int) -> int:
        conn = self._connect()
        try:
            cursor = conn.execute("DELETE FROM events WHERE ts_ns < ?", (cutoff_ns,))
            conn.commit()
            return cursor.rowcount
        finally:
            conn.close()

    async def cleanup_old_events(self, now_ns: int) -> int:
        """Delete events older than ``retention_days`` relative to ``now_ns``.

        Args:
            now_ns: The current monotonic timestamp in ns (events share this clock
                source, so retention is computed against it rather than wall time).

        Returns:
            The number of rows deleted.
        """
        await self.initialize()
        cutoff = int(now_ns) - self.retention_days * 86_400 * 1_000_000_000
        return await asyncio.to_thread(self._cleanup, cutoff)
