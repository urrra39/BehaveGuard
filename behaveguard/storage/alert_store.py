"""SQLite-backed alert history and acknowledgment state.

Defines the persisted :class:`Alert` shape (the alerting package in a later
session builds richer routing on top of this record) and an async store for
saving, querying, and acknowledging alerts. Like :mod:`event_store`, the
synchronous ``sqlite3`` calls run inside :func:`asyncio.to_thread`.
"""

from __future__ import annotations

import asyncio
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, List, Optional

if TYPE_CHECKING:  # pragma: no cover - typing only
    from behaveguard.config.settings import Settings


@dataclass
class Alert:
    """A persisted anomaly alert."""

    process_name: str
    pid: int
    score: float
    severity: str
    explanation: str
    timestamp_ns: int
    alert_id: Optional[int] = None
    acknowledged: bool = False
    ack_note: str = ""
    created_unix: float = 0.0


class AlertStore:
    """Async SQLite store for alert history."""

    def __init__(self, config: "Settings", db_path: Optional[str] = None) -> None:
        if db_path is not None:
            self.db_path = str(db_path)
        else:
            # Co-locate an alerts.db next to the events database.
            self.db_path = str(Path(config.storage.sqlite_path).parent / "alerts.db")
        self._initialized = False

    # ------------------------------------------------------------------ #
    # Connection / schema
    # ------------------------------------------------------------------ #
    def _connect(self) -> sqlite3.Connection:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        conn = self._connect()
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    process_name TEXT    NOT NULL,
                    pid          INTEGER NOT NULL,
                    score        REAL    NOT NULL,
                    severity     TEXT    NOT NULL,
                    explanation  TEXT    NOT NULL,
                    timestamp_ns INTEGER NOT NULL,
                    acknowledged INTEGER NOT NULL DEFAULT 0,
                    ack_note     TEXT    NOT NULL DEFAULT '',
                    created_unix REAL    NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_sev ON alerts(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_proc ON alerts(process_name)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ack ON alerts(acknowledged)")
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
    def _insert(self, alert: Alert) -> int:
        created = alert.created_unix or time.time()
        conn = self._connect()
        try:
            cursor = conn.execute(
                """
                INSERT INTO alerts
                    (process_name, pid, score, severity, explanation, timestamp_ns,
                     acknowledged, ack_note, created_unix)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.process_name,
                    int(alert.pid),
                    float(alert.score),
                    alert.severity,
                    alert.explanation,
                    int(alert.timestamp_ns),
                    1 if alert.acknowledged else 0,
                    alert.ack_note,
                    float(created),
                ),
            )
            conn.commit()
            return int(cursor.lastrowid or 0)
        finally:
            conn.close()

    async def save_alert(self, alert: Alert) -> int:
        """Persist an alert and return its new database id."""
        await self.initialize()
        return await asyncio.to_thread(self._insert, alert)

    # ------------------------------------------------------------------ #
    # Reads
    # ------------------------------------------------------------------ #
    @staticmethod
    def _row_to_alert(row: sqlite3.Row) -> Alert:
        return Alert(
            alert_id=int(row["id"]),
            process_name=row["process_name"],
            pid=int(row["pid"]),
            score=float(row["score"]),
            severity=row["severity"],
            explanation=row["explanation"],
            timestamp_ns=int(row["timestamp_ns"]),
            acknowledged=bool(row["acknowledged"]),
            ack_note=row["ack_note"],
            created_unix=float(row["created_unix"]),
        )

    def _get(self, alert_id: int) -> Optional[Alert]:
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM alerts WHERE id = ?", (int(alert_id),)).fetchone()
            return self._row_to_alert(row) if row is not None else None
        finally:
            conn.close()

    async def get_alert(self, alert_id: int) -> Optional[Alert]:
        """Return one alert by id, or ``None`` if it does not exist."""
        await self.initialize()
        return await asyncio.to_thread(self._get, int(alert_id))

    def _list(
        self,
        severity: Optional[str],
        process_name: Optional[str],
        from_time: Optional[datetime],
        to_time: Optional[datetime],
        acknowledged: Optional[bool],
        limit: int,
        offset: int,
    ) -> List[Alert]:
        clauses: List[str] = []
        params: List[object] = []
        if severity is not None:
            clauses.append("severity = ?")
            params.append(severity)
        if process_name is not None:
            clauses.append("process_name = ?")
            params.append(process_name)
        if from_time is not None:
            clauses.append("created_unix >= ?")
            params.append(from_time.timestamp())
        if to_time is not None:
            clauses.append("created_unix <= ?")
            params.append(to_time.timestamp())
        if acknowledged is not None:
            clauses.append("acknowledged = ?")
            params.append(1 if acknowledged else 0)

        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM alerts{where} ORDER BY created_unix DESC LIMIT ? OFFSET ?"
        params.extend([int(limit), int(offset)])

        conn = self._connect()
        try:
            rows = conn.execute(sql, tuple(params)).fetchall()
            return [self._row_to_alert(r) for r in rows]
        finally:
            conn.close()

    async def list_alerts(
        self,
        severity: Optional[str] = None,
        process_name: Optional[str] = None,
        from_time: Optional[datetime] = None,
        to_time: Optional[datetime] = None,
        acknowledged: Optional[bool] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Alert]:
        """List alerts matching the given filters, newest first."""
        await self.initialize()
        return await asyncio.to_thread(
            self._list, severity, process_name, from_time, to_time, acknowledged, limit, offset
        )

    # ------------------------------------------------------------------ #
    # Mutations
    # ------------------------------------------------------------------ #
    def _acknowledge(self, alert_id: int, note: str) -> bool:
        conn = self._connect()
        try:
            cursor = conn.execute(
                "UPDATE alerts SET acknowledged = 1, ack_note = ? WHERE id = ?",
                (note, int(alert_id)),
            )
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()

    async def acknowledge(self, alert_id: int, note: str = "") -> bool:
        """Mark an alert acknowledged with an optional note; return success."""
        await self.initialize()
        return await asyncio.to_thread(self._acknowledge, int(alert_id), note)

    def _count_unacked(self) -> int:
        conn = self._connect()
        try:
            row = conn.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged = 0").fetchone()
            return int(row[0]) if row else 0
        finally:
            conn.close()

    async def count_unacknowledged(self) -> int:
        """Return the number of unacknowledged alerts."""
        await self.initialize()
        return await asyncio.to_thread(self._count_unacked)
