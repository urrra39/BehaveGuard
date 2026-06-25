"""Alert data classes shared across the notification system.

The persisted :class:`~behaveguard.storage.alert_store.Alert` (defined in the
storage layer) is the canonical alert record; it is re-exported here so the
alerts package is the single import site for alert types. This module adds the
notification-specific value types — channel kinds and per-channel delivery
results — plus a factory that turns a scorer verdict into a persistable alert.

Pure standard library: no fastapi/pydantic/torch, so the whole alerts subsystem
imports and is testable without the web stack installed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

from behaveguard.storage.alert_store import Alert

if TYPE_CHECKING:  # pragma: no cover - typing only
    from behaveguard.scoring.anomaly_scorer import AnomalyScore


class AlertChannelType(str, Enum):
    """The supported alert delivery channels."""

    WEBHOOK = "webhook"
    EMAIL = "email"
    SYSLOG = "syslog"


@dataclass
class DeliveryResult:
    """Outcome of delivering one alert through one channel."""

    channel: str
    success: bool
    detail: str = ""


def build_alert(score: "AnomalyScore") -> Alert:
    """Create a persistable :class:`Alert` from a scorer verdict.

    Accepts any object exposing the :class:`AnomalyScore` attributes
    (``process_name``, ``pid``, ``final_score``, ``severity``, ``explanation``,
    ``timestamp_ns``), so callers are not coupled to the torch-backed scorer at
    import time.
    """
    return Alert(
        process_name=score.process_name,
        pid=int(score.pid),
        score=float(score.final_score),
        severity=str(score.severity),
        explanation=score.explanation,
        timestamp_ns=int(score.timestamp_ns),
    )


def alert_to_dict(alert: Alert) -> dict[str, Any]:
    """Serialize an alert to a JSON-friendly dict (used by the WebSocket feed)."""
    return {
        "alert_id": alert.alert_id,
        "process_name": alert.process_name,
        "pid": alert.pid,
        "score": alert.score,
        "severity": alert.severity,
        "explanation": alert.explanation,
        "timestamp_ns": alert.timestamp_ns,
        "acknowledged": alert.acknowledged,
        "created_unix": alert.created_unix,
    }


__all__ = ["Alert", "AlertChannelType", "DeliveryResult", "build_alert", "alert_to_dict"]
