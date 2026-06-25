"""Storage package: event time-series, alert history, and model registry.

All backends are pure standard library (sqlite3 / json), so this package imports
without torch or numpy.
"""

from behaveguard.storage.alert_store import Alert, AlertStore
from behaveguard.storage.event_store import EventStore
from behaveguard.storage.model_registry import ModelRegistry, ModelVersion

__all__ = [
    "EventStore",
    "AlertStore",
    "Alert",
    "ModelRegistry",
    "ModelVersion",
]
