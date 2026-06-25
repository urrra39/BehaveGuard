"""Alerts package: types, suppression rules, routing, and delivery channels.

Entirely standard-library based (no fastapi/pydantic/torch), so the whole
notification subsystem imports and is testable without the web or ML stacks.
"""

from behaveguard.alerts.alert_manager import AlertManager
from behaveguard.alerts.alert_types import (
    Alert,
    AlertChannelType,
    DeliveryResult,
    alert_to_dict,
    build_alert,
)
from behaveguard.alerts.rules_engine import RulesEngine, SuppressionRule

__all__ = [
    "Alert",
    "AlertChannelType",
    "DeliveryResult",
    "build_alert",
    "alert_to_dict",
    "RulesEngine",
    "SuppressionRule",
    "AlertManager",
]
