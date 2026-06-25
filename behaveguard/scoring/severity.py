"""Maps a 0-100 anomaly score to a discrete severity level.

The HIGH and CRITICAL cutoffs come from configuration
(``scoring.alert_threshold_high`` / ``scoring.alert_threshold_critical``); a
fixed MEDIUM floor separates mild deviations from clearly-normal behavior.
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from behaveguard.config.settings import Settings

DEFAULT_HIGH = 70.0
DEFAULT_CRITICAL = 90.0
DEFAULT_MEDIUM = 40.0


class Severity(str, Enum):
    """Ordered severity levels for an anomaly score."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        """Numeric ordering (LOW=0 .. CRITICAL=3) for comparisons/sorting."""
        return _ORDER[self]


_ORDER = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


def classify(
    score: float,
    high: float = DEFAULT_HIGH,
    critical: float = DEFAULT_CRITICAL,
    medium: float = DEFAULT_MEDIUM,
) -> Severity:
    """Classify a ``0-100`` score into a :class:`Severity`.

    Args:
        score: The anomaly score (clamped into ``[0, 100]`` for comparison).
        high: Inclusive cutoff for HIGH.
        critical: Inclusive cutoff for CRITICAL.
        medium: Inclusive cutoff for MEDIUM.

    Returns:
        The matching :class:`Severity` (highest band whose cutoff is met).
    """
    value = min(100.0, max(0.0, float(score)))
    if value >= critical:
        return Severity.CRITICAL
    if value >= high:
        return Severity.HIGH
    if value >= medium:
        return Severity.MEDIUM
    return Severity.LOW


def classify_from_settings(score: float, settings: "Settings") -> Severity:
    """Classify using the HIGH/CRITICAL thresholds from a :class:`Settings`."""
    return classify(
        score,
        high=float(settings.scoring.alert_threshold_high),
        critical=float(settings.scoring.alert_threshold_critical),
    )
