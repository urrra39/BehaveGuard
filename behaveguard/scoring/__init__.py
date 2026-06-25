"""Scoring package: severity mapping, explanations, and the anomaly scorer.

``severity`` and ``explainer`` are pure Python and imported eagerly. The
:class:`AnomalyScorer` pulls in the torch-backed ensemble, so it is exposed via
PEP 562 lazy ``__getattr__`` to keep ``import behaveguard.scoring`` torch-free.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

from behaveguard.scoring.explainer import FeatureContribution, explain, rank_contributions
from behaveguard.scoring.severity import (
    Severity,
    classify,
    classify_from_settings,
)

_LAZY_EXPORTS = {
    "AnomalyScorer": "anomaly_scorer",
    "AnomalyScore": "anomaly_scorer",
}

__all__ = [
    "Severity",
    "classify",
    "classify_from_settings",
    "explain",
    "rank_contributions",
    "FeatureContribution",
    "AnomalyScorer",
    "AnomalyScore",
]

if TYPE_CHECKING:  # pragma: no cover - type checkers only
    from behaveguard.scoring.anomaly_scorer import AnomalyScore, AnomalyScorer


def __getattr__(name: str) -> Any:
    """Lazily import torch-dependent scoring symbols (PEP 562)."""
    module_name = _LAZY_EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = importlib.import_module(f"behaveguard.scoring.{module_name}")
    return getattr(module, name)
