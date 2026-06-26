"""Models package: anomaly detectors, ensemble, training, persistence, tuning.

Most of this package depends on PyTorch. To keep ``import behaveguard.models``
(and importing the torch-free submodules such as ``base_model``,
``threshold_tuner``, and ``model_store``) cheap and dependency-light, the
torch-heavy symbols are exposed through PEP 562 lazy ``__getattr__`` and are only
imported when actually accessed.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

# Public name -> submodule that defines it.
_LAZY_EXPORTS = {
    "BaseDetector": "base_model",
    "LSTMDetector": "lstm_detector",
    "BehaviorAutoencoder": "autoencoder",
    "EnsembleDetector": "ensemble",
    "EnsembleScore": "ensemble",
    "ThresholdTuner": "threshold_tuner",
    "ModelStore": "model_store",
    "ModelNotFoundError": "model_store",
    "BaselineBuilder": "baseline_builder",
    "TrainingResult": "baseline_builder",
}

# Static (not derived from _LAZY_EXPORTS) so linters see these as re-exported and
# the TYPE_CHECKING imports below are recognized as used.
__all__ = [
    "BaseDetector",
    "LSTMDetector",
    "BehaviorAutoencoder",
    "EnsembleDetector",
    "EnsembleScore",
    "ThresholdTuner",
    "ModelStore",
    "ModelNotFoundError",
    "BaselineBuilder",
    "TrainingResult",
]

if TYPE_CHECKING:  # pragma: no cover - import for type checkers only
    from behaveguard.models.autoencoder import BehaviorAutoencoder
    from behaveguard.models.base_model import BaseDetector
    from behaveguard.models.baseline_builder import BaselineBuilder, TrainingResult
    from behaveguard.models.ensemble import EnsembleDetector, EnsembleScore
    from behaveguard.models.lstm_detector import LSTMDetector
    from behaveguard.models.model_store import ModelNotFoundError, ModelStore
    from behaveguard.models.threshold_tuner import ThresholdTuner


def __getattr__(name: str) -> Any:
    """Lazily import and return a public symbol on first access (PEP 562)."""
    module_name = _LAZY_EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module = importlib.import_module(f"behaveguard.models.{module_name}")
    return getattr(module, name)


def __dir__() -> list[str]:
    return sorted(__all__)
