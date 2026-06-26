"""Feature normalization, fit on training data and reused at inference.

The normalizer is persisted next to each per-process model so that scores at
inference time use exactly the scaling learned during training. numpy is
imported lazily inside the methods so that importing this module (and the wider
``behaveguard.features`` package) never hard-requires numpy — it is only needed
when a normalizer is actually fit, applied, or loaded.
"""

from __future__ import annotations

import pickle
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    import numpy as np


class NormalizerNotFittedError(RuntimeError):
    """Raised when transform is called before :meth:`FeatureNormalizer.fit`."""


class FeatureNormalizer:
    """Scales feature vectors into ``[0, 1]``.

    Two strategies are available and both are persisted, so the consumer chooses
    at transform time:

    * ``minmax``  — ``(x - min) / (max - min)``, clipped to ``[0, 1]``.
    * ``zscore``  — ``(x - mean) / std``, clipped to ``[-3, 3]`` then rescaled to
      ``[0, 1]``.
    """

    def __init__(self) -> None:
        self.min_: Any = None
        self.max_: Any = None
        self.mean_: Any = None
        self.std_: Any = None
        self.fitted: bool = False

    def fit(self, X: Any) -> "FeatureNormalizer":  # noqa: N803
        """Learn per-feature statistics from ``X``, a ``(n_samples, n_features)`` matrix.

        ``X`` keeps its conventional ML capitalization (hence the N803 waiver).
        """
        import numpy as np

        arr = np.asarray(X, dtype=np.float64)
        if arr.ndim != 2:
            raise ValueError(f"fit expects a 2-D matrix, got shape {arr.shape}")

        self.min_ = arr.min(axis=0)
        self.max_ = arr.max(axis=0)
        self.mean_ = arr.mean(axis=0)
        # Guard zero-variance features so later divisions never blow up.
        std = arr.std(axis=0)
        std[std == 0.0] = 1.0
        self.std_ = std
        self.fitted = True
        return self

    def _check_fitted(self) -> None:
        if not self.fitted:
            raise NormalizerNotFittedError("FeatureNormalizer.fit must be called first")

    def transform_minmax(self, x: Any) -> "np.ndarray":
        """MinMax-normalize a vector (or batch), clipping to ``[0, 1]``."""
        import numpy as np

        self._check_fitted()
        vec = np.asarray(x, dtype=np.float64)
        span = self.max_ - self.min_
        safe_span = np.where(span == 0.0, 1.0, span)
        scaled = (vec - self.min_) / safe_span
        return np.clip(scaled, 0.0, 1.0)

    def transform_zscore(self, x: Any) -> "np.ndarray":
        """Z-score normalize, clip to ``[-3, 3]``, then rescale to ``[0, 1]``."""
        import numpy as np

        self._check_fitted()
        vec = np.asarray(x, dtype=np.float64)
        z = (vec - self.mean_) / self.std_
        z = np.clip(z, -3.0, 3.0)
        return (z + 3.0) / 6.0

    def transform(self, x: Any, method: str = "minmax") -> "np.ndarray":
        """Apply the selected normalization ``method`` (``minmax`` or ``zscore``)."""
        if method == "minmax":
            return self.transform_minmax(x)
        if method == "zscore":
            return self.transform_zscore(x)
        raise ValueError(f"unknown normalization method: {method!r}")

    def save(self, path: str) -> None:
        """Persist the fitted statistics to ``path`` (pickle)."""
        import numpy as np

        self._check_fitted()
        payload = {
            "min_": np.asarray(self.min_).tolist(),
            "max_": np.asarray(self.max_).tolist(),
            "mean_": np.asarray(self.mean_).tolist(),
            "std_": np.asarray(self.std_).tolist(),
        }
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("wb") as handle:
            pickle.dump(payload, handle)

    @classmethod
    def load(cls, path: str) -> "FeatureNormalizer":
        """Reconstruct a fitted normalizer previously written by :meth:`save`."""
        import numpy as np

        with Path(path).open("rb") as handle:
            payload = pickle.load(handle)

        norm = cls()
        norm.min_ = np.asarray(payload["min_"], dtype=np.float64)
        norm.max_ = np.asarray(payload["max_"], dtype=np.float64)
        norm.mean_ = np.asarray(payload["mean_"], dtype=np.float64)
        norm.std_ = np.asarray(payload["std_"], dtype=np.float64)
        norm.fitted = True
        return norm
