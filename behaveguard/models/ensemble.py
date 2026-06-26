"""Weighted ensemble combining the LSTM and VAE detectors.

The two detectors look at complementary signals: the VAE scores a single feature
window (point anomalies) while the LSTM scores a sequence of windows (temporal
anomalies). This module fuses their calibrated ``[0, 1]`` scores into a single
``0-100`` ensemble score using configurable weights, gracefully degrading when
either model (or the sequence input) is unavailable.

``torch`` is imported at module top level because :meth:`EnsembleDetector.score`
constructs tensors to feed the underlying models.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence

import torch

from behaveguard.models.autoencoder import BehaviorAutoencoder
from behaveguard.models.lstm_detector import LSTMDetector


@dataclass
class EnsembleScore:
    """Result of scoring one observation through the ensemble.

    All score fields are on a ``0-100`` scale (the underlying detectors return
    ``[0, 1]`` which is multiplied by 100 here).

    Attributes:
        lstm_score: LSTM (sequence) score, or ``None`` when no sequence was
            available or no LSTM is configured.
        vae_score: VAE (single-window) score; ``0.0`` when no VAE is configured.
        final_score: Weighted ensemble score actually used for alerting.
        dominant_model: ``"lstm"`` or ``"vae"`` — whichever contributed the
            larger weighted component to ``final_score``.
    """

    lstm_score: Optional[float]
    vae_score: float
    final_score: float
    dominant_model: str


class EnsembleDetector:
    """Combines an optional :class:`LSTMDetector` and :class:`BehaviorAutoencoder`."""

    def __init__(
        self,
        lstm: Optional[LSTMDetector],
        vae: Optional[BehaviorAutoencoder],
        lstm_weight: float = 0.6,
        vae_weight: float = 0.4,
    ) -> None:
        """Configure the ensemble and normalize its weights.

        At least one of ``lstm``/``vae`` must be provided. If exactly one is
        present, all weight is assigned to it; if both are present, the supplied
        weights are renormalized to sum to 1.

        Args:
            lstm: The sequence detector, or ``None`` if unavailable.
            vae: The single-window detector, or ``None`` if unavailable.
            lstm_weight: Relative weight of the LSTM component.
            vae_weight: Relative weight of the VAE component.

        Raises:
            AssertionError: If both ``lstm`` and ``vae`` are ``None``.
        """
        assert (
            lstm is not None or vae is not None
        ), "EnsembleDetector requires at least one of lstm/vae to be non-None"
        self.lstm = lstm
        self.vae = vae

        if lstm is None:
            self.lstm_weight = 0.0
            self.vae_weight = 1.0
        elif vae is None:
            self.lstm_weight = 1.0
            self.vae_weight = 0.0
        else:
            total = float(lstm_weight) + float(vae_weight)
            if total <= 0.0:
                # Fall back to an even split rather than dividing by zero.
                self.lstm_weight = 0.5
                self.vae_weight = 0.5
            else:
                self.lstm_weight = float(lstm_weight) / total
                self.vae_weight = float(vae_weight) / total

    # ------------------------------------------------------------------ #
    # Scoring
    # ------------------------------------------------------------------ #
    def score(
        self,
        features: Sequence[float],
        sequence: Optional[Sequence[Sequence[float]]],
    ) -> EnsembleScore:
        """Score one observation through both available detectors.

        Args:
            features: A 1-D, length ``input_dim`` array-like for the current
                window — fed to the VAE.
            sequence: A 2-D ``(seq_len, input_dim)`` array-like (or ``None``) of
                recent window vectors — fed to the LSTM. ``None`` means no
                sequence context is available yet.

        Returns:
            An :class:`EnsembleScore` with both component scores (where
            available), the fused ``final_score``, and the dominant model.
        """
        # VAE component (single window). torch.as_tensor avoids any numpy
        # dependency and accepts plain python sequences.
        vae_score: float
        if self.vae is not None:
            features_tensor = torch.as_tensor(features, dtype=torch.float32)
            vae_score = float(self.vae.anomaly_score(features_tensor) * 100.0)
        else:
            vae_score = 0.0

        # LSTM component (sequence) — only when both a model and input exist.
        lstm_score: Optional[float]
        if self.lstm is not None and sequence is not None:
            seq_tensor = torch.as_tensor(sequence, dtype=torch.float32)
            lstm_score = float(self.lstm.anomaly_score(seq_tensor) * 100.0)
        else:
            lstm_score = None

        # Fuse. When the LSTM score is missing, the VAE carries the result.
        if lstm_score is None:
            final_score = vae_score
            dominant_model = "vae"
        else:
            lstm_component = self.lstm_weight * lstm_score
            vae_component = self.vae_weight * vae_score
            final_score = lstm_component + vae_component
            dominant_model = "lstm" if lstm_component >= vae_component else "vae"

        return EnsembleScore(
            lstm_score=lstm_score,
            vae_score=vae_score,
            final_score=float(final_score),
            dominant_model=dominant_model,
        )

    # ------------------------------------------------------------------ #
    # Decision
    # ------------------------------------------------------------------ #
    def is_anomalous(self, score: EnsembleScore, threshold: float = 70.0) -> bool:
        """Return whether a score crosses the anomaly threshold.

        Args:
            score: A previously computed :class:`EnsembleScore`.
            threshold: Inclusive cutoff on the ``0-100`` ``final_score``.

        Returns:
            ``True`` if ``score.final_score >= threshold``.
        """
        return score.final_score >= float(threshold)
