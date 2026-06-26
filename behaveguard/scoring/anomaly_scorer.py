"""The decision engine: turn a window of events into a 0-100 anomaly verdict.

:class:`AnomalyScorer` loads the per-process baseline bundle, extracts features,
maintains a rolling per-PID sequence so the LSTM has temporal context, fuses the
LSTM + VAE scores through the ensemble, applies operational context (known-safe
PIDs are suppressed), assigns a severity, and attaches a human-readable
explanation.

``torch`` (via the ensemble) and the feature normalizer are used at runtime, so
this module is only importable where those are installed; the scoring package's
``__init__`` therefore imports it lazily.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Deque, Dict, List, Optional, Tuple

from behaveguard.collector.event_types import RawEvent
from behaveguard.features.extractor import FeatureExtractor
from behaveguard.models.ensemble import EnsembleDetector
from behaveguard.models.model_store import ModelNotFoundError, ModelStore
from behaveguard.scoring import explainer, severity
from behaveguard.scoring.severity import Severity

if TYPE_CHECKING:  # pragma: no cover - typing only
    from behaveguard.config.settings import Settings


@dataclass
class AnomalyScore:
    """The full verdict for one scoring call."""

    process_name: str
    pid: int
    final_score: float
    lstm_score: Optional[float]
    vae_score: float
    severity: str
    explanation: str
    timestamp_ns: int
    model_available: bool
    suppressed: bool = False
    top_features: List[Dict[str, Any]] = field(default_factory=list)


class AnomalyScorer:
    """Scores process behavior windows into contextual 0-100 anomaly scores."""

    def __init__(self, config: "Settings", model_store: Optional[ModelStore] = None) -> None:
        self.config = config
        self.model_store = model_store if model_store is not None else ModelStore()
        self.extractor = FeatureExtractor(window_seconds=config.features.window_seconds)
        self.sequence_length = int(config.features.sequence_length)
        self.high = float(config.scoring.alert_threshold_high)
        self.critical = float(config.scoring.alert_threshold_critical)

        # Rolling normalized-window history per PID, for LSTM sequence context.
        self._sequences: Dict[int, Deque[List[float]]] = {}
        # PIDs the operator has marked safe (scores suppressed to 0).
        self._safe_pids: set[int] = set()
        # Cache of loaded bundles: process_name -> (ensemble, normalizer, metadata).
        self._bundles: Dict[str, Optional[Tuple[EnsembleDetector, Any, dict]]] = {}

    # ------------------------------------------------------------------ #
    # Context controls
    # ------------------------------------------------------------------ #
    def add_safe_pid(self, pid: int) -> None:
        """Mark a PID as known-safe; its scores are suppressed to 0."""
        self._safe_pids.add(int(pid))

    def remove_safe_pid(self, pid: int) -> None:
        """Remove a PID from the known-safe set."""
        self._safe_pids.discard(int(pid))

    def forget_pid(self, pid: int) -> None:
        """Drop rolling sequence state for a dead PID."""
        self._sequences.pop(int(pid), None)

    # ------------------------------------------------------------------ #
    # Bundle loading
    # ------------------------------------------------------------------ #
    def _load_bundle(self, process_name: str) -> Optional[Tuple[EnsembleDetector, Any, dict]]:
        """Load (and cache) the ensemble/normalizer/metadata for a process."""
        if process_name in self._bundles:
            return self._bundles[process_name]

        try:
            lstm, vae, normalizer, metadata = self.model_store.load(process_name)
        except ModelNotFoundError:
            self._bundles[process_name] = None
            return None

        if lstm is None and vae is None:
            self._bundles[process_name] = None
            return None

        ensemble = EnsembleDetector(
            lstm,
            vae,
            lstm_weight=float(self.config.scoring.lstm_weight),
            vae_weight=float(self.config.scoring.vae_weight),
        )
        bundle = (ensemble, normalizer, metadata)
        self._bundles[process_name] = bundle
        return bundle

    # ------------------------------------------------------------------ #
    # Scoring
    # ------------------------------------------------------------------ #
    def score(self, process_name: str, recent_events: List[RawEvent], pid: int) -> AnomalyScore:
        """Score a window of ``recent_events`` for ``pid`` (process ``process_name``).

        Args:
            process_name: The process ``comm`` keying the trained baseline.
            recent_events: Events observed in the current window for this PID.
            pid: The process id being scored.

        Returns:
            A fully populated :class:`AnomalyScore`. When no baseline exists for
            ``process_name`` the score is ``0`` with ``model_available=False``.
        """
        pid = int(pid)
        timestamp_ns = max((int(e.timestamp_ns) for e in recent_events), default=0)
        raw_features = self.extractor.extract_vector(recent_events)
        feature_names = FeatureExtractor.FEATURE_NAMES

        bundle = self._load_bundle(process_name)
        if bundle is None:
            return AnomalyScore(
                process_name=process_name,
                pid=pid,
                final_score=0.0,
                lstm_score=None,
                vae_score=0.0,
                severity=Severity.LOW.value,
                explanation=f"No trained baseline for {process_name!r}; cannot score yet.",
                timestamp_ns=timestamp_ns,
                model_available=False,
            )

        ensemble, normalizer, _metadata = bundle

        # Normalize features the same way training did, if a normalizer exists.
        baseline_mean: Optional[List[float]] = None
        if normalizer is not None:
            norm_features = normalizer.transform_minmax(raw_features).tolist()
            if getattr(normalizer, "mean_", None) is not None:
                baseline_mean = list(normalizer.mean_.tolist())
        else:
            norm_features = list(raw_features)

        # Maintain rolling sequence context for the LSTM.
        history = self._sequences.setdefault(pid, deque(maxlen=self.sequence_length))
        history.append(norm_features)
        sequence: Optional[List[List[float]]] = (
            list(history) if len(history) == self.sequence_length else None
        )

        ensemble_score = ensemble.score(norm_features, sequence)
        final_score = float(ensemble_score.final_score)

        # Operational context: suppress known-safe PIDs entirely.
        suppressed = pid in self._safe_pids
        if suppressed:
            final_score = 0.0

        sev = severity.classify(final_score, high=self.high, critical=self.critical)
        explanation = (
            f"PID {pid} is on the known-safe list; alert suppressed."
            if suppressed
            else explainer.explain(raw_features, feature_names, process_name, baseline_mean)
        )

        ranked = explainer.rank_contributions(raw_features, feature_names, baseline_mean)
        top_features = [
            {"name": c.name, "value": round(c.value, 4), "contribution": round(c.contribution, 4)}
            for c in ranked[:5]
            if c.contribution > 0.0
        ]

        return AnomalyScore(
            process_name=process_name,
            pid=pid,
            final_score=final_score,
            lstm_score=ensemble_score.lstm_score,
            vae_score=ensemble_score.vae_score,
            severity=sev.value,
            explanation=explanation,
            timestamp_ns=timestamp_ns,
            model_available=True,
            suppressed=suppressed,
            top_features=top_features,
        )

    def explain(self, score: AnomalyScore) -> str:
        """Return the human-readable explanation attached to ``score``."""
        return score.explanation
