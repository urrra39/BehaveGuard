"""Top-level feature extraction.

A window of raw events becomes one fixed-length feature vector — exactly what the
ML models in :mod:`behaveguard.models` consume. The heavy lifting is pure Python
(:meth:`FeatureExtractor.extract_vector` returns a ``list[float]``); numpy is only
used by :meth:`FeatureExtractor.extract` as the array container, imported lazily so
the package stays importable without numpy and the extraction logic can be tested
without it.

``FEATURE_NAMES`` is assembled from the sub-extractors so the names and the vector
can never drift out of sync.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional, Sequence

from behaveguard.collector.event_types import (
    AntiforensicEvent,
    ContainerEscapeEvent,
    DnsTunnelEvent,
    FileEvent,
    InjectionEvent,
    LolbinEvent,
    NetworkEvent,
    ProcessEvent,
    RawEvent,
    SyscallEvent,
)
from behaveguard.features.file_features import FileFeatureExtractor
from behaveguard.features.network_features import NetworkFeatureExtractor
from behaveguard.features.process_features import ProcessFeatureExtractor
from behaveguard.features.syscall_features import SyscallFeatureExtractor

if TYPE_CHECKING:  # pragma: no cover - typing only
    import numpy as np

# Temporal features computed directly here rather than in a sub-extractor.
TEMPORAL_FEATURE_NAMES = ["window_duration_ms", "events_per_second", "cpu_time_ratio"]

# Saturating cap for events/second.
CAP_EVENTS_PER_SEC = 1000.0
# 100 ms activity buckets per second (for the cpu_time_ratio duty cycle).
BUCKET_NS = 100_000_000
BUCKETS_PER_SEC = 10


class FeatureExtractor:
    """Converts a time window of raw events into a fixed-size feature vector."""

    FEATURE_NAMES: List[str] = (
        SyscallFeatureExtractor.feature_names()
        + NetworkFeatureExtractor.feature_names()
        + FileFeatureExtractor.feature_names()
        + ProcessFeatureExtractor.feature_names()
        + TEMPORAL_FEATURE_NAMES
    )
    NUM_FEATURES: int = len(FEATURE_NAMES)

    def __init__(self, window_seconds: int = 30) -> None:
        self.window_seconds = window_seconds
        self._syscall = SyscallFeatureExtractor()
        self._network = NetworkFeatureExtractor()
        self._file = FileFeatureExtractor()
        self._process = ProcessFeatureExtractor()

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def extract_vector(
        self, events: Sequence[RawEvent], window_seconds: Optional[int] = None
    ) -> List[float]:
        """Build the feature vector as a pure-Python ``list[float]`` in ``[0, 1]``.

        Args:
            events: Raw events from one window (any mix of the four event types).
            window_seconds: Override for the window length used in rate features.

        Returns:
            A list of length :data:`NUM_FEATURES`; every value is a finite float in
            ``[0, 1]``.
        """
        ws = self.window_seconds if window_seconds is None else window_seconds
        ordered = sorted(events, key=lambda e: int(e.timestamp_ns))

        syscalls = [e for e in ordered if isinstance(e, SyscallEvent)]
        networks = [e for e in ordered if isinstance(e, NetworkEvent)]
        files = [e for e in ordered if isinstance(e, FileEvent)]
        processes = [e for e in ordered if isinstance(e, ProcessEvent)]
        # Advanced defense-layer events.
        injections = [e for e in ordered if isinstance(e, InjectionEvent)]
        containers = [e for e in ordered if isinstance(e, ContainerEscapeEvent)]
        lolbins = [e for e in ordered if isinstance(e, LolbinEvent)]
        antiforensics = [e for e in ordered if isinstance(e, AntiforensicEvent)]
        dns = [e for e in ordered if isinstance(e, DnsTunnelEvent)]

        vector: List[float] = []
        vector += self._syscall.extract(syscalls, ws)
        vector += self._network.extract(networks, ws, dns_events=dns)
        vector += self._file.extract(files, ws, antiforensic_events=antiforensics)
        vector += self._process.extract(
            processes,
            syscalls,
            ws,
            injection_events=injections,
            container_events=containers,
            lolbin_events=lolbins,
        )
        vector += self._temporal(ordered, ws)

        # Final safety net: clamp to [0, 1] and scrub any NaN/inf.
        cleaned = [self._clamp(v) for v in vector]

        if len(cleaned) != self.NUM_FEATURES:
            raise ValueError(
                f"feature vector length {len(cleaned)} != expected {self.NUM_FEATURES}"
            )
        return cleaned

    def extract(
        self, events: Sequence[RawEvent], window_seconds: Optional[int] = None
    ) -> "np.ndarray":
        """Return the feature vector as a ``float64`` numpy array of shape
        ``(NUM_FEATURES,)``."""
        import numpy as np

        return np.asarray(self.extract_vector(events, window_seconds), dtype=np.float64)

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    @staticmethod
    def _clamp(value: float) -> float:
        v = float(value)
        if v != v or v in (float("inf"), float("-inf")):  # NaN / inf guard
            return 0.0
        return min(1.0, max(0.0, v))

    def _temporal(self, ordered: List[RawEvent], window_seconds: int) -> List[float]:
        """Compute [window_duration_ms, events_per_second, cpu_time_ratio]."""
        if not ordered:
            return [0.0, 0.0, 0.0]

        seconds = float(max(window_seconds, 1))
        timestamps = [int(e.timestamp_ns) for e in ordered]
        min_ts = min(timestamps)
        max_ts = max(timestamps)

        span_ms = (max_ts - min_ts) / 1_000_000.0
        window_duration_ms = min(span_ms / (seconds * 1000.0), 1.0)

        events_per_second = min((len(ordered) / seconds) / CAP_EVENTS_PER_SEC, 1.0)

        # Activity duty cycle: fraction of 100 ms buckets that saw any event.
        active_buckets = {(t - min_ts) // BUCKET_NS for t in timestamps}
        total_buckets = max(int(seconds) * BUCKETS_PER_SEC, 1)
        cpu_time_ratio = min(len(active_buckets) / float(total_buckets), 1.0)

        return [window_duration_ms, events_per_second, cpu_time_ratio]
