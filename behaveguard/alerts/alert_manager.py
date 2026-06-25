"""Alert orchestration: suppress, deduplicate, rate-limit, persist, and route.

:class:`AlertManager` is the funnel every scorer verdict passes through before it
becomes a delivered alert:

1. Below the HIGH threshold -> not alert-worthy, dropped silently.
2. Matched by a suppression rule -> dropped (counted).
3. Seen for the same process within ``dedup_window_seconds`` -> deduplicated.
4. Over ``max_alerts_per_minute`` -> rate-limited.
5. Otherwise -> persisted, fanned out to every channel, and published to any
   live WebSocket subscribers.

Import-safe: no fastapi/pydantic/torch. The scorer verdict is duck-typed.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import TYPE_CHECKING, Any, Deque, Dict, List, Optional, Set

from behaveguard.alerts.alert_types import Alert, DeliveryResult, build_alert

if TYPE_CHECKING:  # pragma: no cover - typing only
    from behaveguard.alerts.channels import AlertChannel
    from behaveguard.alerts.rules_engine import RulesEngine
    from behaveguard.scoring.anomaly_scorer import AnomalyScore
    from behaveguard.storage.alert_store import AlertStore


class AlertManager:
    """Deduplicates, rate-limits, persists, and routes alerts."""

    def __init__(
        self,
        config: Any,
        channels: List["AlertChannel"],
        rules_engine: "RulesEngine",
        alert_store: Optional["AlertStore"] = None,
    ) -> None:
        self.channels = list(channels)
        self.rules = rules_engine
        self.alert_store = alert_store

        self.dedup_window = float(config.alerts.dedup_window_seconds)
        self.max_per_minute = int(config.alerts.max_alerts_per_minute)
        self.high_threshold = float(config.scoring.alert_threshold_high)

        self._last_alert_at: Dict[str, float] = {}
        self._recent: Deque[float] = deque()
        self._subscribers: Set["asyncio.Queue[Alert]"] = set()

        # Counters surfaced via metrics().
        self.sent_count = 0
        self.suppressed_count = 0
        self.deduped_count = 0
        self.rate_limited_count = 0
        self.below_threshold_count = 0

    # ------------------------------------------------------------------ #
    # WebSocket subscription
    # ------------------------------------------------------------------ #
    def subscribe(self) -> "asyncio.Queue[Alert]":
        """Register a live subscriber and return its queue of alerts."""
        queue: "asyncio.Queue[Alert]" = asyncio.Queue(maxsize=100)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: "asyncio.Queue[Alert]") -> None:
        """Remove a subscriber's queue."""
        self._subscribers.discard(queue)

    def _publish(self, alert: Alert) -> None:
        """Push an alert to every subscriber, dropping on a full queue."""
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(alert)
            except asyncio.QueueFull:
                continue

    # ------------------------------------------------------------------ #
    # Processing
    # ------------------------------------------------------------------ #
    async def process(self, score: "AnomalyScore") -> Optional[Alert]:
        """Run a scorer verdict through the alert funnel.

        Returns the delivered :class:`Alert`, or ``None`` if it was not
        alert-worthy / suppressed / deduplicated / rate-limited.
        """
        final_score = float(score.final_score)

        if final_score < self.high_threshold:
            self.below_threshold_count += 1
            return None

        if self.rules.should_suppress(score.process_name, final_score, score.pid):
            self.suppressed_count += 1
            return None

        now = time.monotonic()
        key = score.process_name

        last = self._last_alert_at.get(key)
        if last is not None and (now - last) < self.dedup_window:
            self.deduped_count += 1
            return None

        # Slide the one-minute window and enforce the rate limit.
        cutoff = now - 60.0
        while self._recent and self._recent[0] < cutoff:
            self._recent.popleft()
        if len(self._recent) >= self.max_per_minute:
            self.rate_limited_count += 1
            return None

        alert = build_alert(score)
        alert.created_unix = time.time()

        if self.alert_store is not None:
            alert.alert_id = await self.alert_store.save_alert(alert)

        await self._route(alert)
        self._publish(alert)

        self._last_alert_at[key] = now
        self._recent.append(now)
        self.sent_count += 1
        return alert

    async def _route(self, alert: Alert) -> List[DeliveryResult]:
        """Deliver an alert through every configured channel concurrently."""
        if not self.channels:
            return []
        results = await asyncio.gather(
            *(channel.send(alert) for channel in self.channels),
            return_exceptions=True,
        )
        delivery: List[DeliveryResult] = []
        for channel, result in zip(self.channels, results):
            if isinstance(result, DeliveryResult):
                delivery.append(result)
            else:  # an unexpected raise inside a channel
                delivery.append(DeliveryResult(channel.name, False, str(result)))
        return delivery

    # ------------------------------------------------------------------ #
    # Introspection
    # ------------------------------------------------------------------ #
    def metrics(self) -> Dict[str, int]:
        """Return alert-funnel counters for the metrics endpoint."""
        return {
            "alerts_sent": self.sent_count,
            "alerts_suppressed": self.suppressed_count,
            "alerts_deduplicated": self.deduped_count,
            "alerts_rate_limited": self.rate_limited_count,
            "scores_below_threshold": self.below_threshold_count,
            "active_subscribers": len(self._subscribers),
        }
