"""Unit tests for suppression rules and the alert funnel.

All pure standard library (no fastapi/pydantic/torch). Async paths are driven
with ``asyncio.run`` and a recording mock channel, keeping the tests
dependency-light.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import List

from behaveguard.alerts import AlertManager, RulesEngine, SuppressionRule
from behaveguard.alerts.alert_types import Alert, DeliveryResult


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
class RecordingChannel:
    """A mock alert channel that records every alert it is asked to send."""

    def __init__(self, name: str = "recorder") -> None:
        self.name = name
        self.sent: List[Alert] = []

    async def send(self, alert: Alert) -> DeliveryResult:
        self.sent.append(alert)
        return DeliveryResult(channel=self.name, success=True, detail="recorded")


def _config(high: float = 70.0, dedup: float = 300.0, max_per_min: int = 10):
    return SimpleNamespace(
        alerts=SimpleNamespace(
            dedup_window_seconds=dedup,
            max_alerts_per_minute=max_per_min,
        ),
        scoring=SimpleNamespace(alert_threshold_high=high),
    )


def _score(final_score: float, process_name: str = "evil", pid: int = 6606):
    return SimpleNamespace(
        final_score=final_score,
        process_name=process_name,
        pid=pid,
        severity="HIGH",
        explanation=f"{process_name} did something anomalous",
        timestamp_ns=2_000_000_000_000,
    )


# --------------------------------------------------------------------------- #
# RulesEngine suppression
# --------------------------------------------------------------------------- #
def test_rules_engine_suppresses_below_ceiling(tmp_path):
    engine = RulesEngine(path=str(tmp_path / "rules.yaml"))
    engine.add_rule(
        SuppressionRule(
            process_name="backup",
            reason="backup agent legitimately reads many files",
            max_score_suppress=60.0,
        )
    )
    # Below the ceiling -> suppressed.
    assert engine.should_suppress("backup", 50.0) is True


def test_rules_engine_does_not_suppress_at_or_above_ceiling(tmp_path):
    engine = RulesEngine(path=str(tmp_path / "rules.yaml"))
    engine.add_rule(
        SuppressionRule(process_name="backup", reason="known noisy", max_score_suppress=60.0)
    )
    # At/above the ceiling -> NOT suppressed (the ceiling is exclusive).
    assert engine.should_suppress("backup", 60.0) is False
    assert engine.should_suppress("backup", 95.0) is False


def test_rules_engine_unknown_process_not_suppressed(tmp_path):
    engine = RulesEngine(path=str(tmp_path / "rules.yaml"))
    assert engine.should_suppress("nginx", 10.0) is False


def test_rules_engine_expired_rule_not_applied(tmp_path):
    engine = RulesEngine(path=str(tmp_path / "rules.yaml"))
    engine.add_rule(
        SuppressionRule(
            process_name="backup",
            reason="temporary",
            max_score_suppress=99.0,
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
    )
    assert engine.should_suppress("backup", 10.0) is False


# --------------------------------------------------------------------------- #
# AlertManager funnel
# --------------------------------------------------------------------------- #
def test_alert_manager_fires_once_then_dedups_immediate_repeat(tmp_path):
    async def scenario():
        channel = RecordingChannel()
        rules = RulesEngine(path=str(tmp_path / "rules.yaml"))
        manager = AlertManager(_config(), [channel], rules)

        first = await manager.process(_score(95.0))
        second = await manager.process(_score(95.0))  # same process, immediate
        return first, second, channel

    first, second, channel = asyncio.run(scenario())

    assert first is not None
    assert isinstance(first, Alert)
    assert first.process_name == "evil"
    # The immediate repeat is deduplicated.
    assert second is None
    # The channel was hit exactly once.
    assert len(channel.sent) == 1


def test_alert_manager_drops_below_threshold(tmp_path):
    async def scenario():
        channel = RecordingChannel()
        rules = RulesEngine(path=str(tmp_path / "rules.yaml"))
        manager = AlertManager(_config(high=70.0), [channel], rules)
        # 50 < 70 high threshold -> not alert-worthy.
        result = await manager.process(_score(50.0))
        return result, channel, manager

    result, channel, manager = asyncio.run(scenario())

    assert result is None
    assert channel.sent == []
    assert manager.below_threshold_count == 1


def test_alert_manager_respects_suppression_rule(tmp_path):
    async def scenario():
        channel = RecordingChannel()
        rules = RulesEngine(path=str(tmp_path / "rules.yaml"))
        rules.add_rule(
            SuppressionRule(
                process_name="evil", reason="whitelisted in test", max_score_suppress=100.0
            )
        )
        manager = AlertManager(_config(), [channel], rules)
        # Above the high threshold but suppressed because score < ceiling (100).
        result = await manager.process(_score(95.0))
        return result, channel, manager

    result, channel, manager = asyncio.run(scenario())

    assert result is None
    assert channel.sent == []
    assert manager.suppressed_count == 1


def test_alert_manager_distinct_processes_both_fire(tmp_path):
    async def scenario():
        channel = RecordingChannel()
        rules = RulesEngine(path=str(tmp_path / "rules.yaml"))
        manager = AlertManager(_config(), [channel], rules)
        a = await manager.process(_score(95.0, process_name="proc_a"))
        b = await manager.process(_score(95.0, process_name="proc_b"))
        return a, b, channel

    a, b, channel = asyncio.run(scenario())

    # Different process names are not deduplicated against each other.
    assert a is not None
    assert b is not None
    assert len(channel.sent) == 2
