"""Generic webhook alert channel (Slack, Discord, Teams, custom endpoints).

Posts a compact JSON summary of the alert. Per BehaveGuard's security policy the
payload contains only the alert summary and score — never raw captured event
data. ``aiohttp`` is imported lazily so the module imports without it; a missing
dependency degrades to a failed :class:`DeliveryResult` rather than an error.
"""

from __future__ import annotations

from typing import Optional

from behaveguard.alerts.alert_types import Alert, DeliveryResult


class WebhookChannel:
    """Delivers alerts by HTTP POST to a configured webhook URL."""

    name = "webhook"

    def __init__(self, url: Optional[str], timeout: float = 10.0) -> None:
        self.url = url
        self.timeout = timeout

    async def send(self, alert: Alert) -> DeliveryResult:
        """POST a JSON summary of ``alert`` to the configured URL."""
        if not self.url:
            return DeliveryResult(self.name, False, "no webhook url configured")

        try:
            import aiohttp
        except ImportError:
            return DeliveryResult(self.name, False, "aiohttp not installed")

        # Summary only — deliberately excludes raw event data.
        payload = {
            "source": "behaveguard",
            "process_name": alert.process_name,
            "pid": alert.pid,
            "score": alert.score,
            "severity": alert.severity,
            "explanation": alert.explanation,
            "timestamp_ns": alert.timestamp_ns,
        }
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(self.url, json=payload) as resp:
                    ok = 200 <= resp.status < 300
                    return DeliveryResult(self.name, ok, f"HTTP {resp.status}")
        except Exception as exc:  # noqa: BLE001 - network errors must not crash routing
            return DeliveryResult(self.name, False, str(exc))
