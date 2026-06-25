"""Alert delivery channels.

A channel is anything matching the :class:`AlertChannel` protocol: a ``name`` and
an ``async send(alert) -> DeliveryResult``. The concrete channels (webhook,
email, syslog) match it structurally without importing this package, so there is
no circular import. :func:`build_channels` constructs the enabled channels from a
settings object.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, List, Protocol, runtime_checkable

from behaveguard.alerts.alert_types import Alert, DeliveryResult
from behaveguard.alerts.channels.email_notifier import EmailChannel
from behaveguard.alerts.channels.syslog import SyslogChannel
from behaveguard.alerts.channels.webhook import WebhookChannel

if TYPE_CHECKING:  # pragma: no cover - typing only
    from behaveguard.config.settings import Settings


@runtime_checkable
class AlertChannel(Protocol):
    """Structural type every alert channel satisfies."""

    name: str

    async def send(self, alert: Alert) -> DeliveryResult:
        ...


def build_channels(config: "Settings") -> List[AlertChannel]:
    """Construct the enabled alert channels from configuration.

    Reads ``config.alerts.channels`` (a list of ``{type: ...}`` dicts). A webhook
    channel uses its own ``url`` or falls back to ``config.effective_webhook_url``;
    a syslog channel is included unless explicitly disabled; an email channel is
    built from its SMTP fields.
    """
    channels: List[AlertChannel] = []
    fallback_webhook = getattr(config, "effective_webhook_url", None)

    for entry in getattr(config.alerts, "channels", []) or []:
        ctype = entry.get("type")
        if ctype == "webhook":
            url = entry.get("url") or fallback_webhook
            if url:
                channels.append(WebhookChannel(url=url))
        elif ctype == "syslog":
            if entry.get("enabled", True):
                channels.append(SyslogChannel(address=entry.get("address")))
        elif ctype == "email":
            channels.append(
                EmailChannel(
                    host=entry.get("host", "localhost"),
                    port=int(entry.get("port", 587)),
                    username=entry.get("username"),
                    password=entry.get("password"),
                    from_addr=entry.get("from_addr"),
                    to_addrs=entry.get("to_addrs", []),
                    use_tls=bool(entry.get("use_tls", True)),
                )
            )
    return channels


__all__ = [
    "AlertChannel",
    "WebhookChannel",
    "EmailChannel",
    "SyslogChannel",
    "build_channels",
]
