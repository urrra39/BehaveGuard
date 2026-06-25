"""SMTP email alert channel.

Sends a concise email summary of an alert via ``aiosmtplib`` (imported lazily).
A missing dependency or SMTP failure degrades to a failed :class:`DeliveryResult`
rather than raising, so one bad channel never breaks alert routing.
"""

from __future__ import annotations

from typing import List, Optional

from behaveguard.alerts.alert_types import Alert, DeliveryResult


class EmailChannel:
    """Delivers alerts as SMTP email."""

    name = "email"

    def __init__(
        self,
        host: str,
        port: int = 587,
        username: Optional[str] = None,
        password: Optional[str] = None,
        from_addr: Optional[str] = None,
        to_addrs: Optional[List[str]] = None,
        use_tls: bool = True,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.from_addr = from_addr or (username or "behaveguard@localhost")
        self.to_addrs = to_addrs or []
        self.use_tls = use_tls

    async def send(self, alert: Alert) -> DeliveryResult:
        """Send ``alert`` as an email to the configured recipients."""
        if not self.to_addrs:
            return DeliveryResult(self.name, False, "no recipients configured")

        try:
            import aiosmtplib
        except ImportError:
            return DeliveryResult(self.name, False, "aiosmtplib not installed")

        from email.message import EmailMessage

        message = EmailMessage()
        message["From"] = self.from_addr
        message["To"] = ", ".join(self.to_addrs)
        message["Subject"] = (
            f"[BehaveGuard {alert.severity}] {alert.process_name} "
            f"(pid {alert.pid}) score {alert.score:.0f}"
        )
        message.set_content(
            f"Process : {alert.process_name} (pid {alert.pid})\n"
            f"Severity: {alert.severity}\n"
            f"Score   : {alert.score:.1f}/100\n"
            f"Reason  : {alert.explanation}\n"
        )

        try:
            await aiosmtplib.send(
                message,
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                start_tls=self.use_tls,
            )
            return DeliveryResult(self.name, True, "sent")
        except Exception as exc:  # noqa: BLE001 - SMTP errors must not crash routing
            return DeliveryResult(self.name, False, str(exc))
