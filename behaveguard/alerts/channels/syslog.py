"""System log (syslog) alert channel.

Emits alerts to the local syslog via :class:`logging.handlers.SysLogHandler`
(standard library, so this module imports everywhere). The blocking handler emit
is run in a worker thread. On hosts without a reachable syslog socket the send
degrades to a failed :class:`DeliveryResult` rather than raising.
"""

from __future__ import annotations

import asyncio
import logging
import logging.handlers
import os
from typing import Optional, Tuple, Union

from behaveguard.alerts.alert_types import Alert, DeliveryResult

Address = Union[str, Tuple[str, int]]


class SyslogChannel:
    """Delivers alerts to the local syslog daemon."""

    name = "syslog"

    def __init__(self, address: Optional[Address] = None) -> None:
        if address is not None:
            self.address: Address = address
        else:
            # Unix domain socket on POSIX; UDP localhost elsewhere.
            self.address = "/dev/log" if os.name == "posix" else ("localhost", 514)
        self._logger: Optional[logging.Logger] = None

    def _get_logger(self) -> logging.Logger:
        if self._logger is not None:
            return self._logger
        logger = logging.getLogger("behaveguard.syslog")
        logger.setLevel(logging.WARNING)
        logger.propagate = False
        if not logger.handlers:
            handler = logging.handlers.SysLogHandler(address=self.address)
            handler.setFormatter(logging.Formatter("behaveguard: %(message)s"))
            logger.addHandler(handler)
        self._logger = logger
        return logger

    async def send(self, alert: Alert) -> DeliveryResult:
        """Emit ``alert`` to syslog at WARNING severity."""

        def _emit() -> None:
            logger = self._get_logger()
            logger.warning(
                "%s alert: %s (pid %d) score=%.1f - %s",
                alert.severity,
                alert.process_name,
                alert.pid,
                alert.score,
                alert.explanation,
            )

        try:
            await asyncio.to_thread(_emit)
            return DeliveryResult(self.name, True, "emitted")
        except Exception as exc:  # noqa: BLE001 - missing /dev/log etc.
            return DeliveryResult(self.name, False, str(exc))
