"""BehaveGuard REST API + WebSocket server (FastAPI).

The application factory and module-level ``app`` live in
:mod:`behaveguard.api.server`. Importing this package does not eagerly import
FastAPI; callers ask for the app explicitly via :func:`create_app`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:  # pragma: no cover - typing only
    from behaveguard.config.settings import Settings


def create_app(config: "Optional[Settings]" = None) -> Any:
    """Lazily build the FastAPI app (so importing the package needs no FastAPI)."""
    from behaveguard.api.server import create_app as _create_app

    return _create_app(config)


__all__ = ["create_app"]
