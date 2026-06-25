"""Real-time Dash dashboard for BehaveGuard.

The dashboard is a thin presentation layer over the REST API: it polls the API
every few seconds (``dcc.Interval``) and renders the results with Plotly. Dash is
imported lazily by :func:`create_dashboard` so importing this package does not
require the dashboard stack.
"""

from __future__ import annotations

from typing import Any, Optional


def create_dashboard(
    api_base_url: str = "http://localhost:8888",
    api_token: Optional[str] = None,
    update_interval_ms: int = 5000,
) -> Any:
    """Lazily build and return the Dash application."""
    from behaveguard.dashboard.app import create_dashboard as _create

    return _create(api_base_url, api_token, update_interval_ms)


__all__ = ["create_dashboard"]
