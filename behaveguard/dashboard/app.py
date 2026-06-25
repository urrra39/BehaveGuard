"""Dash application assembly and the REST API data client.

The dashboard never touches the detector internals directly — it reads everything
through the BehaveGuard REST API, so it can run on a different host. The data
client uses only the standard library (``urllib``) so it adds no dependencies of
its own beyond Dash/Plotly.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional


class DashboardDataClient:
    """Minimal REST client the dashboard polls for live data."""

    def __init__(self, base_url: str = "http://localhost:8888", token: Optional[str] = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token

    def _get(self, path: str) -> Any:
        """GET ``path`` and return parsed JSON, or ``None`` on any failure."""
        url = f"{self.base_url}{path}"
        request = urllib.request.Request(url)
        if self.token:
            request.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(request, timeout=4) as response:
                return json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError):
            return None

    def processes(self) -> List[Dict[str, Any]]:
        data = self._get("/api/v1/processes")
        return data.get("processes", []) if isinstance(data, dict) else []

    def process_detail(self, pid: int) -> Dict[str, Any]:
        return self._get(f"/api/v1/processes/{pid}") or {}

    def process_events(self, pid: int) -> List[Dict[str, Any]]:
        data = self._get(f"/api/v1/processes/{pid}/events")
        return data.get("events", []) if isinstance(data, dict) else []

    def alerts(self, limit: int = 50) -> Dict[str, Any]:
        return self._get(f"/api/v1/alerts?limit={limit}") or {"alerts": [], "unacknowledged": 0}

    def models(self) -> List[Dict[str, Any]]:
        data = self._get("/api/v1/models/list")
        return data.get("models", []) if isinstance(data, dict) else []

    def training_jobs(self) -> List[Dict[str, Any]]:
        data = self._get("/api/v1/models/status")
        return data.get("jobs", []) if isinstance(data, dict) else []


def create_dashboard(
    api_base_url: str = "http://localhost:8888",
    api_token: Optional[str] = None,
    update_interval_ms: int = 5000,
) -> Any:
    """Build the Dash app with tabbed layout and a periodic refresh."""
    import dash
    import dash_bootstrap_components as dbc
    from dash import dcc, html

    from behaveguard.dashboard.callbacks import register_callbacks
    from behaveguard.dashboard.layouts import (
        alerts_panel,
        model_stats,
        overview,
        process_view,
    )

    client = DashboardDataClient(api_base_url, api_token)
    app = dash.Dash(
        __name__,
        external_stylesheets=[dbc.themes.DARKLY],
        title="BehaveGuard",
        update_title=None,
    )

    app.layout = dbc.Container(
        [
            dbc.Row(
                dbc.Col(
                    html.H2("🛡️ BehaveGuard — Runtime Behavioral Anomaly Detection"),
                    className="my-3",
                )
            ),
            dcc.Interval(id="refresh", interval=update_interval_ms, n_intervals=0),
            dcc.Store(id="selected-pid"),
            dbc.Tabs(
                [
                    dbc.Tab(overview.layout(), label="Overview", tab_id="overview"),
                    dbc.Tab(process_view.layout(), label="Processes", tab_id="processes"),
                    dbc.Tab(alerts_panel.layout(), label="Alerts", tab_id="alerts"),
                    dbc.Tab(model_stats.layout(), label="Models", tab_id="models"),
                ],
                id="tabs",
                active_tab="overview",
            ),
        ],
        fluid=True,
    )

    register_callbacks(app, client)
    return app


def main() -> None:
    """Run the dashboard server (used by ``behaveguard run``)."""
    host = os.environ.get("BEHAVEGUARD_DASHBOARD_HOST", "0.0.0.0")
    port = int(os.environ.get("BEHAVEGUARD_DASHBOARD_PORT", "8050"))
    api = os.environ.get("BEHAVEGUARD_API_URL", "http://localhost:8888")
    token = os.environ.get("BEHAVEGUARD_API_TOKEN")
    app = create_dashboard(api_base_url=api, api_token=token)
    app.run(host=host, port=port)


if __name__ == "__main__":
    main()
