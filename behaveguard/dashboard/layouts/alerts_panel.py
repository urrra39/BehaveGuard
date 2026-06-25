"""Alerts tab: real-time scrolling alert feed with severity colouring."""

from __future__ import annotations

from typing import Any


def layout() -> Any:
    """Build the alert feed layout (populated by callbacks every interval)."""
    import dash_bootstrap_components as dbc
    from dash import dcc, html

    return dbc.Container(
        [
            dbc.Row(
                [
                    dbc.Col(html.H5("Real-time alert feed"), width=8),
                    dbc.Col(
                        dcc.Dropdown(
                            id="alert-severity-filter",
                            options=[
                                {"label": s, "value": s}
                                for s in ("ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL")
                            ],
                            value="ALL",
                            clearable=False,
                        ),
                        width=4,
                    ),
                ],
                className="my-3",
            ),
            dbc.Row(
                dbc.Col(
                    html.Div(
                        id="alerts-feed",
                        style={"maxHeight": "70vh", "overflowY": "auto"},
                    )
                )
            ),
        ],
        fluid=True,
    )
