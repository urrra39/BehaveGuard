"""Process view tab: per-process behavior graphs (syscalls, network, files)."""

from __future__ import annotations

from typing import Any


def layout() -> Any:
    """Build the per-process detail layout."""
    import dash_bootstrap_components as dbc
    from dash import dcc, html

    return dbc.Container(
        [
            dbc.Row(
                dbc.Col(
                    [
                        html.Label("Select process (PID)"),
                        dcc.Dropdown(id="process-selector", options=[], placeholder="PID…"),
                    ],
                    width=4,
                ),
                className="my-3",
            ),
            dbc.Row(
                [
                    dbc.Col(dbc.Card(dbc.CardBody([
                        html.H5("Syscall frequency"),
                        dcc.Graph(id="proc-syscall-freq"),
                    ])), width=6),
                    dbc.Col(dbc.Card(dbc.CardBody([
                        html.H5("Anomaly score history"),
                        dcc.Graph(id="proc-score-history"),
                    ])), width=6),
                ]
            ),
            dbc.Row(
                [
                    dbc.Col(dbc.Card(dbc.CardBody([
                        html.H5("Event type breakdown"),
                        dcc.Graph(id="proc-event-breakdown"),
                    ])), width=6),
                    dbc.Col(dbc.Card(dbc.CardBody([
                        html.H5("Recent file accesses"),
                        html.Div(id="proc-file-table"),
                    ])), width=6),
                ]
            ),
        ],
        fluid=True,
    )
