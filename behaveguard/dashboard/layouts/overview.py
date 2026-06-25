"""Overview tab: system-wide anomaly heatmap and top suspicious processes."""

from __future__ import annotations

from typing import Any


def layout() -> Any:
    """Build the overview layout (graphs are populated by callbacks)."""
    import dash_bootstrap_components as dbc
    from dash import dcc, html

    summary_cards = dbc.Row(
        [
            dbc.Col(dbc.Card(dbc.CardBody([html.H6("Monitored processes"),
                                           html.H3(id="ov-proc-count", children="0")])), width=3),
            dbc.Col(dbc.Card(dbc.CardBody([html.H6("Unacknowledged alerts"),
                                           html.H3(id="ov-alert-count", children="0")])), width=3),
            dbc.Col(dbc.Card(dbc.CardBody([html.H6("Trained models"),
                                           html.H3(id="ov-model-count", children="0")])), width=3),
            dbc.Col(dbc.Card(dbc.CardBody([html.H6("Max severity"),
                                           html.H3(id="ov-max-severity", children="LOW")])), width=3),
        ],
        className="my-3",
    )

    return dbc.Container(
        [
            summary_cards,
            dbc.Row(
                [
                    dbc.Col(
                        dbc.Card(dbc.CardBody([
                            html.H5("Process anomaly heatmap"),
                            dcc.Graph(id="overview-heatmap"),
                        ])),
                        width=7,
                    ),
                    dbc.Col(
                        dbc.Card(dbc.CardBody([
                            html.H5("Top suspicious processes"),
                            dcc.Graph(id="top-procs"),
                        ])),
                        width=5,
                    ),
                ]
            ),
        ],
        fluid=True,
    )
