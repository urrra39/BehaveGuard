"""Models tab: per-process model performance and training-job status."""

from __future__ import annotations

from typing import Any


def layout() -> Any:
    """Build the model statistics layout."""
    import dash_bootstrap_components as dbc
    from dash import dcc, html

    return dbc.Container(
        [
            dbc.Row(
                dbc.Col(dbc.Card(dbc.CardBody([
                    html.H5("Trained model baselines"),
                    html.Div(id="model-table"),
                ]))),
                className="my-3",
            ),
            dbc.Row(
                [
                    dbc.Col(dbc.Card(dbc.CardBody([
                        html.H5("Per-model anomaly threshold"),
                        dcc.Graph(id="model-threshold-chart"),
                    ])), width=6),
                    dbc.Col(dbc.Card(dbc.CardBody([
                        html.H5("Training jobs"),
                        html.Div(id="training-jobs-table"),
                    ])), width=6),
                ]
            ),
        ],
        fluid=True,
    )
