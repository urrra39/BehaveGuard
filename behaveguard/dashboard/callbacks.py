"""Dash callbacks that refresh every tab from the REST API on a timer.

All callbacks are driven by the shared ``dcc.Interval`` (id ``refresh``) so the
whole UI updates on one cadence. Each callback fetches from the injected
:class:`~behaveguard.dashboard.app.DashboardDataClient`, builds Plotly figures,
and degrades to empty figures when the API is unreachable.
"""

from __future__ import annotations

from typing import Any, Dict, List

# Severity -> colour for consistent visual encoding across the dashboard.
SEVERITY_COLORS = {
    "LOW": "#2dce89",
    "MEDIUM": "#fb6340",
    "HIGH": "#f5365c",
    "CRITICAL": "#8b0000",
}
SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

EVENT_TYPE_NAMES = {
    1: "syscall", 2: "network", 3: "file", 4: "process",
    5: "injection", 6: "container", 7: "lolbin", 8: "antiforensic", 9: "dns_tunnel",
}


def _empty_figure(message: str = "no data") -> Any:
    import plotly.graph_objects as go

    fig = go.Figure()
    fig.add_annotation(text=message, showarrow=False, font={"size": 16})
    fig.update_layout(template="plotly_dark", margin={"l": 20, "r": 20, "t": 30, "b": 20})
    return fig


def register_callbacks(app: Any, client: Any) -> None:
    """Wire every tab's refresh callback onto ``app`` using ``client`` for data."""
    import plotly.graph_objects as go
    from dash import Input, Output, html

    # ------------------------------------------------------------------ #
    # Overview
    # ------------------------------------------------------------------ #
    @app.callback(
        Output("overview-heatmap", "figure"),
        Output("top-procs", "figure"),
        Output("ov-proc-count", "children"),
        Output("ov-alert-count", "children"),
        Output("ov-model-count", "children"),
        Output("ov-max-severity", "children"),
        Input("refresh", "n_intervals"),
    )
    def _update_overview(_n: int):
        processes = client.processes()
        alerts = client.alerts()
        models = client.models()

        if processes:
            labels = [f"{p.get('comm', '?')}:{p.get('pid', 0)}" for p in processes]
            scores = [float(p.get("latest_score", 0.0)) for p in processes]
            heatmap = go.Figure(
                go.Heatmap(z=[scores], x=labels, y=["score"], zmin=0, zmax=100,
                           colorscale="Inferno")
            )
            heatmap.update_layout(template="plotly_dark",
                                  margin={"l": 40, "r": 20, "t": 30, "b": 80})

            ranked = sorted(processes, key=lambda p: float(p.get("latest_score", 0.0)),
                            reverse=True)[:10]
            top = go.Figure(
                go.Bar(
                    x=[float(p.get("latest_score", 0.0)) for p in ranked][::-1],
                    y=[f"{p.get('comm', '?')}:{p.get('pid', 0)}" for p in ranked][::-1],
                    orientation="h",
                    marker_color=[SEVERITY_COLORS.get(p.get("latest_severity", "LOW"), "#5e72e4")
                                  for p in ranked][::-1],
                )
            )
            top.update_layout(template="plotly_dark", xaxis_title="anomaly score",
                              margin={"l": 120, "r": 20, "t": 30, "b": 40})
        else:
            heatmap = _empty_figure("no monitored processes")
            top = _empty_figure("no monitored processes")

        max_sev = "LOW"
        for proc in processes:
            sev = proc.get("latest_severity", "LOW")
            if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(max_sev, 0):
                max_sev = sev

        return (
            heatmap,
            top,
            str(len(processes)),
            str(alerts.get("unacknowledged", 0)),
            str(len(models)),
            max_sev,
        )

    # ------------------------------------------------------------------ #
    # Process selector + per-process view
    # ------------------------------------------------------------------ #
    @app.callback(Output("process-selector", "options"), Input("refresh", "n_intervals"))
    def _update_selector(_n: int):
        return [
            {"label": f"{p.get('comm', '?')} (pid {p.get('pid', 0)})", "value": p.get("pid", 0)}
            for p in client.processes()
        ]

    @app.callback(
        Output("proc-syscall-freq", "figure"),
        Output("proc-score-history", "figure"),
        Output("proc-event-breakdown", "figure"),
        Output("proc-file-table", "children"),
        Input("process-selector", "value"),
        Input("refresh", "n_intervals"),
    )
    def _update_process(pid: Any, _n: int):
        if pid is None:
            empty = _empty_figure("select a process")
            return empty, empty, empty, html.Div("select a process")

        detail = client.process_detail(int(pid))
        events = client.process_events(int(pid))

        # Syscall frequency.
        syscall_counts: Dict[str, int] = {}
        event_counts: Dict[str, int] = {}
        file_rows: List[Any] = []
        for ev in events:
            etype = EVENT_TYPE_NAMES.get(int(ev.get("event_type", 0)), "other")
            event_counts[etype] = event_counts.get(etype, 0) + 1
            detail_fields = ev.get("detail", {})
            if etype == "syscall":
                name = detail_fields.get("syscall_name", "unknown")
                syscall_counts[name] = syscall_counts.get(name, 0) + 1
            elif etype == "file":
                file_rows.append((detail_fields.get("operation", "?"),
                                  detail_fields.get("path", "")))

        if syscall_counts:
            top_sys = sorted(syscall_counts.items(), key=lambda kv: kv[1], reverse=True)[:15]
            syscall_fig = go.Figure(go.Bar(x=[c for _, c in top_sys],
                                           y=[n for n, _ in top_sys], orientation="h"))
            syscall_fig.update_layout(template="plotly_dark",
                                      margin={"l": 100, "r": 20, "t": 20, "b": 40})
        else:
            syscall_fig = _empty_figure("no syscalls")

        history = detail.get("score_history", [])
        if history:
            score_fig = go.Figure(go.Scatter(
                x=[h["timestamp_ns"] for h in history],
                y=[h["score"] for h in history], mode="lines+markers"))
            score_fig.update_layout(template="plotly_dark", yaxis_range=[0, 100],
                                    margin={"l": 40, "r": 20, "t": 20, "b": 40})
        else:
            score_fig = _empty_figure("no score history")

        if event_counts:
            breakdown = go.Figure(go.Pie(labels=list(event_counts.keys()),
                                         values=list(event_counts.values()), hole=0.4))
            breakdown.update_layout(template="plotly_dark",
                                    margin={"l": 20, "r": 20, "t": 20, "b": 20})
        else:
            breakdown = _empty_figure("no events")

        table = html.Table(
            [html.Tr([html.Th("op"), html.Th("path")])]
            + [html.Tr([html.Td(op), html.Td(path)]) for op, path in file_rows[-15:]],
            style={"width": "100%"},
        )
        return syscall_fig, score_fig, breakdown, table

    # ------------------------------------------------------------------ #
    # Alerts feed
    # ------------------------------------------------------------------ #
    @app.callback(
        Output("alerts-feed", "children"),
        Input("refresh", "n_intervals"),
        Input("alert-severity-filter", "value"),
    )
    def _update_alerts(_n: int, severity_filter: str):
        alerts = client.alerts(limit=100).get("alerts", [])
        if severity_filter and severity_filter != "ALL":
            alerts = [a for a in alerts if a.get("severity") == severity_filter]
        if not alerts:
            return html.Div("no alerts")

        cards = []
        for alert in alerts:
            sev = alert.get("severity", "LOW")
            cards.append(
                html.Div(
                    [
                        html.Strong(f"[{sev}] {alert.get('process_name', '?')} "
                                    f"(pid {alert.get('pid', 0)}) — score "
                                    f"{alert.get('score', 0):.0f}/100"),
                        html.Div(alert.get("explanation", ""), style={"fontSize": "0.9em"}),
                        html.Small("acknowledged" if alert.get("acknowledged") else "unacknowledged"),
                    ],
                    style={
                        "borderLeft": f"5px solid {SEVERITY_COLORS.get(sev, '#5e72e4')}",
                        "padding": "8px", "margin": "6px 0", "background": "#1f2233",
                    },
                )
            )
        return cards

    # ------------------------------------------------------------------ #
    # Model stats
    # ------------------------------------------------------------------ #
    @app.callback(
        Output("model-table", "children"),
        Output("model-threshold-chart", "figure"),
        Output("training-jobs-table", "children"),
        Input("refresh", "n_intervals"),
    )
    def _update_models(_n: int):
        models = client.models()
        jobs = client.training_jobs()

        if models:
            model_table = html.Table(
                [html.Tr([html.Th("process"), html.Th("threshold"), html.Th("windows")])]
                + [
                    html.Tr([
                        html.Td(m.get("process_name", "?")),
                        html.Td(f"{m.get('metadata', {}).get('threshold', 0):.3f}"),
                        html.Td(str(m.get("metadata", {}).get("num_windows", 0))),
                    ])
                    for m in models
                ],
                style={"width": "100%"},
            )
            thr_fig = go.Figure(go.Bar(
                x=[m.get("process_name", "?") for m in models],
                y=[float(m.get("metadata", {}).get("threshold", 0.0)) for m in models],
            ))
            thr_fig.update_layout(template="plotly_dark",
                                  margin={"l": 40, "r": 20, "t": 20, "b": 60})
        else:
            model_table = html.Div("no trained models")
            thr_fig = _empty_figure("no trained models")

        if jobs:
            jobs_table = html.Table(
                [html.Tr([html.Th("job"), html.Th("process"), html.Th("state")])]
                + [
                    html.Tr([html.Td(j.get("job_id", "")[:8]),
                             html.Td(j.get("process_name", "?")),
                             html.Td(j.get("state", "?"))])
                    for j in jobs
                ],
                style={"width": "100%"},
            )
        else:
            jobs_table = html.Div("no training jobs")

        return model_table, thr_fig, jobs_table
