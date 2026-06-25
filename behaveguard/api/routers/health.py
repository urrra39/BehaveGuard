"""Health and metrics endpoints."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse

from behaveguard import __version__
from behaveguard.api.schemas import HealthResponse

if TYPE_CHECKING:  # pragma: no cover - typing only
    from behaveguard.api.server import AppState

router = APIRouter()


@router.get("", response_model=HealthResponse)
@router.get("/", response_model=HealthResponse)
async def health(request: Request) -> HealthResponse:
    """Liveness probe. Returns ``status: ok`` plus version and uptime."""
    state: "AppState" = request.app.state.bg
    return HealthResponse(status="ok", version=__version__, uptime_seconds=state.uptime())


@router.get("/metrics", response_class=PlainTextResponse)
async def metrics(request: Request) -> str:
    """Prometheus-format metrics for the alert funnel and uptime."""
    state: "AppState" = request.app.state.bg
    funnel = state.alert_manager.metrics()
    lines = [
        "# HELP behaveguard_uptime_seconds Process uptime in seconds.",
        "# TYPE behaveguard_uptime_seconds gauge",
        f"behaveguard_uptime_seconds {state.uptime():.3f}",
    ]
    for key, value in funnel.items():
        lines.append(f"# TYPE behaveguard_{key} counter")
        lines.append(f"behaveguard_{key} {value}")
    return "\n".join(lines) + "\n"
