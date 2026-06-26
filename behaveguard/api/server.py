"""FastAPI application: REST API + real-time WebSocket alert stream.

The app exposes a shared :class:`AppState` (config, stores, scorer, alert
manager, training jobs) on ``app.state.bg`` that the routers read. Security
follows the project policy:

* a Bearer token (generated on init, read from ``BEHAVEGUARD_API_TOKEN``) guards
  every ``/api/v1`` route and the WebSocket;
* a lightweight in-memory rate limiter caps requests per client IP.

The torch-backed scorer and the eBPF collector are created lazily/optionally so
that importing this module — and running the health endpoint — never requires
torch or BCC.
"""

from __future__ import annotations

import os
import secrets
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, AsyncIterator, Deque, Dict, Optional

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import JSONResponse

from behaveguard import __version__
from behaveguard.alerts.alert_types import alert_to_dict

if TYPE_CHECKING:  # pragma: no cover - typing only
    from behaveguard.alerts.alert_manager import AlertManager
    from behaveguard.config.settings import Settings
    from behaveguard.storage.alert_store import AlertStore
    from behaveguard.storage.event_store import EventStore

# Requests allowed per client IP within the rolling window (project policy: 100/min).
RATE_LIMIT_MAX = 100
RATE_LIMIT_WINDOW = 60.0


class AppState:
    """Shared application state attached to ``app.state.bg``."""

    def __init__(self, config: "Settings") -> None:
        self.config = config
        self.started_at = time.monotonic()
        self.api_token: str = os.environ.get("BEHAVEGUARD_API_TOKEN") or secrets.token_hex(16)

        # Stores are pure-stdlib and safe to construct eagerly.
        from behaveguard.storage.alert_store import AlertStore
        from behaveguard.storage.event_store import EventStore
        from behaveguard.storage.model_registry import ModelRegistry

        self.event_store: "EventStore" = EventStore(config)
        self.alert_store: "AlertStore" = AlertStore(config)
        self.model_registry = ModelRegistry()

        # Suppression rules + alert manager (no torch needed).
        from behaveguard.alerts.alert_manager import AlertManager
        from behaveguard.alerts.channels import build_channels
        from behaveguard.alerts.rules_engine import RulesEngine

        self.rules_engine = RulesEngine()
        try:
            self.rules_engine.load()
        except Exception:  # noqa: BLE001 - missing/þunreadable rules file is fine
            pass
        self.alert_manager: "AlertManager" = AlertManager(
            config, build_channels(config), self.rules_engine, self.alert_store
        )

        # In-memory training job registry (job_id -> status dict).
        self.train_jobs: Dict[str, Dict[str, Any]] = {}

        # Per-IP request timestamps for rate limiting.
        self._rate: Dict[str, Deque[float]] = defaultdict(deque)

    def uptime(self) -> float:
        return time.monotonic() - self.started_at

    def check_rate(self, client: str) -> bool:
        """Return True if a request from ``client`` is within the rate limit."""
        now = time.monotonic()
        bucket = self._rate[client]
        cutoff = now - RATE_LIMIT_WINDOW
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= RATE_LIMIT_MAX:
            return False
        bucket.append(now)
        return True


def _extract_token(request: Request) -> Optional[str]:
    """Pull a Bearer token from the Authorization header, if present."""
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return None


def create_app(config: Optional["Settings"] = None) -> FastAPI:
    """Build and return the configured FastAPI application."""
    if config is None:
        from behaveguard.config.settings import get_settings

        config = get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        state: AppState = app.state.bg
        await state.event_store.initialize()
        await state.alert_store.initialize()
        yield
        # Nothing to tear down explicitly; sqlite connections are per-call.

    app = FastAPI(
        title="BehaveGuard API",
        description="Runtime behavioral anomaly detection for Linux processes",
        version=__version__,
        lifespan=lifespan,
    )
    app.state.bg = AppState(config)

    # ------------------------------------------------------------------ #
    # Cross-cutting middleware: auth + rate limit for /api/v1 routes.
    # ------------------------------------------------------------------ #
    @app.middleware("http")
    async def _guard(request: Request, call_next: Any) -> Any:
        path = request.url.path
        # Liveness is unauthenticated so orchestrators can probe it; everything
        # else under /api/v1 requires the Bearer token.
        protected = path.startswith("/api/v1") and path != "/api/v1/health"

        client = request.client.host if request.client else "unknown"
        if not request.app.state.bg.check_rate(client):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "rate limit exceeded"},
            )

        if protected:
            token = _extract_token(request)
            if not token or not secrets.compare_digest(token, request.app.state.bg.api_token):
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "missing or invalid bearer token"},
                )
        return await call_next(request)

    # ------------------------------------------------------------------ #
    # Routers
    # ------------------------------------------------------------------ #
    from behaveguard.api.routers import alerts, health, models, processes

    app.include_router(health.router, prefix="/api/v1/health", tags=["health"])
    app.include_router(processes.router, prefix="/api/v1/processes", tags=["processes"])
    app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["alerts"])
    app.include_router(models.router, prefix="/api/v1/models", tags=["models"])

    # ------------------------------------------------------------------ #
    # WebSocket: real-time alert stream.
    # ------------------------------------------------------------------ #
    @app.websocket("/ws/alerts")
    async def alert_stream(websocket: WebSocket) -> None:
        """Stream alerts to a client in real time.

        The Bearer token is supplied via the ``token`` query parameter (browsers
        cannot set WebSocket headers). The socket is accepted only after the
        token validates.
        """
        state: AppState = websocket.app.state.bg
        token = websocket.query_params.get("token", "")
        if not token or not secrets.compare_digest(token, state.api_token):
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        await websocket.accept()
        queue = state.alert_manager.subscribe()
        try:
            while True:
                alert = await queue.get()
                await websocket.send_json(alert_to_dict(alert))
        except WebSocketDisconnect:
            pass
        finally:
            state.alert_manager.unsubscribe(queue)

    return app


# Module-level app for ``uvicorn behaveguard.api.server:app``.
app = create_app()
