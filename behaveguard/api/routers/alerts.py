"""Alert management endpoints: list, detail, acknowledge, and suppress."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Optional

from fastapi import APIRouter, HTTPException, Query, Request

from behaveguard.alerts.alert_types import alert_to_dict
from behaveguard.alerts.rules_engine import SuppressionRule
from behaveguard.api.schemas import (
    AcknowledgeRequest,
    AlertListResponse,
    AlertOut,
    SimpleStatusResponse,
    SuppressRequest,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from behaveguard.api.server import AppState

router = APIRouter()


def _to_out(alert) -> AlertOut:
    return AlertOut(**alert_to_dict(alert))


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    request: Request,
    severity: Optional[str] = Query(default=None),
    process_name: Optional[str] = Query(default=None),
    acknowledged: Optional[bool] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> AlertListResponse:
    """List alerts with optional severity/process/ack filters."""
    state: "AppState" = request.app.state.bg
    alerts = await state.alert_store.list_alerts(
        severity=severity,
        process_name=process_name,
        acknowledged=acknowledged,
        limit=limit,
        offset=offset,
    )
    unacked = await state.alert_store.count_unacknowledged()
    return AlertListResponse(
        alerts=[_to_out(a) for a in alerts],
        total=len(alerts),
        unacknowledged=unacked,
    )


@router.get("/{alert_id}", response_model=AlertOut)
async def get_alert(request: Request, alert_id: int) -> AlertOut:
    """Fetch a single alert (with its explanation) by id."""
    state: "AppState" = request.app.state.bg
    alert = await state.alert_store.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail=f"alert {alert_id} not found")
    return _to_out(alert)


@router.post("/{alert_id}/acknowledge", response_model=SimpleStatusResponse)
async def acknowledge_alert(
    request: Request, alert_id: int, body: AcknowledgeRequest
) -> SimpleStatusResponse:
    """Acknowledge an alert, optionally attaching a note."""
    state: "AppState" = request.app.state.bg
    ok = await state.alert_store.acknowledge(alert_id, body.note)
    if not ok:
        raise HTTPException(status_code=404, detail=f"alert {alert_id} not found")
    return SimpleStatusResponse(status="acknowledged", detail=f"alert {alert_id}")


@router.post("/suppress", response_model=SimpleStatusResponse)
async def suppress(request: Request, body: SuppressRequest) -> SimpleStatusResponse:
    """Add a suppression rule for a process to filter known false positives."""
    state: "AppState" = request.app.state.bg
    expires: Optional[datetime] = None
    if body.expires_at:
        try:
            expires = datetime.fromisoformat(body.expires_at)
        except ValueError:
            raise HTTPException(status_code=422, detail="expires_at must be ISO-8601")

    rule = SuppressionRule(
        process_name=body.process_name,
        reason=body.reason,
        max_score_suppress=body.max_score_suppress,
        expires_at=expires,
        created_by=body.created_by,
    )
    state.rules_engine.add_rule(rule)
    try:
        state.rules_engine.save()
    except Exception:  # noqa: BLE001 - persistence is best-effort
        pass
    return SimpleStatusResponse(status="suppressed", detail=body.process_name)
