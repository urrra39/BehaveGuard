"""Process monitoring endpoints: list processes, detail, and raw event feed."""

from __future__ import annotations

from dataclasses import fields
from typing import TYPE_CHECKING, List

from fastapi import APIRouter, Query, Request

from behaveguard.api.schemas import (
    EventFeedResponse,
    EventOut,
    ProcessDetailResponse,
    ProcessListResponse,
    ProcessSummary,
    ScorePoint,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from behaveguard.api.server import AppState

router = APIRouter()

# Widest practical time bound (ns); event timestamps are monotonic ns.
_TS_MAX = 1 << 63


def _event_to_out(event) -> EventOut:
    """Flatten a typed event dataclass into the API event shape."""
    detail = {}
    for f in fields(event):
        if f.name in ("timestamp_ns", "pid", "comm", "event_type"):
            continue
        detail[f.name] = getattr(event, f.name)
    return EventOut(
        timestamp_ns=int(event.timestamp_ns),
        event_type=int(event.event_type),
        pid=int(getattr(event, "pid", 0)),
        comm=str(getattr(event, "comm", "")),
        detail=detail,
    )


@router.get("", response_model=ProcessListResponse)
async def list_processes(request: Request) -> ProcessListResponse:
    """List monitored processes seen by the live collector (if running).

    The collector is optional: when it is not attached (e.g. off-Linux, or the
    daemon isn't running) an empty list is returned rather than erroring.
    """
    state: "AppState" = request.app.state.bg
    summaries: List[ProcessSummary] = []

    collector = getattr(state, "collector", None)
    window_mgr = getattr(state, "window_manager", None)
    if window_mgr is not None:
        for pid in window_mgr.get_all_pids():
            window = window_mgr.get_window(pid)
            if window is None:
                continue
            events = window.get_events()
            comm = events[-1].comm if events else ""
            last_seen = max((int(e.timestamp_ns) for e in events), default=0)
            summaries.append(
                ProcessSummary(
                    pid=pid,
                    comm=comm,
                    event_count=len(events),
                    last_seen_ns=last_seen,
                )
            )
    return ProcessListResponse(processes=summaries, total=len(summaries))


@router.get("/{pid}", response_model=ProcessDetailResponse)
async def process_detail(request: Request, pid: int) -> ProcessDetailResponse:
    """Return per-process detail including any recorded score history."""
    state: "AppState" = request.app.state.bg
    history: List[ScorePoint] = []
    score_log = getattr(state, "score_history", {})
    for point in score_log.get(pid, []):
        history.append(
            ScorePoint(
                timestamp_ns=int(point["timestamp_ns"]),
                score=float(point["score"]),
                severity=str(point["severity"]),
            )
        )

    comm = ""
    event_count = 0
    window_mgr = getattr(state, "window_manager", None)
    if window_mgr is not None:
        window = window_mgr.get_window(pid)
        if window is not None:
            events = window.get_events()
            event_count = len(events)
            comm = events[-1].comm if events else ""

    return ProcessDetailResponse(
        pid=pid, comm=comm, event_count=event_count, score_history=history
    )


@router.get("/{pid}/events", response_model=EventFeedResponse)
async def process_events(
    request: Request,
    pid: int,
    limit: int = Query(default=1000, ge=1, le=10000),
) -> EventFeedResponse:
    """Return the most recent stored events for a process."""
    state: "AppState" = request.app.state.bg
    events = await state.event_store.query_by_pid(pid, 0, _TS_MAX)
    events = events[-limit:]
    return EventFeedResponse(
        pid=pid,
        events=[_event_to_out(e) for e in events],
        total=len(events),
    )
