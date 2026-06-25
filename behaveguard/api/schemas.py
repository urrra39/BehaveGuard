"""Pydantic request/response models for the BehaveGuard REST API."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------- #
# Health / metrics
# --------------------------------------------------------------------------- #
class HealthResponse(BaseModel):
    """Liveness response."""

    status: str = "ok"
    version: str
    uptime_seconds: float


# --------------------------------------------------------------------------- #
# Processes
# --------------------------------------------------------------------------- #
class ProcessSummary(BaseModel):
    """One monitored process and its latest known anomaly score."""

    pid: int
    comm: str
    event_count: int
    last_seen_ns: int
    latest_score: float = 0.0
    latest_severity: str = "LOW"


class ProcessListResponse(BaseModel):
    processes: List[ProcessSummary]
    total: int


class ScorePoint(BaseModel):
    timestamp_ns: int
    score: float
    severity: str


class ProcessDetailResponse(BaseModel):
    pid: int
    comm: str
    event_count: int
    score_history: List[ScorePoint]


class EventOut(BaseModel):
    """A raw event row from the event store."""

    timestamp_ns: int
    event_type: int
    pid: int
    comm: str
    detail: Dict[str, Any]


class EventFeedResponse(BaseModel):
    pid: int
    events: List[EventOut]
    total: int


# --------------------------------------------------------------------------- #
# Alerts
# --------------------------------------------------------------------------- #
class AlertOut(BaseModel):
    alert_id: Optional[int]
    process_name: str
    pid: int
    score: float
    severity: str
    explanation: str
    timestamp_ns: int
    acknowledged: bool
    created_unix: float


class AlertListResponse(BaseModel):
    alerts: List[AlertOut]
    total: int
    unacknowledged: int


class AcknowledgeRequest(BaseModel):
    note: str = ""


class SuppressRequest(BaseModel):
    process_name: str
    reason: str
    max_score_suppress: float = Field(default=100.0, ge=0.0, le=100.0)
    expires_at: Optional[str] = None  # ISO-8601, optional
    created_by: str = "user"


class SimpleStatusResponse(BaseModel):
    status: str
    detail: str = ""


# --------------------------------------------------------------------------- #
# Models / training
# --------------------------------------------------------------------------- #
class TrainRequest(BaseModel):
    process_name: str
    observation_minutes: int = Field(default=60, ge=1, le=1440)


class TrainJobResponse(BaseModel):
    job_id: str
    process_name: str
    state: str


class TrainStatus(BaseModel):
    job_id: str
    process_name: str
    state: str
    detail: str = ""
    started_unix: float
    finished_unix: Optional[float] = None


class TrainStatusListResponse(BaseModel):
    jobs: List[TrainStatus]


class ModelInfo(BaseModel):
    process_name: str
    metadata: Dict[str, Any]


class ModelListResponse(BaseModel):
    models: List[ModelInfo]
    total: int
