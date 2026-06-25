"""Model management endpoints: trigger training, check status, list, delete.

Training is launched as a background task. The torch-backed
:class:`~behaveguard.models.baseline_builder.BaselineBuilder` is imported lazily
inside the task so this router (and the whole API) imports without torch.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from typing import TYPE_CHECKING, List

from fastapi import APIRouter, HTTPException, Request

from behaveguard.api.schemas import (
    ModelInfo,
    ModelListResponse,
    TrainJobResponse,
    TrainRequest,
    TrainStatus,
    TrainStatusListResponse,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from behaveguard.api.server import AppState

router = APIRouter()


async def _run_training(state: "AppState", job_id: str, process_name: str, minutes: int) -> None:
    """Background training task: build a baseline and update the job record."""
    job = state.train_jobs[job_id]
    job["state"] = "running"
    try:
        # Lazy import keeps torch out of the API import path.
        from behaveguard.models.baseline_builder import BaselineBuilder

        builder = BaselineBuilder(state.config)
        results = await asyncio.to_thread(builder.train_from_running_processes, minutes)
        trained = list(results.keys())
        job["state"] = "completed"
        job["detail"] = f"trained: {', '.join(trained) if trained else 'none'}"
    except Exception as exc:  # noqa: BLE001 - report failures via the job record
        job["state"] = "failed"
        job["detail"] = str(exc)
    finally:
        job["finished_unix"] = time.time()


@router.post("/train", response_model=TrainJobResponse)
async def train(request: Request, body: TrainRequest) -> TrainJobResponse:
    """Start a background training job for a process baseline."""
    state: "AppState" = request.app.state.bg
    job_id = secrets.token_hex(8)
    state.train_jobs[job_id] = {
        "job_id": job_id,
        "process_name": body.process_name,
        "state": "queued",
        "detail": "",
        "started_unix": time.time(),
        "finished_unix": None,
    }
    # Fire-and-forget; status is polled via /models/status.
    asyncio.create_task(
        _run_training(state, job_id, body.process_name, body.observation_minutes)
    )
    return TrainJobResponse(job_id=job_id, process_name=body.process_name, state="queued")


@router.get("/status", response_model=TrainStatusListResponse)
async def train_status(request: Request) -> TrainStatusListResponse:
    """Return the status of all known training jobs."""
    state: "AppState" = request.app.state.bg
    jobs = [TrainStatus(**job) for job in state.train_jobs.values()]
    return TrainStatusListResponse(jobs=jobs)


@router.get("/list", response_model=ModelListResponse)
async def list_models(request: Request) -> ModelListResponse:
    """List the trained model bundles known to the model store."""
    state: "AppState" = request.app.state.bg
    from behaveguard.models.model_store import ModelStore

    store = ModelStore()
    infos: List[ModelInfo] = [
        ModelInfo(process_name=meta.get("process_name", "unknown"), metadata=meta)
        for meta in store.list_models()
    ]
    return ModelListResponse(models=infos, total=len(infos))


@router.delete("/{process_name}")
async def delete_model(request: Request, process_name: str) -> dict:
    """Delete a trained model bundle by process name."""
    from behaveguard.models.model_store import ModelStore

    store = ModelStore()
    if not store.exists(process_name):
        raise HTTPException(status_code=404, detail=f"no model for {process_name!r}")
    store.delete(process_name)
    return {"status": "deleted", "process_name": process_name}
