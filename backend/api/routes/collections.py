"""Collection orchestration API routes."""

from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.schemas.collections import (
    CollectionRunQueuedResponse,
    CollectionRunRequest,
    CollectionRunResponse,
    CollectionRunStatusResponse,
)
from backend.services.collection_runs import CollectionRunService
from backend.services.collection_workflows import collection_run_status_response, queue_collection_run, run_collection_job
from backend.storage.database import get_db_session

router = APIRouter(tags=["collections"])


@router.post(
    "/collections/run",
    response_model=CollectionRunResponse | CollectionRunQueuedResponse,
    status_code=status.HTTP_200_OK,
)
async def run_collection(
    payload: CollectionRunRequest,
    background_tasks: BackgroundTasks,
    response: Response,
    session: AsyncSession = Depends(get_db_session),
):
    """Run approved passive collectors for a single target and optionally persist findings."""

    if payload.async_mode:
        queued = await queue_collection_run(
            payload,
            run_scope="ad_hoc",
            background_tasks=background_tasks,
            session=session,
        )
        response.status_code = status.HTTP_202_ACCEPTED
        return queued
    return await run_collection_job(payload, session=session)


@router.get("/collections/runs/{run_id}", response_model=CollectionRunStatusResponse)
async def get_collection_run(run_id: UUID, session: AsyncSession = Depends(get_db_session)):
    """Return persisted status for an in-process background collection run."""

    run = await CollectionRunService(session).get_run(run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Collection run not found")
    return collection_run_status_response(run)

