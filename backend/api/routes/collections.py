"""Collection orchestration API routes."""

from uuid import UUID

from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.routes._audit import record_route_audit_event
from backend.api.schemas.collections import (
    CollectionRunListResponse,
    CollectionRunQueuedResponse,
    CollectionRunRequest,
    CollectionRunResponse,
    CollectionRunStatusResponse,
)
from backend.api.security import Principal, require_permission
from backend.services.collection_runs import CollectionRunService
from backend.services.collection_workflows import collection_run_status_response, queue_collection_run, run_collection_job
from backend.storage.database import get_db_session

router = APIRouter(tags=["collections"])


@router.post(
    "/collections/run",
    response_model=CollectionRunResponse | CollectionRunQueuedResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_permission("collection:run"))],
)
async def run_collection(
    payload: CollectionRunRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_db_session),
    principal: Principal | None = Depends(require_permission("collection:run")),
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


@router.get(
    "/collections/runs",
    response_model=CollectionRunListResponse,
    dependencies=[Depends(require_permission("collection:status"))],
)
async def list_collection_runs(
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
    session: AsyncSession = Depends(get_db_session),
):
    """Return recent persisted background collection runs for operator review."""

    runs = await CollectionRunService(session).list_runs(limit=limit)
    return CollectionRunListResponse(runs=[collection_run_status_response(run) for run in runs])


@router.get(
    "/collections/runs/{run_id}",
    response_model=CollectionRunStatusResponse,
    dependencies=[Depends(require_permission("collection:status"))],
)
async def get_collection_run(run_id: UUID, session: AsyncSession = Depends(get_db_session)):
    """Return persisted status for an in-process background collection run."""

    run = await CollectionRunService(session).get_run(run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Collection run not found")
    return collection_run_status_response(run)


@router.post(
    "/collections/runs/{run_id}/cancel",
    response_model=CollectionRunStatusResponse,
    dependencies=[Depends(require_permission("collection:run"))],
)
async def cancel_collection_run(
    run_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_db_session),
    _: Principal | None = Depends(require_permission("collection:run")),
):
    """Cancel a queued or running collection run."""

    run = await CollectionRunService(session).mark_cancelled(run_id)
    if run is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Collection run not found")
    await record_route_audit_event(
        request=request,
        principal=_,
        event_type="collection.run.cancelled",
        status="success",
        resource_type="collection_run",
        resource_id=str(run_id),
    )
    return collection_run_status_response(run)


@router.get(
    "/targets/{target_id}/collection-runs",
    response_model=CollectionRunListResponse,
    dependencies=[Depends(require_permission("collection:status"))],
)
async def list_target_collection_runs(
    target_id: UUID,
    limit: Annotated[int, Query(ge=1, le=50)] = 10,
    session: AsyncSession = Depends(get_db_session),
):
    """Return recent collection runs for a specific target."""

    runs = await CollectionRunService(session).list_runs_for_entity(target_id=target_id, limit=limit)
    return CollectionRunListResponse(runs=[collection_run_status_response(run) for run in runs])


@router.get(
    "/investigations/{investigation_id}/collection-runs",
    response_model=CollectionRunListResponse,
    dependencies=[Depends(require_permission("collection:status"))],
)
async def list_investigation_collection_runs(
    investigation_id: UUID,
    limit: Annotated[int, Query(ge=1, le=50)] = 10,
    session: AsyncSession = Depends(get_db_session),
):
    """Return recent collection runs for a specific investigation."""

    runs = await CollectionRunService(session).list_runs_for_entity(
        investigation_id=investigation_id, limit=limit,
    )
    return CollectionRunListResponse(runs=[collection_run_status_response(run) for run in runs])