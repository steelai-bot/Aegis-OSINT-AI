"""Investigation API routes."""

from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.schemas.collections import (
    CollectionInvestigationRunResponse,
    CollectionRunQueuedResponse,
    CollectionWorkflowRunRequest,
)
from backend.api.schemas.investigations import InvestigationCreate, InvestigationRead
from backend.api.security import require_permission
from backend.services.collection_workflows import queue_investigation_collection_run, run_investigation_collection_job
from backend.services.crud import InvestigationService
from backend.storage.database import get_db_session

router = APIRouter(tags=["investigations"])


@router.post(
    "/investigations",
    response_model=InvestigationRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("investigation:create"))],
)
async def create_investigation(
    payload: InvestigationCreate,
    session: AsyncSession = Depends(get_db_session),
):
    return await InvestigationService(session).create_investigation(payload.title)


@router.get(
    "/investigations",
    response_model=list[InvestigationRead],
    dependencies=[Depends(require_permission("investigation:read"))],
)
async def list_investigations(session: AsyncSession = Depends(get_db_session)):
    return await InvestigationService(session).list_investigations()


@router.get(
    "/investigations/{investigation_id}",
    response_model=InvestigationRead,
    dependencies=[Depends(require_permission("investigation:read"))],
)
async def get_investigation(
    investigation_id: UUID,
    session: AsyncSession = Depends(get_db_session),
):
    investigation = await InvestigationService(session).get_investigation(investigation_id)
    if investigation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    return investigation


@router.post(
    "/investigations/{investigation_id}/collect",
    response_model=CollectionInvestigationRunResponse | CollectionRunQueuedResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_permission("collection:run"))],
)
async def collect_investigation_targets(
    investigation_id: UUID,
    payload: CollectionWorkflowRunRequest,
    background_tasks: BackgroundTasks,
    response: Response,
    session: AsyncSession = Depends(get_db_session),
):
    """Run approved passive collectors for every target in an investigation."""

    investigation = await InvestigationService(session).get_investigation(investigation_id)
    if investigation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")

    if payload.async_mode:
        queued = await queue_investigation_collection_run(
            investigation_id,
            payload,
            background_tasks=background_tasks,
            session=session,
        )
        response.status_code = status.HTTP_202_ACCEPTED
        return queued
    return await run_investigation_collection_job(investigation_id, payload, session=session)
