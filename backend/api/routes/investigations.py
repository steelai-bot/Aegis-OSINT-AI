"""Investigation API routes."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.routes.collections import run_collection_job
from backend.api.schemas.collections import (
    CollectionInvestigationRunResponse,
    CollectionRunRequest,
    CollectionWorkflowRunRequest,
)
from backend.api.schemas.investigations import InvestigationCreate, InvestigationRead
from backend.services.crud import InvestigationService, TargetService
from backend.storage.database import get_db_session

router = APIRouter(tags=["investigations"])


@router.post("/investigations", response_model=InvestigationRead, status_code=status.HTTP_201_CREATED)
async def create_investigation(
    payload: InvestigationCreate,
    session: AsyncSession = Depends(get_db_session),
):
    return await InvestigationService(session).create_investigation(payload.title)


@router.get("/investigations", response_model=list[InvestigationRead])
async def list_investigations(session: AsyncSession = Depends(get_db_session)):
    return await InvestigationService(session).list_investigations()


@router.get("/investigations/{investigation_id}", response_model=InvestigationRead)
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
    response_model=CollectionInvestigationRunResponse,
    status_code=status.HTTP_200_OK,
)
async def collect_investigation_targets(
    investigation_id: UUID,
    payload: CollectionWorkflowRunRequest,
    session: AsyncSession = Depends(get_db_session),
):
    """Run approved passive collectors for every target in an investigation."""

    investigation = await InvestigationService(session).get_investigation(investigation_id)
    if investigation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")

    target_results = []
    for target in await TargetService(session).list_targets(investigation_id):
        target_results.append(
            await run_collection_job(
                CollectionRunRequest(
                    target=target.value,
                    target_type=target.type,
                    plugin_name=payload.plugin_name,
                    investigation_id=investigation_id,
                    target_id=target.id,
                    priority=payload.priority,
                    config=payload.config,
                    enrich=payload.enrich,
                ),
                session=session,
            )
        )

    return CollectionInvestigationRunResponse(
        investigation_id=investigation_id,
        target_results=target_results,
        persisted_count=sum(result.persisted_count for result in target_results),
        errors={
            f"{result.target}:{plugin_name}": error
            for result in target_results
            for plugin_name, error in result.errors.items()
        },
    )
