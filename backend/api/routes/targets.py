"""Target API routes."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.routes.collections import run_collection_job
from backend.api.schemas.collections import (
    CollectionRunRequest,
    CollectionRunResponse,
    CollectionWorkflowRunRequest,
)
from backend.api.schemas.targets import TargetCreate, TargetRead
from backend.services.crud import InvestigationService, TargetService
from backend.storage.database import get_db_session

router = APIRouter(tags=["targets"])


@router.post("/targets", response_model=TargetRead, status_code=status.HTTP_201_CREATED)
async def create_target(payload: TargetCreate, session: AsyncSession = Depends(get_db_session)):
    investigation = await InvestigationService(session).get_investigation(payload.investigation_id)
    if investigation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    return await TargetService(session).create_target(payload.investigation_id, payload.type, payload.value)


@router.get("/investigations/{investigation_id}/targets", response_model=list[TargetRead])
async def list_targets(investigation_id: UUID, session: AsyncSession = Depends(get_db_session)):
    return await TargetService(session).list_targets(investigation_id)


@router.post("/targets/{target_id}/collect", response_model=CollectionRunResponse, status_code=status.HTTP_200_OK)
async def collect_target(
    target_id: UUID,
    payload: CollectionWorkflowRunRequest,
    session: AsyncSession = Depends(get_db_session),
):
    """Run approved passive collectors for an existing target and persist findings to its investigation."""

    target = await TargetService(session).get_target(target_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    return await run_collection_job(
        CollectionRunRequest(
            target=target.value,
            target_type=target.type,
            plugin_name=payload.plugin_name,
            investigation_id=target.investigation_id,
            target_id=target.id,
            priority=payload.priority,
            config=payload.config,
            enrich=payload.enrich,
        ),
        session=session,
    )
