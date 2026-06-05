"""Target API routes."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

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
