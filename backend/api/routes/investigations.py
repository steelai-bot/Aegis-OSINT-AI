"""Investigation API routes."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.schemas.investigations import InvestigationCreate, InvestigationRead
from backend.services.crud import InvestigationService
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
