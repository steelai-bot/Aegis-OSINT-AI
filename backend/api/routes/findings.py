"""Finding API routes."""

from uuid import UUID

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.schemas.findings import FindingCreate, FindingRead
from backend.services.crud import FindingService
from backend.storage.database import get_db_session

router = APIRouter(tags=["findings"])


@router.post("/findings", response_model=FindingRead, status_code=status.HTTP_201_CREATED)
async def create_finding(payload: FindingCreate, session: AsyncSession = Depends(get_db_session)):
    return await FindingService(session).create_finding(
        investigation_id=payload.investigation_id,
        target_id=payload.target_id,
        source=payload.source,
        confidence=payload.confidence,
        severity=payload.severity,
        data=payload.data,
    )


@router.get("/findings", response_model=list[FindingRead])
async def list_findings(session: AsyncSession = Depends(get_db_session)):
    return await FindingService(session).list_findings()


@router.get("/investigations/{investigation_id}/findings", response_model=list[FindingRead])
async def list_investigation_findings(investigation_id: UUID, session: AsyncSession = Depends(get_db_session)):
    return await FindingService(session).list_findings(investigation_id=investigation_id)
