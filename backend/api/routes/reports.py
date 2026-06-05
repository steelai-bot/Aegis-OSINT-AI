"""Report API routes."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.schemas.reports import ReportCreate, ReportRead, ReportRenderRequest, ReportRenderResponse
from backend.reports import render_report
from backend.services.crud import FindingService, InvestigationService, ReportService
from backend.storage.database import get_db_session

router = APIRouter(tags=["reports"])


@router.post("/reports", response_model=ReportRead, status_code=status.HTTP_201_CREATED)
async def create_report(payload: ReportCreate, session: AsyncSession = Depends(get_db_session)):
    return await ReportService(session).create_report(payload.investigation_id, payload.path, payload.format)


@router.get("/reports", response_model=list[ReportRead])
async def list_reports(session: AsyncSession = Depends(get_db_session)):
    return await ReportService(session).list_reports()


@router.get("/investigations/{investigation_id}/reports", response_model=list[ReportRead])
async def list_investigation_reports(investigation_id: UUID, session: AsyncSession = Depends(get_db_session)):
    return await ReportService(session).list_reports(investigation_id=investigation_id)


@router.post("/investigations/{investigation_id}/reports/render", response_model=ReportRenderResponse)
async def render_investigation_report(
    investigation_id: UUID,
    payload: ReportRenderRequest,
    session: AsyncSession = Depends(get_db_session),
):
    investigation = await InvestigationService(session).get_investigation(investigation_id)
    if investigation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found.")

    findings = await FindingService(session).list_findings(investigation_id=investigation_id)
    return ReportRenderResponse(
        investigation_id=investigation_id,
        format=payload.format,
        content=render_report(payload.format, investigation, findings),
    )
