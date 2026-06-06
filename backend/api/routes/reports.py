"""Report API routes."""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.routes._audit import record_route_audit_event
from backend.api.schemas.reports import ReportCreate, ReportRead, ReportRenderRequest, ReportRenderResponse
from backend.api.security import Principal, require_permission
from backend.reports import render_report
from backend.services.crud import FindingService, InvestigationService, ReportService
from backend.storage.database import get_db_session

router = APIRouter(tags=["reports"])


@router.post(
    "/reports",
    response_model=ReportRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("report:create"))],
)
async def create_report(payload: ReportCreate, session: AsyncSession = Depends(get_db_session)):
    return await ReportService(session).create_report(payload.investigation_id, payload.path, payload.format)


@router.get(
    "/reports",
    response_model=list[ReportRead],
    dependencies=[Depends(require_permission("report:read"))],
)
async def list_reports(session: AsyncSession = Depends(get_db_session)):
    return await ReportService(session).list_reports()


@router.get(
    "/investigations/{investigation_id}/reports",
    response_model=list[ReportRead],
    dependencies=[Depends(require_permission("report:read"))],
)
async def list_investigation_reports(investigation_id: UUID, session: AsyncSession = Depends(get_db_session)):
    return await ReportService(session).list_reports(investigation_id=investigation_id)


@router.post(
    "/investigations/{investigation_id}/reports/render",
    response_model=ReportRenderResponse,
)
async def render_investigation_report(
    investigation_id: UUID,
    payload: ReportRenderRequest,
    request: Request,
    session: AsyncSession = Depends(get_db_session),
    principal: Principal | None = Depends(require_permission("report:render")),
):
    investigation = await InvestigationService(session).get_investigation(investigation_id)
    if investigation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found.")

    findings = await FindingService(session).list_findings(investigation_id=investigation_id)
    content = render_report(payload.format, investigation, findings)
    await record_route_audit_event(
        request=request,
        principal=principal,
        event_type="report.rendered",
        status="success",
        resource_type="investigation",
        resource_id=str(investigation_id),
        metadata={"format": payload.format, "finding_count": len(findings)},
    )
    return ReportRenderResponse(
        investigation_id=investigation_id,
        format=payload.format,
        content=content,
    )
