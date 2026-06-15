"""Report export API routes — CSV and PDF download."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.routes._audit import record_route_audit_event
from backend.api.security import Principal, require_permission
from backend.services.crud import InvestigationService, FindingService, TargetService
from backend.services.report_export import generate_csv_report, generate_html_report
from backend.storage.database import get_db_session

router = APIRouter(prefix="/reports/export", tags=["report-export"])


@router.get(
    "/{investigation_id}/csv",
    dependencies=[Depends(require_permission("report:read"))],
)
async def export_csv(
    investigation_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_db_session),
    principal: Principal | None = Depends(require_permission("report:read")),
):
    """Download investigation findings as CSV."""
    investigation = await InvestigationService(session).get_investigation(investigation_id)
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found")

    findings = await FindingService(session).list_findings(investigation_id=investigation_id)
    targets = await TargetService(session).list_targets(investigation_id=investigation_id)

    finding_dicts = [
        {
            "id": str(f.id), "source": f.source, "severity": f.severity,
            "threat_category": f.threat_category, "indicator_type": f.indicator_type,
            "confidence": f.confidence, "risk_score": f.risk_score,
            "exploitability": f.exploitability, "remediation_status": f.remediation_status,
            "created_at": f.created_at.isoformat() if f.created_at else "",
        }
        for f in findings
    ]
    target_dicts = [
        {"id": str(t.id), "value": t.value, "type": t.type, "created_at": t.created_at.isoformat() if t.created_at else ""}
        for t in targets
    ]

    inv_dict = {"id": str(investigation.id), "title": investigation.title, "generated_at": datetime.now(UTC).isoformat()}
    csv_data = generate_csv_report(inv_dict, finding_dicts, target_dicts)

    await record_route_audit_event(
        request=request, principal=principal,
        event_type="report.export.csv", status="success",
        resource_type="investigation", resource_id=str(investigation_id),
        metadata={"finding_count": len(finding_dicts)},
    )

    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=\"aegis-report-{investigation_id}.csv\""},
    )


@router.get(
    "/{investigation_id}/pdf",
    dependencies=[Depends(require_permission("report:read"))],
)
async def export_pdf(
    investigation_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_db_session),
    principal: Principal | None = Depends(require_permission("report:read")),
):
    """Download investigation as a PDF-ready HTML report (open in browser and print to PDF)."""
    investigation = await InvestigationService(session).get_investigation(investigation_id)
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found")

    findings = await FindingService(session).list_findings(investigation_id=investigation_id)
    targets = await TargetService(session).list_targets(investigation_id=investigation_id)

    finding_dicts = [
        {
            "id": str(f.id), "source": f.source, "severity": f.severity,
            "threat_category": f.threat_category, "indicator_type": f.indicator_type,
            "confidence": f.confidence, "risk_score": f.risk_score,
            "exploitability": f.exploitability, "remediation_status": f.remediation_status,
            "created_at": f.created_at.isoformat() if f.created_at else "",
        }
        for f in findings
    ]
    target_dicts = [
        {"id": str(t.id), "value": t.value, "type": t.type, "created_at": t.created_at.isoformat() if t.created_at else ""}
        for t in targets
    ]

    inv_dict = {"id": str(investigation.id), "title": investigation.title, "generated_at": datetime.now(UTC).isoformat()}
    html = generate_html_report(inv_dict, finding_dicts, target_dicts)

    await record_route_audit_event(
        request=request, principal=principal,
        event_type="report.export.pdf", status="success",
        resource_type="investigation", resource_id=str(investigation_id),
    )

    return Response(
        content=html,
        media_type="text/html",
        headers={"Content-Disposition": f"inline; filename=\"aegis-report-{investigation_id}.html\""},
    )