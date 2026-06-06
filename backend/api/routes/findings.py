"""Finding API routes."""

from uuid import UUID

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.schemas.findings import FindingCreate, FindingRead
from backend.api.security import require_permission
from backend.services.crud import FindingService
from backend.storage.database import get_db_session

router = APIRouter(tags=["findings"])


@router.post(
    "/findings",
    response_model=FindingRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission("finding:create"))],
)
async def create_finding(payload: FindingCreate, session: AsyncSession = Depends(get_db_session)):
    return await FindingService(session).create_finding(
        investigation_id=payload.investigation_id,
        target_id=payload.target_id,
        source=payload.source,
        confidence=payload.confidence,
        severity=payload.severity,
        data=payload.data,
        threat_category=payload.threat_category,
        indicator_type=payload.indicator_type,
        first_seen=payload.first_seen,
        last_seen=payload.last_seen,
        breach_date=payload.breach_date,
        threat_actor=payload.threat_actor,
        campaign_id=payload.campaign_id,
        source_url=payload.source_url,
        collector_plugin=payload.collector_plugin,
        raw_evidence=payload.raw_evidence,
        enriched=payload.enriched,
        enrichment_data=payload.enrichment_data,
        risk_score=payload.risk_score,
        exploitability=payload.exploitability,
        remediation_status=payload.remediation_status,
        remediation_notes=payload.remediation_notes,
    )


@router.get(
    "/findings",
    response_model=list[FindingRead],
    dependencies=[Depends(require_permission("finding:read"))],
)
async def list_findings(
    investigation_id: UUID | None = None,
    threat_category: str | None = None,
    indicator_type: str | None = None,
    severity: str | None = None,
    remediation_status: str | None = None,
    session: AsyncSession = Depends(get_db_session),
):
    return await FindingService(session).list_findings(
        investigation_id=investigation_id,
        threat_category=threat_category,
        indicator_type=indicator_type,
        severity=severity,
        remediation_status=remediation_status,
    )


@router.get(
    "/investigations/{investigation_id}/findings",
    response_model=list[FindingRead],
    dependencies=[Depends(require_permission("finding:read"))],
)
async def list_investigation_findings(investigation_id: UUID, session: AsyncSession = Depends(get_db_session)):
    return await FindingService(session).list_findings(investigation_id=investigation_id)
