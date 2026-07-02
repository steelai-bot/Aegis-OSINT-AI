"""Threat intelligence enrichment API routes."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.routes._audit import record_route_audit_event
from backend.api.security import Principal, require_permission
from backend.services.enrichment_pipeline import EnrichmentPipeline
from backend.storage.database import get_db_session

router = APIRouter(prefix="/enrichment", tags=["enrichment"])


# ── Schemas ────────────────────────────────────────────────────────────────


class EnrichmentRequest(BaseModel):
    indicator: str
    indicator_type: str  # email, ip, domain, url, phone
    source_finding_id: str | None = None


class EnrichmentResponse(BaseModel):
    indicator: str
    indicator_type: str
    enriched: bool
    enrichment_data: dict
    risk_score: float | None = None


class EnrichmentBatchRequest(BaseModel):
    indicators: list[EnrichmentRequest]


class EnrichmentBatchResponse(BaseModel):
    results: list[EnrichmentResponse]


# ── Routes ─────────────────────────────────────────────────────────────────


@router.post(
    "/enrich",
    response_model=EnrichmentResponse,
    status_code=status.HTTP_200_OK,
)
async def enrich_indicator(
    payload: EnrichmentRequest,
    request: Request,
    session: AsyncSession = Depends(get_db_session),
    principal: Principal | None = Depends(require_permission("finding:create")),
):
    """Enrich a single indicator using available threat intelligence plugins."""
    pipeline = EnrichmentPipeline()
    finding = {
        "value": payload.indicator,
        "indicator_type": payload.indicator_type,
        "source_finding_id": payload.source_finding_id,
    }
    enriched = await pipeline.enrich(finding)

    await record_route_audit_event(
        request=request,
        principal=principal,
        event_type="enrichment.indicator",
        status="success",
        resource_type="indicator",
        metadata={"indicator_type": payload.indicator_type, "enriched": enriched.get("enriched", False)},
    )

    return EnrichmentResponse(
        indicator=payload.indicator,
        indicator_type=payload.indicator_type,
        enriched=enriched.get("enriched", False),
        enrichment_data=enriched.get("enrichment_data", {}),
        risk_score=enriched.get("risk_score"),
    )


@router.post(
    "/enrich/batch",
    response_model=EnrichmentBatchResponse,
    status_code=status.HTTP_200_OK,
)
async def enrich_batch(
    payload: EnrichmentBatchRequest,
    request: Request,
    session: AsyncSession = Depends(get_db_session),
    principal: Principal | None = Depends(require_permission("finding:create")),
):
    """Enrich multiple indicators at once."""
    pipeline = EnrichmentPipeline()
    results = []

    for item in payload.indicators:
        finding = {
            "value": item.indicator,
            "indicator_type": item.indicator_type,
            "source_finding_id": item.source_finding_id,
        }
        enriched = await pipeline.enrich(finding)
        results.append(
            EnrichmentResponse(
                indicator=item.indicator,
                indicator_type=item.indicator_type,
                enriched=enriched.get("enriched", False),
                enrichment_data=enriched.get("enrichment_data", {}),
                risk_score=enriched.get("risk_score"),
            )
        )

    await record_route_audit_event(
        request=request,
        principal=principal,
        event_type="enrichment.batch",
        status="success",
        metadata={"count": len(results)},
    )

    return EnrichmentBatchResponse(results=results)