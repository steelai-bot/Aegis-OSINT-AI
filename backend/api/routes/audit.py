"""Audit event read API routes."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.schemas.audit import AuditEventListResponse, AuditEventRead
from backend.api.security import Principal, require_permission
from backend.services.audit import AuditEventService
from backend.storage.database import get_db_session

router = APIRouter(tags=["audit"])


@router.get("/audit/events", response_model=AuditEventListResponse)
async def list_audit_events(
    event_type: str | None = Query(default=None, max_length=100),
    event_type_prefix: str | None = Query(default="tool.execution.", max_length=100),
    status_filter: str | None = Query(default=None, alias="status", max_length=30),
    actor_id: str | None = Query(default=None, max_length=255),
    resource_type: str | None = Query(default=None, max_length=100),
    resource_id: str | None = Query(default=None, max_length=100),
    limit: int = Query(default=100, ge=1, le=500),
    session: AsyncSession = Depends(get_db_session),
    _: Principal | None = Depends(require_permission("audit:read")),
):
    """List recent audit events, defaulting to the tool execution audit trail."""

    events = await AuditEventService(session).list_events(
        event_type=event_type,
        event_type_prefix=None if event_type else event_type_prefix,
        status=status_filter,
        actor_id=actor_id,
        resource_type=resource_type,
        resource_id=resource_id,
        limit=limit,
    )
    return AuditEventListResponse(events=[AuditEventRead.model_validate(event) for event in events])


@router.get("/audit/events/{event_id}", response_model=AuditEventRead)
async def get_audit_event(
    event_id: UUID,
    session: AsyncSession = Depends(get_db_session),
    _: Principal | None = Depends(require_permission("audit:read")),
):
    """Return one audit event by id."""

    event = await AuditEventService(session).get_event(event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit event not found")
    return event
