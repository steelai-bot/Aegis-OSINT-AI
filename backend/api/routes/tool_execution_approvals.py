"""Persistent tool execution approval API routes."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.routes._audit import record_route_audit_event
from backend.api.schemas.tool_execution_approvals import (
    ToolExecutionApprovalCreate,
    ToolExecutionApprovalCreated,
    ToolExecutionApprovalListResponse,
    ToolExecutionApprovalRead,
)
from backend.api.security import Principal, require_permission
from backend.services.tool_execution_approvals import ToolExecutionApprovalService
from backend.storage.database import get_db_session

router = APIRouter(tags=["tool-execution"])


@router.post(
    "/tool-execution/approvals",
    response_model=ToolExecutionApprovalCreated,
    status_code=status.HTTP_201_CREATED,
)
async def create_tool_execution_approval(
    payload: ToolExecutionApprovalCreate,
    request: Request,
    session: AsyncSession = Depends(get_db_session),
    principal: Principal | None = Depends(require_permission("tool_execution:approve")),
):
    """Create a scoped approval token for gated non-passive tool execution."""

    created = await ToolExecutionApprovalService(session).create_approval(
        plugin_name=payload.plugin_name,
        target_type=payload.target_type,
        target=payload.target,
        target_hash=payload.target_hash,
        execution_mode=payload.execution_mode,
        authorized_scope=payload.authorized_scope,
        reason=payload.reason,
        requested_by=payload.requested_by,
        approved_by=principal.id if principal is not None else None,
        expires_in_minutes=payload.expires_in_minutes,
        max_uses=payload.max_uses,
        metadata=payload.metadata,
    )
    await record_route_audit_event(
        request=request,
        principal=principal,
        event_type="tool.execution.approval.created",
        status="success",
        resource_type="tool_execution_approval",
        resource_id=str(created.approval.id),
        metadata={
            "plugin_name": created.approval.plugin_name,
            "target_type": created.approval.target_type,
            "target_hash": created.approval.target_hash,
            "execution_mode": created.approval.execution_mode,
            "max_uses": created.approval.max_uses,
        },
    )
    response_data = ToolExecutionApprovalRead.model_validate(created.approval).model_dump()
    return ToolExecutionApprovalCreated(**response_data, approval_token=created.token)


@router.get(
    "/tool-execution/approvals",
    response_model=ToolExecutionApprovalListResponse,
)
async def list_tool_execution_approvals(
    status_filter: str | None = Query(default=None, alias="status", max_length=30),
    limit: int = Query(default=100, ge=1, le=500),
    session: AsyncSession = Depends(get_db_session),
    _: Principal | None = Depends(require_permission("tool_execution:approve")),
):
    """List recent persistent approval records without exposing token material."""

    approvals = await ToolExecutionApprovalService(session).list_approvals(status=status_filter, limit=limit)
    return ToolExecutionApprovalListResponse(approvals=[ToolExecutionApprovalRead.model_validate(item) for item in approvals])


@router.get(
    "/tool-execution/approvals/{approval_id}",
    response_model=ToolExecutionApprovalRead,
)
async def get_tool_execution_approval(
    approval_id: UUID,
    session: AsyncSession = Depends(get_db_session),
    _: Principal | None = Depends(require_permission("tool_execution:approve")),
):
    """Return one approval record without token material."""

    approval = await ToolExecutionApprovalService(session).get_approval(approval_id)
    if approval is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tool execution approval not found")
    return approval


@router.delete(
    "/tool-execution/approvals/{approval_id}",
    response_model=ToolExecutionApprovalRead,
)
async def revoke_tool_execution_approval(
    approval_id: UUID,
    request: Request,
    session: AsyncSession = Depends(get_db_session),
    principal: Principal | None = Depends(require_permission("tool_execution:approve")),
):
    """Revoke an approval token before it can be used again."""

    approval = await ToolExecutionApprovalService(session).revoke_approval(approval_id)
    if approval is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tool execution approval not found")
    await record_route_audit_event(
        request=request,
        principal=principal,
        event_type="tool.execution.approval.revoked",
        status="success",
        resource_type="tool_execution_approval",
        resource_id=str(approval.id),
        metadata={"plugin_name": approval.plugin_name, "target_type": approval.target_type, "target_hash": approval.target_hash},
    )
    return approval