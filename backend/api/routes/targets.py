"""Target API routes."""

from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.routes._audit import record_route_audit_event
from backend.api.schemas.collections import (
    CollectionRunQueuedResponse,
    CollectionRunRequest,
    CollectionRunResponse,
    CollectionWorkflowRunRequest,
)
from backend.api.schemas.targets import TargetCreate, TargetRead
from backend.api.security import Principal, require_permission
from backend.services.collection_workflows import queue_collection_run, run_collection_job
from backend.services.crud import InvestigationService, TargetService
from backend.storage.database import get_db_session

router = APIRouter(tags=["targets"])


@router.post(
    "/targets",
    response_model=TargetRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_target(
    payload: TargetCreate,
    request: Request,
    session: AsyncSession = Depends(get_db_session),
    principal: Principal | None = Depends(require_permission("target:create")),
):
    investigation = await InvestigationService(session).get_investigation(payload.investigation_id)
    if investigation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    target = await TargetService(session).create_target(payload.investigation_id, payload.type, payload.value)
    await record_route_audit_event(
        request=request,
        principal=principal,
        event_type="target.created",
        status="success",
        resource_type="target",
        resource_id=str(target.id),
        metadata={
            "investigation_id": str(payload.investigation_id),
            "target_type": payload.type,
            "target_value_length": len(payload.value),
        },
    )
    return target


@router.get(
    "/investigations/{investigation_id}/targets",
    response_model=list[TargetRead],
    dependencies=[Depends(require_permission("target:read"))],
)
async def list_targets(investigation_id: UUID, session: AsyncSession = Depends(get_db_session)):
    return await TargetService(session).list_targets(investigation_id)


@router.post(
    "/targets/{target_id}/collect",
    response_model=CollectionRunResponse | CollectionRunQueuedResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_permission("collection:run"))],
)
async def collect_target(
    target_id: UUID,
    payload: CollectionWorkflowRunRequest,
    background_tasks: BackgroundTasks,
    response: Response,
    session: AsyncSession = Depends(get_db_session),
):
    """Run approved passive collectors for an existing target and persist findings to its investigation."""

    target = await TargetService(session).get_target(target_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    collection_payload = CollectionRunRequest(
        target=target.value,
        target_type=target.type,
        plugin_name=payload.plugin_name,
        investigation_id=target.investigation_id,
        target_id=target.id,
        priority=payload.priority,
        config=payload.config,
        enrich=payload.enrich,
        execution_mode=payload.execution_mode,
        approval_token=payload.approval_token,
        authorized_scope=payload.authorized_scope,
    )
    if payload.async_mode:
        queued = await queue_collection_run(
            collection_payload,
            run_scope="target",
            background_tasks=background_tasks,
            session=session,
        )
        response.status_code = status.HTTP_202_ACCEPTED
        return queued
    return await run_collection_job(collection_payload, session=session)
