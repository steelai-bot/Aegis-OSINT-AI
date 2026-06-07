"""Shared passive collection workflow helpers.

This module keeps collection execution and process-local background queue helpers
out of FastAPI route modules so routes can depend on service/use-case helpers
instead of importing from each other.
"""

from typing import Any
from uuid import UUID

from fastapi import BackgroundTasks, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.schemas.collections import (
    CollectionInvestigationRunResponse,
    CollectionPluginResultRead,
    CollectionRunQueuedResponse,
    CollectionRunRequest,
    CollectionRunResponse,
    CollectionRunStatusResponse,
    CollectionWorkflowRunRequest,
)
from backend.core.config import get_settings
from backend.plugins.registry import PluginRegistry
from backend.services.collection_runs import CollectionRunService
from backend.services.collection_orchestrator import CollectionJob, CollectionOrchestrator
from backend.services.crud import InvestigationService, TargetService
from backend.storage.database import AsyncSessionLocal


async def run_collection_job(payload: CollectionRunRequest, *, session: AsyncSession) -> CollectionRunResponse:
    """Run a collection job and return the normalized API response."""

    await validate_collection_scope(payload, session=session)

    job = CollectionJob(
        target=payload.target,
        target_type=payload.target_type,
        plugin_name=payload.plugin_name,
        investigation_id=payload.investigation_id,
        target_id=payload.target_id,
        priority=payload.priority,
        config=payload.config,
        enrich=payload.enrich,
        execution_mode=payload.execution_mode,
        approval_token=payload.approval_token,
        authorized_scope=payload.authorized_scope,
    )
    result = await CollectionOrchestrator(
        registry=PluginRegistry(plugin_configs=_plugin_configs_from_payload(payload)),
        session=session,
    ).run_job(job)
    return CollectionRunResponse(
        target=result.target,
        target_type=payload.target_type,
        target_id=payload.target_id,
        plugin_results=[
            CollectionPluginResultRead(
                plugin_name=plugin_result.plugin_name,
                status=plugin_result.status,
                findings=plugin_result.findings,
                metadata=plugin_result.metadata,
            )
            for plugin_result in result.plugin_results
        ],
        findings=result.findings,
        persisted_count=result.persisted_count,
        errors=result.errors,
    )


async def queue_collection_run(
    payload: CollectionRunRequest,
    *,
    run_scope: str,
    background_tasks: BackgroundTasks,
    session: AsyncSession,
) -> CollectionRunQueuedResponse:
    """Persist a queued collection run and schedule process-local execution."""

    await validate_collection_scope(payload, session=session)

    run = await CollectionRunService(session).create_run(
        run_scope=run_scope,
        target=payload.target,
        target_type=payload.target_type,
        investigation_id=payload.investigation_id,
        target_id=payload.target_id,
        plugin_name=payload.plugin_name,
        priority=payload.priority,
        config=payload.config,
        enrich=payload.enrich,
    )
    background_tasks.add_task(execute_collection_run_background, run.id, payload)
    return CollectionRunQueuedResponse(
        run_id=run.id,
        status=run.status,
        status_url=f"{get_settings().api_prefix}/collections/runs/{run.id}",
    )


async def queue_investigation_collection_run(
    investigation_id: UUID,
    payload: CollectionWorkflowRunRequest,
    *,
    background_tasks: BackgroundTasks,
    session: AsyncSession,
) -> CollectionRunQueuedResponse:
    """Persist a queued investigation-wide run and schedule process-local execution."""

    await validate_investigation_scope(investigation_id, session=session)

    run = await CollectionRunService(session).create_run(
        run_scope="investigation",
        investigation_id=investigation_id,
        plugin_name=payload.plugin_name,
        priority=payload.priority,
        config=payload.config,
        enrich=payload.enrich,
    )
    background_tasks.add_task(execute_investigation_collection_background, run.id, investigation_id, payload)
    return CollectionRunQueuedResponse(
        run_id=run.id,
        status=run.status,
        status_url=f"{get_settings().api_prefix}/collections/runs/{run.id}",
    )


async def execute_collection_run_background(run_id: UUID, payload: CollectionRunRequest) -> None:
    """Execute a queued collection run in the current API process."""

    async with AsyncSessionLocal() as session:
        service = CollectionRunService(session)
        await service.mark_running(run_id)
        try:
            result = await run_collection_job(payload, session=session)
        except Exception as exc:  # Keep the status endpoint useful if background execution fails.
            await session.rollback()
            await service.mark_failed(run_id, error={"message": str(exc)})
            return
        await service.mark_completed(
            run_id,
            result=result.model_dump(mode="json"),
            persisted_count=result.persisted_count,
        )


async def execute_investigation_collection_background(
    run_id: UUID,
    investigation_id: UUID,
    payload: CollectionWorkflowRunRequest,
) -> None:
    """Execute queued collection for every target in an investigation in the current API process."""

    async with AsyncSessionLocal() as session:
        service = CollectionRunService(session)
        await service.mark_running(run_id)
        try:
            result = await run_investigation_collection_job(investigation_id, payload, session=session)
        except Exception as exc:  # Keep the status endpoint useful if background execution fails.
            await session.rollback()
            await service.mark_failed(run_id, error={"message": str(exc)})
            return
        await service.mark_completed(
            run_id,
            result=result.model_dump(mode="json"),
            persisted_count=result.persisted_count,
        )


async def run_investigation_collection_job(
    investigation_id: UUID,
    payload: CollectionWorkflowRunRequest,
    *,
    session: AsyncSession,
) -> CollectionInvestigationRunResponse:
    """Run approved passive collectors for every target in an investigation."""

    await validate_investigation_scope(investigation_id, session=session)

    target_results = []
    for target in await TargetService(session).list_targets(investigation_id):
        target_results.append(
            await run_collection_job(
                CollectionRunRequest(
                    target=target.value,
                    target_type=target.type,
                    plugin_name=payload.plugin_name,
                    investigation_id=investigation_id,
                    target_id=target.id,
                    priority=payload.priority,
                    config=payload.config,
                    enrich=payload.enrich,
                    execution_mode=payload.execution_mode,
                    approval_token=payload.approval_token,
                    authorized_scope=payload.authorized_scope,
                ),
                session=session,
            )
        )

    return CollectionInvestigationRunResponse(
        investigation_id=investigation_id,
        target_results=target_results,
        persisted_count=sum(result.persisted_count for result in target_results),
        errors={
            f"{result.target}:{plugin_name}": error
            for result in target_results
            for plugin_name, error in result.errors.items()
        },
    )


async def validate_collection_scope(payload: CollectionRunRequest, *, session: AsyncSession) -> None:
    """Validate optional persistence scope before collection can create linked findings."""

    if payload.investigation_id is not None:
        await validate_investigation_scope(payload.investigation_id, session=session)

    if payload.target_id is None:
        return

    target = await TargetService(session).get_target(payload.target_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target not found")

    if payload.investigation_id is not None and target.investigation_id != payload.investigation_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target does not belong to the requested investigation",
        )

    if target.value != payload.target or target.type != payload.target_type:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Collection target does not match the requested target_id",
        )


async def validate_investigation_scope(investigation_id: UUID, *, session: AsyncSession) -> None:
    """Validate that an investigation exists before collection uses it as persistence scope."""

    investigation = await InvestigationService(session).get_investigation(investigation_id)
    if investigation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")


def collection_run_status_response(run: Any) -> CollectionRunStatusResponse:
    """Map a persisted run row to an API-safe status response."""

    return CollectionRunStatusResponse(
        run_id=run.id,
        run_scope=run.run_scope,
        status=run.status,
        target=run.target,
        target_type=run.target_type,
        target_id=run.target_id,
        investigation_id=run.investigation_id,
        plugin_name=run.plugin_name,
        priority=run.priority,
        enrich=run.enrich,
        persisted_count=run.persisted_count,
        result=run.result_json,
        errors=run.error_json,
        started_at=run.started_at,
        completed_at=run.completed_at,
        created_at=run.created_at,
        updated_at=run.updated_at,
    )


def _plugin_configs_from_payload(payload: CollectionRunRequest) -> dict[str, dict]:
    """Map request config into registry plugin configs without global configuration changes."""

    if payload.plugin_name is not None:
        return {payload.plugin_name: payload.config}
    return {name: config for name, config in payload.config.items() if isinstance(name, str) and isinstance(config, dict)}