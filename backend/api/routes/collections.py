"""Collection orchestration API routes."""

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.schemas.collections import CollectionPluginResultRead, CollectionRunRequest, CollectionRunResponse
from backend.plugins.registry import PluginRegistry
from backend.services.collection_orchestrator import CollectionJob, CollectionOrchestrator
from backend.storage.database import get_db_session

router = APIRouter(tags=["collections"])


@router.post("/collections/run", response_model=CollectionRunResponse, status_code=status.HTTP_200_OK)
async def run_collection(payload: CollectionRunRequest, session: AsyncSession = Depends(get_db_session)):
    """Run approved passive collectors for a single target and optionally persist findings."""

    return await run_collection_job(payload, session=session)


async def run_collection_job(payload: CollectionRunRequest, *, session: AsyncSession) -> CollectionRunResponse:
    """Run a collection job and return the normalized API response."""

    job = CollectionJob(
        target=payload.target,
        target_type=payload.target_type,
        plugin_name=payload.plugin_name,
        investigation_id=payload.investigation_id,
        target_id=payload.target_id,
        priority=payload.priority,
        config=payload.config,
        enrich=payload.enrich,
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


def _plugin_configs_from_payload(payload: CollectionRunRequest) -> dict[str, dict]:
    """Map request config into registry plugin configs without global configuration changes."""

    if payload.plugin_name is not None:
        return {payload.plugin_name: payload.config}
    return {name: config for name, config in payload.config.items() if isinstance(name, str) and isinstance(config, dict)}