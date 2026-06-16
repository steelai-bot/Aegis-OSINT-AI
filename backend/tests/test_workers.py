"""Tests for the arq-based distributed collection worker."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.api.schemas.collections import CollectionRunRequest, CollectionWorkflowRunRequest
from backend.workers.collection_worker import enqueue_collection_run_via_arq

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# enqueue_collection_run_via_arq
# ---------------------------------------------------------------------------

async def test_enqueue_single_collection_run() -> None:
    """Enqueue a single-target collection run and verify arq is called correctly."""
    fake_job = MagicMock()
    fake_job.job_id = "arq-job-001"

    fake_pool = AsyncMock()
    fake_pool.enqueue_job = AsyncMock(return_value=fake_job)

    with patch("backend.workers.collection_worker.create_pool", AsyncMock(return_value=fake_pool)):
        job_id = await enqueue_collection_run_via_arq(
            run_id="550e8400-e29b-41d4-a716-446655440000",
            payload_dict={"target": "example.com", "target_type": "domain"},
        )

    assert job_id == "arq-job-001"
    fake_pool.enqueue_job.assert_awaited_once_with(
        "run_collection_job_worker",
        "550e8400-e29b-41d4-a716-446655440000",
        {"target": "example.com", "target_type": "domain"},
        _job_timeout_seconds=600,
    )


async def test_enqueue_investigation_collection_run() -> None:
    """Enqueue an investigation-wide collection run and verify arq is called correctly."""
    fake_job = MagicMock()
    fake_job.job_id = "arq-job-002"

    fake_pool = AsyncMock()
    fake_pool.enqueue_job = AsyncMock(return_value=fake_job)

    with patch("backend.workers.collection_worker.create_pool", AsyncMock(return_value=fake_pool)):
        job_id = await enqueue_collection_run_via_arq(
            run_id="550e8400-e29b-41d4-a716-446655440001",
            payload_dict={"target": "example.com", "target_type": "domain"},
            investigation_id="550e8400-e29b-41d4-a716-446655440099",
        )

    assert job_id == "arq-job-002"
    fake_pool.enqueue_job.assert_awaited_once_with(
        "run_investigation_job_worker",
        "550e8400-e29b-41d4-a716-446655440001",
        "550e8400-e29b-41d4-a716-446655440099",
        {"target": "example.com", "target_type": "domain"},
        _job_timeout_seconds=600,
    )


async def test_enqueue_returns_none_on_connection_failure() -> None:
    """When Redis is unreachable the helper returns None without raising."""
    with patch("backend.workers.collection_worker.create_pool", AsyncMock(side_effect=ConnectionError("No Redis"))):
        job_id = await enqueue_collection_run_via_arq(
            run_id="550e8400-e29b-41d4-a716-446655440002",
            payload_dict={"target": "example.com"},
        )

    assert job_id is None


async def test_enqueue_returns_none_when_job_is_none() -> None:
    """When arq returns None (e.g. queue full) the helper returns None."""
    fake_pool = AsyncMock()
    fake_pool.enqueue_job = AsyncMock(return_value=None)

    with patch("backend.workers.collection_worker.create_pool", AsyncMock(return_value=fake_pool)):
        job_id = await enqueue_collection_run_via_arq(
            run_id="550e8400-e29b-41d4-a716-446655440003",
            payload_dict={"target": "example.com"},
        )

    assert job_id is None


# ---------------------------------------------------------------------------
# queue_collection_run / queue_investigation_collection_run feature flag
# ---------------------------------------------------------------------------

async def test_queue_collection_run_uses_arq_when_backend_is_arq() -> None:
    """When settings.queue_backend == 'arq', enqueue via arq instead of background_tasks."""
    from unittest.mock import ANY, AsyncMock, MagicMock, patch

    from fastapi import BackgroundTasks

    from backend.api.schemas.collections import CollectionRunRequest
    from backend.services.collection_workflows import queue_collection_run

    payload = CollectionRunRequest(target="example.com", target_type="domain", plugin_name="dns")
    background_tasks = BackgroundTasks()
    session = AsyncMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=None)

    # Mock CollectionRunService.create_run to return a fake run
    fake_run = MagicMock()
    fake_run.id = "550e8400-e29b-41d4-a716-446655440010"
    fake_run.status = "queued"

    with (
        patch("backend.services.collection_workflows.CollectionRunService") as mock_service_cls,
        patch("backend.services.collection_workflows.get_settings") as mock_settings,
        patch("backend.workers.collection_worker.enqueue_collection_run_via_arq", AsyncMock()) as mock_enqueue,
    ):
        mock_service = mock_service_cls.return_value
        mock_service.create_run = AsyncMock(return_value=fake_run)

        mock_settings.return_value.queue_backend = "arq"
        mock_settings.return_value.api_prefix = "/api/v1"

        result = await queue_collection_run(
            payload,
            run_scope="target",
            background_tasks=background_tasks,
            session=session,
        )

    from uuid import UUID

    assert result.run_id == UUID("550e8400-e29b-41d4-a716-446655440010")
    assert result.status == "queued"
    mock_enqueue.assert_awaited_once_with(ANY, ANY)
    # The background_tasks queue should NOT contain any tasks (arq path skips add_task)
    assert background_tasks.tasks == []


async def test_queue_collection_run_uses_in_process_when_backend_in_process() -> None:
    """When settings.queue_backend == 'in_process', use BackgroundTasks as before."""
    from unittest.mock import AsyncMock, MagicMock, patch
    from uuid import UUID

    from fastapi import BackgroundTasks

    from backend.api.schemas.collections import CollectionRunRequest
    from backend.services.collection_workflows import queue_collection_run

    payload = CollectionRunRequest(target="example.com", target_type="domain", plugin_name="dns")
    background_tasks = BackgroundTasks()
    session = AsyncMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=None)

    fake_run = MagicMock()
    fake_run.id = "550e8400-e29b-41d4-a716-446655440020"
    fake_run.status = "queued"

    with (
        patch("backend.services.collection_workflows.CollectionRunService") as mock_service_cls,
        patch("backend.services.collection_workflows.get_settings") as mock_settings,
    ):
        mock_service = mock_service_cls.return_value
        mock_service.create_run = AsyncMock(return_value=fake_run)

        mock_settings.return_value.queue_backend = "in_process"
        mock_settings.return_value.api_prefix = "/api/v1"

        result = await queue_collection_run(
            payload,
            run_scope="target",
            background_tasks=background_tasks,
            session=session,
        )

    assert result.run_id == UUID("550e8400-e29b-41d4-a716-446655440020")
    # BackgroundTasks should now have one task (the in-process path)
    assert len(background_tasks.tasks) == 1


# ---------------------------------------------------------------------------
# queue_collection_run / queue_investigation_collection_run enqueue failure
# ---------------------------------------------------------------------------

async def test_queue_collection_run_raises_503_when_arq_enqueue_fails() -> None:
    """When enqueue_collection_run_via_arq returns None, raise HTTPException 503."""
    from unittest.mock import AsyncMock, MagicMock, patch
    from fastapi import BackgroundTasks, HTTPException

    from backend.api.schemas.collections import CollectionRunRequest
    from backend.services.collection_workflows import queue_collection_run

    payload = CollectionRunRequest(target="example.com", target_type="domain", plugin_name="dns")
    background_tasks = BackgroundTasks()
    session = AsyncMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=None)

    fake_run = MagicMock()
    fake_run.id = "550e8400-e29b-41d4-a716-446655440030"
    fake_run.status = "queued"

    with (
        patch("backend.services.collection_workflows.CollectionRunService") as mock_service_cls,
        patch("backend.services.collection_workflows.get_settings") as mock_settings,
        patch("backend.workers.collection_worker.enqueue_collection_run_via_arq", AsyncMock(return_value=None)) as mock_enqueue,
    ):
        mock_service = mock_service_cls.return_value
        mock_service.create_run = AsyncMock(return_value=fake_run)

        mock_settings.return_value.queue_backend = "arq"
        mock_settings.return_value.api_prefix = "/api/v1"

        try:
            await queue_collection_run(
                payload,
                run_scope="target",
                background_tasks=background_tasks,
                session=session,
            )
            assert False, "Expected HTTPException 503"
        except HTTPException as exc:
            assert exc.status_code == 503
            assert exc.detail == "Worker queue unavailable"

    # enqueue should have been called
    mock_enqueue.assert_awaited_once()


async def test_queue_investigation_collection_run_raises_503_when_arq_enqueue_fails() -> None:
    """When enqueue_collection_run_via_arq returns None for investigation run, raise HTTPException 503."""
    from unittest.mock import AsyncMock, MagicMock, patch
    from fastapi import BackgroundTasks, HTTPException
    from uuid import UUID

    from backend.api.schemas.collections import CollectionWorkflowRunRequest
    from backend.services.collection_workflows import queue_investigation_collection_run

    investigation_id = UUID("550e8400-e29b-41d4-a716-446655440099")
    payload = CollectionWorkflowRunRequest(plugin_name="dns")
    background_tasks = BackgroundTasks()
    session = AsyncMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=None)

    fake_run = MagicMock()
    fake_run.id = "550e8400-e29b-41d4-a716-446655440040"
    fake_run.status = "queued"

    with (
        patch("backend.services.collection_workflows.CollectionRunService") as mock_service_cls,
        patch("backend.services.collection_workflows.get_settings") as mock_settings,
        patch("backend.workers.collection_worker.enqueue_collection_run_via_arq", AsyncMock(return_value=None)) as mock_enqueue,
        patch("backend.services.collection_workflows.validate_investigation_scope", AsyncMock()),
    ):
        mock_service = mock_service_cls.return_value
        mock_service.create_run = AsyncMock(return_value=fake_run)

        mock_settings.return_value.queue_backend = "arq"
        mock_settings.return_value.api_prefix = "/api/v1"

        try:
            await queue_investigation_collection_run(
                investigation_id,
                payload,
                background_tasks=background_tasks,
                session=session,
            )
            assert False, "Expected HTTPException 503"
        except HTTPException as exc:
            assert exc.status_code == 503
            assert exc.detail == "Worker queue unavailable"

    mock_enqueue.assert_awaited_once()