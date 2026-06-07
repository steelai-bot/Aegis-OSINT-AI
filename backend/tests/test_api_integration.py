"""FastAPI integration tests with an isolated async SQLite database."""

import base64
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from backend.api.app import create_app
from backend.api.schemas.collections import CollectionRunResponse
from backend.models import AgentContextSnapshot, AgentTaskResult, Finding, Investigation, Report, Target
from backend.models.base import Base
from backend.storage.database import get_db_session

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def client() -> AsyncIterator[AsyncClient]:
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    async with engine.begin() as connection:
        await connection.run_sync(
            Base.metadata.create_all,
            tables=[
                Investigation.__table__,
                Target.__table__,
                Finding.__table__,
                Report.__table__,
                AgentContextSnapshot.__table__,
                AgentTaskResult.__table__,
            ],
        )

    async def override_db_session() -> AsyncIterator[AsyncSession]:
        async with session_factory() as session:
            yield session

    app = create_app()
    app.dependency_overrides[get_db_session] = override_db_session

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as test_client:
        yield test_client

    app.dependency_overrides.clear()
    await engine.dispose()


async def test_health_and_metrics_routes(client: AsyncClient) -> None:
    health = await client.get("/health")
    metrics = await client.get("/metrics")

    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert metrics.status_code == 200
    assert metrics.json()["metrics"]["requests_total"] == 0


async def test_investigation_target_finding_and_report_flow(client: AsyncClient) -> None:
    investigation_response = await client.post("/investigations", json={"title": "Example investigation"})
    assert investigation_response.status_code == 201
    investigation = investigation_response.json()
    assert investigation["title"] == "Example investigation"
    assert investigation["status"] == "pending"

    target_response = await client.post(
        "/targets",
        json={
            "investigation_id": investigation["id"],
            "type": "domain",
            "value": "example.com",
        },
    )
    assert target_response.status_code == 201
    target = target_response.json()

    finding_response = await client.post(
        "/findings",
        json={
            "investigation_id": investigation["id"],
            "target_id": target["id"],
            "source": "integration-test",
            "confidence": 0.92,
            "severity": "high",
            "data": {"title": "Passive DNS signal", "summary": "Observed from persisted test data."},
        },
    )
    assert finding_response.status_code == 201
    finding = finding_response.json()
    assert finding["data"]["title"] == "Passive DNS signal"

    investigations = await client.get("/investigations")
    assert investigations.status_code == 200
    assert [item["id"] for item in investigations.json()] == [investigation["id"]]

    findings = await client.get(f"/investigations/{investigation['id']}/findings")
    assert findings.status_code == 200
    assert [item["id"] for item in findings.json()] == [finding["id"]]

    render_response = await client.post(
        f"/investigations/{investigation['id']}/reports/render",
        json={"format": "markdown"},
    )
    assert render_response.status_code == 200
    rendered = render_response.json()
    assert rendered["format"] == "markdown"
    assert "Example investigation" in rendered["content"]
    assert "Passive DNS signal" in rendered["content"]

    html_response = await client.post(
        f"/investigations/{investigation['id']}/reports/render",
        json={"format": "html"},
    )
    assert html_response.status_code == 200
    html_rendered = html_response.json()
    assert html_rendered["format"] == "html"
    assert "<!doctype html>" in html_rendered["content"]
    assert "Passive DNS signal" in html_rendered["content"]

    pdf_response = await client.post(
        f"/investigations/{investigation['id']}/reports/render",
        json={"format": "pdf"},
    )
    assert pdf_response.status_code == 200
    pdf_rendered = pdf_response.json()
    assert pdf_rendered["format"] == "pdf"
    assert base64.b64decode(pdf_rendered["content"]).startswith(b"%PDF-1.4")


async def test_target_creation_returns_404_for_missing_investigation(client: AsyncClient) -> None:
    response = await client.post(
        "/targets",
        json={
            "investigation_id": "00000000-0000-0000-0000-000000000000",
            "type": "domain",
            "value": "example.com",
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Investigation not found"


async def test_target_collection_forwards_tool_execution_controls(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = {}

    async def fake_run_collection_job(payload, *, session):  # noqa: ANN001
        captured["payload"] = payload
        return CollectionRunResponse(target=payload.target, target_type=payload.target_type, target_id=payload.target_id)

    monkeypatch.setattr("backend.api.routes.targets.run_collection_job", fake_run_collection_job)

    investigation_response = await client.post("/investigations", json={"title": "Approval forwarding"})
    target_response = await client.post(
        "/targets",
        json={
            "investigation_id": investigation_response.json()["id"],
            "type": "domain",
            "value": "example.com",
        },
    )

    collect_response = await client.post(
        f"/targets/{target_response.json()['id']}/collect",
        json={
            "plugin_name": "operator_tool",
            "execution_mode": "operator_assisted",
            "approval_token": "one-time-token",
            "authorized_scope": "ticket-123 approved domain run",
        },
    )

    assert collect_response.status_code == 200
    payload = captured["payload"]
    assert payload.plugin_name == "operator_tool"
    assert payload.execution_mode == "operator_assisted"
    assert payload.approval_token == "one-time-token"
    assert payload.authorized_scope == "ticket-123 approved domain run"


async def test_agent_run_persists_task_result_metadata(client: AsyncClient) -> None:
    investigation_response = await client.post("/investigations", json={"title": "Agent persistence"})
    investigation_id = investigation_response.json()["id"]

    response = await client.post(
        "/agents/run",
        json={
            "investigation_id": investigation_id,
            "target": "example.com",
            "target_type": "domain",
            "metadata": {"source": "integration-test"},
        },
    )

    assert response.status_code == 200
    results = response.json()
    assert [item["agent_name"] for item in results] == ["recon", "domain", "social", "threat_intel", "report"]
    assert all(item["status"] == "completed" for item in results)
    assert all(item["metadata"]["task_result_id"] for item in results)
    assert results[-1]["metadata"]["finding_count"] == 3
