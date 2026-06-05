"""FastAPI integration tests with an isolated async SQLite database."""

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from backend.api.app import create_app
from backend.models import Finding, Investigation, Report, Target
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
            tables=[Investigation.__table__, Target.__table__, Finding.__table__, Report.__table__],
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
