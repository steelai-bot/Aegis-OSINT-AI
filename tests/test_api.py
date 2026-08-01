from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


def test_api_status():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "status" in data["data"]


def test_api_plugins():
    response = client.get("/api/plugins")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert isinstance(data["data"], list)


def test_api_providers():
    response = client.get("/api/providers")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert isinstance(data["data"], list)


def test_api_stats():
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "targets" in data["data"]
    assert "plugins" in data["data"]


def test_delete_target():
    # Create target first
    create_resp = client.post(
        "/api/targets", json={"query": "testdelete.com", "target_type": "domain"}
    )
    assert create_resp.status_code == 200
    target_id = create_resp.json()["data"]["id"]

    # Delete target
    del_resp = client.delete(f"/api/targets/{target_id}")
    assert del_resp.status_code == 200
    assert del_resp.json()["success"] is True
