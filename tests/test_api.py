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
