"""
Pytest configuration and fixtures for threat intelligence API tests
"""
import pytest
import asyncio
from fastapi.testclient import TestClient
from app.main import app
from app.core.auth import fake_users_db, get_password_hash
from app.models.schemas import UserInDB


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for each test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def client():
    """Create a test client for the FastAPI application"""
    return TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_users():
    """Setup test users before each test"""
    fake_users_db.clear()
    fake_users_db["admin"] = UserInDB(
        username="admin",
        hashed_password=get_password_hash("admin123"),
        disabled=False
    )
    fake_users_db["testuser"] = UserInDB(
        username="testuser",
        hashed_password=get_password_hash("testpass123"),
        disabled=False
    )
    yield
    fake_users_db.clear()


@pytest.fixture
def auth_headers(client):
    """Get authentication headers with valid token"""
    response = client.post(
        "/auth/token",
        data={"username": "admin", "password": "admin123"}
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def sample_indicators():
    """Sample indicators for testing"""
    return {
        "ip": "8.8.8.8",
        "domain": "google.com",
        "url": "https://example.com",
        "hash_md5": "5d41402abc4b2a76b9719d911017c592",
        "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
