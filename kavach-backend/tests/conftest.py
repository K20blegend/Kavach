# ruff: noqa: E402
import os

os.environ["KAVACH_ENVIRONMENT"] = "test"
os.environ["KAVACH_DATABASE_URL"] = "sqlite:///:memory:"
os.environ["KAVACH_JWT_SECRET"] = "test-only-secret-48-characters-long-never-use-outside-tests"
os.environ["KAVACH_RATE_LIMIT_PER_MINUTE"] = "1000"
os.environ["KAVACH_SCAN_LIMIT_PER_MINUTE"] = "1000"

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app


@pytest.fixture
def db_session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _):
        connection.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        yield session
    engine.dispose()


@pytest.fixture
def client(db_session):
    def override_db():
        yield db_session

    app.dependency_overrides[get_db] = override_db
    app.middleware_stack = None
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def auth_headers(client):
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "tester@example.com",
            "display_name": "Test User",
            "password": "a-secure-test-password",
        },
    )
    assert response.status_code == 201, response.text
    return {"Authorization": "Bearer " + response.json()["access_token"]}
