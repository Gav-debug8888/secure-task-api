import os
import secrets

# Test configuration must be set before the app is imported (settings validate at import).
os.environ["JWT_SECRET_KEY"] = secrets.token_urlsafe(48)
os.environ["DATABASE_URL"] = "sqlite:///./test_tasks.db"
os.environ["ENVIRONMENT"] = "test"
os.environ["CORS_ORIGINS"] = "https://app.example.com"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.database import Base, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.middleware.rate_limiter import limiter  # noqa: E402

STRONG_PASSWORD = "Correct-Horse-42!"


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    limiter.reset()
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def client():
    # https base URL so Secure cookies are sent back, as in production.
    with TestClient(app, base_url="https://testserver") as c:
        yield c


def register(client, username="alice", email=None, password=STRONG_PASSWORD):
    return client.post(
        "/api/auth/register",
        json={"username": username, "email": email or f"{username}@example.com", "password": password},
    )


def login(client, username="alice", password=STRONG_PASSWORD):
    return client.post("/api/auth/login", json={"username": username, "password": password})


@pytest.fixture()
def auth_client(client):
    assert register(client).status_code == 201
    assert login(client).status_code == 200
    return client


def pytest_sessionfinish(session, exitstatus):
    if os.path.exists("test_tasks.db"):
        os.remove("test_tasks.db")
