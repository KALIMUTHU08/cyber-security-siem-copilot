"""
backend/tests/test_auth.py — Authentication and JWT tests.
"""
import uuid
from datetime import datetime, timedelta
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.database.session import get_db
from app.models.user import UserModel
from app.core.security import hash_password, create_access_token


@pytest.fixture
def unmocked_client(db_session):
    """Client with real get_current_user (no bypass) to test JWT authentication."""
    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def test_login_success(unmocked_client, db_session):
    # Seed user with known password
    user_id = str(uuid.uuid4())
    user = UserModel(
        id=user_id,
        email="realuser@siem.test",
        full_name="Real User",
        hashed_password=hash_password("SuperSecret123!"),
        role="SECURITY_ANALYST",
        is_active=True,
        created_at=datetime.utcnow(),
    )
    db_session.add(user)
    db_session.commit()

    resp = unmocked_client.post(
        "/api/auth/login",
        json={"email": "realuser@siem.test", "password": "SuperSecret123!"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "accessToken" in data
    assert data["tokenType"] == "bearer"
    assert data["user"]["email"] == "realuser@siem.test"
    assert data["user"]["role"] == "SECURITY_ANALYST"
    assert "incidents.investigate" in data["permissions"]


def test_login_wrong_password(unmocked_client, db_session):
    user = UserModel(
        id=str(uuid.uuid4()),
        email="wrongpw@siem.test",
        full_name="Wrong PW",
        hashed_password=hash_password("CorrectPassword!"),
        role="VIEWER",
        is_active=True,
        created_at=datetime.utcnow(),
    )
    db_session.add(user)
    db_session.commit()

    resp = unmocked_client.post(
        "/api/auth/login",
        json={"email": "wrongpw@siem.test", "password": "WrongPassword!"},
    )
    assert resp.status_code == 401


def test_login_inactive_user(unmocked_client, db_session):
    user = UserModel(
        id=str(uuid.uuid4()),
        email="inactive@siem.test",
        full_name="Inactive User",
        hashed_password=hash_password("SomePassword123!"),
        role="VIEWER",
        is_active=False,
        created_at=datetime.utcnow(),
    )
    db_session.add(user)
    db_session.commit()

    resp = unmocked_client.post(
        "/api/auth/login",
        json={"email": "inactive@siem.test", "password": "SomePassword123!"},
    )
    assert resp.status_code == 403
    assert "deactivated" in resp.text.lower()


def test_login_nonexistent_user(unmocked_client):
    resp = unmocked_client.post(
        "/api/auth/login",
        json={"email": "doesnotexist@siem.test", "password": "AnyPassword123!"},
    )
    assert resp.status_code == 401


def test_me_authenticated(unmocked_client, db_session):
    user = UserModel(
        id=str(uuid.uuid4()),
        email="me_test@siem.test",
        full_name="Me Test",
        hashed_password=hash_password("Password123!"),
        role="SOC_OPERATOR",
        is_active=True,
        created_at=datetime.utcnow(),
    )
    db_session.add(user)
    db_session.commit()

    token = create_access_token(user.id)
    resp = unmocked_client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["user"]["email"] == "me_test@siem.test"
    assert data["user"]["role"] == "SOC_OPERATOR"
    assert "response.execute" in data["permissions"]


def test_me_unauthenticated(unmocked_client):
    resp = unmocked_client.get("/api/auth/me")
    assert resp.status_code == 401


def test_invalid_token(unmocked_client):
    resp = unmocked_client.get(
        "/api/auth/me",
        headers={"Authorization": "Bearer not-a-valid-token-string"},
    )
    assert resp.status_code == 401


def test_expired_token(unmocked_client, db_session):
    user = UserModel(
        id=str(uuid.uuid4()),
        email="expired_test@siem.test",
        full_name="Expired User",
        hashed_password=hash_password("Password123!"),
        role="VIEWER",
        is_active=True,
        created_at=datetime.utcnow(),
    )
    db_session.add(user)
    db_session.commit()

    # Create token already expired
    token = create_access_token(
        user.id,
        expires_delta=timedelta(seconds=-10),
    )
    resp = unmocked_client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401
