import uuid
from datetime import datetime
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.deps import get_current_user
from app.database.base import Base
from app.database.session import get_db
from app.main import app
from app.models.user import UserModel
from app.services.siem_pipeline import seed_default_rules_if_empty

# In-memory SQLite for testing
TEST_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# ---------------------------------------------------------------------------
# Shared admin user for test auth override — avoids JWTs in tests
# ---------------------------------------------------------------------------
_TEST_ADMIN_ID = str(uuid.uuid4())
_TEST_ADMIN = UserModel(
    id=_TEST_ADMIN_ID,
    email="testadmin@siem.test",
    full_name="Test Admin",
    hashed_password="irrelevant-in-tests",  # never used; auth is overridden
    role="ADMIN",
    is_active=True,
    created_at=datetime.utcnow(),
)


def _override_get_current_user():
    """Return a synthetic ADMIN user — bypasses JWT for unit tests."""
    return _TEST_ADMIN


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    seed_default_rules_if_empty(db)
    # Insert the test admin user so FK references in auth tests work
    db.merge(_TEST_ADMIN)
    db.commit()
    db.close()
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def db_session():
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = _override_get_current_user
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def analyst_client(db_session):
    """Client authenticated as SECURITY_ANALYST."""
    analyst = UserModel(
        id=str(uuid.uuid4()),
        email="analyst@siem.test",
        full_name="Test Analyst",
        hashed_password="irrelevant",
        role="SECURITY_ANALYST",
        is_active=True,
        created_at=datetime.utcnow(),
    )
    db_session.merge(analyst)
    db_session.flush()

    def override_get_db():
        yield db_session

    def override_get_user():
        return analyst

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_user
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def operator_client(db_session):
    """Client authenticated as SOC_OPERATOR."""
    operator = UserModel(
        id=str(uuid.uuid4()),
        email="operator@siem.test",
        full_name="Test Operator",
        hashed_password="irrelevant",
        role="SOC_OPERATOR",
        is_active=True,
        created_at=datetime.utcnow(),
    )
    db_session.merge(operator)
    db_session.flush()

    def override_get_db():
        yield db_session

    def override_get_user():
        return operator

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_user
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def viewer_client(db_session):
    """Client authenticated as VIEWER."""
    viewer = UserModel(
        id=str(uuid.uuid4()),
        email="viewer@siem.test",
        full_name="Test Viewer",
        hashed_password="irrelevant",
        role="VIEWER",
        is_active=True,
        created_at=datetime.utcnow(),
    )
    db_session.merge(viewer)
    db_session.flush()

    def override_get_db():
        yield db_session

    def override_get_user():
        return viewer

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_user
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
