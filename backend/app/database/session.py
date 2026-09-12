import re
from typing import Generator
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import OperationalError
from app.core.config import settings


def _redact_url(url: str) -> str:
    """Replace credentials in a DATABASE_URL with [REDACTED] for safe logging."""
    return re.sub(r"://[^@]+@", "://[REDACTED]@", url)


connect_args = {}
is_sqlite = settings.DATABASE_URL.startswith("sqlite")
if is_sqlite:
    connect_args["check_same_thread"] = False

try:
    engine = create_engine(
        settings.DATABASE_URL,
        connect_args=connect_args,
        # pool_pre_ping keeps Postgres connections alive; harmless for SQLite
        pool_pre_ping=not is_sqlite,
        echo=False,
    )
except Exception as exc:
    # Redact credentials before raising so DATABASE_URL never appears in logs
    safe_url = _redact_url(settings.DATABASE_URL)
    raise RuntimeError(
        f"Failed to create database engine for '{safe_url}': {type(exc).__name__}"
    ) from None

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
