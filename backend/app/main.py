from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.database.base import Base
from app.database.session import engine, SessionLocal
from app.models import *  # Ensure all models are loaded
from app.api import api_router
from app.services.siem_pipeline import seed_default_rules_if_empty, run_pipeline_on_records
from app.ingestion.parser import parse_upload_file
from app.models.log import SecurityLogModel
from app.models.user import UserModel
from app.core.security import hash_password
import uuid
from datetime import datetime


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Create tables
    Base.metadata.create_all(bind=engine)

    # Seed rules & initial demo data if database is empty
    db = SessionLocal()
    try:
        seed_default_rules_if_empty(db)
        _seed_default_admin_if_empty(db)
        log_count = db.query(SecurityLogModel).count()
        if log_count == 0:
            sample_file = Path(__file__).resolve().parent.parent / "data" / "samples" / "demo_security_logs.csv"
            if sample_file.exists():
                content = sample_file.read_bytes()
                records, _ = parse_upload_file("demo_security_logs.csv", content)
                if records:
                    run_pipeline_on_records(db, records)
                    print(f"✓ Initialized SIEM database with {len(records)} demo security events, alerts, and incidents.")
    except Exception as e:
        print(f"Warning during startup initialization: {e}")
    finally:
        db.close()

    yield
    # Shutdown logic if needed


def _seed_default_admin_if_empty(db) -> None:
    """Create the default ADMIN account on first startup (empty users table).
    Credentials come from env vars: DEFAULT_ADMIN_EMAIL / DEFAULT_ADMIN_PASSWORD.
    Logs a clear reminder to change the password if the default is being used.
    """
    from app.models.user import UserModel  # local import avoids circular at module level
    from app.core.security import hash_password
    import uuid
    from datetime import datetime

    if db.query(UserModel).count() > 0:
        return

    email = settings.DEFAULT_ADMIN_EMAIL
    password = settings.DEFAULT_ADMIN_PASSWORD
    if not password:
        password = "ChangeMe@SIEM2024!"  # fallback ONLY if env var not set
        print("⚠️  DEFAULT_ADMIN_PASSWORD not set — using insecure default. CHANGE IMMEDIATELY after first login.")
    else:
        print("✓  Admin account seeded from DEFAULT_ADMIN_PASSWORD env var.")

    admin = UserModel(
        id=str(uuid.uuid4()),
        email=email,
        full_name="System Administrator",
        hashed_password=hash_password(password),
        role="ADMIN",
        is_active=True,
        created_at=datetime.utcnow(),
    )
    db.add(admin)
    db.commit()
    print(f"✓  Default admin account created: {email}")
    print("   ⚠️  REMINDER: Change the default admin password after first login!")


app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Enterprise Cyber Security SIEM Copilot Backend for Threat Hunting and Incident Investigation",
    version="1.0.0",
    lifespan=lifespan,
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register health check
@app.get("/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "api_docs": "/docs",
    }


# Register all API endpoints
app.include_router(api_router, prefix=settings.API_V1_STR)
