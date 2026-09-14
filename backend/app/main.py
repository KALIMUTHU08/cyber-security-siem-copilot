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
        _bootstrap_demo_accounts(db)
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


def _bootstrap_demo_accounts(db) -> None:
    """
    Bootstrap demo/admin accounts at startup.

    A) Admin — Fresh DB (admin email not found):
       Requires DEFAULT_ADMIN_PASSWORD to be explicitly set via env var.
       If missing, logs a clear error and skips creation — no hardcoded
       fallback password is ever written to the database.

    B) Admin — Existing DB + BOOTSTRAP_ADMIN_PASSWORD_SYNC=true:
       Finds the admin row by DEFAULT_ADMIN_EMAIL and re-hashes its stored
       password to match the current DEFAULT_ADMIN_PASSWORD.
       BOOTSTRAP_ADMIN_PASSWORD_SYNC ONLY affects the admin account.
       Remove this env var and redeploy immediately after the one-time sync.

    C) Admin — Existing DB, sync disabled (normal steady-state):
       Skips silently. Never mutates the existing admin password.

    D) Analyst — controlled separately, never touched by sync flag:
       If DEFAULT_ANALYST_PASSWORD is set and the analyst account does not
       yet exist, creates it as SECURITY_ANALYST.
       If the analyst account already exists, it is NEVER modified
       automatically — a deliberate password reset via the admin UI or
       a separate explicit mechanism must be used instead.
       If DEFAULT_ANALYST_PASSWORD is empty, skips silently.

    Security guarantees:
    - No hardcoded default password is ever persisted.
    - BOOTSTRAP_ADMIN_PASSWORD_SYNC never touches analyst or any other user.
    - Analyst password is never overwritten automatically.
    - Plaintext passwords are never stored, logged, or returned.
    - Works identically against SQLite (local/tests) and PostgreSQL (production).
    """
    from app.models.user import UserModel  # local import avoids circular at module level
    from app.core.security import hash_password
    import uuid
    from datetime import datetime

    # ------------------------------------------------------------------ Admin
    admin_email = settings.DEFAULT_ADMIN_EMAIL
    admin_password = settings.DEFAULT_ADMIN_PASSWORD
    sync_flag = settings.BOOTSTRAP_ADMIN_PASSWORD_SYNC

    existing_admin = db.query(UserModel).filter(UserModel.email == admin_email).first()

    if existing_admin is None:
        # Fresh DB — admin account does not exist yet.
        if not admin_password:
            # Fail safely: refuse to create an account with no configured password.
            # A hardcoded fallback would create a publicly-known credential.
            print(
                "⚠️  BOOTSTRAP SKIPPED: DEFAULT_ADMIN_PASSWORD is not set. "
                "Set it via environment variable and restart to provision the admin account. "
                "The application will start, but no admin account will be available until then."
            )
            return
        admin = UserModel(
            id=str(uuid.uuid4()),
            email=admin_email,
            full_name="System Administrator",
            hashed_password=hash_password(admin_password),
            role="ADMIN",
            is_active=True,
            created_at=datetime.utcnow(),
        )
        db.add(admin)
        db.commit()
        print(f"✓  Admin account created: {admin_email}")
    elif sync_flag:
        # One-time admin password sync — BOOTSTRAP_ADMIN_PASSWORD_SYNC=true only.
        if not admin_password:
            print(
                "⚠️  BOOTSTRAP_ADMIN_PASSWORD_SYNC=true but DEFAULT_ADMIN_PASSWORD is empty — "
                "skipping admin password sync to avoid locking out the account. "
                "Set DEFAULT_ADMIN_PASSWORD and restart."
            )
        else:
            existing_admin.hashed_password = hash_password(admin_password)
            db.commit()
            print(
                f"✓  Admin password re-hashed for {admin_email} (BOOTSTRAP_ADMIN_PASSWORD_SYNC). "
                "IMPORTANT: Remove BOOTSTRAP_ADMIN_PASSWORD_SYNC from env vars and redeploy now."
            )
    else:
        # Steady state — admin exists, no sync requested. Leave password untouched.
        print(f"✓  Admin account {admin_email} exists — no changes.")
        if not admin_password:
            print(
                "   ⚠️  DEFAULT_ADMIN_PASSWORD is not configured. "
                "If you cannot log in, set it and redeploy with BOOTSTRAP_ADMIN_PASSWORD_SYNC=true."
            )

    # ---------------------------------------------------------------- Analyst
    # Analyst provisioning is independent of the admin sync flag.
    # An existing analyst's password is NEVER overwritten automatically.
    analyst_email = settings.DEFAULT_ANALYST_EMAIL
    analyst_password = settings.DEFAULT_ANALYST_PASSWORD

    if not analyst_password:
        # Opt-in only — skip silently if not configured.
        return

    existing_analyst = db.query(UserModel).filter(UserModel.email == analyst_email).first()

    if existing_analyst is None:
        analyst = UserModel(
            id=str(uuid.uuid4()),
            email=analyst_email,
            full_name="Security Analyst",
            hashed_password=hash_password(analyst_password),
            role="SECURITY_ANALYST",
            is_active=True,
            created_at=datetime.utcnow(),
        )
        db.add(analyst)
        db.commit()
        print(f"✓  Demo analyst account created: {analyst_email}")
    else:
        # Analyst exists — never auto-overwrite. Use admin UI or a deliberate reset.
        print(f"✓  Analyst account {analyst_email} exists — password unchanged.")


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
