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


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Create tables
    Base.metadata.create_all(bind=engine)

    # Seed rules & initial demo data if database is empty
    db = SessionLocal()
    try:
        seed_default_rules_if_empty(db)
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
