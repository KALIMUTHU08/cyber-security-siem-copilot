"""
dataset.py — API endpoints for dataset management and evaluation.

Routes:
    GET  /api/dataset/info     — metadata about the available dataset CSV
    POST /api/dataset/seed     — async background seed (non-blocking)
    GET  /api/dataset/status   — persistent seed progress from SQLite
    GET  /api/dataset/evaluate — run evaluation metrics (TP/FP/FN/TN)
"""

import threading
import time
import uuid
from pathlib import Path
from typing import Optional, Dict, Any

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.deps import get_current_user
from app.core.permissions import Permission, require_permission
from app.database.session import SessionLocal, get_db
from app.ingestion.dataset_adapter import stream_dataset_chunks, get_dataset_info
from app.models.user import UserModel
from app.services.siem_pipeline import run_pipeline_on_records
from app.services.dataset_status_service import (
    get_persistent_seed_status,
    update_persistent_seed_status,
)

router = APIRouter(prefix="/dataset", tags=["Dataset"])

# Default dataset path relative to project root
_DEFAULT_CSV = str(
    Path(__file__).parent.parent.parent.parent / "dataset" / "cybersecurity_threat_detection_logs.csv"
)


class SeedRequest(BaseModel):
    limit: int = 50_000       # 0 = all rows
    chunk_size: int = 5_000
    reset: bool = False


def _seed_worker(csv_path: str, limit: int, chunk_size: int, reset: bool, batch_id: str):
    db = SessionLocal()
    try:
        if reset:
            from app.database.base import Base
            from app.database.session import engine
            Base.metadata.drop_all(bind=engine)
            Base.metadata.create_all(bind=engine)

        update_persistent_seed_status(db, {
            "running": True,
            "done": False,
            "started_at": time.time(),
            "finished_at": None,
            "error": None,
            "limit": limit,
            "chunk_size": chunk_size,
            "batch_id": batch_id,
        })
    finally:
        db.close()

    max_rows = limit if limit > 0 else None
    error_msg = None

    try:
        for chunk, cumulative in stream_dataset_chunks(csv_path, chunk_size=chunk_size, max_rows=max_rows):
            chunk_db = SessionLocal()
            try:
                stats, alerts = run_pipeline_on_records(chunk_db, chunk)
                current = get_persistent_seed_status(chunk_db)
                update_persistent_seed_status(chunk_db, {
                    "rows_processed": current.get("rows_processed", 0) + stats.processed,
                    "alerts_generated": current.get("alerts_generated", 0) + stats.alerts_generated,
                    "incidents_updated": current.get("incidents_updated", 0) + stats.incidents_updated,
                })
            except Exception as e:
                error_msg = str(e)
            finally:
                chunk_db.close()

    except Exception as e:
        error_msg = str(e)
    finally:
        final_db = SessionLocal()
        try:
            update_persistent_seed_status(final_db, {
                "running": False,
                "done": True,
                "finished_at": time.time(),
                "error": error_msg,
            })
        finally:
            final_db.close()


@router.get("/info")
def dataset_info(_: UserModel = Depends(get_current_user)):
    info = get_dataset_info(_DEFAULT_CSV)
    return info


@router.post("/seed")
def seed_dataset(
    req: SeedRequest,
    _: UserModel = Depends(require_permission(Permission.LOGS_INGEST)),
    db: Session = Depends(get_db),
):
    status = get_persistent_seed_status(db)
    if status.get("running"):
        raise HTTPException(status_code=409, detail="Seed already in progress")

    csv_path = _DEFAULT_CSV
    if not Path(csv_path).exists():
        raise HTTPException(status_code=404, detail=f"Dataset CSV not found at {csv_path}")

    batch_id = f"batch-{uuid.uuid4().hex[:8]}"

    # Initialize status
    update_persistent_seed_status(db, {
        "running": True,
        "done": False,
        "rows_processed": 0,
        "alerts_generated": 0,
        "incidents_updated": 0,
        "error": None,
        "started_at": time.time(),
        "finished_at": None,
        "limit": req.limit,
        "chunk_size": req.chunk_size,
        "batch_id": batch_id,
    })

    t = threading.Thread(
        target=_seed_worker,
        args=(csv_path, req.limit, req.chunk_size, req.reset, batch_id),
        daemon=True,
    )
    t.start()
    return {"message": "Seed started", "limit": req.limit, "chunk_size": req.chunk_size, "batch_id": batch_id}


@router.get("/status")
def seed_status(
    _: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve current seeding status backed persistently by SQLite."""
    return get_persistent_seed_status(db)


@router.get("/evaluate")
def evaluate_detection(_: UserModel = Depends(require_permission(Permission.LOGS_VIEW))):
    """Run TP/FP/FN/TN evaluation against ground truth labels."""
    try:
        import sys
        from pathlib import Path as P
        sys.path.insert(0, str(P(__file__).parent.parent.parent))
        from evaluation import run_evaluation
        report = run_evaluation()
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
