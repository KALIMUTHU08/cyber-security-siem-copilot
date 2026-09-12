"""
dataset_status_service.py — Persistent tracking of dataset seeding operations.

Uses the SQLite-backed SystemSettingModel so seeding status survives server
restarts/reloads and remains synchronized across CLI scripts and FastAPI endpoints.
"""

import json
import time
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models.setting import SystemSettingModel
from app.models.log import SecurityLogModel

STATUS_KEY = "dataset_seed_status"
STATUS_CATEGORY = "dataset"

DEFAULT_STATUS: Dict[str, Any] = {
    "running": False,
    "done": False,
    "started_at": None,
    "finished_at": None,
    "rows_processed": 0,
    "alerts_generated": 0,
    "incidents_updated": 0,
    "error": None,
    "limit": 0,
    "chunk_size": 5000,
    "elapsed_seconds": 0.0,
    "rows_per_second": 0.0,
    "source_file": "cybersecurity_threat_detection_logs.csv",
    "batch_id": None,
}


def get_persistent_seed_status(db: Session) -> Dict[str, Any]:
    """Retrieve persistent dataset seed status from SQLite."""
    setting = db.query(SystemSettingModel).filter(SystemSettingModel.key == STATUS_KEY).first()
    if setting and setting.value:
        try:
            data = json.loads(setting.value)
            # Dynamically refresh elapsed and rate if a job is actively marked running
            if data.get("running") and data.get("started_at"):
                elapsed = time.time() - data["started_at"]
                data["elapsed_seconds"] = round(elapsed, 1)
                data["rows_per_second"] = round(data.get("rows_processed", 0) / elapsed, 0) if elapsed > 0 else 0.0
            return data
        except Exception:
            pass

    # Fallback: check actual count of dataset records in database
    ds_count = db.query(SecurityLogModel).filter(SecurityLogModel.id.like("ds-%")).count()
    status = dict(DEFAULT_STATUS)
    if ds_count > 0:
        status["rows_processed"] = ds_count
        status["done"] = True
    return status


def update_persistent_seed_status(db: Session, updates: Dict[str, Any]) -> Dict[str, Any]:
    """Update persistent dataset seed status in SQLite."""
    current = get_persistent_seed_status(db)
    current.update(updates)

    # Compute elapsed seconds and rate
    if current.get("started_at"):
        end_time = current.get("finished_at") or time.time()
        elapsed = end_time - current["started_at"]
        current["elapsed_seconds"] = round(elapsed, 1)
        current["rows_per_second"] = round(current.get("rows_processed", 0) / elapsed, 0) if elapsed > 0 else 0.0

    setting = db.query(SystemSettingModel).filter(SystemSettingModel.key == STATUS_KEY).first()
    if not setting:
        setting = SystemSettingModel(
            key=STATUS_KEY,
            value=json.dumps(current),
            category=STATUS_CATEGORY,
        )
        db.add(setting)
    else:
        setting.value = json.dumps(current)

    db.commit()
    return current
