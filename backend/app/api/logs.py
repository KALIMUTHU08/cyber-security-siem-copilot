from typing import Optional, List
from fastapi import APIRouter, Depends, Query, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.core.permissions import Permission, require_permission
from app.database.session import get_db
from app.models.log import SecurityLogModel
from app.models.user import UserModel
from app.schemas.log import SecurityLog, BatchIdsRequest, IngestStats
from app.schemas.common import PaginatedResult
from app.ingestion.parser import parse_upload_file
from app.services.siem_pipeline import run_pipeline_on_records

router = APIRouter(prefix="/logs", tags=["Logs"])


@router.get("", response_model=PaginatedResult[SecurityLog])
def list_logs(
    search: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None, alias="sourceIp"),
    destination_ip: Optional[str] = Query(None, alias="destinationIp"),
    username: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None, alias="eventType"),
    status: Optional[str] = Query(None),
    device: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100, alias="pageSize"),
    _: UserModel = Depends(require_permission(Permission.LOGS_VIEW)),
    db: Session = Depends(get_db),
):
    query = db.query(SecurityLogModel)

    if search:
        s = f"%{search.lower()}%"
        query = query.filter(
            or_(
                SecurityLogModel.source_ip.ilike(s),
                SecurityLogModel.destination_ip.ilike(s),
                SecurityLogModel.username.ilike(s),
                SecurityLogModel.event_type.ilike(s),
                SecurityLogModel.device.ilike(s),
                SecurityLogModel.raw_log.ilike(s),
            )
        )

    if source_ip:
        query = query.filter(SecurityLogModel.source_ip == source_ip)
    if destination_ip:
        query = query.filter(SecurityLogModel.destination_ip == destination_ip)
    if username:
        query = query.filter(SecurityLogModel.username.ilike(f"%{username}%"))
    if event_type:
        query = query.filter(SecurityLogModel.event_type == event_type)
    if status:
        query = query.filter(SecurityLogModel.status == status)
    if device:
        query = query.filter(SecurityLogModel.device.ilike(f"%{device}%"))

    total = query.count()
    items = (
        query.order_by(SecurityLogModel.timestamp.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return PaginatedResult[SecurityLog](
        items=[SecurityLog.model_validate(l) for l in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("/batch", response_model=List[SecurityLog])
def get_logs_by_ids_post(
    request: BatchIdsRequest,
    _: UserModel = Depends(require_permission(Permission.LOGS_VIEW)),
    db: Session = Depends(get_db),
):
    if not request.ids:
        return []
    logs = db.query(SecurityLogModel).filter(SecurityLogModel.id.in_(request.ids)).all()
    return [SecurityLog.model_validate(l) for l in logs]


@router.get("/batch", response_model=List[SecurityLog])
def get_logs_by_ids_get(
    ids: str = Query(""),
    _: UserModel = Depends(require_permission(Permission.LOGS_VIEW)),
    db: Session = Depends(get_db),
):
    id_list = [i.strip() for i in ids.split(",") if i.strip()]
    if not id_list:
        return []
    logs = db.query(SecurityLogModel).filter(SecurityLogModel.id.in_(id_list)).all()
    return [SecurityLog.model_validate(l) for l in logs]


@router.get("/{log_id}", response_model=SecurityLog)
def get_log_by_id(
    log_id: str,
    _: UserModel = Depends(require_permission(Permission.LOGS_VIEW)),
    db: Session = Depends(get_db),
):
    log = db.query(SecurityLogModel).filter(SecurityLogModel.id == log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail=f"Log {log_id} not found")
    return SecurityLog.model_validate(log)


@router.post("/upload", response_model=IngestStats)
async def upload_log_file(
    file: UploadFile = File(...),
    _: UserModel = Depends(require_permission(Permission.LOGS_INGEST)),
    db: Session = Depends(get_db),
):
    content_bytes = await file.read()
    records, errors = parse_upload_file(file.filename or "upload.csv", content_bytes)

    if not records and errors:
        raise HTTPException(status_code=400, detail="; ".join(errors))

    stats, _ = run_pipeline_on_records(db, records)
    stats.errors.extend(errors)
    return stats
