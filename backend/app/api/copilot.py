from typing import Optional, List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.permissions import Permission, require_permission
from app.database.session import get_db
from app.models.user import UserModel
from app.schemas.copilot import CopilotChatRequest, CopilotMessage
from app.copilot.service import copilot_service

router = APIRouter(prefix="/copilot", tags=["Copilot"])


@router.post("/chat", response_model=CopilotMessage)
def chat_with_copilot(
    request: CopilotChatRequest,
    _: UserModel = Depends(require_permission(Permission.COPILOT_USE)),
    db: Session = Depends(get_db),
):
    return copilot_service.process_chat(db, request.message, request.incident_id)


@router.get("/history", response_model=List[CopilotMessage])
def get_copilot_history(
    incident_id: Optional[str] = Query(None, alias="incidentId"),
    _: UserModel = Depends(require_permission(Permission.COPILOT_USE)),
    db: Session = Depends(get_db),
):
    return copilot_service.get_history(db, incident_id)
