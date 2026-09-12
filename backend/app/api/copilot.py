from typing import Optional, List
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.schemas.copilot import CopilotChatRequest, CopilotMessage
from app.copilot.service import copilot_service

router = APIRouter(prefix="/copilot", tags=["Copilot"])


@router.post("/chat", response_model=CopilotMessage)
def chat_with_copilot(request: CopilotChatRequest, db: Session = Depends(get_db)):
    return copilot_service.process_chat(db, request.message, request.incident_id)


@router.get("/history", response_model=List[CopilotMessage])
def get_copilot_history(
    incident_id: Optional[str] = Query(None, alias="incidentId"),
    db: Session = Depends(get_db),
):
    return copilot_service.get_history(db, incident_id)
