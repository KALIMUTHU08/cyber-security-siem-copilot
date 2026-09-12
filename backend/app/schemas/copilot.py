from typing import Optional, List
from datetime import datetime
from pydantic import field_serializer
from app.schemas.common import CamelModel


class CopilotChatRequest(CamelModel):
    message: str
    incident_id: Optional[str] = None


class CopilotResponse(CamelModel):
    lead_in: str
    event_count: Optional[int] = None
    observed_evidence: List[str] = []
    ai_assessment: str
    recommended_next_steps: List[str] = []


class CopilotMessage(CamelModel):
    id: str
    role: str  # 'analyst' | 'copilot'
    content: str
    timestamp: datetime
    incident_id: Optional[str] = None
    response: Optional[CopilotResponse] = None

    @field_serializer("timestamp")
    def serialize_timestamp(self, dt: datetime, _info) -> str:
        return dt.isoformat()
