from typing import Optional, List
from datetime import datetime
from pydantic import field_serializer
from app.schemas.common import CamelModel


class ThreatHuntRequest(CamelModel):
    query_text: str


class ThreatHuntQuery(CamelModel):
    id: str
    query_text: str
    timestamp: datetime
    status: str = "done"
    interpretation: Optional[str] = None
    matching_log_ids: List[str] = []
    related_alert_ids: List[str] = []
    risk_indicators: List[str] = []

    @field_serializer("timestamp")
    def serialize_timestamp(self, dt: datetime, _info) -> str:
        return dt.isoformat()
