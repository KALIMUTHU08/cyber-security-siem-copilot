from typing import Optional, List, Dict
from datetime import datetime
from pydantic import field_serializer
from app.schemas.common import CamelModel, RiskScore


class TimelineEvent(CamelModel):
    id: str
    timestamp: datetime
    title: str
    description: str
    event_type: str
    severity: str
    related_log_ids: List[str] = []
    related_alert_ids: List[str] = []
    metadata: Optional[Dict[str, str]] = None

    @field_serializer("timestamp")
    def serialize_timestamp(self, dt: datetime, _info) -> str:
        return dt.isoformat()


class Incident(CamelModel):
    id: str
    title: str
    severity: str
    status: str
    risk_score: RiskScore
    source_ip: str
    destination_ip: Optional[str] = None
    target_user: str
    affected_device: str
    first_seen: datetime
    last_seen: datetime
    summary: str = ""
    attack_vector: str = ""
    timeline: List[TimelineEvent] = []
    related_alert_ids: List[str] = []
    related_log_ids: List[str] = []
    observed_evidence: List[str] = []
    ai_assessment: str = ""
    recommended_next_steps: List[str] = []
    tags: List[str] = []

    @field_serializer("first_seen")
    def serialize_first_seen(self, dt: datetime, _info) -> str:
        return dt.isoformat()

    @field_serializer("last_seen")
    def serialize_last_seen(self, dt: datetime, _info) -> str:
        return dt.isoformat()
