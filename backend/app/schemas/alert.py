from typing import Optional, List
from datetime import datetime
from pydantic import field_serializer
from app.schemas.common import CamelModel, RiskScore


class SecurityAlert(CamelModel):
    id: str
    title: str
    severity: str
    status: str
    risk_score: RiskScore
    detection_rule_id: str
    detection_rule_name: str
    detection_condition: str
    source_ip: str
    destination_ip: Optional[str] = None
    username: str = ""
    device: str = ""
    first_seen: datetime
    last_seen: datetime
    match_count: int = 1
    matching_summary: str = ""
    matching_log_ids: List[str] = []
    related_incident_id: Optional[str] = None
    tags: List[str] = []

    @field_serializer("first_seen")
    def serialize_first_seen(self, dt: datetime, _info) -> str:
        return dt.isoformat()

    @field_serializer("last_seen")
    def serialize_last_seen(self, dt: datetime, _info) -> str:
        return dt.isoformat()


class AlertFilter(CamelModel):
    search: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    source_ip: Optional[str] = None
    username: Optional[str] = None
    detection_type: Optional[str] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None


class AlertStatusUpdate(CamelModel):
    status: str
