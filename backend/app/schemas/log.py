from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import field_serializer
from app.schemas.common import CamelModel


class SecurityLog(CamelModel):
    id: str
    timestamp: datetime
    source_ip: str
    destination_ip: str = ""
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    username: str = ""
    event_type: str
    status: str
    device: str = ""
    raw_log: str = ""
    parsed_fields: Dict[str, Any] = {}
    related_alert_ids: List[str] = []
    related_incident_ids: List[str] = []

    @field_serializer("timestamp")
    def serialize_timestamp(self, dt: datetime, _info) -> str:
        return dt.isoformat()


class LogFilter(CamelModel):
    search: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    event_type: Optional[str] = None
    status: Optional[str] = None
    device: Optional[str] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None


class BatchIdsRequest(CamelModel):
    ids: List[str]


class IngestStats(CamelModel):
    total_rows: int
    processed: int
    failed: int
    alerts_generated: int
    incidents_updated: int
    errors: List[str] = []
