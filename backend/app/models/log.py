from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Text, JSON
from app.database.base import Base


class SecurityLogModel(Base):
    __tablename__ = "security_logs"

    id = Column(String(64), primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    source_ip = Column(String(64), nullable=False, index=True)
    destination_ip = Column(String(64), nullable=False, default="")
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    username = Column(String(128), nullable=False, default="", index=True)
    event_type = Column(String(64), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="SUCCESS", index=True)
    device = Column(String(128), nullable=False, default="")
    raw_log = Column(Text, nullable=False, default="")
    parsed_fields = Column(JSON, nullable=False, default=dict)
    related_alert_ids = Column(JSON, nullable=False, default=list)
    related_incident_ids = Column(JSON, nullable=False, default=list)
