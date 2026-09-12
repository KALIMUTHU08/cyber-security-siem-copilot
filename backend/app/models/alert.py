from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Text, JSON
from app.database.base import Base


class AlertModel(Base):
    __tablename__ = "alerts"

    id = Column(String(64), primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(32), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="NEW", index=True)
    
    # Risk score components
    risk_score = Column(Integer, nullable=False, default=0)
    risk_level = Column(String(32), nullable=False, default="LOW")
    risk_factors = Column(JSON, nullable=False, default=list)
    
    # Rule metadata
    detection_rule_id = Column(String(64), nullable=False, default="")
    detection_rule_name = Column(String(128), nullable=False, default="")
    detection_condition = Column(Text, nullable=False, default="")
    
    source_ip = Column(String(64), nullable=False, default="", index=True)
    destination_ip = Column(String(64), nullable=True)
    username = Column(String(128), nullable=False, default="", index=True)
    device = Column(String(128), nullable=False, default="")
    
    first_seen = Column(DateTime, nullable=False, index=True)
    last_seen = Column(DateTime, nullable=False, index=True)
    match_count = Column(Integer, nullable=False, default=1)
    matching_summary = Column(Text, nullable=False, default="")
    matching_log_ids = Column(JSON, nullable=False, default=list)
    related_incident_id = Column(String(64), nullable=True, index=True)
    tags = Column(JSON, nullable=False, default=list)
