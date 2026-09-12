from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Text, JSON, ForeignKey
from sqlalchemy.orm import relationship
from app.database.base import Base


class IncidentTimelineEventModel(Base):
    __tablename__ = "incident_timeline_events"

    id = Column(String(64), primary_key=True, index=True)
    incident_id = Column(String(64), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False, default="")
    event_type = Column(String(64), nullable=False)
    severity = Column(String(32), nullable=False, default="MEDIUM")
    related_log_ids = Column(JSON, nullable=False, default=list)
    related_alert_ids = Column(JSON, nullable=False, default=list)
    event_metadata = Column(JSON, nullable=False, default=dict)

    incident = relationship("IncidentModel", back_populates="timeline_events")


class IncidentModel(Base):
    __tablename__ = "incidents"

    id = Column(String(64), primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(32), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="OPEN", index=True)
    
    # Risk score components
    risk_score = Column(Integer, nullable=False, default=0)
    risk_level = Column(String(32), nullable=False, default="LOW")
    risk_factors = Column(JSON, nullable=False, default=list)
    
    source_ip = Column(String(64), nullable=False, default="", index=True)
    destination_ip = Column(String(64), nullable=True)
    target_user = Column(String(128), nullable=False, default="", index=True)
    affected_device = Column(String(128), nullable=False, default="")
    
    first_seen = Column(DateTime, nullable=False, index=True)
    last_seen = Column(DateTime, nullable=False, index=True)
    summary = Column(Text, nullable=False, default="")
    attack_vector = Column(String(255), nullable=False, default="")
    
    related_alert_ids = Column(JSON, nullable=False, default=list)
    related_log_ids = Column(JSON, nullable=False, default=list)
    
    # 3-Block structured assessment
    observed_evidence = Column(JSON, nullable=False, default=list)
    ai_assessment = Column(Text, nullable=False, default="")
    recommended_next_steps = Column(JSON, nullable=False, default=list)
    tags = Column(JSON, nullable=False, default=list)

    timeline_events = relationship(
        "IncidentTimelineEventModel",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentTimelineEventModel.timestamp",
    )
