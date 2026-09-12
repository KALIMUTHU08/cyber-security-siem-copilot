from datetime import datetime
from sqlalchemy import Column, String, Integer, DateTime, Text, JSON
from app.database.base import Base


class CopilotMessageModel(Base):
    __tablename__ = "copilot_messages"

    id = Column(String(64), primary_key=True, index=True)
    role = Column(String(32), nullable=False)  # 'analyst' | 'copilot'
    content = Column(Text, nullable=False)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)
    incident_id = Column(String(64), nullable=True, index=True)
    
    # Structured response fields (when role == 'copilot')
    response_lead_in = Column(Text, nullable=True)
    response_event_count = Column(Integer, nullable=True)
    response_observed_evidence = Column(JSON, nullable=True)
    response_ai_assessment = Column(Text, nullable=True)
    response_recommended_next_steps = Column(JSON, nullable=True)
