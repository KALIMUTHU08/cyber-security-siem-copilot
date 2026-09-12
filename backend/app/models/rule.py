from sqlalchemy import Column, String, Integer, Boolean, Text
from app.database.base import Base


class DetectionRuleModel(Base):
    __tablename__ = "detection_rules"

    id = Column(String(64), primary_key=True, index=True)
    name = Column(String(128), nullable=False)
    category = Column(String(64), nullable=False)
    condition = Column(Text, nullable=False)
    condition_raw = Column(Text, nullable=True)
    severity = Column(String(32), nullable=False, default="MEDIUM")
    enabled = Column(Boolean, nullable=False, default=True)
    trigger_count = Column(Integer, nullable=False, default=0)
    description = Column(Text, nullable=False, default="")
