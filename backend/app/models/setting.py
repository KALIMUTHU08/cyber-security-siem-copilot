from sqlalchemy import Column, String, Text
from app.database.base import Base


class SystemSettingModel(Base):
    __tablename__ = "system_settings"

    key = Column(String(64), primary_key=True, index=True)
    value = Column(Text, nullable=False)
    category = Column(String(64), nullable=False, default="general")
