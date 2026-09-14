"""
app/models/audit_log.py — Append-only audit log.

Written by app.core.audit.log_audit().
No UPDATE or DELETE API is ever exposed for this table.
"""
from datetime import datetime
from sqlalchemy import Column, DateTime, JSON, String, Text
from app.database.base import Base


class AuditLogModel(Base):
    __tablename__ = "audit_logs"

    id = Column(String(64), primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    # nullable for pre-auth events like login-failure before identity confirmed
    user_id = Column(String(64), nullable=True, index=True)
    user_email = Column(String(255), nullable=True)
    action = Column(String(128), nullable=False, index=True)     # e.g. "login.success"
    resource_type = Column(String(64), nullable=True)            # e.g. "user", "response_action"
    resource_id = Column(String(64), nullable=True, index=True)
    result = Column(String(32), nullable=False)                  # "success" | "failure"
    source_ip = Column(String(64), nullable=True)
    details = Column(JSON, nullable=False, default=dict)
