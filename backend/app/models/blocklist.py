"""
app/models/blocklist.py — Simulated IP blocklist.

BLOCK_IP response actions write here.  No real firewall command runs — ever.
"""
from datetime import datetime
from sqlalchemy import Column, DateTime, String, Text
from app.database.base import Base


class BlocklistEntryModel(Base):
    __tablename__ = "blocklist_entries"

    id = Column(String(64), primary_key=True, index=True)
    ip = Column(String(64), nullable=False, index=True)
    # BLOCKED | EXPIRED | UNBLOCKED
    status = Column(String(32), nullable=False, default="BLOCKED", index=True)
    reason = Column(Text, nullable=False, default="")
    # duration_seconds=None means no auto-expiry
    duration_seconds = Column(String(32), nullable=True)
    created_by = Column(String(64), nullable=False)   # user.id who executed
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True, index=True)
    response_action_id = Column(String(64), nullable=False)


class SimulatedAccountLockModel(Base):
    __tablename__ = "simulated_account_locks"

    id = Column(String(64), primary_key=True, index=True)
    username = Column(String(128), nullable=False, index=True)
    # TEMPORARILY_LOCKED | UNLOCKED | EXPIRED
    status = Column(String(32), nullable=False, default="TEMPORARILY_LOCKED", index=True)
    reason = Column(Text, nullable=False, default="")
    duration_seconds = Column(String(32), nullable=True)
    created_by = Column(String(64), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True, index=True)
    response_action_id = Column(String(64), nullable=False)
