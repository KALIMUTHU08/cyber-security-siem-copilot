"""
app/models/response_action.py — Defensive response action with strict state machine.

Action types (WHITELIST — never extended at runtime or by LLM):
  BLOCK_IP | ADD_WATCHLIST_IP | INCREASE_MONITORING | LOCK_ACCOUNT | ISOLATE_HOST

State machine (see app.core.response_actions for enforcement):
  PENDING_APPROVAL → APPROVED → EXECUTING → EXECUTED
                  ↘ REJECTED
                              ↘ FAILED
                              ↘ EXPIRED
                              ↘ CANCELLED
"""
from datetime import datetime
from sqlalchemy import Column, DateTime, JSON, String, Text
from app.database.base import Base


class ResponseActionModel(Base):
    __tablename__ = "response_actions"

    id = Column(String(64), primary_key=True, index=True)
    incident_id = Column(String(64), nullable=False, index=True)

    # One of the whitelisted action types — enforced before INSERT and before EXECUTE
    action_type = Column(String(64), nullable=False)
    # action-specific payload, e.g. {"ip": "1.2.3.4"} or {"username": "jsmith"}
    parameters = Column(JSON, nullable=False, default=dict)

    # State machine — transitions enforced in app.core.response_actions
    status = Column(String(32), nullable=False, default="PENDING_APPROVAL", index=True)

    # Who/when recommended this action
    # nullable for analyst-created actions (non-copilot origin)
    recommended_by = Column(String(64), nullable=True)    # user.id or "copilot"
    recommended_at = Column(DateTime, nullable=False)
    # Copilot's justification text (null for manually-created actions)
    copilot_reasoning = Column(Text, nullable=True)

    # Approval / rejection
    approved_by = Column(String(64), nullable=True)       # user.id
    approved_at = Column(DateTime, nullable=True)
    rejected_by = Column(String(64), nullable=True)
    rejected_at = Column(DateTime, nullable=True)

    # Execution
    executed_by = Column(String(64), nullable=True)       # user.id
    executed_at = Column(DateTime, nullable=True)

    # General notes (analyst free-text at any stage)
    notes = Column(Text, nullable=False, default="")

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
