"""
app/schemas/response_action.py — Pydantic v2 schemas for response actions.
"""
from datetime import datetime
from typing import Dict, Any, List, Optional

from app.schemas.common import CamelModel

# Authoritative whitelist — never extended at runtime or from LLM output
VALID_ACTION_TYPES = {
    "BLOCK_IP",
    "ADD_WATCHLIST_IP",
    "INCREASE_MONITORING",
    "LOCK_ACCOUNT",
    "ISOLATE_HOST",
}

# Valid state transitions (enforced in app.core.response_actions)
VALID_STATES = {
    "PENDING_APPROVAL",
    "APPROVED",
    "EXECUTING",
    "EXECUTED",
    "REJECTED",
    "FAILED",
    "EXPIRED",
    "CANCELLED",
}


class ResponseActionCreate(CamelModel):
    """Analyst creates a response action (PENDING_APPROVAL state)."""
    action_type: str
    parameters: Dict[str, Any] = {}
    notes: str = ""
    # When created from a Copilot suggestion, the reasoning is preserved
    copilot_reasoning: Optional[str] = None


class ResponseActionApprove(CamelModel):
    notes: str = ""


class ResponseActionReject(CamelModel):
    notes: str = ""


class ResponseActionOut(CamelModel):
    id: str
    incident_id: str
    action_type: str
    parameters: Dict[str, Any]
    status: str
    recommended_by: Optional[str] = None
    recommended_at: datetime
    copilot_reasoning: Optional[str] = None
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    rejected_by: Optional[str] = None
    rejected_at: Optional[datetime] = None
    executed_by: Optional[str] = None
    executed_at: Optional[datetime] = None
    notes: str
    created_at: datetime
    updated_at: datetime


class SuggestedResponseAction(CamelModel):
    """
    Copilot suggestion — NOT a ResponseAction yet.
    An analyst must explicitly click 'Create Response Action' to promote it.
    The Copilot service has NO code path to auto-create or auto-approve actions.
    """
    action_type: str
    parameters: Dict[str, Any]
    reasoning: str
