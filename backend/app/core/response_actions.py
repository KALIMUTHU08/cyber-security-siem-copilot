"""
app/core/response_actions.py — Whitelisted action types and strict state machine.

DESIGN RULES (never violated):
1. The whitelist is a frozenset — it cannot be modified at runtime.
2. Every valid state transition is enumerated; everything else is FORBIDDEN.
3. transition() raises ValueError with a descriptive message on any invalid move.
4. No shell commands, no real firewall changes, no OS actions of any kind.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app.models.response_action import ResponseActionModel
from app.schemas.response_action import VALID_ACTION_TYPES

# ---------------------------------------------------------------------------
# Whitelisted action types (frozen — never extended dynamically)
# ---------------------------------------------------------------------------
ACTION_TYPE_WHITELIST: frozenset[str] = frozenset(VALID_ACTION_TYPES)

# ---------------------------------------------------------------------------
# Valid state transitions:
#   PENDING_APPROVAL → APPROVED | REJECTED | CANCELLED | EXPIRED
#   APPROVED         → EXECUTING | REJECTED | CANCELLED | EXPIRED
#   EXECUTING        → EXECUTED | FAILED
# All others are terminal and cannot be transitioned further.
# ---------------------------------------------------------------------------
_VALID_TRANSITIONS: dict[str, frozenset[str]] = {
    "PENDING_APPROVAL": frozenset({"APPROVED", "REJECTED", "CANCELLED", "EXPIRED"}),
    "APPROVED": frozenset({"EXECUTING", "CANCELLED", "EXPIRED"}),
    "EXECUTING": frozenset({"EXECUTED", "FAILED"}),
    # Terminal states — no further transitions
    "EXECUTED": frozenset(),
    "REJECTED": frozenset(),
    "FAILED": frozenset(),
    "EXPIRED": frozenset(),
    "CANCELLED": frozenset(),
}


def validate_action_type(action_type: str) -> None:
    """Raise ValueError if action_type is not in the whitelist."""
    if action_type not in ACTION_TYPE_WHITELIST:
        raise ValueError(
            f"Action type '{action_type}' is not in the approved whitelist "
            f"{sorted(ACTION_TYPE_WHITELIST)}."
        )


def validate_transition(current_status: str, new_status: str) -> None:
    """
    Raise ValueError if the transition from current_status → new_status is not permitted.

    Specific forbidden transitions detected here:
    - REJECTED → any (terminal)
    - EXECUTED → any (terminal / double-execution)
    - PENDING_APPROVAL → EXECUTED (skip approval)
    """
    allowed = _VALID_TRANSITIONS.get(current_status, frozenset())
    if new_status not in allowed:
        raise ValueError(
            f"Cannot transition from '{current_status}' to '{new_status}'. "
            f"Allowed from '{current_status}': {sorted(allowed) or 'none (terminal state)'}."
        )


def validate_parameters(action_type: str, parameters: dict) -> None:
    """Validate that required parameters are present and safe for each action type."""
    if action_type == "BLOCK_IP":
        ip = parameters.get("ip", "").strip()
        if not ip:
            raise ValueError("BLOCK_IP requires parameter 'ip'.")
        # Very basic IP format guard — not a full validation, but prevents obviously bad input
        parts = ip.split(".")
        if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            raise ValueError(f"BLOCK_IP parameter 'ip' does not look like a valid IPv4: '{ip}'.")

    elif action_type == "ADD_WATCHLIST_IP":
        ip = parameters.get("ip", "").strip()
        if not ip:
            raise ValueError("ADD_WATCHLIST_IP requires parameter 'ip'.")

    elif action_type == "LOCK_ACCOUNT":
        username = parameters.get("username", "").strip()
        if not username:
            raise ValueError("LOCK_ACCOUNT requires parameter 'username'.")

    elif action_type == "INCREASE_MONITORING":
        target = parameters.get("target", "").strip()
        if not target:
            raise ValueError("INCREASE_MONITORING requires parameter 'target'.")

    elif action_type == "ISOLATE_HOST":
        host = parameters.get("host", "").strip()
        if not host:
            raise ValueError("ISOLATE_HOST requires parameter 'host'.")
    # No else needed — validate_action_type() already gated unknown types
