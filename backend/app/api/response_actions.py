"""
app/api/response_actions.py — Incident response action lifecycle endpoints.

All endpoints require authentication.
Approval: SECURITY_ANALYST or ADMIN (response.approve permission)
Execution: SOC_OPERATOR or ADMIN (response.execute permission)
Creation: SECURITY_ANALYST or ADMIN (response.recommend permission)
Viewing: all authenticated users with response.view permission

State machine is enforced in app.core.response_actions — NOT here.
NO shell commands, NO real firewall changes, NO OS actions. Ever.
"""
import uuid
from datetime import datetime, timedelta
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.audit import log_audit
from app.core.deps import get_current_user
from app.core.permissions import Permission, require_permission
from app.core.response_actions import (
    validate_action_type,
    validate_parameters,
    validate_transition,
)
from app.database.session import get_db
from app.models.blocklist import BlocklistEntryModel, SimulatedAccountLockModel
from app.models.incident import IncidentModel
from app.models.response_action import ResponseActionModel
from app.models.user import UserModel
from app.schemas.response_action import (
    ResponseActionApprove,
    ResponseActionCreate,
    ResponseActionOut,
    ResponseActionReject,
)

router = APIRouter(tags=["Response Actions"])

_DEFAULT_BLOCK_DURATION_SECONDS = 3600 * 24  # 24 hours simulated block


def _to_out(ra: ResponseActionModel) -> ResponseActionOut:
    return ResponseActionOut(
        id=ra.id,
        incident_id=ra.incident_id,
        action_type=ra.action_type,
        parameters=ra.parameters or {},
        status=ra.status,
        recommended_by=ra.recommended_by,
        recommended_at=ra.recommended_at,
        copilot_reasoning=ra.copilot_reasoning,
        approved_by=ra.approved_by,
        approved_at=ra.approved_at,
        rejected_by=ra.rejected_by,
        rejected_at=ra.rejected_at,
        executed_by=ra.executed_by,
        executed_at=ra.executed_at,
        notes=ra.notes,
        created_at=ra.created_at,
        updated_at=ra.updated_at,
    )


@router.get(
    "/incidents/{incident_id}/response-actions",
    response_model=List[ResponseActionOut],
)
def list_response_actions(
    incident_id: str,
    _: UserModel = Depends(require_permission(Permission.RESPONSE_VIEW)),
    db: Session = Depends(get_db),
):
    """List all response actions for an incident."""
    incident = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    actions = (
        db.query(ResponseActionModel)
        .filter(ResponseActionModel.incident_id == incident_id)
        .order_by(ResponseActionModel.created_at.asc())
        .all()
    )
    return [_to_out(a) for a in actions]


@router.post(
    "/incidents/{incident_id}/response-actions",
    response_model=ResponseActionOut,
    status_code=status.HTTP_201_CREATED,
)
def create_response_action(
    incident_id: str,
    body: ResponseActionCreate,
    current_user: UserModel = Depends(require_permission(Permission.RESPONSE_RECOMMEND)),
    db: Session = Depends(get_db),
):
    """
    Analyst explicitly creates a response action (PENDING_APPROVAL).

    This is the ONLY way a ResponseAction enters the system — NOT auto-created by the Copilot.
    The Copilot produces suggestions; the analyst decides to promote one here.
    """
    incident = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")

    # Whitelist check (422 on unknown type)
    try:
        validate_action_type(body.action_type)
        validate_parameters(body.action_type, body.parameters)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    action = ResponseActionModel(
        id=str(uuid.uuid4()),
        incident_id=incident_id,
        action_type=body.action_type,
        parameters=body.parameters,
        status="PENDING_APPROVAL",
        recommended_by=current_user.id,
        recommended_at=datetime.utcnow(),
        copilot_reasoning=body.copilot_reasoning,
        notes=body.notes,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.add(action)

    log_audit(
        db,
        action="response_action.created",
        result="success",
        user_id=current_user.id,
        user_email=current_user.email,
        resource_type="response_action",
        resource_id=action.id,
        details={
            "incident_id": incident_id,
            "action_type": body.action_type,
            "parameters": body.parameters,
        },
    )
    db.commit()
    db.refresh(action)
    return _to_out(action)


@router.post(
    "/incidents/{incident_id}/response-actions/{action_id}/approve",
    response_model=ResponseActionOut,
)
def approve_response_action(
    incident_id: str,
    action_id: str,
    body: ResponseActionApprove = ResponseActionApprove(),
    current_user: UserModel = Depends(require_permission(Permission.RESPONSE_APPROVE)),
    db: Session = Depends(get_db),
):
    """Approve a PENDING_APPROVAL response action → APPROVED."""
    action = _get_action_or_404(db, incident_id, action_id)

    try:
        validate_transition(action.status, "APPROVED")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    action.status = "APPROVED"
    action.approved_by = current_user.id
    action.approved_at = datetime.utcnow()
    action.notes = body.notes if body.notes else action.notes
    action.updated_at = datetime.utcnow()

    log_audit(
        db,
        action="response_action.approved",
        result="success",
        user_id=current_user.id,
        user_email=current_user.email,
        resource_type="response_action",
        resource_id=action_id,
        details={"incident_id": incident_id, "action_type": action.action_type},
    )
    db.commit()
    db.refresh(action)
    return _to_out(action)


@router.post(
    "/incidents/{incident_id}/response-actions/{action_id}/reject",
    response_model=ResponseActionOut,
)
def reject_response_action(
    incident_id: str,
    action_id: str,
    body: ResponseActionReject = ResponseActionReject(),
    current_user: UserModel = Depends(require_permission(Permission.RESPONSE_APPROVE)),
    db: Session = Depends(get_db),
):
    """Reject a PENDING_APPROVAL or APPROVED response action → REJECTED."""
    action = _get_action_or_404(db, incident_id, action_id)

    try:
        validate_transition(action.status, "REJECTED")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    action.status = "REJECTED"
    action.rejected_by = current_user.id
    action.rejected_at = datetime.utcnow()
    action.notes = body.notes if body.notes else action.notes
    action.updated_at = datetime.utcnow()

    log_audit(
        db,
        action="response_action.rejected",
        result="success",
        user_id=current_user.id,
        user_email=current_user.email,
        resource_type="response_action",
        resource_id=action_id,
        details={"incident_id": incident_id, "action_type": action.action_type, "notes": body.notes},
    )
    db.commit()
    db.refresh(action)
    return _to_out(action)


@router.post(
    "/incidents/{incident_id}/response-actions/{action_id}/execute",
    response_model=ResponseActionOut,
)
def execute_response_action(
    incident_id: str,
    action_id: str,
    current_user: UserModel = Depends(require_permission(Permission.RESPONSE_EXECUTE)),
    db: Session = Depends(get_db),
):
    """
    Execute an APPROVED response action (SOC_OPERATOR or ADMIN).

    Full validation checklist (per spec, in order):
      ✓ user authenticated (Depends(get_current_user) via require_permission)
      ✓ user has response.execute permission (403)
      ✓ response action exists (404)
      ✓ action belongs to referenced incident (404/409)
      ✓ action_type in whitelist (422)
      ✓ parameters are valid (422)
      ✓ status is APPROVED (409)
      ✓ not already executed (409)
      ✓ not rejected/cancelled/expired (409)
      ✓ incident exists (404)

    NOTE: No shell commands, no real network actions — purely database records.
    """
    # Incident existence check
    incident = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")

    action = _get_action_or_404(db, incident_id, action_id)

    # Whitelist and parameter re-validation (defence in depth)
    try:
        validate_action_type(action.action_type)
        validate_parameters(action.action_type, action.parameters or {})
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    # State validation — detailed per spec
    if action.status == "EXECUTED":
        raise HTTPException(status_code=409, detail="Action has already been executed.")
    if action.status in ("REJECTED", "CANCELLED", "EXPIRED"):
        raise HTTPException(
            status_code=409,
            detail=f"Action is in terminal state '{action.status}' and cannot be executed.",
        )
    if action.status == "PENDING_APPROVAL":
        raise HTTPException(
            status_code=409,
            detail="Action must be APPROVED before it can be executed.",
        )

    # Transition to EXECUTING (also validates via state machine)
    try:
        validate_transition(action.status, "EXECUTING")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    action.status = "EXECUTING"
    action.updated_at = datetime.utcnow()
    db.flush()

    # Perform the simulated defensive action
    try:
        _simulate_defensive_action(db, action, current_user)
    except Exception as exc:
        action.status = "FAILED"
        action.updated_at = datetime.utcnow()
        log_audit(
            db,
            action="response_action.failed",
            result="failure",
            user_id=current_user.id,
            user_email=current_user.email,
            resource_type="response_action",
            resource_id=action_id,
            details={"error": str(exc)},
        )
        db.commit()
        raise HTTPException(status_code=500, detail=f"Execution failed: {exc}")

    # Mark as EXECUTED
    action.status = "EXECUTED"
    action.executed_by = current_user.id
    action.executed_at = datetime.utcnow()
    action.updated_at = datetime.utcnow()

    log_audit(
        db,
        action="response_action.executed",
        result="success",
        user_id=current_user.id,
        user_email=current_user.email,
        resource_type="response_action",
        resource_id=action_id,
        details={
            "incident_id": incident_id,
            "action_type": action.action_type,
            "parameters": action.parameters,
        },
    )
    db.commit()
    db.refresh(action)
    return _to_out(action)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_action_or_404(
    db: Session, incident_id: str, action_id: str
) -> ResponseActionModel:
    """Fetch the action and verify it belongs to the incident."""
    action = (
        db.query(ResponseActionModel)
        .filter(ResponseActionModel.id == action_id)
        .first()
    )
    if not action:
        raise HTTPException(status_code=404, detail=f"Response action '{action_id}' not found.")
    if action.incident_id != incident_id:
        raise HTTPException(
            status_code=409,
            detail=f"Response action '{action_id}' does not belong to incident '{incident_id}'.",
        )
    return action


def _simulate_defensive_action(
    db: Session, action: ResponseActionModel, executor: UserModel
) -> None:
    """
    Perform the simulated (DB-only) defensive action.

    SAFETY CONTRACT: no subprocess, no os.system, no real network, no real OS accounts.
    All effects are confined to the application database.
    """
    params = action.parameters or {}
    now = datetime.utcnow()

    if action.action_type == "BLOCK_IP":
        duration = int(params.get("duration_seconds", _DEFAULT_BLOCK_DURATION_SECONDS))
        entry = BlocklistEntryModel(
            id=str(uuid.uuid4()),
            ip=params["ip"],
            status="BLOCKED",
            reason=f"Simulated block via response action {action.id}",
            duration_seconds=str(duration),
            created_by=executor.id,
            created_at=now,
            expires_at=now + timedelta(seconds=duration),
            response_action_id=action.id,
        )
        db.add(entry)

    elif action.action_type == "LOCK_ACCOUNT":
        duration = int(params.get("duration_seconds", 3600))
        lock = SimulatedAccountLockModel(
            id=str(uuid.uuid4()),
            username=params["username"],
            status="TEMPORARILY_LOCKED",
            reason=f"Simulated lock via response action {action.id}",
            duration_seconds=str(duration),
            created_by=executor.id,
            created_at=now,
            expires_at=now + timedelta(seconds=duration),
            response_action_id=action.id,
        )
        db.add(lock)

    elif action.action_type in ("ADD_WATCHLIST_IP", "INCREASE_MONITORING", "ISOLATE_HOST"):
        # For these, the ResponseAction row itself IS the simulated record.
        # No additional model is needed — status=EXECUTED documents the action.
        pass

    db.flush()
