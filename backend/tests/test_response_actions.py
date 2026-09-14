"""
backend/tests/test_response_actions.py — Response Action lifecycle, state machine, and simulated execution tests.
"""
import uuid
from datetime import datetime
import pytest

from app.models.incident import IncidentModel
from app.models.response_action import ResponseActionModel
from app.models.blocklist import BlocklistEntryModel, SimulatedAccountLockModel


@pytest.fixture
def test_incident(db_session):
    inc_id = str(uuid.uuid4())
    inc = IncidentModel(
        id=inc_id,
        title="Test Security Incident",
        summary="Testing response actions",
        severity="HIGH",
        status="OPEN",
        source_ip="198.51.100.42",
        target_user="alice_test",
        affected_device="srv-app-01",
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
    )
    db_session.add(inc)
    db_session.commit()
    return inc


def test_full_lifecycle_block_ip(client, test_incident, db_session):
    # 1. Recommend (client is ADMIN, has all permissions)
    rec_resp = client.post(
        f"/api/incidents/{test_incident.id}/response-actions",
        json={
            "actionType": "BLOCK_IP",
            "parameters": {"ip": "198.51.100.42", "duration_seconds": 3600},
            "notes": "Recommend perimeter block",
        },
    )
    assert rec_resp.status_code == 201
    action_data = rec_resp.json()
    action_id = action_data["id"]
    assert action_data["status"] == "PENDING_APPROVAL"
    assert action_data["actionType"] == "BLOCK_IP"

    # 2. Approve
    app_resp = client.post(
        f"/api/incidents/{test_incident.id}/response-actions/{action_id}/approve",
        json={"notes": "Approved by SOC lead"},
    )
    assert app_resp.status_code == 200
    assert app_resp.json()["status"] == "APPROVED"

    # 3. Execute
    exec_resp = client.post(
        f"/api/incidents/{test_incident.id}/response-actions/{action_id}/execute"
    )
    assert exec_resp.status_code == 200
    assert exec_resp.json()["status"] == "EXECUTED"

    # 4. Verify simulated blocklist entry was written to DB
    block_entry = (
        db_session.query(BlocklistEntryModel)
        .filter(BlocklistEntryModel.response_action_id == action_id)
        .first()
    )
    assert block_entry is not None
    assert block_entry.ip == "198.51.100.42"
    assert block_entry.status == "BLOCKED"


def test_lock_account_simulated_execution(client, test_incident, db_session):
    rec_resp = client.post(
        f"/api/incidents/{test_incident.id}/response-actions",
        json={
            "actionType": "LOCK_ACCOUNT",
            "parameters": {"username": "alice_test", "duration_seconds": 1800},
            "notes": "Lock suspected compromised account",
        },
    )
    action_id = rec_resp.json()["id"]

    client.post(f"/api/incidents/{test_incident.id}/response-actions/{action_id}/approve")
    exec_resp = client.post(f"/api/incidents/{test_incident.id}/response-actions/{action_id}/execute")
    assert exec_resp.status_code == 200
    assert exec_resp.json()["status"] == "EXECUTED"

    lock_entry = (
        db_session.query(SimulatedAccountLockModel)
        .filter(SimulatedAccountLockModel.response_action_id == action_id)
        .first()
    )
    assert lock_entry is not None
    assert lock_entry.username == "alice_test"
    assert lock_entry.status == "TEMPORARILY_LOCKED"


def test_execute_without_approval_fails(client, test_incident):
    rec_resp = client.post(
        f"/api/incidents/{test_incident.id}/response-actions",
        json={
            "actionType": "BLOCK_IP",
            "parameters": {"ip": "198.51.100.42"},
            "notes": "Testing premature execution",
        },
    )
    action_id = rec_resp.json()["id"]

    # Try executing while still PENDING_APPROVAL
    exec_resp = client.post(f"/api/incidents/{test_incident.id}/response-actions/{action_id}/execute")
    assert exec_resp.status_code == 409


def test_reject_action(client, test_incident):
    rec_resp = client.post(
        f"/api/incidents/{test_incident.id}/response-actions",
        json={
            "actionType": "INCREASE_MONITORING",
            "parameters": {"target": "srv-web-01"},
            "notes": "Testing rejection",
        },
    )
    assert rec_resp.status_code == 201
    action_id = rec_resp.json()["id"]

    rej_resp = client.post(
        f"/api/incidents/{test_incident.id}/response-actions/{action_id}/reject",
        json={"notes": "False positive"},
    )
    assert rej_resp.status_code == 200
    assert rej_resp.json()["status"] == "REJECTED"

    # Cannot execute a rejected action
    exec_resp = client.post(f"/api/incidents/{test_incident.id}/response-actions/{action_id}/execute")
    assert exec_resp.status_code == 409


def test_invalid_action_type_rejected(client, test_incident):
    resp = client.post(
        f"/api/incidents/{test_incident.id}/response-actions",
        json={
            "actionType": "DROP_DATABASE_TABLE",  # Not in whitelist
            "parameters": {},
        },
    )
    assert resp.status_code == 422


def test_missing_required_parameters_rejected(client, test_incident):
    resp = client.post(
        f"/api/incidents/{test_incident.id}/response-actions",
        json={
            "actionType": "BLOCK_IP",
            "parameters": {},  # missing 'ip'
        },
    )
    assert resp.status_code == 422
