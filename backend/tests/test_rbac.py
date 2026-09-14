"""
backend/tests/test_rbac.py — Role-based access control permission tests.
"""
import uuid
from datetime import datetime
import pytest

from app.models.incident import IncidentModel
from app.models.response_action import ResponseActionModel


def test_viewer_can_read_dashboard_and_alerts(viewer_client):
    resp = viewer_client.get("/api/dashboard")
    assert resp.status_code == 200

    resp = viewer_client.get("/api/alerts")
    assert resp.status_code == 200


def test_viewer_cannot_ingest_logs(viewer_client):
    resp = viewer_client.post(
        "/api/logs/upload",
        files={"file": ("test.csv", b"timestamp,source_ip,destination_ip,username,event_type,status,device\n")},
    )
    assert resp.status_code == 403


def test_viewer_cannot_manage_users(viewer_client):
    resp = viewer_client.get("/api/auth/users")
    assert resp.status_code == 403

    resp = viewer_client.post(
        "/api/auth/users",
        json={"email": "new@siem.test", "fullName": "New", "password": "Password123!", "role": "VIEWER"},
    )
    assert resp.status_code == 403


def test_viewer_cannot_toggle_rules(viewer_client):
    resp = viewer_client.patch(
        "/api/settings/detection-rules/RULE-001",
        json={"enabled": False},
    )
    assert resp.status_code == 403


from app.models.alert import AlertModel


def test_analyst_can_update_alert_status(analyst_client, db_session):
    alert_id = str(uuid.uuid4())
    alert = AlertModel(
        id=alert_id,
        title="Test Alert",
        severity="HIGH",
        status="NEW",
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
    )
    db_session.add(alert)
    db_session.commit()

    resp = analyst_client.patch(
        f"/api/alerts/{alert_id}",
        json={"status": "INVESTIGATING"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "INVESTIGATING"


def test_analyst_can_recommend_action(analyst_client, db_session):
    incident_id = str(uuid.uuid4())
    inc = IncidentModel(
        id=incident_id,
        title="Test Incident",
        summary="Test",
        severity="HIGH",
        status="OPEN",
        source_ip="192.168.1.50",
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
    )
    db_session.add(inc)
    db_session.commit()

    resp = analyst_client.post(
        f"/api/incidents/{incident_id}/response-actions",
        json={
            "actionType": "BLOCK_IP",
            "parameters": {"ip": "192.168.1.50"},
            "notes": "Recommend blocking suspicious IP",
        },
    )
    assert resp.status_code == 201
    assert resp.json()["status"] == "PENDING_APPROVAL"


def test_analyst_cannot_execute_action(analyst_client, db_session):
    incident_id = str(uuid.uuid4())
    action_id = str(uuid.uuid4())
    inc = IncidentModel(
        id=incident_id,
        title="Test Incident",
        summary="Test",
        severity="HIGH",
        status="OPEN",
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
    )
    action = ResponseActionModel(
        id=action_id,
        incident_id=incident_id,
        action_type="BLOCK_IP",
        parameters={"ip": "10.0.0.99"},
        status="APPROVED",
        recommended_at=datetime.utcnow(),
        approved_at=datetime.utcnow(),
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db_session.add(inc)
    db_session.add(action)
    db_session.commit()

    # Analyst does NOT have response.execute permission
    resp = analyst_client.post(
        f"/api/incidents/{incident_id}/response-actions/{action_id}/execute"
    )
    assert resp.status_code == 403


def test_operator_can_execute_action(operator_client, db_session):
    incident_id = str(uuid.uuid4())
    action_id = str(uuid.uuid4())
    inc = IncidentModel(
        id=incident_id,
        title="Test Incident",
        summary="Test",
        severity="HIGH",
        status="OPEN",
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
    )
    action = ResponseActionModel(
        id=action_id,
        incident_id=incident_id,
        action_type="BLOCK_IP",
        parameters={"ip": "10.0.0.99"},
        status="APPROVED",
        recommended_at=datetime.utcnow(),
        approved_at=datetime.utcnow(),
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db_session.add(inc)
    db_session.add(action)
    db_session.commit()

    # Operator DOES have response.execute permission
    resp = operator_client.post(
        f"/api/incidents/{incident_id}/response-actions/{action_id}/execute"
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "EXECUTED"


def test_operator_cannot_manage_users(operator_client):
    resp = operator_client.get("/api/auth/users")
    assert resp.status_code == 403


def test_admin_can_manage_users(client):
    resp = client.get("/api/auth/users")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
