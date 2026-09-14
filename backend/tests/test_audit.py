"""
backend/tests/test_audit.py — Audit logging tests.
"""
import pytest
from app.models.audit_log import AuditLogModel
from app.core.audit import log_audit


def test_audit_log_admin_read(client, db_session):
    # Create test audit entry
    log_audit(
        db_session,
        action="test.action",
        result="success",
        resource_type="system",
        resource_id="sys-1",
        details={"test_key": "test_val"},
    )
    db_session.commit()

    resp = client.get("/api/audit-logs")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert any(item["action"] == "test.action" for item in data)


def test_audit_log_viewer_forbidden(viewer_client):
    resp = viewer_client.get("/api/audit-logs")
    assert resp.status_code == 403


def test_audit_log_analyst_forbidden(analyst_client):
    resp = analyst_client.get("/api/audit-logs")
    assert resp.status_code == 403


def test_audit_filtering(client, db_session):
    log_audit(
        db_session,
        action="login.success",
        result="success",
        details={"user": "alpha"},
    )
    log_audit(
        db_session,
        action="rule.modified",
        result="success",
        details={"rule": "RULE-001"},
    )
    db_session.commit()

    resp = client.get("/api/audit-logs?action=login")
    assert resp.status_code == 200
    data = resp.json()
    assert all("login" in item["action"].lower() for item in data)
