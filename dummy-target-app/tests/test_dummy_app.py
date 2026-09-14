"""
Unit and integration tests for the dummy target application.
Ensures route integrity, safe pattern-matching, log formatting, and SIEM forwarding.
"""

import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app import app
from logger import (
    create_security_log,
    get_raw_buffer,
    clear_buffered_events,
)
from forwarder import forward_logs_to_siem


@pytest.fixture(autouse=True)
def clean_buffer():
    """Clear log buffer before and after each test."""
    clear_buffered_events()
    yield
    clear_buffered_events()


@pytest.fixture
def client():
    return TestClient(app)


def test_health_check(client):
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["host"] == "127.0.0.1"


def test_home_page_generates_benign_log(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "Apex Portal" in res.text

    buffer = get_raw_buffer()
    assert len(buffer) == 1
    log = buffer[0]
    assert log["event_type"] == "FILE_ACCESS"
    assert log["status"] == "SUCCESS"
    assert log["parsed_fields"]["request_path"] == "/"


def test_files_page_and_download(client):
    res = client.get("/files")
    assert res.status_code == 200

    res_dl = client.get("/files/download?file=test_report.pdf", follow_redirects=False)
    assert res_dl.status_code == 307 or res_dl.status_code == 302 or res_dl.status_code == 303

    buffer = get_raw_buffer()
    assert len(buffer) == 2
    dl_log = buffer[1]
    assert "test_report.pdf" in dl_log["message"]
    assert dl_log["status"] == "SUCCESS"


def test_login_success(client):
    res = client.post(
        "/login",
        data={"username": "demo_user", "password": "DemoPass123!", "source_ip": "198.51.100.50"},
        follow_redirects=True,
    )
    assert res.status_code == 200
    assert "Authentication Successful" in res.text

    buffer = get_raw_buffer()
    assert len(buffer) == 1
    log = buffer[0]
    assert log["event_type"] == "LOGIN"
    assert log["status"] == "SUCCESS"
    assert log["username"] == "demo_user"
    assert log["source_ip"] == "198.51.100.50"


def test_login_failure(client):
    res = client.post(
        "/login",
        data={"username": "admin", "password": "WrongPassword123", "source_ip": "198.51.100.90"},
        follow_redirects=True,
    )
    assert res.status_code == 200
    assert "Authentication Failed" in res.text

    buffer = get_raw_buffer()
    assert len(buffer) == 1
    log = buffer[0]
    assert log["event_type"] == "LOGIN_FAILED"
    assert log["status"] == "FAILURE"
    assert log["username"] == "admin"
    assert log["source_ip"] == "198.51.100.90"


def test_search_benign_input(client):
    res = client.post(
        "/search",
        data={"query": "annual review summary"},
        follow_redirects=True,
    )
    assert res.status_code == 200
    assert "Benign Search" in res.text

    buffer = get_raw_buffer()
    assert len(buffer) == 1
    log = buffer[0]
    assert log["event_type"] == "FILE_ACCESS"
    assert log["status"] == "SUCCESS"
    assert "detection" not in log["parsed_fields"]


def test_search_suspicious_input_pattern_detection(client):
    # Test common injection patterns
    for query in ["' union select 1,2,3--", "admin' or '1'='1", "../../etc/passwd", "test; drop table users;"]:
        clear_buffered_events()
        res = client.post("/search", data={"query": query}, follow_redirects=True)
        assert res.status_code == 200
        assert "Suspicious Input Pattern Detected" in res.text

        buffer = get_raw_buffer()
        assert len(buffer) == 1
        log = buffer[0]
        assert log["event_type"] == "FILE_ACCESS"
        assert log["status"] == "SUCCESS"
        assert log["parsed_fields"]["detection"] == "exploit_pattern_matched"
        assert f"/search?q={query}" in log["parsed_fields"]["request_path"]


def test_admin_sensitive_path_access(client):
    res = client.get("/admin")
    assert res.status_code == 200
    assert "403 Forbidden" in res.text

    buffer = get_raw_buffer()
    assert len(buffer) == 1
    log = buffer[0]
    assert log["event_type"] == "NETWORK_CONNECTION"
    assert log["status"] == "BLOCKED"
    assert log["parsed_fields"]["action"] == "blocked"
    assert log["parsed_fields"]["request_path"] == "/admin"


def test_simulate_brute_force_sequence(client):
    ip = "198.51.100.99"
    res = client.post("/api/simulate-brute-force", data={"source_ip": ip})
    assert res.status_code == 200
    data = res.json()
    assert data["generated_count"] == 11
    assert data["source_ip"] == ip

    buffer = get_raw_buffer()
    assert len(buffer) == 11
    # Check all events are LOGIN_FAILED with same source IP
    for log in buffer:
        assert log["event_type"] == "LOGIN_FAILED"
        assert log["status"] == "FAILURE"
        assert log["source_ip"] == ip
        assert log["username"] == "admin"


def test_forward_logs_mocked():
    events = [
        create_security_log(
            event_type="LOGIN_FAILED",
            status="FAILURE",
            source_ip="198.51.100.99",
            username="admin",
        )
    ]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "totalRows": 1,
        "processed": 1,
        "failed": 0,
        "alertsGenerated": 1,
        "incidentsUpdated": 1,
        "errors": [],
    }

    with patch("httpx.Client.post", return_value=mock_resp) as mock_post:
        result = forward_logs_to_siem(events, target_url="http://127.0.0.1:8000/api/logs/upload")
        assert result["success"] is True
        assert "1 alert(s)" in result["message"]
        assert mock_post.called

        # Verify call arguments
        call_args = mock_post.call_args
        files_arg = call_args[1]["files"]
        assert "file" in files_arg
        filename, content, content_type = files_arg["file"]
        assert filename == "dummy_events.json"
        assert content_type == "application/json"


def test_forward_logs_connection_error():
    events = [{"event": "dummy"}]
    import httpx
    with patch("httpx.Client.post", side_effect=httpx.ConnectError("Connection refused")):
        result = forward_logs_to_siem(events, target_url="http://127.0.0.1:8000/api/logs/upload")
        assert result["success"] is False
        assert "Connection refused" in result["message"]
