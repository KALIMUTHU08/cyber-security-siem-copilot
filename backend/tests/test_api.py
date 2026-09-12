from datetime import datetime
from app.models.log import SecurityLogModel
from app.models.alert import AlertModel
from app.models.incident import IncidentModel


def test_health_check(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"


def test_dashboard_api(client, db_session):
    res = client.get("/api/dashboard")
    assert res.status_code == 200
    data = res.json()
    assert "totalEvents" in data
    assert "activeAlerts" in data
    assert "systemHealth" in data


def test_logs_api(client, db_session):
    # Insert test log
    log = SecurityLogModel(
        id="test-log-1",
        timestamp=datetime.utcnow(),
        source_ip="192.168.1.100",
        destination_ip="10.0.0.1",
        username="test_user",
        event_type="LOGIN",
        status="SUCCESS",
        device="TestHost",
    )
    db_session.add(log)
    db_session.commit()

    # Query logs
    res = client.get("/api/logs?username=test_user")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 1
    assert data["items"][0]["sourceIp"] == "192.168.1.100"

    # Batch logs
    res_batch = client.post("/api/logs/batch", json={"ids": ["test-log-1"]})
    assert res_batch.status_code == 200
    assert len(res_batch.json()) == 1


def test_alerts_api(client, db_session):
    alert = AlertModel(
        id="alert-test-1",
        title="Test Alert",
        severity="HIGH",
        status="NEW",
        risk_score=60,
        risk_level="HIGH",
        detection_rule_id="rule-001",
        detection_rule_name="Brute Force",
        source_ip="1.2.3.4",
        username="admin",
        device="Server01",
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
    )
    db_session.add(alert)
    db_session.commit()

    res = client.get("/api/alerts")
    assert res.status_code == 200
    assert res.json()["total"] >= 1

    # Update status
    res_patch = client.patch("/api/alerts/alert-test-1", json={"status": "INVESTIGATING"})
    assert res_patch.status_code == 200
    assert res_patch.json()["status"] == "INVESTIGATING"


def test_threat_hunting_api(client, db_session):
    res = client.post("/api/threat-hunting/query", json={"queryText": "find brute force login from 192.168.1.50"})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "done"
    assert "192.168.1.50" in data["interpretation"]


def test_copilot_chat_api(client, db_session):
    res = client.post(
        "/api/copilot/chat",
        json={"message": "Summarize what happened in this incident", "incidentId": None},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["role"] == "copilot"
    assert "response" in data
    assert len(data["response"]["observedEvidence"]) > 0
    assert len(data["response"]["recommendedNextSteps"]) > 0


def test_settings_detection_rules_api(client, db_session):
    res = client.get("/api/settings/detection-rules")
    assert res.status_code == 200
    rules = res.json()
    assert len(rules) >= 8

    # Toggle rule
    rule_id = rules[0]["id"]
    res_toggle = client.patch(f"/api/settings/detection-rules/{rule_id}", json={"enabled": False})
    assert res_toggle.status_code == 200
    assert res_toggle.json()["enabled"] is False


def test_analytics_api(client, db_session):
    res = client.get("/api/analytics?days=7")
    assert res.status_code == 200
    data = res.json()
    assert "eventsOverTime" in data
    assert "severityDistribution" in data
    assert "topSourceIps" in data


def test_threat_hunting_multiple_alerts_queries(client, db_session):
    # Seed alerts and logs for multi-alert source IP
    source_ip = "198.51.100.55"
    a1 = AlertModel(
        id="alert-hunt-1",
        title="Scanner User-Agent from 198.51.100.55",
        severity="HIGH",
        status="NEW",
        risk_score=30,
        risk_level="MEDIUM",
        detection_rule_id="rule-012",
        detection_rule_name="Scanner User-Agent Detected",
        source_ip=source_ip,
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
    )
    a2 = AlertModel(
        id="alert-hunt-2",
        title="Sensitive Admin Path Access from 198.51.100.55",
        severity="HIGH",
        status="NEW",
        risk_score=30,
        risk_level="MEDIUM",
        detection_rule_id="rule-010",
        detection_rule_name="Sensitive Admin Path Access",
        source_ip=source_ip,
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
    )
    log1 = SecurityLogModel(
        id="log-hunt-1",
        timestamp=datetime.utcnow(),
        source_ip=source_ip,
        destination_ip="10.0.0.5",
        username="anonymous",
        event_type="NETWORK_CONNECTION",
        status="SUCCESS",
        device="WebSrv01",
    )
    db_session.add_all([a1, a2, log1])
    db_session.commit()

    test_queries = [
        "Find suspicious activity from source IPs with multiple alerts",
        "Show IPs with multiple alerts",
        "Find repeated alerts from the same source",
    ]

    for q in test_queries:
        res = client.post("/api/threat-hunting/query", json={"queryText": q})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "done"
        assert "multiple confirmed alerts" in data["interpretation"].lower() or "correlating source ips" in data["interpretation"].lower()
        # Verify it identified the multi-alert source IP
        assert len(data["relatedAlertIds"]) >= 2
        assert "alert-hunt-1" in data["relatedAlertIds"]
        assert "alert-hunt-2" in data["relatedAlertIds"]
        assert "log-hunt-1" in data["matchingLogIds"]


def test_copilot_evidence_grounding_single_scanner_alert(client, db_session):
    # Setup single Rule-012 scanner incident
    inc = IncidentModel(
        id="INC-TEST-R12",
        title="Security Incident on IDS-SENSOR",
        severity="HIGH",
        status="OPEN",
        risk_score=30,
        risk_level="MEDIUM",
        source_ip="203.0.113.88",
        target_user="www-data",
        affected_device="IDS-SENSOR",
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
        summary="Automated scanner detected probing sensitive path",
        attack_vector="Scanner User-Agent Probing",
        related_alert_ids=["alert-r12-1"],
        related_log_ids=["log-r12-1"],
        observed_evidence=[
            "[00:00:00] Alert 'Scanner User-Agent from 203.0.113.88 (HIGH)': Scanner signature 'SQLMap/1.6-dev' on path '/?..\\..\\etc\\passwd' [scanner UA (+10), exploit pattern (+20)] (Source: 203.0.113.88)"
        ],
        ai_assessment="",
        recommended_next_steps=[],
    )
    log = SecurityLogModel(
        id="log-r12-1",
        timestamp=datetime.utcnow(),
        source_ip="203.0.113.88",
        destination_ip="10.0.0.2",
        username="",
        event_type="NETWORK_CONNECTION",
        status="BLOCKED",
        device="IDS-SENSOR",
        raw_log="HTTP GET /?..\\..\\etc\\passwd SQLMap/1.6-dev",
    )
    db_session.add_all([inc, log])
    db_session.commit()

    # Query 1: Overview / What happened
    res1 = client.post(
        "/api/copilot/chat",
        json={"message": "Summarize what happened in this incident", "incidentId": "INC-TEST-R12"},
    )
    assert res1.status_code == 200
    r1 = res1.json()["response"]
    assessment1 = r1["aiAssessment"].lower()

    # Must NOT claim authentication or post-exploitation occurred
    assert "following the initial authentication phase" not in assessment1
    assert "authentication phase" not in assessment1
    assert "post-exploitation behavior was observed" not in assessment1
    assert "compromise" not in assessment1 or "does not directly confirm" in assessment1 or "potential" in assessment1

    # Must use cautious / hedged language
    assert any(w in assessment1 for w in ["consistent with", "potential", "does not directly confirm", "may indicate"])

    # Query 2: What happened after
    res2 = client.post(
        "/api/copilot/chat",
        json={"message": "What happened after the initial detection?", "incidentId": "INC-TEST-R12"},
    )
    assert res2.status_code == 200
    r2 = res2.json()["response"]
    assessment2 = r2["aiAssessment"].lower()

    # Must NOT claim post-exploitation or command execution occurred
    assert "command execution" not in assessment2 or "no direct evidence" in assessment2
    assert "post-exploitation" not in assessment2 or "no direct evidence" in assessment2
    assert "data exfiltration" not in assessment2 or "no direct evidence" in assessment2

    # Query 3: Recommendations check
    recs = " ".join(r1["recommendedNextSteps"]).lower()
    # Must use analyst-in-the-loop recommendation (not automatic block)
    assert "consider blocking or restricting" in recs
    assert "after analyst validation" in recs

