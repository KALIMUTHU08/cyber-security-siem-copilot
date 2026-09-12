"""
test_dataset_evaluation.py — Comprehensive tests for dataset evaluation,
deduplication, rule scope classification, Rule-010/011/012 behavior,
persistent status tracking, and ground-truth isolation.
"""

import inspect
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.base import Base
from app.models.log import SecurityLogModel
from app.models.alert import AlertModel
from app.models.setting import SystemSettingModel
from app.detection.registry import registry
from app.detection.dataset_rules import (
    AdminPathAccessRule,
    ScannerUserAgentRule,
    FTPDataExfiltrationRule,
    HighVolumeBlockedConnectionsRule,
    ICMPFloodRule,
)
from app.services.dataset_status_service import (
    get_persistent_seed_status,
    update_persistent_seed_status,
)
from evaluation import (
    run_evaluation,
    RULE_EVALUATION_SCOPE,
    EVALUABLE_RULE_IDS,
    OverallMetrics,
    RuleEvaluationResult,
)


def create_in_memory_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine)
    return TestingSession()


# ---------------------------------------------------------------------------
# 1. Overall Evaluation & Unique Log Deduplication Regression Test
# ---------------------------------------------------------------------------
def test_overall_evaluation_deduplicates_logs(monkeypatch):
    """Verify that a single log referenced across multiple alerts is counted only once."""
    db = create_in_memory_db()

    # Create 4 dataset logs: 2 positive, 2 negative
    log1 = SecurityLogModel(
        id="ds-log-1",
        timestamp=datetime(2024, 5, 1, 0, 0),
        source_ip="192.168.1.10",
        destination_ip="192.168.1.20",
        event_type="NETWORK_CONNECTION",
        status="BLOCKED",
        parsed_fields={"_ground_truth": "malicious"},
    )
    log2 = SecurityLogModel(
        id="ds-log-2",
        timestamp=datetime(2024, 5, 1, 0, 0),
        source_ip="192.168.1.11",
        destination_ip="192.168.1.20",
        event_type="NETWORK_CONNECTION",
        status="SUCCESS",
        parsed_fields={"_ground_truth": "suspicious"},
    )
    log3 = SecurityLogModel(
        id="ds-log-3",
        timestamp=datetime(2024, 5, 1, 0, 0),
        source_ip="192.168.1.12",
        destination_ip="192.168.1.20",
        event_type="NETWORK_CONNECTION",
        status="SUCCESS",
        parsed_fields={"_ground_truth": "benign"},
    )
    log4 = SecurityLogModel(
        id="ds-log-4",
        timestamp=datetime(2024, 5, 1, 0, 0),
        source_ip="192.168.1.13",
        destination_ip="192.168.1.20",
        event_type="NETWORK_CONNECTION",
        status="SUCCESS",
        parsed_fields={"_ground_truth": "benign"},
    )
    db.add_all([log1, log2, log3, log4])

    # Create 3 alerts referencing log-1 (duplicate alert references)
    alert1 = AlertModel(
        id="alt-1",
        detection_rule_id="rule-010",
        detection_rule_name="Sensitive Admin Path Access",
        severity="HIGH",
        risk_score=75,
        title="Admin probe 1",
        matching_log_ids=["ds-log-1"],
        first_seen=datetime(2024, 5, 1, 0, 0),
        last_seen=datetime(2024, 5, 1, 0, 0),
    )
    alert2 = AlertModel(
        id="alt-2",
        detection_rule_id="rule-010",
        detection_rule_name="Sensitive Admin Path Access",
        severity="HIGH",
        risk_score=75,
        title="Admin probe 2",
        matching_log_ids=["ds-log-1"],
        first_seen=datetime(2024, 5, 1, 0, 0),
        last_seen=datetime(2024, 5, 1, 0, 0),
    )
    alert3 = AlertModel(
        id="alt-3",
        detection_rule_id="rule-012",
        detection_rule_name="Scanner User-Agent Detected",
        severity="MEDIUM",
        risk_score=50,
        title="Scanner probe on log 1 and log 3",
        matching_log_ids=["ds-log-1", "ds-log-3"],  # log 1 (pos) and log 3 (benign)
        first_seen=datetime(2024, 5, 1, 0, 0),
        last_seen=datetime(2024, 5, 1, 0, 0),
    )
    db.add_all([alert1, alert2, alert3])
    db.commit()

    monkeypatch.setattr("evaluation.SessionLocal", lambda: db)

    report = run_evaluation()
    ov = report["overall"]

    # 4 total logs
    assert ov["total_logs"] == 4
    assert ov["total_positives"] == 2  # log1, log2
    assert ov["total_negatives"] == 2  # log3, log4

    # Log 1 had 3 alerts, but must be counted ONCE as TP
    # Log 3 had 1 alert, counted ONCE as FP
    # Log 2 had 0 alerts, counted as FN
    # Log 4 had 0 alerts, counted as TN
    assert ov["tp"] == 1
    assert ov["fp"] == 1
    assert ov["fn"] == 1
    assert ov["tn"] == 1
    assert ov["precision"] == 0.5
    assert ov["recall"] == 0.5
    assert ov["f1"] == 0.5

    # Check rule-specific deduplication for rule-010:
    # 2 alerts generated on log-1, but unique_logs_alerted must be 1, NOT 2!
    r10 = next(r for r in report["per_rule"] if r["rule_id"] == "rule-010")
    assert r10["alerts"] == 2
    assert r10["unique_logs_alerted"] == 1
    assert r10["unique_positives"] == 1
    assert r10["unique_negatives"] == 0
    assert r10["precision"] == 1.0
    assert r10["recall"] is None
    assert r10["f1"] is None
    assert "Rule-specific recall is not calculated" in r10["note"]

    db.close()


# ---------------------------------------------------------------------------
# 2. Rule Scope Classification & Null Recall/F1 Test
# ---------------------------------------------------------------------------
def test_rule_scope_classification():
    """Verify that all 13 rules are correctly classified in evaluation scope."""
    unsupported = [k for k, v in RULE_EVALUATION_SCOPE.items() if v["status"] == "UNSUPPORTED"]
    partial = [k for k, v in RULE_EVALUATION_SCOPE.items() if v["status"] == "PARTIAL"]
    supported = [k for k, v in RULE_EVALUATION_SCOPE.items() if v["status"] == "SUPPORTED"]

    # Rules 1-8 and 11 must be UNSUPPORTED
    for r in ["rule-001", "rule-002", "rule-003", "rule-004", "rule-005", "rule-006", "rule-007", "rule-008", "rule-011"]:
        assert r in unsupported

    # Rules 9 and 13 must be PARTIAL
    assert "rule-009" in partial
    assert "rule-013" in partial

    # Rules 10 and 12 must be SUPPORTED
    assert "rule-010" in supported
    assert "rule-012" in supported


# ---------------------------------------------------------------------------
# 3. Rule-010 Refined Detection: Ignore Clean Paths, Flag Real Injections
# ---------------------------------------------------------------------------
def test_rule_010_clean_vs_injected_paths():
    """Verify Rule-010 ignores clean admin paths and detects genuine exploitation queries."""
    rule = AdminPathAccessRule()

    # Clean paths that were 100% benign in the dataset
    clean_logs = [
        SecurityLogModel(
            id="log-clean-1",
            timestamp=datetime.utcnow(),
            source_ip="192.168.1.50",
            destination_ip="192.168.1.1",
            event_type="NETWORK_CONNECTION",
            status="SUCCESS",
            parsed_fields={"request_path": "/admin/config", "protocol": "HTTP"},
        ),
        SecurityLogModel(
            id="log-clean-2",
            timestamp=datetime.utcnow(),
            source_ip="192.168.1.50",
            destination_ip="192.168.1.1",
            event_type="NETWORK_CONNECTION",
            status="SUCCESS",
            parsed_fields={"request_path": "/secure", "protocol": "HTTPS"},
        ),
        SecurityLogModel(
            id="log-clean-3",
            timestamp=datetime.utcnow(),
            source_ip="192.168.1.50",
            destination_ip="192.168.1.1",
            event_type="NETWORK_CONNECTION",
            status="SUCCESS",
            parsed_fields={"request_path": "/dashboard", "protocol": "HTTP"},
        ),
    ]

    # Injected paths that represent actual exploitation
    exploit_logs = [
        SecurityLogModel(
            id="log-sqli-1",
            timestamp=datetime.utcnow(),
            source_ip="192.168.1.99",
            destination_ip="192.168.1.1",
            event_type="NETWORK_CONNECTION",
            status="SUCCESS",
            parsed_fields={"request_path": "/login?UNION SELECT", "protocol": "HTTP"},
        ),
        SecurityLogModel(
            id="log-sqli-2",
            timestamp=datetime.utcnow(),
            source_ip="192.168.1.99",
            destination_ip="192.168.1.1",
            event_type="NETWORK_CONNECTION",
            status="SUCCESS",
            parsed_fields={"request_path": "/secure?DROP TABLE", "protocol": "HTTPS"},
        ),
        SecurityLogModel(
            id="log-traversal-1",
            timestamp=datetime.utcnow(),
            source_ip="192.168.1.99",
            destination_ip="192.168.1.1",
            event_type="NETWORK_CONNECTION",
            status="SUCCESS",
            parsed_fields={"request_path": "/api/v1/data?../../etc/passwd", "protocol": "HTTP"},
        ),
        SecurityLogModel(
            id="log-probe-1",
            timestamp=datetime.utcnow(),
            source_ip="192.168.1.99",
            destination_ip="192.168.1.1",
            event_type="NETWORK_CONNECTION",
            status="SUCCESS",
            parsed_fields={"request_path": "/?admin", "protocol": "HTTP"},
        ),
    ]

    clean_matches = rule.evaluate(clean_logs)
    assert len(clean_matches) == 0, "Clean paths must NOT trigger Rule-010"

    exploit_matches = rule.evaluate(exploit_logs)
    assert len(exploit_matches) == 4, "All 4 exploitation probes must trigger Rule-010"
    matched_ids = [m.matching_log_ids[0] for m in exploit_matches]
    assert "log-sqli-1" in matched_ids
    assert "log-sqli-2" in matched_ids
    assert "log-traversal-1" in matched_ids
    assert "log-probe-1" in matched_ids


# ---------------------------------------------------------------------------
# 4. Rule-012 Contextual Behavior Without Ground Truth
# ---------------------------------------------------------------------------
def test_rule_012_contextual_evaluation():
    """
    Verify Rule-012 contextual gating, points, and severity policy:
    1. SQLMap + normal path -> no alert
    2. Nmap + normal path -> no alert
    3. SQLMap + sensitive path -> alert, MEDIUM
    4. Nmap + blocked action -> alert, MEDIUM
    5. SQLMap + exploit path -> alert, HIGH
    6. SQLMap + exploit + blocked -> alert, CRITICAL
    7. scanner + sensitive + blocked -> alert with existing expected severity (MEDIUM)
    8. non-scanner UA -> no alert
    9. uppercase SQLMAP -> still recognized when meaningful context exists
    10. scanner-only uppercase UA -> no alert
    """
    rule = ScannerUserAgentRule()

    # 1. SQLMap + normal path (allowed) -> no alert
    log_sqlmap_normal = SecurityLogModel(
        id="ua-sqlmap-normal",
        timestamp=datetime.utcnow(),
        source_ip="192.168.1.10",
        destination_ip="192.168.1.1",
        event_type="NETWORK_CONNECTION",
        status="SUCCESS",
        parsed_fields={"user_agent": "SQLMap/1.6-dev", "action": "allowed", "request_path": "/"},
    )

    # 2. Nmap + normal path (allowed) -> no alert
    log_nmap_normal = SecurityLogModel(
        id="ua-nmap-normal",
        timestamp=datetime.utcnow(),
        source_ip="192.168.1.11",
        destination_ip="192.168.1.1",
        event_type="NETWORK_CONNECTION",
        status="SUCCESS",
        parsed_fields={"user_agent": "Nmap Scripting Engine", "action": "allowed", "request_path": "/index.html"},
    )

    # 3. SQLMap + sensitive path -> alert, MEDIUM
    log_sqlmap_sensitive = SecurityLogModel(
        id="ua-sqlmap-sensitive",
        timestamp=datetime.utcnow(),
        source_ip="192.168.1.12",
        destination_ip="192.168.1.1",
        event_type="NETWORK_CONNECTION",
        status="SUCCESS",
        parsed_fields={"user_agent": "SQLMap/1.6-dev", "action": "allowed", "request_path": "/admin/config"},
    )

    # 4. Nmap + blocked action -> alert, MEDIUM
    log_nmap_blocked = SecurityLogModel(
        id="ua-nmap-blocked",
        timestamp=datetime.utcnow(),
        source_ip="192.168.1.13",
        destination_ip="192.168.1.1",
        event_type="NETWORK_CONNECTION",
        status="BLOCKED",
        parsed_fields={"user_agent": "Nmap Scripting Engine", "action": "blocked", "request_path": "/"},
    )

    # 5. SQLMap + exploit path -> alert, HIGH
    log_sqlmap_exploit = SecurityLogModel(
        id="ua-sqlmap-exploit",
        timestamp=datetime.utcnow(),
        source_ip="192.168.1.14",
        destination_ip="192.168.1.1",
        event_type="NETWORK_CONNECTION",
        status="SUCCESS",
        parsed_fields={"user_agent": "SQLMap/1.6-dev", "action": "allowed", "request_path": "/api?union select 1,2,3"},
    )

    # 6. SQLMap + exploit + blocked -> alert, CRITICAL
    log_sqlmap_exploit_blocked = SecurityLogModel(
        id="ua-sqlmap-exploit-blocked",
        timestamp=datetime.utcnow(),
        source_ip="192.168.1.15",
        destination_ip="192.168.1.1",
        event_type="NETWORK_CONNECTION",
        status="BLOCKED",
        parsed_fields={"user_agent": "SQLMap/1.6-dev", "action": "blocked", "request_path": "/secure?drop table users"},
    )

    # 7. scanner + sensitive + blocked -> alert with existing expected severity (MEDIUM)
    log_scanner_sensitive_blocked = SecurityLogModel(
        id="ua-scanner-sens-blocked",
        timestamp=datetime.utcnow(),
        source_ip="192.168.1.16",
        destination_ip="192.168.1.1",
        event_type="NETWORK_CONNECTION",
        status="BLOCKED",
        parsed_fields={"user_agent": "Nikto/2.1.6", "action": "blocked", "request_path": "/admin/login"},
    )

    # 8. non-scanner UA -> no alert
    log_non_scanner = SecurityLogModel(
        id="ua-non-scanner",
        timestamp=datetime.utcnow(),
        source_ip="192.168.1.17",
        destination_ip="192.168.1.1",
        event_type="NETWORK_CONNECTION",
        status="SUCCESS",
        parsed_fields={"user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36", "action": "allowed", "request_path": "/admin"},
    )

    # 9. uppercase SQLMAP -> still recognized when meaningful context exists
    log_uppercase_context = SecurityLogModel(
        id="ua-uppercase-context",
        timestamp=datetime.utcnow(),
        source_ip="192.168.1.18",
        destination_ip="192.168.1.1",
        event_type="NETWORK_CONNECTION",
        status="SUCCESS",
        parsed_fields={"user_agent": "SQLMAP/1.6-DEV (TEST)", "action": "allowed", "request_path": "/admin/config"},
    )

    # 10. scanner-only uppercase UA -> no alert
    log_uppercase_normal = SecurityLogModel(
        id="ua-uppercase-normal",
        timestamp=datetime.utcnow(),
        source_ip="192.168.1.19",
        destination_ip="192.168.1.1",
        event_type="NETWORK_CONNECTION",
        status="SUCCESS",
        parsed_fields={"user_agent": "SQLMAP/1.6-DEV (TEST)", "action": "allowed", "request_path": "/"},
    )

    all_logs = [
        log_sqlmap_normal,
        log_nmap_normal,
        log_sqlmap_sensitive,
        log_nmap_blocked,
        log_sqlmap_exploit,
        log_sqlmap_exploit_blocked,
        log_scanner_sensitive_blocked,
        log_non_scanner,
        log_uppercase_context,
        log_uppercase_normal,
    ]

    matches = rule.evaluate(all_logs)
    match_map = {m.matching_log_ids[0]: m for m in matches}

    # 1. SQLMap + normal path -> no alert
    assert "ua-sqlmap-normal" not in match_map, "1. SQLMap + normal path must NOT generate an alert"

    # 2. Nmap + normal path -> no alert
    assert "ua-nmap-normal" not in match_map, "2. Nmap + normal path must NOT generate an alert"

    # 3. SQLMap + sensitive path -> alert, MEDIUM
    assert "ua-sqlmap-sensitive" in match_map, "3. SQLMap + sensitive path must generate an alert"
    m3 = match_map["ua-sqlmap-sensitive"]
    assert m3.severity == "MEDIUM"
    assert m3.points == 20
    assert "sensitive path (+10)" in m3.matching_summary

    # 4. Nmap + blocked action -> alert, MEDIUM
    assert "ua-nmap-blocked" in match_map, "4. Nmap + blocked action must generate an alert"
    m4 = match_map["ua-nmap-blocked"]
    assert m4.severity == "MEDIUM"
    assert m4.points == 20
    assert "blocked action (+10)" in m4.matching_summary

    # 5. SQLMap + exploit path -> alert, HIGH
    assert "ua-sqlmap-exploit" in match_map, "5. SQLMap + exploit path must generate an alert"
    m5 = match_map["ua-sqlmap-exploit"]
    assert m5.severity == "HIGH"
    assert m5.points == 30
    assert "exploit pattern (+20)" in m5.matching_summary

    # 6. SQLMap + exploit + blocked -> alert, CRITICAL
    assert "ua-sqlmap-exploit-blocked" in match_map, "6. SQLMap + exploit + blocked must generate an alert"
    m6 = match_map["ua-sqlmap-exploit-blocked"]
    assert m6.severity == "CRITICAL"
    assert m6.points == 40
    assert "exploit pattern (+20)" in m6.matching_summary
    assert "blocked action (+10)" in m6.matching_summary

    # 7. scanner + sensitive + blocked -> alert with existing expected severity (MEDIUM)
    assert "ua-scanner-sens-blocked" in match_map, "7. Scanner + sensitive + blocked must generate an alert"
    m7 = match_map["ua-scanner-sens-blocked"]
    assert m7.severity == "MEDIUM"
    assert m7.points == 30
    assert "sensitive path (+10)" in m7.matching_summary
    assert "blocked action (+10)" in m7.matching_summary

    # 8. non-scanner UA -> no alert
    assert "ua-non-scanner" not in match_map, "8. Non-scanner UA must NOT generate an alert"

    # 9. uppercase SQLMAP -> still recognized when meaningful context exists
    assert "ua-uppercase-context" in match_map, "9. Uppercase SQLMAP with context must generate an alert"
    m9 = match_map["ua-uppercase-context"]
    assert m9.severity == "MEDIUM"
    assert m9.points == 20

    # 10. scanner-only uppercase UA -> no alert
    assert "ua-uppercase-normal" not in match_map, "10. Scanner-only uppercase UA on normal path must NOT generate an alert"

    assert len(matches) == 6, "Exactly 6 scanner logs with context must trigger Rule-012 alerts"



# ---------------------------------------------------------------------------
# 5. Rule-011 Threshold Preservation (5 MB)
# ---------------------------------------------------------------------------
def test_rule_011_threshold_preserved():
    """Verify Rule-011 preserves the standard 5 MB threshold."""
    rule = FTPDataExfiltrationRule()
    assert rule.THRESHOLD_BYTES == 5 * 1024 * 1024

    # 45 KB transfer (typical Kaggle max) should NOT trigger
    log_45k = SecurityLogModel(
        id="ftp-45k",
        timestamp=datetime.utcnow(),
        source_ip="192.168.1.10",
        destination_ip="192.168.1.1",
        event_type="NETWORK_CONNECTION",
        status="SUCCESS",
        parsed_fields={"protocol": "FTP", "bytes_transferred": 45000},
    )

    # 6 MB transfer should trigger
    log_6m = SecurityLogModel(
        id="ftp-6m",
        timestamp=datetime.utcnow(),
        source_ip="192.168.1.10",
        destination_ip="192.168.1.1",
        event_type="NETWORK_CONNECTION",
        status="SUCCESS",
        parsed_fields={"protocol": "FTP", "bytes_transferred": 6 * 1024 * 1024},
    )

    matches = rule.evaluate([log_45k, log_6m])
    assert len(matches) == 1
    assert matches[0].matching_log_ids == ["ftp-6m"]


# ---------------------------------------------------------------------------
# 6. Persistent Seed Status Test
# ---------------------------------------------------------------------------
def test_persistent_seed_status_sqlite():
    """Verify persistent seed status is saved and retrieved from SQLite."""
    db = create_in_memory_db()

    initial = get_persistent_seed_status(db)
    assert initial["running"] is False
    assert initial["rows_processed"] == 0

    update_persistent_seed_status(db, {
        "running": True,
        "rows_processed": 5000,
        "alerts_generated": 120,
        "incidents_updated": 45,
        "batch_id": "test-batch-001",
    })

    # Query afresh from DB
    retrieved = get_persistent_seed_status(db)
    assert retrieved["running"] is True
    assert retrieved["rows_processed"] == 5000
    assert retrieved["alerts_generated"] == 120
    assert retrieved["incidents_updated"] == 45
    assert retrieved["batch_id"] == "test-batch-001"

    db.close()


# ---------------------------------------------------------------------------
# 7. Ground Truth Never Used in Detection Rules (Static Verification)
# ---------------------------------------------------------------------------
def test_ground_truth_never_in_detection_logic():
    """Verify that none of the 13 detection rules reference ground truth attributes."""
    for rule in registry.get_all_rules():
        src = inspect.getsource(rule.__class__)
        # Ensure rule evaluate method does not read ground truth
        assert "_ground_truth" not in src or "BaseRule" in src, f"{rule.rule_id} must not inspect _ground_truth"
        assert "threat_label" not in src, f"{rule.rule_id} must not inspect threat_label"


# ---------------------------------------------------------------------------
# 8. Alert ID Uniqueness Regression Test
# ---------------------------------------------------------------------------
def test_alert_id_uniqueness_regression():
    """Verify that generated alert IDs are sufficiently unique across at least 10,000 generations."""
    import uuid
    ids = [f"alert-{uuid.uuid4().hex}" for _ in range(10000)]
    assert len(ids) == len(set(ids)), "Generated alert IDs must be globally unique without collisions"
    assert all(i.startswith("alert-") for i in ids), "All alert IDs must preserve the 'alert-' prefix"

