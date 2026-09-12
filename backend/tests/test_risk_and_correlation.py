from datetime import datetime, timedelta
from app.risk.engine import compute_risk_score, calculate_risk_level
from app.models.alert import AlertModel
from app.models.incident import IncidentModel
from app.correlation.engine import correlate_alerts


def test_risk_scoring_math():
    # Base 20 + privileged 20 = 40 (MEDIUM)
    score, level, factors = compute_risk_score(20, ["rule alert"], is_privileged_target=True)
    assert score == 40
    assert level == "MEDIUM"
    assert len(factors) == 2

    # High points clamped to 100 (CRITICAL)
    score_clamped, level_crit, _ = compute_risk_score(80, ["rule"], is_privileged_target=True, is_external_connection=True)
    assert score_clamped == 100
    assert level_crit == "CRITICAL"


# ---------------------------------------------------------------------------
# Correlation v3 Test Suite (Requirements 1 - 15)
# ---------------------------------------------------------------------------

def test_1_single_medium_alert_no_incident(db_session):
    """1. Single MEDIUM alert -> no incident."""
    alert = AlertModel(
        id="a-med",
        title="Scanner Probe",
        severity="MEDIUM",
        status="NEW",
        risk_score=25,
        risk_level="LOW",
        detection_rule_id="rule-012",
        detection_rule_name="Scanner User-Agent",
        source_ip="192.168.1.10",
        destination_ip="10.0.0.5",
        device="Server01",
        first_seen=datetime(2024, 5, 10, 10, 0, 0),
        last_seen=datetime(2024, 5, 10, 10, 0, 0),
        matching_log_ids=["l1"],
    )
    db_session.add(alert)
    db_session.commit()

    incidents = correlate_alerts(db_session, [alert])
    db_session.commit()

    assert len(incidents) == 0, "Single MEDIUM alert must not create an incident"
    assert alert.related_incident_id is None, "related_incident_id must remain None"
    assert db_session.query(IncidentModel).count() == 0


def test_2_single_low_alert_no_incident(db_session):
    """2. Single LOW alert -> no incident."""
    alert = AlertModel(
        id="a-low",
        title="Minor Probe",
        severity="LOW",
        status="NEW",
        risk_score=10,
        risk_level="LOW",
        detection_rule_id="rule-012",
        detection_rule_name="Scanner User-Agent",
        source_ip="192.168.1.10",
        destination_ip="10.0.0.5",
        device="Server01",
        first_seen=datetime(2024, 5, 10, 10, 0, 0),
        last_seen=datetime(2024, 5, 10, 10, 0, 0),
        matching_log_ids=["l1"],
    )
    db_session.add(alert)
    db_session.commit()

    incidents = correlate_alerts(db_session, [alert])
    db_session.commit()

    assert len(incidents) == 0, "Single LOW alert must not create an incident"
    assert alert.related_incident_id is None
    assert db_session.query(IncidentModel).count() == 0


def test_3_single_high_alert_creates_incident(db_session):
    """3. Single HIGH alert -> incident."""
    alert = AlertModel(
        id="a-high",
        title="Admin Path Access",
        severity="HIGH",
        status="NEW",
        risk_score=60,
        risk_level="HIGH",
        detection_rule_id="rule-010",
        detection_rule_name="Admin Path Access",
        source_ip="192.168.1.10",
        destination_ip="10.0.0.5",
        device="Server01",
        first_seen=datetime(2024, 5, 10, 10, 0, 0),
        last_seen=datetime(2024, 5, 10, 10, 0, 0),
        matching_log_ids=["l1"],
    )
    db_session.add(alert)
    db_session.commit()

    incidents = correlate_alerts(db_session, [alert])
    db_session.commit()

    assert len(incidents) == 1, "Single HIGH alert must create an incident"
    assert alert.related_incident_id == incidents[0].id
    assert incidents[0].severity == "HIGH"
    assert "a-high" in incidents[0].related_alert_ids


def test_4_single_critical_alert_creates_incident(db_session):
    """4. Single CRITICAL alert -> incident."""
    alert = AlertModel(
        id="a-crit",
        title="Exploit Probe",
        severity="CRITICAL",
        status="NEW",
        risk_score=85,
        risk_level="CRITICAL",
        detection_rule_id="rule-012",
        detection_rule_name="Scanner User-Agent",
        source_ip="192.168.1.10",
        destination_ip="10.0.0.5",
        device="Server01",
        first_seen=datetime(2024, 5, 10, 10, 0, 0),
        last_seen=datetime(2024, 5, 10, 10, 0, 0),
        matching_log_ids=["l1"],
    )
    db_session.add(alert)
    db_session.commit()

    incidents = correlate_alerts(db_session, [alert])
    db_session.commit()

    assert len(incidents) == 1, "Single CRITICAL alert must create an incident"
    assert alert.related_incident_id == incidents[0].id
    assert incidents[0].severity == "CRITICAL"
    assert "a-crit" in incidents[0].related_alert_ids


def test_5_same_source_same_day_same_destination(db_session):
    """5. Same source + same day + same destination -> one incident."""
    day = datetime(2024, 5, 10, 10, 0, 0)
    alert1 = AlertModel(
        id="a5-1",
        title="Scanner Probe 1",
        severity="MEDIUM",
        status="NEW",
        risk_score=25,
        risk_level="LOW",
        detection_rule_id="rule-012",
        detection_rule_name="Scanner User-Agent",
        source_ip="192.168.1.10",
        destination_ip="10.0.0.5",
        device="Server01",
        first_seen=day,
        last_seen=day,
        matching_log_ids=["l1"],
    )
    alert2 = AlertModel(
        id="a5-2",
        title="Scanner Probe 2",
        severity="MEDIUM",
        status="NEW",
        risk_score=25,
        risk_level="LOW",
        detection_rule_id="rule-012",
        detection_rule_name="Scanner User-Agent",
        source_ip="192.168.1.10",
        destination_ip="10.0.0.5",
        device="Server01",
        first_seen=day + timedelta(minutes=15),
        last_seen=day + timedelta(minutes=15),
        matching_log_ids=["l2"],
    )
    db_session.add_all([alert1, alert2])
    db_session.commit()

    incidents = correlate_alerts(db_session, [alert1, alert2])
    db_session.commit()

    assert len(incidents) == 1, "Multiple alerts with same source, day, and destination must correlate into one incident"
    inc = incidents[0]
    assert "a5-1" in inc.related_alert_ids
    assert "a5-2" in inc.related_alert_ids


def test_6_same_source_same_day_different_rules(db_session):
    """6. Same source + same day + different rules -> one incident."""
    day = datetime(2024, 5, 10, 10, 0, 0)
    alert1 = AlertModel(
        id="a6-1",
        title="Admin Path Access",
        severity="MEDIUM",
        status="NEW",
        risk_score=30,
        risk_level="MEDIUM",
        detection_rule_id="rule-010",
        detection_rule_name="Admin Path Access",
        source_ip="192.168.1.10",
        destination_ip="10.0.0.5",
        device="Server01",
        first_seen=day,
        last_seen=day,
        matching_log_ids=["l1"],
    )
    alert2 = AlertModel(
        id="a6-2",
        title="Scanner User-Agent",
        severity="MEDIUM",
        status="NEW",
        risk_score=30,
        risk_level="MEDIUM",
        detection_rule_id="rule-012",
        detection_rule_name="Scanner User-Agent",
        source_ip="192.168.1.10",
        destination_ip="10.0.0.6",
        device="Server01",
        first_seen=day + timedelta(minutes=20),
        last_seen=day + timedelta(minutes=20),
        matching_log_ids=["l2"],
    )
    db_session.add_all([alert1, alert2])
    db_session.commit()

    incidents = correlate_alerts(db_session, [alert1, alert2])
    db_session.commit()

    assert len(incidents) == 1, "Alerts with same source and day but different rules must correlate into one incident"
    inc = incidents[0]
    assert "a6-1" in inc.related_alert_ids
    assert "a6-2" in inc.related_alert_ids


def test_7_same_source_same_day_related_event_types(db_session):
    """7. Same source + same day + related event types -> one incident."""
    day = datetime(2024, 5, 10, 10, 0, 0)
    alert1 = AlertModel(
        id="a7-1",
        title="Brute Force Attempt",
        severity="MEDIUM",
        status="NEW",
        risk_score=30,
        risk_level="MEDIUM",
        detection_rule_id="rule-001",
        detection_rule_name="Brute Force",
        source_ip="192.168.1.10",
        destination_ip="10.0.0.5",
        device="Server01",
        first_seen=day,
        last_seen=day,
        matching_log_ids=["l1"],
    )
    alert1.event_type = "LOGIN_FAILED"

    alert2 = AlertModel(
        id="a7-2",
        title="Successful Login",
        severity="MEDIUM",
        status="NEW",
        risk_score=30,
        risk_level="MEDIUM",
        detection_rule_id="rule-001",
        detection_rule_name="Brute Force",
        source_ip="192.168.1.10",
        destination_ip="10.0.0.6",
        device="Server01",
        first_seen=day + timedelta(minutes=30),
        last_seen=day + timedelta(minutes=30),
        matching_log_ids=["l2"],
    )
    alert2.event_type = "LOGIN"

    db_session.add_all([alert1, alert2])
    db_session.commit()

    incidents = correlate_alerts(db_session, [alert1, alert2])
    db_session.commit()

    assert len(incidents) == 1, "Alerts with related event types (LOGIN_FAILED -> LOGIN) must correlate into one incident"
    inc = incidents[0]
    assert "a7-1" in inc.related_alert_ids
    assert "a7-2" in inc.related_alert_ids


def test_8_same_source_same_day_unrelated_alerts(db_session):
    """8. Same source + same day but unrelated alerts -> remain separate."""
    day = datetime(2024, 5, 10, 10, 0, 0)
    alert1 = AlertModel(
        id="a8-1",
        title="Scanner Probe 1",
        severity="MEDIUM",
        status="NEW",
        risk_score=20,
        risk_level="LOW",
        detection_rule_id="rule-012",
        detection_rule_name="Scanner User-Agent",
        source_ip="192.168.1.10",
        destination_ip="10.0.0.5",
        device="Server01",
        first_seen=day,
        last_seen=day,
        matching_log_ids=["l1"],
    )
    alert1.event_type = "NETWORK_CONNECTION"

    alert2 = AlertModel(
        id="a8-2",
        title="Scanner Probe 2",
        severity="MEDIUM",
        status="NEW",
        risk_score=20,
        risk_level="LOW",
        detection_rule_id="rule-012",
        detection_rule_name="Scanner User-Agent",
        source_ip="192.168.1.10",
        destination_ip="10.0.0.6",  # Different destination
        device="Server01",
        first_seen=day + timedelta(hours=1),
        last_seen=day + timedelta(hours=1),
        matching_log_ids=["l2"],
    )
    alert2.event_type = "NETWORK_CONNECTION"  # Same event type, not in EVENT_RELATIONS

    db_session.add_all([alert1, alert2])
    db_session.commit()

    incidents = correlate_alerts(db_session, [alert1, alert2])
    db_session.commit()

    assert len(incidents) == 0, "Unrelated MEDIUM alerts must remain separate and produce no combined incident"
    assert db_session.query(IncidentModel).count() == 0


def test_9_different_source_same_day_separate(db_session):
    """9. Different source + same day -> separate."""
    day = datetime(2024, 5, 10, 10, 0, 0)
    alert1 = AlertModel(
        id="a9-1",
        title="Scan from IP 1",
        severity="HIGH",
        status="NEW",
        risk_score=60,
        risk_level="HIGH",
        detection_rule_id="rule-012",
        detection_rule_name="Scanner User-Agent",
        source_ip="10.0.0.1",
        destination_ip="192.168.1.1",
        device="Server01",
        first_seen=day,
        last_seen=day,
        matching_log_ids=["l1"],
    )
    alert2 = AlertModel(
        id="a9-2",
        title="Scan from IP 2",
        severity="HIGH",
        status="NEW",
        risk_score=60,
        risk_level="HIGH",
        detection_rule_id="rule-012",
        detection_rule_name="Scanner User-Agent",
        source_ip="10.0.0.2",
        destination_ip="192.168.1.1",
        device="Server01",
        first_seen=day,
        last_seen=day,
        matching_log_ids=["l2"],
    )
    db_session.add_all([alert1, alert2])
    db_session.commit()

    incidents = correlate_alerts(db_session, [alert1, alert2])
    db_session.commit()

    assert len(incidents) == 2, "Different source IPs must produce separate incidents"
    assert incidents[0].id != incidents[1].id
    assert {inc.source_ip for inc in incidents} == {"10.0.0.1", "10.0.0.2"}


def test_10_same_source_different_day_separate(db_session):
    """10. Same source + different day -> separate."""
    day1 = datetime(2024, 5, 10, 10, 0, 0)
    day2 = datetime(2024, 5, 11, 10, 0, 0)
    alert1 = AlertModel(
        id="a10-1",
        title="Scan Day 1",
        severity="HIGH",
        status="NEW",
        risk_score=60,
        risk_level="HIGH",
        detection_rule_id="rule-012",
        detection_rule_name="Scanner User-Agent",
        source_ip="192.168.1.50",
        destination_ip="10.0.0.5",
        device="Server01",
        first_seen=day1,
        last_seen=day1,
        matching_log_ids=["l1"],
    )
    alert2 = AlertModel(
        id="a10-2",
        title="Scan Day 2",
        severity="HIGH",
        status="NEW",
        risk_score=60,
        risk_level="HIGH",
        detection_rule_id="rule-012",
        detection_rule_name="Scanner User-Agent",
        source_ip="192.168.1.50",
        destination_ip="10.0.0.5",
        device="Server01",
        first_seen=day2,
        last_seen=day2,
        matching_log_ids=["l2"],
    )
    db_session.add_all([alert1, alert2])
    db_session.commit()

    incidents = correlate_alerts(db_session, [alert1, alert2])
    db_session.commit()

    assert len(incidents) == 2, "Alerts on different calendar days must produce separate incidents"
    assert incidents[0].id != incidents[1].id
    assert incidents[0].first_seen.date() != incidents[1].first_seen.date()


def test_11_existing_open_incident_meaningful_matching_alert(db_session):
    """11. Existing OPEN incident with meaningful matching alert -> merge."""
    day = datetime(2024, 5, 10, 8, 0, 0)
    existing_alert = AlertModel(
        id="a11-1",
        title="Brute Force Initial",
        severity="MEDIUM",
        status="NEW",
        risk_score=30,
        risk_level="MEDIUM",
        detection_rule_id="rule-001",
        detection_rule_name="Brute Force",
        source_ip="192.168.1.50",
        destination_ip="10.0.0.5",
        device="Server01",
        first_seen=day,
        last_seen=day,
        matching_log_ids=["l1"],
    )
    existing_incident = IncidentModel(
        id="INC-00011",
        title="Existing Incident",
        severity="MEDIUM",
        status="OPEN",
        risk_score=30,
        risk_level="MEDIUM",
        source_ip="192.168.1.50",
        destination_ip="10.0.0.5",
        affected_device="Server01",
        first_seen=day,
        last_seen=day,
        related_alert_ids=["a11-1"],
        related_log_ids=["l1"],
        timeline_events=[],
    )
    db_session.add_all([existing_alert, existing_incident])
    db_session.commit()

    new_alert = AlertModel(
        id="a11-2",
        title="Account Compromise",
        severity="MEDIUM",
        status="NEW",
        risk_score=40,
        risk_level="MEDIUM",
        detection_rule_id="rule-002",  # Different rule -> meaningful relationship
        detection_rule_name="Account Compromise",
        source_ip="192.168.1.50",
        destination_ip="10.0.0.6",
        device="Server01",
        first_seen=day + timedelta(hours=2),
        last_seen=day + timedelta(hours=2),
        matching_log_ids=["l2"],
    )
    db_session.add(new_alert)
    db_session.commit()

    incidents = correlate_alerts(db_session, [new_alert])
    db_session.commit()

    assert len(incidents) == 1
    assert incidents[0].id == "INC-00011"
    all_incidents = db_session.query(IncidentModel).all()
    assert len(all_incidents) == 1
    assert "a11-2" in all_incidents[0].related_alert_ids


def test_12_existing_investigating_incident_meaningful_matching_alert(db_session):
    """12. Existing INVESTIGATING incident with meaningful matching alert -> merge."""
    day = datetime(2024, 5, 10, 8, 0, 0)
    existing_alert = AlertModel(
        id="a12-1",
        title="Brute Force Initial",
        severity="MEDIUM",
        status="NEW",
        risk_score=30,
        risk_level="MEDIUM",
        detection_rule_id="rule-001",
        detection_rule_name="Brute Force",
        source_ip="192.168.1.60",
        destination_ip="10.0.0.5",
        device="Server01",
        first_seen=day,
        last_seen=day,
        matching_log_ids=["l1"],
    )
    existing_incident = IncidentModel(
        id="INC-00012",
        title="Investigating Incident",
        severity="MEDIUM",
        status="INVESTIGATING",
        risk_score=30,
        risk_level="MEDIUM",
        source_ip="192.168.1.60",
        destination_ip="10.0.0.5",
        affected_device="Server01",
        first_seen=day,
        last_seen=day,
        related_alert_ids=["a12-1"],
        related_log_ids=["l1"],
        timeline_events=[],
    )
    db_session.add_all([existing_alert, existing_incident])
    db_session.commit()

    new_alert = AlertModel(
        id="a12-2",
        title="Port Scan",
        severity="MEDIUM",
        status="NEW",
        risk_score=35,
        risk_level="MEDIUM",
        detection_rule_id="rule-005",  # Different rule -> meaningful relationship
        detection_rule_name="Port Scan",
        source_ip="192.168.1.60",
        destination_ip="10.0.0.6",
        device="Server01",
        first_seen=day + timedelta(hours=2),
        last_seen=day + timedelta(hours=2),
        matching_log_ids=["l2"],
    )
    db_session.add(new_alert)
    db_session.commit()

    incidents = correlate_alerts(db_session, [new_alert])
    db_session.commit()

    assert len(incidents) == 1
    assert incidents[0].id == "INC-00012"
    all_incidents = db_session.query(IncidentModel).all()
    assert len(all_incidents) == 1
    assert "a12-2" in all_incidents[0].related_alert_ids


def test_13_existing_same_source_day_incident_unrelated_alert_no_merge(db_session):
    """13. Existing same source/day incident but unrelated alert -> do not merge."""
    day = datetime(2024, 5, 10, 8, 0, 0)
    existing_alert = AlertModel(
        id="a13-1",
        title="Scanner Probe",
        severity="MEDIUM",
        status="NEW",
        risk_score=20,
        risk_level="LOW",
        detection_rule_id="rule-012",
        detection_rule_name="Scanner User-Agent",
        source_ip="192.168.1.70",
        destination_ip="10.0.0.5",
        device="Server01",
        first_seen=day,
        last_seen=day,
        matching_log_ids=["l1"],
    )
    existing_alert.event_type = "NETWORK_CONNECTION"

    existing_incident = IncidentModel(
        id="INC-00013",
        title="Existing Incident",
        severity="MEDIUM",
        status="OPEN",
        risk_score=20,
        risk_level="LOW",
        source_ip="192.168.1.70",
        destination_ip="10.0.0.5",
        affected_device="Server01",
        first_seen=day,
        last_seen=day,
        related_alert_ids=["a13-1"],
        related_log_ids=["l1"],
        timeline_events=[],
    )
    db_session.add_all([existing_alert, existing_incident])
    db_session.commit()

    new_alert = AlertModel(
        id="a13-2",
        title="Scanner Probe",
        severity="MEDIUM",
        status="NEW",
        risk_score=20,
        risk_level="LOW",
        detection_rule_id="rule-012",  # Same rule
        detection_rule_name="Scanner User-Agent",
        source_ip="192.168.1.70",
        destination_ip="10.0.0.6",  # Different destination
        device="Server01",
        first_seen=day + timedelta(hours=2),
        last_seen=day + timedelta(hours=2),
        matching_log_ids=["l2"],
    )
    new_alert.event_type = "NETWORK_CONNECTION"  # Same event type, unrelated
    db_session.add(new_alert)
    db_session.commit()

    incidents = correlate_alerts(db_session, [new_alert])
    db_session.commit()

    # Must NOT merge into existing incident and must NOT create new incident since it's single MEDIUM
    assert len(incidents) == 0, "Unrelated alert must not merge into existing incident"
    all_incidents = db_session.query(IncidentModel).all()
    assert len(all_incidents) == 1
    assert "a13-2" not in all_incidents[0].related_alert_ids


def test_14_missing_source_ip_no_global_merge(db_session):
    """14. Missing source IP -> no global merge."""
    day = datetime(2024, 5, 10, 10, 0, 0)
    alert1 = AlertModel(
        id="no-src-1",
        title="Alert without IP 1",
        severity="HIGH",
        status="NEW",
        risk_score=60,
        risk_level="HIGH",
        detection_rule_id="rule-010",
        detection_rule_name="Admin Path",
        source_ip="",  # missing source IP
        device="Server01",
        first_seen=day,
        last_seen=day,
        matching_log_ids=["l1"],
    )
    alert2 = AlertModel(
        id="no-src-2",
        title="Alert without IP 2",
        severity="HIGH",
        status="NEW",
        risk_score=60,
        risk_level="HIGH",
        detection_rule_id="rule-010",
        detection_rule_name="Admin Path",
        source_ip="",  # missing source IP
        device="Server02",
        first_seen=day,
        last_seen=day,
        matching_log_ids=["l2"],
    )
    db_session.add_all([alert1, alert2])
    db_session.commit()

    incidents = correlate_alerts(db_session, [alert1, alert2])
    db_session.commit()

    assert len(incidents) == 2, "Missing source IP alerts must not globally merge together"
    assert incidents[0].id != incidents[1].id


def test_15_same_title_alerts_timeline_preserves_events(db_session):
    """15. Same title alerts -> timeline preserves separate alert events."""
    day = datetime(2024, 5, 10, 10, 0, 0)
    alert1 = AlertModel(
        id="a15-1",
        title="Scanner User-Agent Detected",
        severity="MEDIUM",
        status="NEW",
        risk_score=20,
        risk_level="LOW",
        detection_rule_id="rule-012",
        detection_rule_name="Scanner User-Agent",
        matching_summary="Scanner probe on /admin",
        source_ip="192.168.1.80",
        destination_ip="10.0.0.5",
        device="Server01",
        first_seen=day,
        last_seen=day,
        matching_log_ids=["l1"],
    )
    alert2 = AlertModel(
        id="a15-2",
        title="Scanner User-Agent Detected",  # Exact same title
        severity="MEDIUM",
        status="NEW",
        risk_score=20,
        risk_level="LOW",
        detection_rule_id="rule-012",
        detection_rule_name="Scanner User-Agent",
        matching_summary="Scanner probe on /login",
        source_ip="192.168.1.80",
        destination_ip="10.0.0.5",  # Same destination -> correlates
        device="Server01",
        first_seen=day + timedelta(minutes=5),
        last_seen=day + timedelta(minutes=5),
        matching_log_ids=["l2"],
    )
    db_session.add_all([alert1, alert2])
    db_session.commit()

    incidents = correlate_alerts(db_session, [alert1, alert2])
    db_session.commit()

    assert len(incidents) == 1
    inc = incidents[0]
    assert len(inc.timeline_events) == 2, "Timeline must preserve both events despite identical titles"
    timeline_alert_ids = [t.related_alert_ids[0] for t in inc.timeline_events if t.related_alert_ids]
    assert "a15-1" in timeline_alert_ids
    assert "a15-2" in timeline_alert_ids


