from datetime import datetime, timedelta
from app.models.log import SecurityLogModel
from app.detection.rules import (
    BruteForceRule,
    AccountCompromiseRule,
    PortScanRule,
    PrivilegeEscalationRule,
    SuspiciousOutboundConnectionRule,
)


def test_brute_force_rule_triggers():
    rule = BruteForceRule()
    base_time = datetime(2026, 9, 7, 10, 0, 0)
    logs = [
        SecurityLogModel(
            id=f"log-{i}",
            timestamp=base_time + timedelta(seconds=i * 2),
            source_ip="192.168.1.50",
            destination_ip="10.0.0.10",
            username="admin",
            event_type="LOGIN_FAILED",
            status="FAILURE",
            device="Server01",
        )
        for i in range(12)
    ]

    matches = rule.evaluate(logs)
    assert len(matches) == 1
    assert matches[0].rule_id == "rule-001"
    assert len(matches[0].matching_log_ids) >= 10
    assert matches[0].source_ip == "192.168.1.50"


def test_brute_force_rule_ignores_isolated_failures():
    rule = BruteForceRule()
    base_time = datetime(2026, 9, 7, 10, 0, 0)
    logs = [
        SecurityLogModel(
            id=f"log-{i}",
            timestamp=base_time + timedelta(minutes=i * 5),  # spread out across 15 minutes
            source_ip="192.168.1.50",
            destination_ip="10.0.0.10",
            username="admin",
            event_type="LOGIN_FAILED",
            status="FAILURE",
            device="Server01",
        )
        for i in range(3)
    ]

    matches = rule.evaluate(logs)
    assert len(matches) == 0


def test_account_compromise_rule():
    rule = AccountCompromiseRule()
    base_time = datetime(2026, 9, 7, 10, 0, 0)
    # 6 failures then 1 success
    logs = [
        SecurityLogModel(
            id=f"fail-{i}",
            timestamp=base_time + timedelta(seconds=i * 5),
            source_ip="192.168.1.50",
            destination_ip="10.0.0.10",
            username="admin",
            event_type="LOGIN_FAILED",
            status="FAILURE",
            device="Server01",
        )
        for i in range(6)
    ]
    logs.append(
        SecurityLogModel(
            id="success-1",
            timestamp=base_time + timedelta(seconds=35),
            source_ip="192.168.1.50",
            destination_ip="10.0.0.10",
            username="admin",
            event_type="LOGIN",
            status="SUCCESS",
            device="Server01",
        )
    )

    matches = rule.evaluate(logs)
    assert len(matches) == 1
    assert matches[0].rule_id == "rule-002"
    assert matches[0].severity == "CRITICAL"


def test_port_scan_rule():
    rule = PortScanRule()
    base_time = datetime(2026, 9, 7, 10, 0, 0)
    logs = [
        SecurityLogModel(
            id=f"scan-{i}",
            timestamp=base_time + timedelta(seconds=i),
            source_ip="192.168.1.72",
            destination_ip="10.0.0.15",
            destination_port=20 + i,
            username="",
            event_type="PORT_SCAN",
            status="BLOCKED",
            device="Firewall",
        )
        for i in range(18)
    ]

    matches = rule.evaluate(logs)
    assert len(matches) == 1
    assert matches[0].rule_id == "rule-005"


def test_privilege_escalation_rule():
    rule = PrivilegeEscalationRule()
    log = SecurityLogModel(
        id="priv-1",
        timestamp=datetime.utcnow(),
        source_ip="192.168.1.50",
        destination_ip="10.0.0.10",
        username="admin",
        event_type="PRIVILEGE_CHANGE",
        status="SUCCESS",
        device="Server01",
        raw_log="sudo su root",
    )
    matches = rule.evaluate([log])
    assert len(matches) == 1
    assert matches[0].rule_id == "rule-003"
    assert matches[0].severity == "CRITICAL"


def test_suspicious_outbound_rule():
    rule = SuspiciousOutboundConnectionRule()
    log = SecurityLogModel(
        id="net-1",
        timestamp=datetime.utcnow(),
        source_ip="10.0.0.10",
        destination_ip="203.0.113.45",
        destination_port=443,
        username="root",
        event_type="NETWORK_CONNECTION",
        status="SUCCESS",
        device="Server01",
    )
    matches = rule.evaluate([log])
    assert len(matches) == 1
    assert matches[0].rule_id == "rule-004"
    assert matches[0].destination_ip == "203.0.113.45"
