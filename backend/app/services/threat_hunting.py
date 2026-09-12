import re
from datetime import datetime
from typing import List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, func, desc

from app.models.log import SecurityLogModel
from app.models.alert import AlertModel
from app.schemas.threat_hunting import ThreatHuntQuery


def parse_threat_hunting_intent(query_text: str) -> Tuple[Dict[str, Any], str, List[str]]:
    """
    Controlled intent parser.
    Extracts recognized patterns without arbitrary SQL execution.
    """
    q = query_text.lower().strip()
    filters: Dict[str, Any] = {}
    interpretations: List[str] = []
    risk_indicators: List[str] = []

    # Source IPs with multiple / repeated alerts
    multi_alert_terms = [
        "multiple alert",
        "repeated alert",
        "several alert",
        "multiple confirmed alert",
        "frequent alert",
        "ips with multiple alerts",
        "source ips with multiple alerts",
        "ips generating several alerts",
        "repeated alerts from the same source",
    ]
    is_multi_alert = any(term in q for term in multi_alert_terms) or (
        ("multiple" in q or "repeated" in q or "several" in q or "same source" in q) and "alert" in q
    )
    if is_multi_alert:
        filters["multiple_alerts"] = True
        interpretations.append("Correlating source IPs with multiple confirmed alerts")
        risk_indicators.append("Aggregated threat activity: source IPs triggering multiple distinct alerts")

    # IP regex pattern
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", q)
    if ip_match:
        ip = ip_match.group(0)
        filters["ip"] = ip
        interpretations.append(f"Targeting IP address '{ip}'")

    # Brute force / failed authentication
    if any(k in q for k in ["brute", "failed login", "authentication fail", "fail"]):
        filters["event_type"] = "LOGIN_FAILED"
        interpretations.append("Filtering for failed authentication events")
        risk_indicators.append("Potential automated brute-force or credential guessing attempt")

    # Privilege escalation
    if any(k in q for k in ["privilege", "escalat", "sudo", "root", "elevation"]):
        filters["event_type"] = "PRIVILEGE_CHANGE"
        interpretations.append("Searching for privilege change / elevation activities")
        risk_indicators.append("Elevated administrative access granted or attempted")

    # External / Outbound connection
    if any(k in q for k in ["external", "outbound", "c2", "connection", "beacon"]):
        filters["event_type"] = "NETWORK_CONNECTION"
        interpretations.append("Searching for external or suspicious network connections")
        risk_indicators.append("Network egress to external non-whitelisted destination")

    # Port scanning
    if any(k in q for k in ["scan", "probe", "port"]):
        filters["event_type"] = "PORT_SCAN"
        interpretations.append("Searching for port scan or reconnaissance probes")
        risk_indicators.append("Network discovery probing multiple ports")

    # Username mention
    for user in ["admin", "root", "john.doe", "analyst", "service_acc"]:
        if user in q:
            filters["username"] = user
            interpretations.append(f"Filtering for username '{user}'")
            if user in ["admin", "root"]:
                risk_indicators.append("Privileged superuser account targeted")
            break

    # High risk / critical
    if "high" in q or "critical" in q or "incident" in q:
        filters["high_risk"] = True
        interpretations.append("Focusing on high-risk and critical correlated activity")

    interpretation_str = " | ".join(interpretations) if interpretations else f"General log search for '{query_text}'"
    return filters, interpretation_str, risk_indicators


def execute_threat_hunt(db: Session, query_text: str) -> ThreatHuntQuery:
    filters, interpretation, base_risk_indicators = parse_threat_hunting_intent(query_text)

    query = db.query(SecurityLogModel)
    related_alert_ids = set()
    multi_alert_ips: List[str] = []

    if filters.get("multiple_alerts"):
        # Safe parameterized ORM aggregation: find source IPs with > 1 alerts
        subq = (
            db.query(AlertModel.source_ip, func.count(AlertModel.id).label("alert_count"))
            .filter(AlertModel.source_ip != "")
            .group_by(AlertModel.source_ip)
            .having(func.count(AlertModel.id) > 1)
            .order_by(desc("alert_count"))
            .limit(10)
            .all()
        )
        multi_alert_ips = [row.source_ip for row in subq]

        if multi_alert_ips:
            # Query confirmed alerts from those source IPs
            found_alerts = (
                db.query(AlertModel)
                .filter(AlertModel.source_ip.in_(multi_alert_ips))
                .order_by(AlertModel.last_seen.desc())
                .limit(20)
                .all()
            )
            for a in found_alerts:
                related_alert_ids.add(a.id)

            if "ip" not in filters:
                query = query.filter(SecurityLogModel.source_ip.in_(multi_alert_ips))

    if "ip" in filters:
        query = query.filter(
            or_(
                SecurityLogModel.source_ip == filters["ip"],
                SecurityLogModel.destination_ip == filters["ip"],
            )
        )

    if "event_type" in filters:
        query = query.filter(SecurityLogModel.event_type == filters["event_type"])

    if "username" in filters:
        query = query.filter(SecurityLogModel.username.ilike(f"%{filters['username']}%"))

    # Execute search with reasonable limit
    matching_logs = query.order_by(SecurityLogModel.timestamp.desc()).limit(50).all()
    matching_log_ids = [l.id for l in matching_logs]

    # Find related alerts from logs if not already populated
    for l in matching_logs:
        if l.related_alert_ids:
            for aid in l.related_alert_ids:
                related_alert_ids.add(aid)

    # If no direct link from logs, also check alerts matching IP or username
    if not related_alert_ids and ("ip" in filters or "username" in filters):
        alert_q = db.query(AlertModel)
        if "ip" in filters:
            alert_q = alert_q.filter(AlertModel.source_ip == filters["ip"])
        if "username" in filters:
            alert_q = alert_q.filter(AlertModel.username.ilike(f"%{filters['username']}%"))
        found_alerts = alert_q.limit(10).all()
        for a in found_alerts:
            related_alert_ids.add(a.id)

    risk_indicators = list(base_risk_indicators)
    if multi_alert_ips:
        risk_indicators.append(
            f"Correlated {len(multi_alert_ips)} source IPs generating repeated alerts: {', '.join(multi_alert_ips[:3])}"
        )
    if len(matching_logs) > 10:
        risk_indicators.append(f"High event volume: {len(matching_logs)} matching events identified")
    if related_alert_ids:
        risk_indicators.append(f"{len(related_alert_ids)} confirmed security alerts linked to this search pattern")

    return ThreatHuntQuery(
        id=f"hunt-{int(datetime.utcnow().timestamp())}",
        query_text=query_text,
        timestamp=datetime.utcnow(),
        status="done",
        interpretation=interpretation,
        matching_log_ids=matching_log_ids,
        related_alert_ids=list(related_alert_ids),
        risk_indicators=risk_indicators,
    )
