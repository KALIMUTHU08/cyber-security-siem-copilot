from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional, Any, Set
from collections import defaultdict
import uuid

from sqlalchemy.orm import Session
from app.models.alert import AlertModel
from app.models.incident import IncidentModel, IncidentTimelineEventModel
from app.models.log import SecurityLogModel
from app.risk.engine import compute_risk_score, calculate_risk_level


EVENT_RELATIONS = {
    ("LOGIN_FAILED", "LOGIN"),
    ("LOGIN", "FILE_ACCESS"),
    ("FILE_ACCESS", "DATA_EXFILTRATION"),
    ("NETWORK_CONNECTION", "FILE_ACCESS"),
    ("CONNECTION_BLOCKED", "NETWORK_CONNECTION"),
}


def generate_incident_id(db: Session) -> str:
    count = db.query(IncidentModel).count()
    return f"INC-{10000 + count + 1:05d}"


def get_alert_event_types(db: Session, alert: AlertModel) -> Set[str]:
    """Resolves event types associated with an alert."""
    types = set()
    if hasattr(alert, "event_type") and alert.event_type:
        types.add(str(alert.event_type).upper())

    if alert.matching_log_ids:
        try:
            logs = db.query(SecurityLogModel.event_type).filter(SecurityLogModel.id.in_(alert.matching_log_ids)).all()
            for (evt_type,) in logs:
                if evt_type:
                    types.add(str(evt_type).upper())
        except Exception:
            pass

    if not types and alert.detection_rule_id:
        rule_inferred = {
            "rule-001": "LOGIN_FAILED",
            "rule-002": "LOGIN",
            "rule-003": "PRIVILEGE_CHANGE",
            "rule-004": "NETWORK_CONNECTION",
            "rule-005": "PORT_SCAN",
            "rule-006": "LOGIN_FAILED",
            "rule-007": "LOGIN_FAILED",
            "rule-008": "LOGIN",
            "rule-009": "CONNECTION_BLOCKED",
            "rule-011": "DATA_EXFILTRATION",
            "rule-013": "NETWORK_CONNECTION",
        }.get(alert.detection_rule_id)
        if rule_inferred:
            types.add(rule_inferred)

    return types


def are_alerts_related(a1: AlertModel, a2: AlertModel, events_map: Dict[str, Set[str]]) -> bool:
    """
    Determines if two alerts in the same candidate group have a meaningful relationship.
    At least ONE of:
    1. same destination_ip (both non-empty)
    2. different detection_rule_id (both non-empty)
    3. related event types (undirected / bidirectional)
    """
    # 1. Same destination IP (must both be non-empty)
    if a1.destination_ip and a2.destination_ip and a1.destination_ip.strip() and a1.destination_ip == a2.destination_ip:
        return True

    # 2. Different detection rule ID (must both be non-empty)
    if a1.detection_rule_id and a2.detection_rule_id and a1.detection_rule_id != a2.detection_rule_id:
        return True

    # 3. Related event types (undirected / order-independent)
    e1_set = events_map.get(a1.id, set())
    e2_set = events_map.get(a2.id, set())
    for e1 in e1_set:
        for e2 in e2_set:
            if (e1, e2) in EVENT_RELATIONS or (e2, e1) in EVENT_RELATIONS:
                return True

    return False


def is_alert_related_to_incident(
    alert: AlertModel,
    incident: IncidentModel,
    existing_alerts: List[AlertModel],
    events_map: Dict[str, Set[str]],
) -> bool:
    """Checks if an alert is meaningfully related to an existing incident."""
    for ex_alert in existing_alerts:
        if are_alerts_related(alert, ex_alert, events_map):
            return True

    if alert.destination_ip and incident.destination_ip and alert.destination_ip.strip() and alert.destination_ip == incident.destination_ip:
        return True

    return False


def build_incident_assessment(
    alerts: List[AlertModel],
    target_user: str,
    device: str,
    source_ip: str,
) -> Tuple[List[str], str, List[str], str, str]:
    """
    Builds the 3-block assessment (Observed Evidence, AI Assessment, Recommendations)
    plus attack vector and summary.
    """
    observed_evidence: List[str] = []
    rule_names = {a.detection_rule_name for a in alerts}

    for alert in sorted(alerts, key=lambda a: a.first_seen):
        ts_str = alert.first_seen.strftime("%H:%M:%S")
        observed_evidence.append(
            f"[{ts_str}] Alert '{alert.title}': {alert.matching_summary} (Source: {alert.source_ip})"
        )

    # Determine attack sequence pattern
    has_brute = any("Brute Force" in r for r in rule_names)
    has_compromise = any("Account Compromise" in r for r in rule_names)
    has_priv = any("Privilege Escalation" in r for r in rule_names)
    has_c2 = any("External" in r or "Outbound" in r for r in rule_names)
    has_scan = any("Port Scan" in r for r in rule_names)

    if has_brute and (has_compromise or has_priv or has_c2):
        title = f"Multi-Stage Account Compromise & Lateral Probing — {device}"
        attack_vector = "Automated Brute Force → Credential Guessing → Post-Exploitation"
        summary = (
            f"Correlated attack sequence detected against {target_user or 'host'} on {device}. "
            f"Initial authentication probing was followed by privilege change or external connection activity."
        )
        ai_assessment = (
            f"The observed progression of events is consistent with an automated brute-force attack from "
            f"{source_ip} against {target_user or 'system accounts'}, followed by post-compromise activity on {device}. "
            f"The temporal sequence and behavioral indicators suggest automated post-exploitation tooling. "
            f"This is a behavioral assessment; immediate containment and credential invalidation are advised."
        )
        recommendations = [
            f"Isolate {device} from the local network to contain potential lateral movement",
            f"Immediately revoke credentials for {target_user or 'affected accounts'} and terminate active sessions",
            f"Review egress network logs and block external connection destinations at firewall",
            f"Perform forensic memory and process inspection on {device}",
            "Audit access logs across other internal servers for similar source IPs",
        ]
    elif has_scan:
        title = f"Reconnaissance & Port Probing Activity — {device}"
        attack_vector = "Network Port Scanning / Service Discovery"
        summary = f"Port scanning sequence observed from {source_ip} probing multiple service ports on {device}."
        ai_assessment = (
            f"Multiple service ports on {device} were probed within a short window from {source_ip}. "
            f"This activity is characteristic of network discovery prior to targeted exploitation."
        )
        recommendations = [
            f"Inspect firewall logs to verify if connections were dropped or accepted",
            f"Block or rate-limit source IP {source_ip} at the network perimeter",
            f"Verify exposed listening services on {device}",
        ]
    else:
        title = f"Correlated Security Incident on {device}"
        attack_vector = "Correlated Suspicious Behavioral Events"
        summary = f"Multiple security alerts correlated across {len(alerts)} events targeting {device}."
        ai_assessment = (
            f"Multiple detection rules triggered in proximity for {device}. "
            f"Evidence indicates suspicious patterns requiring analyst review."
        )
        recommendations = [
            f"Review individual alerts and matching raw logs",
            f"Verify whether {source_ip} belongs to authorized administrative subnets",
            f"Check device health and authentication status on {device}",
        ]

    return observed_evidence, ai_assessment, recommendations, title, attack_vector


def correlate_alerts(db: Session, alerts: List[AlertModel]) -> List[IncidentModel]:
    """
    Correlates alerts using Correlation v3:
    - Candidate key: source_ip + calendar_day
    - Clusters alerts within each candidate group based on meaningful relationships:
      (same destination_ip, different detection_rule_id, or related event types)
    - Single LOW/MEDIUM alerts remain isolated (no incident created, related_incident_id remains None).
    - Single HIGH/CRITICAL alerts create an incident.
    - Multi-alert related clusters create or merge into a correlated incident.
    - Unrelated alerts with same source/day remain separate.
    - Missing source_ip alerts are never globally merged.
    """
    if not alerts:
        return []

    # Pre-populate event types for incoming alerts
    events_map: Dict[str, Set[str]] = {}
    for alert in alerts:
        events_map[alert.id] = get_alert_event_types(db, alert)

    updated_incidents: List[IncidentModel] = []
    
    # 1. Group alerts by correlation candidate key: (source_ip, calendar_day)
    groups: Dict[Any, List[AlertModel]] = defaultdict(list)
    for alert in alerts:
        if alert.source_ip:
            day = alert.first_seen.date() if alert.first_seen else datetime.utcnow().date()
            key = (alert.source_ip, day)
        else:
            # Safe fallback: isolate missing-source alerts
            key = ("__no_source__", alert.id)
        groups[key].append(alert)

    for key, group_alerts in groups.items():
        sample = group_alerts[0]
        device = sample.device or "Unknown-Host"
        source_ip = sample.source_ip or ""

        # Fetch existing open/investigating incidents for this source_ip and calendar day
        existing_incidents: List[IncidentModel] = []
        existing_incident_alerts: Dict[str, List[AlertModel]] = {}
        if source_ip and isinstance(key, tuple) and key[0] != "__no_source__":
            cal_day = key[1]
            day_start = datetime.combine(cal_day, datetime.min.time())
            next_day = day_start + timedelta(days=1)

            existing_incidents = (
                db.query(IncidentModel)
                .filter(
                    IncidentModel.status.in_(["OPEN", "INVESTIGATING"]),
                    IncidentModel.source_ip == source_ip,
                    IncidentModel.first_seen >= day_start,
                    IncidentModel.first_seen < next_day,
                )
                .all()
            )
            for ex_inc in existing_incidents:
                rel_ids = ex_inc.related_alert_ids or []
                if rel_ids:
                    ex_alerts = db.query(AlertModel).filter(AlertModel.id.in_(rel_ids)).all()
                else:
                    ex_alerts = []
                existing_incident_alerts[ex_inc.id] = ex_alerts
                for a in ex_alerts:
                    if a.id not in events_map:
                        events_map[a.id] = get_alert_event_types(db, a)

        # 2. Cluster group_alerts into connected components of related alerts
        n = len(group_alerts)
        if n == 1:
            components = [[group_alerts[0]]]
        else:
            adj = defaultdict(list)
            for i in range(n):
                for j in range(i + 1, n):
                    if are_alerts_related(group_alerts[i], group_alerts[j], events_map):
                        adj[i].append(j)
                        adj[j].append(i)

            visited = set()
            components = []
            for i in range(n):
                if i not in visited:
                    comp = []
                    queue = [i]
                    visited.add(i)
                    while queue:
                        curr = queue.pop(0)
                        comp.append(group_alerts[curr])
                        for neighbor in adj[curr]:
                            if neighbor not in visited:
                                visited.add(neighbor)
                                queue.append(neighbor)
                    components.append(comp)

        # 3. Process each component
        for comp in components:
            target_user = next((a.username for a in comp if a.username and a.username != "multiple"), "admin")
            comp_device = next((a.device for a in comp if a.device and a.device != "Unknown-Host"), device)

            # Check if this component can merge into an existing incident
            target_incident: Optional[IncidentModel] = None
            if existing_incidents:
                for ex_inc in existing_incidents:
                    ex_alerts = existing_incident_alerts.get(ex_inc.id, [])
                    if any(is_alert_related_to_incident(a, ex_inc, ex_alerts, events_map) for a in comp):
                        target_incident = ex_inc
                        break

            if target_incident:
                # Merge into existing incident
                updated_alerts = list(target_incident.related_alert_ids or [])
                for a in comp:
                    if a.id not in updated_alerts:
                        updated_alerts.append(a.id)
                    a.related_incident_id = target_incident.id
                target_incident.related_alert_ids = updated_alerts

                updated_logs = list(target_incident.related_log_ids or [])
                for a in comp:
                    for log_id in (a.matching_log_ids or []):
                        if log_id not in updated_logs:
                            updated_logs.append(log_id)
                target_incident.related_log_ids = updated_logs

                target_incident.first_seen = min(target_incident.first_seen, min(a.first_seen for a in comp))
                target_incident.last_seen = max(target_incident.last_seen, max(a.last_seen for a in comp))
                if target_incident.affected_device == "Unknown-Host" and comp_device != "Unknown-Host":
                    target_incident.affected_device = comp_device

                # Recompute metadata & risk
                all_incident_alerts = list(existing_incident_alerts.get(target_incident.id, []))
                for a in comp:
                    if a not in all_incident_alerts:
                        all_incident_alerts.append(a)

                observed, ai_assess, recs, title, attack_vec = build_incident_assessment(
                    all_incident_alerts, target_user, target_incident.affected_device, source_ip or "Unknown-IP"
                )
                target_incident.observed_evidence = observed
                target_incident.ai_assessment = ai_assess
                target_incident.recommended_next_steps = recs
                if not target_incident.title or target_incident.title.startswith("Correlated Security Incident"):
                    target_incident.title = title
                target_incident.attack_vector = attack_vec
                target_incident.summary = (
                    f"Correlated incident involving {len(target_incident.related_alert_ids)} alerts and "
                    f"{len(target_incident.related_log_ids)} security events on {target_incident.affected_device}."
                )

                total_score = min(100, sum(a.risk_score for a in all_incident_alerts))
                target_incident.risk_score = max(target_incident.risk_score, total_score)
                target_incident.risk_level = calculate_risk_level(target_incident.risk_score)
                target_incident.severity = (
                    "CRITICAL" if target_incident.risk_score >= 75 or any(a.severity == "CRITICAL" for a in all_incident_alerts)
                    else "HIGH" if target_incident.risk_score >= 50 or any(a.severity == "HIGH" for a in all_incident_alerts)
                    else "MEDIUM"
                )

                # Update timeline events
                existing_timeline_alert_ids = set()
                for t in target_incident.timeline_events:
                    if t.related_alert_ids:
                        existing_timeline_alert_ids.update(t.related_alert_ids)

                for a in comp:
                    if a.id not in existing_timeline_alert_ids:
                        evt = IncidentTimelineEventModel(
                            id=f"evt-{uuid.uuid4().hex[:8]}",
                            incident_id=target_incident.id,
                            timestamp=a.first_seen,
                            title=a.title,
                            description=a.matching_summary,
                            event_type="ALERT",
                            severity=a.severity,
                            related_log_ids=(a.matching_log_ids or [])[:5],
                            related_alert_ids=[a.id],
                            event_metadata={"rule_id": a.detection_rule_id, "source_ip": a.source_ip},
                        )
                        db.add(evt)
                        existing_timeline_alert_ids.add(a.id)

                if target_incident not in updated_incidents:
                    updated_incidents.append(target_incident)

            else:
                # No existing incident merged.
                # Two-level model:
                # 1. Correlated alert group (len(comp) >= 2) -> create incident
                # 2. Isolated HIGH or CRITICAL alert (len(comp) == 1 and HIGH/CRITICAL) -> create incident
                # 3. Isolated LOW or MEDIUM alert (len(comp) == 1 and LOW/MEDIUM) -> DO NOT create incident
                should_create = (len(comp) >= 2) or (len(comp) == 1 and comp[0].severity in ("HIGH", "CRITICAL"))

                if should_create:
                    inc_id = generate_incident_id(db)
                    first_seen = min(a.first_seen for a in comp)
                    last_seen = max(a.last_seen for a in comp)
                    all_log_ids = []
                    all_alert_ids = []
                    for a in comp:
                        all_alert_ids.append(a.id)
                        all_log_ids.extend(a.matching_log_ids or [])
                        a.related_incident_id = inc_id

                    comp_sample = comp[0]
                    incident = IncidentModel(
                        id=inc_id,
                        title="",
                        severity="MEDIUM",
                        status="OPEN",
                        risk_score=0,
                        risk_level="MEDIUM",
                        risk_factors=[],
                        source_ip=source_ip,
                        destination_ip=comp_sample.destination_ip,
                        target_user=target_user,
                        affected_device=comp_device,
                        first_seen=first_seen,
                        last_seen=last_seen,
                        summary="",
                        attack_vector="",
                        related_alert_ids=all_alert_ids,
                        related_log_ids=list(dict.fromkeys(all_log_ids)),
                        observed_evidence=[],
                        ai_assessment="",
                        recommended_next_steps=[],
                        tags=list(dict.fromkeys(sum([a.tags or [] for a in comp], []))),
                    )
                    db.add(incident)
                    db.flush()

                    observed, ai_assess, recs, title, attack_vec = build_incident_assessment(
                        comp, target_user, comp_device, source_ip or "Unknown-IP"
                    )
                    incident.observed_evidence = observed
                    incident.ai_assessment = ai_assess
                    incident.recommended_next_steps = recs
                    if not incident.title or incident.title.startswith("Correlated Security Incident"):
                        incident.title = title
                    incident.attack_vector = attack_vec
                    incident.summary = (
                        f"Correlated incident involving {len(incident.related_alert_ids)} alerts and "
                        f"{len(incident.related_log_ids)} security events on {comp_device}."
                    )

                    total_score = min(100, sum(a.risk_score for a in comp))
                    incident.risk_score = max(incident.risk_score, total_score)
                    incident.risk_level = calculate_risk_level(incident.risk_score)
                    incident.severity = (
                        "CRITICAL" if incident.risk_score >= 75 or any(a.severity == "CRITICAL" for a in comp)
                        else "HIGH" if incident.risk_score >= 50 or any(a.severity == "HIGH" for a in comp)
                        else "MEDIUM"
                    )

                    # Timeline events
                    existing_timeline_alert_ids = set()
                    for a in comp:
                        if a.id not in existing_timeline_alert_ids:
                            evt = IncidentTimelineEventModel(
                                id=f"evt-{uuid.uuid4().hex[:8]}",
                                incident_id=incident.id,
                                timestamp=a.first_seen,
                                title=a.title,
                                description=a.matching_summary,
                                event_type="ALERT",
                                severity=a.severity,
                                related_log_ids=(a.matching_log_ids or [])[:5],
                                related_alert_ids=[a.id],
                                event_metadata={"rule_id": a.detection_rule_id, "source_ip": a.source_ip},
                            )
                            db.add(evt)
                            existing_timeline_alert_ids.add(a.id)

                    updated_incidents.append(incident)
                    existing_incidents.append(incident)
                    existing_incident_alerts[incident.id] = list(comp)

    db.flush()
    return updated_incidents
