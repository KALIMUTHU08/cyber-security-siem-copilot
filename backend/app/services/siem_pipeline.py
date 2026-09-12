from typing import List, Dict, Any, Tuple
from sqlalchemy.orm import Session
import uuid

from app.models.log import SecurityLogModel
from app.models.rule import DetectionRuleModel
from app.models.alert import AlertModel
from app.models.incident import IncidentModel
from app.detection.registry import registry
from app.detection.base import RuleMatch
from app.risk.engine import compute_risk_score
from app.correlation.engine import correlate_alerts
from app.schemas.log import IngestStats


def seed_default_rules_if_empty(db: Session):
    """Upsert all registered rules — inserts missing rules even on non-empty DB."""
    existing_ids = {r.id for r in db.query(DetectionRuleModel).all()}
    added = 0
    for rule in registry.get_all_rules():
        if rule.rule_id not in existing_ids:
            db_rule = DetectionRuleModel(
                id=rule.rule_id,
                name=rule.name,
                category=rule.category,
                condition=rule.condition,
                condition_raw=rule.condition_raw,
                severity=rule.severity,
                enabled=True,
                trigger_count=0,
                description=rule.description,
            )
            db.add(db_rule)
            added += 1
    if added:
        db.commit()


def run_pipeline_on_records(db: Session, records: List[Dict[str, Any]]) -> Tuple[IngestStats, List[AlertModel]]:
    seed_default_rules_if_empty(db)
    
    if not records:
        return IngestStats(
            total_rows=0,
            processed=0,
            failed=0,
            alerts_generated=0,
            incidents_updated=0,
            errors=[],
        ), []

    new_logs: List[SecurityLogModel] = []
    log_map: Dict[str, SecurityLogModel] = {}
    
    for r in records:
        log = SecurityLogModel(
            id=r["id"],
            timestamp=r["timestamp"],
            source_ip=r["source_ip"],
            destination_ip=r["destination_ip"],
            source_port=r["source_port"],
            destination_port=r["destination_port"],
            username=r["username"],
            event_type=r["event_type"],
            status=r["status"],
            device=r["device"],
            raw_log=r["raw_log"],
            parsed_fields=r["parsed_fields"],
            related_alert_ids=[],
            related_incident_ids=[],
        )
        db.add(log)
        new_logs.append(log)
        log_map[log.id] = log

    db.flush()

    # Get enabled rules from database
    db_rules = db.query(DetectionRuleModel).all()
    enabled_rule_ids = {r.id for r in db_rules if r.enabled}
    rule_lookup = {r.id: r for r in db_rules}

    # Evaluate detection engine
    matches: List[RuleMatch] = registry.evaluate_all(new_logs, enabled_rule_ids=enabled_rule_ids)
    new_alerts: List[AlertModel] = []

    for match in matches:
        # Calculate risk score
        is_priv = (
            "admin" in match.username.lower()
            or "root" in match.username.lower()
            or match.rule_id == "rule-003"
        )
        is_ext = match.rule_id == "rule-004"
        is_off = match.rule_id == "rule-008"

        score, level, factors = compute_risk_score(
            base_points=match.points,
            factors=[f"Triggered rule '{match.rule_name}' ({match.severity})"],
            is_privileged_target=is_priv,
            is_external_connection=is_ext,
            is_after_hours=is_off,
        )

        alert_id = f"alert-{uuid.uuid4().hex}"
        alert = AlertModel(
            id=alert_id,
            title=match.title,
            severity=match.severity,
            status="NEW",
            risk_score=score,
            risk_level=level,
            risk_factors=factors,
            detection_rule_id=match.rule_id,
            detection_rule_name=match.rule_name,
            detection_condition=match.detection_condition,
            source_ip=match.source_ip,
            destination_ip=match.destination_ip,
            username=match.username,
            device=match.device,
            first_seen=match.first_seen,
            last_seen=match.last_seen,
            match_count=len(match.matching_log_ids),
            matching_summary=match.matching_summary,
            matching_log_ids=match.matching_log_ids,
            related_incident_id=None,
            tags=match.tags,
        )
        db.add(alert)
        new_alerts.append(alert)

        # Update trigger count on rule
        if match.rule_id in rule_lookup:
            rule_lookup[match.rule_id].trigger_count += 1

        # Link alert to logs
        for log_id in match.matching_log_ids:
            if log_id in log_map:
                log_map[log_id].related_alert_ids = list(
                    dict.fromkeys(log_map[log_id].related_alert_ids + [alert_id])
                )

    db.flush()

    # Correlate alerts into incidents
    updated_incidents = correlate_alerts(db, new_alerts)

    # Link incidents back to logs
    for incident in updated_incidents:
        for log_id in incident.related_log_ids:
            if log_id in log_map:
                log_map[log_id].related_incident_ids = list(
                    dict.fromkeys(log_map[log_id].related_incident_ids + [incident.id])
                )

    db.commit()

    stats = IngestStats(
        total_rows=len(records),
        processed=len(new_logs),
        failed=0,
        alerts_generated=len(new_alerts),
        incidents_updated=len(updated_incidents),
        errors=[],
    )
    return stats, new_alerts
