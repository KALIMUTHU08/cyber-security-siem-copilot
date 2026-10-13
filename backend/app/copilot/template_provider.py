from typing import List, Optional, Any
from app.copilot.provider import LLMProvider
from app.schemas.copilot import CopilotResponse
from app.schemas.response_action import SuggestedResponseAction
from app.models.incident import IncidentModel
from app.models.log import SecurityLogModel


class DeterministicTemplateProvider(LLMProvider):
    """
    Deterministic fallback provider.
    Constructs an evidence-grounded response using the structured timeline,
    rules, alerts, and logs from the incident, ensuring the application operates fully
    even without an external LLM API key.
    """

    def generate_response(
        self,
        question: str,
        incident: Optional[IncidentModel] = None,
        evidence_logs: Optional[List[SecurityLogModel]] = None,
        alerts: Optional[List[Any]] = None,
    ) -> CopilotResponse:
        q_lower = question.lower()

        if incident:
            event_count = len(incident.related_log_ids or [])
            lead_in = f"Analysis based on {event_count} correlated security events across {incident.id}"

            # 1. Observed Evidence Aggregation
            observed: List[str] = [
                f"Incident {incident.id} (Severity: {incident.severity}) on device {incident.affected_device}",
                f"Target account: {incident.target_user}, Source IP: {incident.source_ip}",
                f"First seen: {incident.first_seen.strftime('%Y-%m-%d %H:%M:%S')}, Last seen: {incident.last_seen.strftime('%Y-%m-%d %H:%M:%S')}",
            ]

            if alerts:
                for a in alerts[:3]:
                    title = getattr(a, "title", "Security Alert")
                    desc = getattr(a, "description", None) or getattr(a, "matching_summary", "")
                    rule = getattr(a, "detection_rule_id", None) or getattr(a, "rule_id", "N/A")
                    sev = getattr(a, "severity", "UNKNOWN")
                    observed.append(f"Correlated Alert '{title}': {desc} (Rule: {rule}, Severity: {sev})")
            elif incident.observed_evidence:
                for e in incident.observed_evidence[:3]:
                    if e not in observed:
                        observed.append(e)

            if evidence_logs:
                for l in evidence_logs[:4]:
                    observed.append(f"Evidence log: [{l.timestamp.strftime('%H:%M:%S')}] {l.event_type} {l.status} from {l.source_ip} to {l.device}")

            # 2. Analyze concrete evidence present
            alert_texts = [
                f"{getattr(a, 'title', '')} {getattr(a, 'description', '')} {getattr(a, 'matching_summary', '')} {getattr(a, 'detection_rule_id', '')} {getattr(a, 'rule_id', '')}"
                for a in (alerts or [])
            ]
            all_evidence_text = " ".join(
                list(incident.observed_evidence or [])
                + alert_texts
                + [l.event_type for l in (evidence_logs or [])]
                + [l.raw_log or "" for l in (evidence_logs or [])]
                + [incident.summary or "", incident.title or "", incident.attack_vector or ""]
            ).lower()

            has_scanner = any(k in all_evidence_text for k in ["scanner", "sqlmap", "nmap", "rule-012", "user-agent"])
            has_exploit_pattern = any(k in all_evidence_text for k in ["exploit", "path traversal", "rule-010", "sensitive_path", "..\\", "../", "passwd"])
            has_auth_success = any(k in all_evidence_text for k in ["successful login", "login success", "rule-002", "authentication post failures"])
            has_auth_failure = any(k in all_evidence_text for k in ["failed login", "login_failed", "rule-001", "rule-007", "brute force", "authentication sequence"])
            has_priv_esc = any(k in all_evidence_text for k in ["privilege", "sudo", "rule-003", "root access", "elevation"])
            has_exfil = any(k in all_evidence_text for k in ["exfiltration", "data transfer", "rule-011", "ftp large"])
            is_scanner_only = has_scanner and not (has_auth_success or has_priv_esc or has_exfil or has_auth_failure)

            failed_logs = [
                l for l in (evidence_logs or [])
                if "fail" in (l.status or "").lower() or "fail" in (l.event_type or "").lower()
            ]
            failed_count = len(failed_logs) if failed_logs else event_count
            rule_tag = "Rule-001 (Brute Force Authentication Sequence)" if ("rule-001" in all_evidence_text or "brute force" in all_evidence_text) else "Authentication Failure Detection Rule"

            # 3. Evidence-grounded assessment and recommendations
            if is_scanner_only:
                if any(k in q_lower for k in ["after", "post", "next", "follow", "subsequent"]):
                    ai_assessment = (
                        f"Observed telemetry indicates inbound scanner requests from {incident.source_ip} probing {incident.affected_device}. "
                        f"The available incident evidence does not indicate that initial access was achieved. "
                        f"There is no direct evidence of subsequent authentication, command execution, post-exploitation activity, or data exfiltration following the scan."
                    )
                    recommendations = [
                        f"Consider blocking or restricting the source IP {incident.source_ip} after analyst validation.",
                        f"Inspect outbound connection logs from {incident.affected_device} to ensure no reverse shells or callbacks occurred.",
                        "Audit system audit logs on the targeted host for abnormal child processes.",
                    ]
                elif any(k in q_lower for k in ["summar", "what happen", "overview", "analyz", "investigat"]):
                    ai_assessment = (
                        f"The alert shows scanner activity with an exploit-pattern request and a related network connection. "
                        f"This is consistent with a potential exploitation attempt, but the available incident evidence "
                        f"does not directly confirm successful authentication or post-exploitation activity. "
                        f"There is no direct evidence of host compromise. Observed telemetry reflects automated reconnaissance or vulnerability scanning targeting {incident.affected_device}."
                    )
                    recommendations = [
                        f"Consider blocking or restricting the source IP {incident.source_ip} after analyst validation.",
                        f"Audit endpoint access logs on {incident.affected_device} to verify HTTP response status codes for scanned paths.",
                        "Review perimeter firewall and WAF rules to filter known scanner user-agents and exploit strings.",
                        "Verify that host operating system and web services are patched against known exploits.",
                    ]
                elif any(k in q_lower for k in ["why", "suspicious", "flag", "detect"]):
                    ai_assessment = (
                        f"The activity was flagged because an automated security scanner signature was detected targeting {incident.affected_device}. "
                        f"While scanning may occur across Internet-facing services, requests referencing exploit patterns or sensitive paths "
                        f"may indicate pre-attack discovery. No direct evidence of successful host compromise was identified."
                    )
                    recommendations = [
                        f"Consider blocking or restricting the source IP {incident.source_ip} after analyst validation.",
                        f"Verify whether {incident.source_ip} is an authorized vulnerability assessment scanner.",
                    ]
                else:
                    ai_assessment = (
                        f"Telemetry across {incident.id} shows scanner activity targeting {incident.affected_device}. "
                        f"This may indicate automated reconnaissance, but available incident evidence does not directly "
                        f"confirm authentication, command execution, or post-exploitation activity."
                    )
                    recommendations = [
                        f"Consider blocking or restricting the source IP {incident.source_ip} after analyst validation.",
                        f"Continue triage on {incident.id} and preserve web server access logs for review.",
                    ]
            elif has_auth_failure and not has_auth_success:
                # Dedicated brute-force / failed authentication sequence analysis
                if any(k in q_lower for k in ["summar", "what happen", "overview", "analyz", "investigat", "brute"]):
                    ai_assessment = (
                        f"Observed Facts: Incident {incident.id} (Severity: {incident.severity}) records {failed_count} failed login attempts "
                        f"originating from source IP {incident.source_ip} targeting account '{incident.target_user}' on device {incident.affected_device} "
                        f"between {incident.first_seen.strftime('%Y-%m-%d %H:%M:%S')} and {incident.last_seen.strftime('%Y-%m-%d %H:%M:%S')}. "
                        f"Detection rule {rule_tag} triggered after rapid sequential authentication failures exceeded the correlation threshold. "
                        f"\n\nInferences: The telemetry reflects an active brute-force / credential-guessing campaign directed at the target user account. "
                        f"\n\nMissing Information: No subsequent successful authentication (Rule-002) was observed in the ingested security events. "
                        f"There is no direct evidence confirming account compromise, session creation, or lateral movement."
                    )
                    recommendations = [
                        f"Containment Action: Recommend blocking source IP {incident.source_ip} (BLOCK_IP) at the network perimeter pending analyst approval.",
                        f"Account Defense: Temporarily lock target user '{incident.target_user}' (LOCK_ACCOUNT) or initiate a forced credential rotation.",
                        f"Audit endpoint logs on {incident.affected_device} to verify whether connection attempts ceased after the burst.",
                    ]
                elif any(k in q_lower for k in ["why", "suspicious", "flag", "detect"]):
                    ai_assessment = (
                        f"Observed Facts: Incident {incident.id} (Severity: {incident.severity}) was detected because {rule_tag} triggered on host {incident.affected_device}. "
                        f"A total of {failed_count} consecutive failed authentication events were recorded from source IP {incident.source_ip} "
                        f"targeting account '{incident.target_user}' within a compressed time interval between {incident.first_seen.strftime('%Y-%m-%d %H:%M:%S')} "
                        f"and {incident.last_seen.strftime('%Y-%m-%d %H:%M:%S')}. "
                        f"\n\nInferences: The volume and repetition rate exceed normal human login behavior and are consistent with automated brute-force password guessing. "
                        f"\n\nMissing Information: Telemetry shows zero successful logins for this sequence. There is no evidence that the attacker successfully accessed the account."
                    )
                    recommendations = [
                        f"Containment Action: Recommend blocking source IP {incident.source_ip} (BLOCK_IP) at the perimeter firewall pending analyst approval.",
                        f"Account Verification: Recommend verifying account '{incident.target_user}' with its legitimate user or applying temporary lockout (LOCK_ACCOUNT).",
                        f"Audit endpoint access logs on {incident.affected_device} to ensure no alternative access paths were utilized.",
                    ]
                else:
                    ai_assessment = (
                        f"Observed Facts: Telemetry for {incident.id} demonstrates an authentication storm: {failed_count} failed attempts "
                        f"from {incident.source_ip} against user '{incident.target_user}' on {incident.affected_device}. "
                        f"\n\nInferences: Pattern is indicative of automated brute-force authentication. "
                        f"\n\nMissing Information: No successful authentication identified."
                    )
                    recommendations = [
                        f"Containment Action: Recommend blocking source IP {incident.source_ip} (BLOCK_IP) after analyst approval.",
                        f"Verify authentication logs for user '{incident.target_user}' across adjacent systems.",
                    ]
            else:
                # Multi-stage or other complex incidents
                if any(k in q_lower for k in ["summar", "what happen", "overview", "analyz", "investigat"]):
                    if has_auth_success and has_auth_failure:
                        ai_assessment = (
                            f"Observed evidence reflects multiple failed authentication attempts followed by a successful login for user '{incident.target_user}'. "
                            f"This pattern is consistent with potential credential guessing or account compromise, but requires analyst verification "
                            f"to confirm whether the login was authorized."
                        )
                    elif has_priv_esc:
                        ai_assessment = (
                            f"Observed evidence indicates potential privilege modification activity on {incident.affected_device}. "
                            f"This may indicate unauthorized administrative elevation, though analyst confirmation of authorized maintenance is advised."
                        )
                    else:
                        ai_assessment = (
                            f"Correlated telemetry across {incident.id} indicates anomalous security events on {incident.affected_device}. "
                            f"This pattern is consistent with suspicious activity, but available telemetry does not directly confirm unauthorized access."
                        )
                    recommendations = [
                        f"Consider blocking or restricting the source IP {incident.source_ip} after analyst validation.",
                        f"Confirm with user {incident.target_user} whether this activity was authorized.",
                        f"Audit endpoint access and process execution logs on {incident.affected_device}.",
                    ]
                elif any(k in q_lower for k in ["after", "post", "next", "follow"]):
                    if has_priv_esc or has_exfil:
                        ai_assessment = (
                            f"Following the initial detection, subsequent telemetry shows activity potentially consistent with post-access exploration. "
                            f"However, available audit logs do not directly confirm persistence or extensive lateral movement."
                        )
                    else:
                        ai_assessment = (
                            f"Following the initial detection, subsequent activity appears limited based on currently ingested logs. "
                            f"There is no direct evidence confirming post-exploitation command execution or lateral spread on {incident.affected_device}."
                        )
                    recommendations = [
                        f"Consider blocking or restricting the source IP {incident.source_ip} after analyst validation.",
                        f"Audit outbound connection logs from {incident.affected_device}.",
                        f"Check file integrity and inspect temporary directories on {incident.affected_device}.",
                    ]
                elif any(k in q_lower for k in ["why", "suspicious", "flag", "detect"]):
                    ai_assessment = (
                        f"The activity was flagged because multiple detection rules triggered in rapid temporal succession. "
                        f"While individual events may have benign explanations, the statistical likelihood of this sequential "
                        f"pattern occurring legitimately is exceptionally low, and it may indicate an unauthorized operation."
                    )
                    recommendations = [
                        f"Consider blocking or restricting the source IP {incident.source_ip} after analyst validation.",
                        f"Confirm with user {incident.target_user} whether this activity was authorized.",
                    ]
                else:
                    ai_assessment = (
                        f"Evidence across {incident.id} demonstrates anomalous behavioral indicators potentially requiring incident mitigation. "
                        f"Analyst review is recommended before taking disruptive remediation actions."
                    )
                    recommendations = [
                        f"Consider blocking or restricting the source IP {incident.source_ip} after analyst validation.",
                        f"Continue triage on {incident.id} and preserve system audit logs for forensic review.",
                    ]

            # 4. Suggested Response Actions (Containment)
            suggested_actions: List[SuggestedResponseAction] = []
            if incident.source_ip and incident.source_ip not in ("N/A", "127.0.0.1", ""):
                suggested_actions.append(
                    SuggestedResponseAction(
                        action_type="BLOCK_IP",
                        parameters={"ip": incident.source_ip, "duration_seconds": 86400},
                        reasoning=f"Inbound traffic from source IP {incident.source_ip} associated with incident {incident.id}. Perimeter containment recommended pending analyst approval.",
                    )
                )
            if incident.target_user and incident.target_user not in ("N/A", "unknown", "anonymous", "") and (has_auth_failure or has_auth_success):
                suggested_actions.append(
                    SuggestedResponseAction(
                        action_type="LOCK_ACCOUNT",
                        parameters={"username": incident.target_user, "duration_seconds": 3600},
                        reasoning=f"Suspicious authentication activity detected for user account '{incident.target_user}'. Temporary lockout recommended pending analyst confirmation.",
                    )
                )
            if has_scanner and incident.source_ip and incident.source_ip not in ("N/A", "127.0.0.1", ""):
                suggested_actions.append(
                    SuggestedResponseAction(
                        action_type="ADD_WATCHLIST_IP",
                        parameters={"ip": incident.source_ip},
                        reasoning=f"Add reconnaissance scanner IP {incident.source_ip} to watchlist for heightened monitoring.",
                    )
                )

            # Ensure human analyst approval notice is always prominent
            approval_notice = "Notice: Suggested response actions require human analyst review and approval before execution. Automated execution is strictly prohibited."
            if approval_notice not in recommendations:
                recommendations.append(approval_notice)

            return CopilotResponse(
                lead_in=lead_in,
                event_count=event_count,
                observed_evidence=observed[:8],
                ai_assessment=ai_assessment,
                recommended_next_steps=recommendations,
                suggested_response_actions=suggested_actions,
            )

        # General query without incident context (Explicit general mode)
        return CopilotResponse(
            lead_in="Analysis based on general security posture telemetry (No incident selected)",
            event_count=None,
            observed_evidence=[
                "Investigation scope: General Environment Posture (no active incident context attached)",
                "Telemetry sources: Ingested authentication logs, network flow, and endpoint telemetry across all devices",
                "Detection engine: 8 active detection categories operating across baseline rules",
            ],
            ai_assessment=(
                "Operating in General Security Analysis Mode. No specific incident or alert context is currently selected. "
                "Guidance provided reflects general environment telemetry and baseline detection methodology. "
                "To conduct an evidence-grounded investigation of a specific threat, select an incident from the Investigation Context sidebar."
            ),
            recommended_next_steps=[
                "Select an active incident from the sidebar to ground analysis in concrete evidence",
                "Review the Security Overview dashboard for high-priority alerts",
                "Execute a targeted Threat Hunt query to isolate suspicious IP addresses or user accounts",
            ],
            suggested_response_actions=[],
        )
