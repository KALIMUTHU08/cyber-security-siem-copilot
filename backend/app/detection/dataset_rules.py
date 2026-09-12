"""
dataset_rules.py — Detection rules designed for the Kaggle dataset schema.

These rules work on fields available in the dataset:
  protocol, action, log_type, request_path, user_agent, bytes_transferred

They are ADDITIVE to existing rules (rules.py) and follow the same
BaseRule interface. Ground truth (_ground_truth) is never consulted.
"""

from collections import defaultdict
from datetime import timedelta
from typing import List, Dict
from app.detection.base import BaseRule, RuleMatch
from app.models.log import SecurityLogModel


class HighVolumeBlockedConnectionsRule(BaseRule):
    rule_id = "rule-009"
    name = "High-Volume Blocked Connections"
    category = "Network"
    condition = "More than 50 blocked connections from the same source IP within 5 minutes"
    condition_raw = "status:BLOCKED AND count >= 50 WITHIN 300s GROUP BY source_ip"
    severity = "HIGH"
    points = 20
    description = (
        "Detects aggressive scanning or flood activity by tracking repeated blocked connections from a single source. "
        "Note: In day-level timestamp datasets, sliding windows group connections across the same calendar date."
    )

    def evaluate(self, logs: List[SecurityLogModel]) -> List[RuleMatch]:
        matches = []
        blocked_by_ip: Dict[str, List[SecurityLogModel]] = defaultdict(list)
        for log in logs:
            if log.status == "BLOCKED" and log.source_ip:
                blocked_by_ip[log.source_ip].append(log)

        window = timedelta(seconds=300)
        threshold = 50

        for ip, ip_logs in blocked_by_ip.items():
            sorted_logs = sorted(ip_logs, key=lambda l: l.timestamp)
            left = 0
            for right in range(len(sorted_logs)):
                while sorted_logs[right].timestamp - sorted_logs[left].timestamp > window:
                    left += 1
                count = right - left + 1
                if count >= threshold:
                    matched = sorted_logs[left:right + 1]
                    delta = int((matched[-1].timestamp - matched[0].timestamp).total_seconds())
                    matches.append(RuleMatch(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        severity=self.severity,
                        points=self.points,
                        title=f"High-Volume Blocked Traffic from {ip}",
                        matching_log_ids=[m.id for m in matched[:50]],
                        matching_summary=f"{count} blocked connections from {ip} within {delta}s",
                        detection_condition=self.condition,
                        source_ip=ip,
                        destination_ip=matched[0].destination_ip,
                        username=matched[0].username,
                        device=matched[0].device,
                        first_seen=matched[0].timestamp,
                        last_seen=matched[-1].timestamp,
                        tags=["network", "flood", "blocked"],
                    ))
                    break  # one match per IP per batch
        return matches


class AdminPathAccessRule(BaseRule):
    rule_id = "rule-010"
    name = "Sensitive Admin Path Access"
    category = "Web Application"
    condition = "HTTP/HTTPS request containing SQL injection, directory traversal, or administrative exploitation payloads"
    condition_raw = "request_path CONTAINS injection_payload (UNION SELECT, DROP TABLE, ../, ?admin, etc.) AND protocol IN ('HTTP','HTTPS')"
    severity = "HIGH"
    points = 25
    description = (
        "Detects web requests attempting exploitation via SQL injection, directory traversal, or administrative "
        "parameter probes. Clean base administrative paths without exploit payloads are not flagged."
    )

    INJECTION_PAYLOADS = [
        "union select",
        "drop table",
        "../",
        "..\\",
        "backup.sql",
        "phpmyadmin",
        "?admin",
        "?sqlmap",
        "?hydra",
        "?nmap",
        "?login",
    ]
    SYSTEM_TARGETS = ("/etc/passwd", "/bin/bash", "/root")

    def evaluate(self, logs: List[SecurityLogModel]) -> List[RuleMatch]:
        matches = []
        for log in logs:
            pf = log.parsed_fields or {}
            path = (pf.get("request_path") or "").lower()
            proto = (pf.get("protocol") or "").upper()
            if proto in ("HTTP", "HTTPS"):
                has_payload = any(p in path for p in self.INJECTION_PAYLOADS)
                has_sys_target = ("?" in path) and any(st in path for st in self.SYSTEM_TARGETS)

                if has_payload or has_sys_target:
                    # Identify matched signature for explainability
                    matched_pattern = next((p for p in self.INJECTION_PAYLOADS if p in path), None)
                    if not matched_pattern and has_sys_target:
                        matched_pattern = next((st for st in self.SYSTEM_TARGETS if st in path), "system-probe")

                    matches.append(RuleMatch(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        severity=self.severity,
                        points=self.points,
                        title=f"Exploit Payload Probe: {pf.get('request_path', '')} from {log.source_ip}",
                        matching_log_ids=[log.id],
                        matching_summary=f"Exploitation probe detected matching '{matched_pattern}' on {proto} path '{pf.get('request_path', '')}'",
                        detection_condition=self.condition,
                        source_ip=log.source_ip,
                        destination_ip=log.destination_ip,
                        username=log.username,
                        device=log.device,
                        first_seen=log.timestamp,
                        last_seen=log.timestamp,
                        tags=["web", "injection", "exploit"],
                    ))
        return matches


class FTPDataExfiltrationRule(BaseRule):
    rule_id = "rule-011"
    name = "FTP Large Data Transfer"
    category = "Data Exfiltration"
    condition = "FTP transfer > 5MB from an internal source IP"
    condition_raw = "protocol:FTP AND bytes_transferred > 5242880 AND status:SUCCESS"
    severity = "HIGH"
    points = 22
    description = (
        "Detects abnormally large FTP transfers that may indicate data exfiltration activity. "
        "Preserved with standard 5 MB threshold; note that synthetic datasets bounded to <=50 KB will not trigger this rule."
    )

    THRESHOLD_BYTES = 5 * 1024 * 1024  # 5 MB standard SOC threshold

    def evaluate(self, logs: List[SecurityLogModel]) -> List[RuleMatch]:
        matches = []
        for log in logs:
            pf = log.parsed_fields or {}
            proto = pf.get("protocol", "")
            bt = pf.get("bytes_transferred", 0) or 0
            try:
                bt = int(bt)
            except (ValueError, TypeError):
                bt = 0

            if proto == "FTP" and bt > self.THRESHOLD_BYTES and log.status == "SUCCESS":
                matches.append(RuleMatch(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    severity=self.severity,
                    points=self.points,
                    title=f"Large FTP Transfer from {log.source_ip} ({bt // 1024}KB)",
                    matching_log_ids=[log.id],
                    matching_summary=f"FTP transfer of {bt:,} bytes from {log.source_ip} to {log.destination_ip}",
                    detection_condition=self.condition,
                    source_ip=log.source_ip,
                    destination_ip=log.destination_ip,
                    username=log.username,
                    device=log.device,
                    first_seen=log.timestamp,
                    last_seen=log.timestamp,
                    tags=["exfiltration", "ftp", "data-loss"],
                ))
        return matches


class ScannerUserAgentRule(BaseRule):
    rule_id = "rule-012"
    name = "Scanner User-Agent Detected"
    category = "Network Reconnaissance"
    condition = "HTTP request with a known scanner user-agent signature (Nmap, sqlmap, nikto, masscan) and meaningful security context"
    condition_raw = "user_agent CONTAINS ('Nmap','sqlmap','nikto','masscan','ZAP','DirBuster') AND (request_path CONTAINS sensitive/exploit OR action = 'blocked')"
    severity = "MEDIUM"
    points = 20
    description = (
        "Detects network requests from known automated scanning tools (Nmap, SQLMap, etc.) with "
        "meaningful security context (sensitive path, exploit pattern, or firewall block action)."
    )

    SCANNER_STRINGS = ["nmap", "sqlmap", "nikto", "masscan", "zap", "dirbuster", "gobuster", "nessus"]
    SENSITIVE_PATHS = ("/admin", "/login", "/root", "/etc", "/secure")
    EXPLOIT_PATTERNS = ("union select", "drop table", "../", "..\\", "etc/passwd", "backup.sql")

    def evaluate(self, logs: List[SecurityLogModel]) -> List[RuleMatch]:
        matches = []
        for log in logs:
            pf = log.parsed_fields or {}
            ua_raw = pf.get("user_agent") or ""
            ua = ua_raw.lower()
            if any(scanner in ua for scanner in self.SCANNER_STRINGS):
                path = (pf.get("request_path") or "").lower()
                action = (pf.get("action") or log.status or "").lower()
                is_blocked = action in ("blocked", "block")
                has_exploit = any(x in path for x in self.EXPLOIT_PATTERNS)
                has_sensitive = any(s in path for s in self.SENSITIVE_PATHS)

                # Meaningful security context gating:
                # Scanner-only on normal path MUST NOT generate a Rule-012 alert.
                if not (has_exploit or has_sensitive or is_blocked):
                    continue

                # Signals:
                # 1. Scanner UA base evidence: +10
                points = 10
                evidence = ["scanner UA (+10)"]

                # 2. Exploit pattern (+20) OR Sensitive path (+10)
                if has_exploit:
                    points += 20
                    evidence.append("exploit pattern (+20)")
                elif has_sensitive:
                    points += 10
                    evidence.append("sensitive path (+10)")

                # 3. Blocked action: +10
                if is_blocked:
                    points += 10
                    evidence.append("blocked action (+10)")

                # Severity policy:
                # Scanner UA + exploit pattern + blocked action -> CRITICAL
                # Scanner UA + exploit pattern -> HIGH
                # Scanner UA + sensitive path OR blocked action -> MEDIUM
                # Scanner UA + sensitive path + blocked action -> MEDIUM
                if has_exploit and is_blocked:
                    sev = "CRITICAL"
                elif has_exploit:
                    sev = "HIGH"
                else:
                    sev = "MEDIUM"

                summary = f"Scanner signature '{ua_raw[:60]}' on path '{pf.get('request_path', '')}' [{', '.join(evidence)}]"

                matches.append(RuleMatch(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    severity=sev,
                    points=points,
                    title=f"Scanner User-Agent from {log.source_ip} ({sev})",
                    matching_log_ids=[log.id],
                    matching_summary=summary,
                    detection_condition=self.condition,
                    source_ip=log.source_ip,
                    destination_ip=log.destination_ip,
                    username=log.username,
                    device=log.device,
                    first_seen=log.timestamp,
                    last_seen=log.timestamp,
                    tags=["recon", "scanner", "contextual"],
                ))
        return matches



class ICMPFloodRule(BaseRule):
    rule_id = "rule-013"
    name = "ICMP Flood / Ping Sweep"
    category = "Network"
    condition = "More than 100 ICMP packets from same source IP within 60 seconds"
    condition_raw = "protocol:ICMP AND count >= 100 WITHIN 60s GROUP BY source_ip"
    severity = "MEDIUM"
    points = 15
    description = (
        "Detects ICMP flood or ping sweep reconnaissance activity from a single source. "
        "Note: In day-level timestamp datasets, sliding windows group packets across the same calendar date."
    )

    def evaluate(self, logs: List[SecurityLogModel]) -> List[RuleMatch]:
        matches = []
        icmp_by_ip: Dict[str, List[SecurityLogModel]] = defaultdict(list)
        for log in logs:
            pf = log.parsed_fields or {}
            if pf.get("protocol") == "ICMP" and log.source_ip:
                icmp_by_ip[log.source_ip].append(log)

        window = timedelta(seconds=60)
        threshold = 100

        for ip, ip_logs in icmp_by_ip.items():
            sorted_logs = sorted(ip_logs, key=lambda l: l.timestamp)
            left = 0
            for right in range(len(sorted_logs)):
                while sorted_logs[right].timestamp - sorted_logs[left].timestamp > window:
                    left += 1
                count = right - left + 1
                if count >= threshold:
                    matched = sorted_logs[left:right + 1]
                    delta = int((matched[-1].timestamp - matched[0].timestamp).total_seconds())
                    matches.append(RuleMatch(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        severity=self.severity,
                        points=self.points,
                        title=f"ICMP Flood from {ip} ({count} packets)",
                        matching_log_ids=[m.id for m in matched[:30]],
                        matching_summary=f"{count} ICMP packets from {ip} within {delta}s",
                        detection_condition=self.condition,
                        source_ip=ip,
                        destination_ip=matched[0].destination_ip,
                        username="",
                        device=matched[0].device,
                        first_seen=matched[0].timestamp,
                        last_seen=matched[-1].timestamp,
                        tags=["icmp", "flood", "recon"],
                    ))
                    break
        return matches
