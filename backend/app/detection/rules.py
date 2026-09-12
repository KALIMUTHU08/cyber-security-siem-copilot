from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict
from app.detection.base import BaseRule, RuleMatch
from app.models.log import SecurityLogModel
from app.core.config import settings


class BruteForceRule(BaseRule):
    rule_id = "rule-001"
    name = "Brute Force Login"
    category = "Authentication"
    condition = "More than 10 failed login attempts from the same source IP within 1 minute"
    condition_raw = "event_type:LOGIN_FAILED AND count >= 10 WITHIN 60s GROUP BY source_ip"
    severity = "HIGH"
    points = 20
    description = "Detects rapid repeated authentication failures from a single source, indicative of automated brute-force activity."

    def evaluate(self, logs: List[SecurityLogModel]) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        # Group failed logins by source IP
        failed_by_ip: Dict[str, List[SecurityLogModel]] = defaultdict(list)
        for log in logs:
            if log.event_type == "LOGIN_FAILED":
                failed_by_ip[log.source_ip].append(log)

        window = timedelta(seconds=settings.BRUTE_FORCE_WINDOW_SECONDS)
        threshold = settings.BRUTE_FORCE_THRESHOLD

        for ip, ip_logs in failed_by_ip.items():
            sorted_logs = sorted(ip_logs, key=lambda l: l.timestamp)
            left = 0
            found_window = False
            for right in range(len(sorted_logs)):
                while sorted_logs[right].timestamp - sorted_logs[left].timestamp > window:
                    left += 1
                count = right - left + 1
                if count >= threshold and not found_window:
                    matched = sorted_logs[left:right + 1]
                    matches.append(
                        RuleMatch(
                            rule_id=self.rule_id,
                            rule_name=self.name,
                            severity=self.severity,
                            points=self.points,
                            title=f"Brute Force Authentication Sequence — {ip}",
                            matching_log_ids=[m.id for m in matched],
                            matching_summary=f"{len(matched)} failed attempts within {int((matched[-1].timestamp - matched[0].timestamp).total_seconds())} seconds",
                            detection_condition=self.condition,
                            source_ip=ip,
                            destination_ip=matched[0].destination_ip,
                            username=matched[0].username,
                            device=matched[0].device,
                            first_seen=matched[0].timestamp,
                            last_seen=matched[-1].timestamp,
                            tags=["auth", "brute-force", "ssh"],
                        )
                    )
                    found_window = True  # Prevent duplicate overlapping matches in same batch
                    break
        return matches


class AccountCompromiseRule(BaseRule):
    rule_id = "rule-002"
    name = "Account Compromise"
    category = "Authentication"
    condition = "Successful login following consecutive failed attempts from the same source IP"
    condition_raw = "event_type:LOGIN AND status:SUCCESS FOLLOWING failed_sequence FROM same source_ip"
    severity = "CRITICAL"
    points = 25
    description = "Detects authentication success immediately after a brute-force failure pattern — high confidence indicator of credential compromise."

    def evaluate(self, logs: List[SecurityLogModel]) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        logs_by_ip: Dict[str, List[SecurityLogModel]] = defaultdict(list)
        for log in logs:
            if log.event_type in ("LOGIN_FAILED", "LOGIN"):
                logs_by_ip[log.source_ip].append(log)

        for ip, ip_logs in logs_by_ip.items():
            sorted_logs = sorted(ip_logs, key=lambda l: l.timestamp)
            failures_before_success: List[SecurityLogModel] = []
            for log in sorted_logs:
                if log.event_type == "LOGIN_FAILED":
                    failures_before_success.append(log)
                elif log.event_type == "LOGIN" and log.status == "SUCCESS":
                    if len(failures_before_success) >= 5:
                        # Success occurred after a streak of failures
                        matched = failures_before_success[-10:] + [log]
                        delta_sec = int((log.timestamp - failures_before_success[0].timestamp).total_seconds())
                        matches.append(
                            RuleMatch(
                                rule_id=self.rule_id,
                                rule_name=self.name,
                                severity=self.severity,
                                points=self.points,
                                title=f"Account Compromise — Successful Login Post Failures ({ip})",
                                matching_log_ids=[m.id for m in matched],
                                matching_summary=f"Successful login for {log.username} after {len(failures_before_success)} failed attempts within {delta_sec}s",
                                detection_condition=self.condition,
                                source_ip=ip,
                                destination_ip=log.destination_ip,
                                username=log.username,
                                device=log.device,
                                first_seen=matched[0].timestamp,
                                last_seen=log.timestamp,
                                tags=["compromise", "auth", "critical"],
                            )
                        )
                        failures_before_success = []
                    else:
                        failures_before_success = []
        return matches


class PortScanRule(BaseRule):
    rule_id = "rule-005"
    name = "Port Scan Detected"
    category = "Network Reconnaissance"
    condition = "Connection attempts to more than 15 distinct ports on the same destination IP within 30 seconds"
    condition_raw = "distinct_port_count >= 15 WITHIN 30s FROM same source_ip TO same destination_ip"
    severity = "MEDIUM"
    points = 20
    description = "Detects sequential or randomized port probing behavior characteristic of network reconnaissance activity."

    def evaluate(self, logs: List[SecurityLogModel]) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        port_logs: Dict[str, List[SecurityLogModel]] = defaultdict(list)
        for log in logs:
            if (log.destination_port or log.event_type == "PORT_SCAN") and log.source_ip:
                port_logs[f"{log.source_ip}->{log.destination_ip}"].append(log)

        window = timedelta(seconds=settings.PORT_SCAN_WINDOW_SECONDS)
        threshold = settings.PORT_SCAN_PORT_THRESHOLD

        for pair, pair_logs in port_logs.items():
            sorted_logs = sorted(pair_logs, key=lambda l: l.timestamp)
            distinct_ports = {l.destination_port for l in sorted_logs if l.destination_port}
            if len(distinct_ports) >= threshold or any(l.event_type == "PORT_SCAN" for l in sorted_logs):
                first_ts = sorted_logs[0].timestamp
                last_ts = sorted_logs[-1].timestamp
                delta_sec = max(int((last_ts - first_ts).total_seconds()), 1)
                matches.append(
                    RuleMatch(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        severity=self.severity,
                        points=self.points,
                        title=f"Port Scan Detected from {sorted_logs[0].source_ip}",
                        matching_log_ids=[l.id for l in sorted_logs[:20]],
                        matching_summary=f"Probed {max(len(distinct_ports), 15)} distinct ports on {sorted_logs[0].destination_ip} within {delta_sec}s",
                        detection_condition=self.condition,
                        source_ip=sorted_logs[0].source_ip,
                        destination_ip=sorted_logs[0].destination_ip,
                        username=sorted_logs[0].username,
                        device=sorted_logs[0].device,
                        first_seen=first_ts,
                        last_seen=last_ts,
                        tags=["recon", "port-scan", "network"],
                    )
                )
        return matches


class CredentialSprayRule(BaseRule):
    rule_id = "rule-006"
    name = "Credential Spray"
    category = "Authentication"
    condition = "Failed login attempts across 5 or more distinct usernames from the same source IP within 5 minutes"
    condition_raw = "event_type:LOGIN_FAILED AND distinct_username_count >= 5 WITHIN 300s GROUP BY source_ip"
    severity = "HIGH"
    points = 20
    description = "Detects low-and-slow password spray attacks that spread authentication attempts across many accounts."

    def evaluate(self, logs: List[SecurityLogModel]) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        failed_by_ip: Dict[str, List[SecurityLogModel]] = defaultdict(list)
        for log in logs:
            if log.event_type == "LOGIN_FAILED" and log.username:
                failed_by_ip[log.source_ip].append(log)

        window = timedelta(seconds=settings.CREDENTIAL_SPRAY_WINDOW_SECONDS)
        threshold = settings.CREDENTIAL_SPRAY_USER_THRESHOLD

        for ip, ip_logs in failed_by_ip.items():
            sorted_logs = sorted(ip_logs, key=lambda l: l.timestamp)
            distinct_users = {l.username for l in sorted_logs}
            if len(distinct_users) >= threshold:
                first_ts = sorted_logs[0].timestamp
                last_ts = sorted_logs[-1].timestamp
                matches.append(
                    RuleMatch(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        severity=self.severity,
                        points=self.points,
                        title=f"Credential Spray Attack from {ip}",
                        matching_log_ids=[l.id for l in sorted_logs],
                        matching_summary=f"Targeted {len(distinct_users)} distinct usernames from {ip} in spray pattern",
                        detection_condition=self.condition,
                        source_ip=ip,
                        destination_ip=sorted_logs[0].destination_ip,
                        username="multiple",
                        device=sorted_logs[0].device,
                        first_seen=first_ts,
                        last_seen=last_ts,
                        tags=["auth", "credential-spray"],
                    )
                )
        return matches


class DistributedBruteForceRule(BaseRule):
    rule_id = "rule-007"
    name = "Distributed Brute Force"
    category = "Authentication"
    condition = "Failed login attempts against the same username from 3 or more distinct source IPs within 10 minutes"
    condition_raw = "event_type:LOGIN_FAILED AND distinct_source_ip_count >= 3 WITHIN 600s GROUP BY username"
    severity = "MEDIUM"
    points = 20
    description = "Detects coordinated attack patterns where multiple source IPs target the same account."

    def evaluate(self, logs: List[SecurityLogModel]) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        failed_by_user: Dict[str, List[SecurityLogModel]] = defaultdict(list)
        for log in logs:
            if log.event_type == "LOGIN_FAILED" and log.username:
                failed_by_user[log.username].append(log)

        threshold = settings.DISTRIBUTED_ATTACK_IP_THRESHOLD

        for username, u_logs in failed_by_user.items():
            sorted_logs = sorted(u_logs, key=lambda l: l.timestamp)
            distinct_ips = {l.source_ip for l in sorted_logs}
            if len(distinct_ips) >= threshold:
                matches.append(
                    RuleMatch(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        severity=self.severity,
                        points=self.points,
                        title=f"Distributed Brute-Force against {username}",
                        matching_log_ids=[l.id for l in sorted_logs],
                        matching_summary=f"Attacked from {len(distinct_ips)} distinct IPs targeting user {username}",
                        detection_condition=self.condition,
                        source_ip="multiple",
                        destination_ip=sorted_logs[0].destination_ip,
                        username=username,
                        device=sorted_logs[0].device,
                        first_seen=sorted_logs[0].timestamp,
                        last_seen=sorted_logs[-1].timestamp,
                        tags=["auth", "distributed"],
                    )
                )
        return matches


class OffHoursLoginRule(BaseRule):
    rule_id = "rule-008"
    name = "Off-Hours Login"
    category = "User Behavior"
    condition = "Successful login for a standard user account between 00:00–06:00 local time on a weekday"
    condition_raw = "event_type:LOGIN AND status:SUCCESS AND hour_of_day BETWEEN 0 AND 6"
    severity = "LOW"
    points = 15
    description = "Flags logins outside normal business hours for review — low severity, often benign but worth tracking."

    def evaluate(self, logs: List[SecurityLogModel]) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        for log in logs:
            if log.event_type == "LOGIN" and log.status == "SUCCESS":
                hour = log.timestamp.hour
                if settings.OFF_HOURS_START <= hour < settings.OFF_HOURS_END:
                    matches.append(
                        RuleMatch(
                            rule_id=self.rule_id,
                            rule_name=self.name,
                            severity=self.severity,
                            points=self.points,
                            title=f"Off-Hours Login Detected — {log.username}",
                            matching_log_ids=[log.id],
                            matching_summary=f"Successful authentication by {log.username} at {log.timestamp.strftime('%H:%M')} during non-business hours",
                            detection_condition=self.condition,
                            source_ip=log.source_ip,
                            destination_ip=log.destination_ip,
                            username=log.username,
                            device=log.device,
                            first_seen=log.timestamp,
                            last_seen=log.timestamp,
                            tags=["behavior", "off-hours"],
                        )
                    )
        return matches


class PrivilegeEscalationRule(BaseRule):
    rule_id = "rule-003"
    name = "Privilege Escalation"
    category = "Privilege Management"
    condition = "A PRIVILEGE_CHANGE event for a user on a monitored host"
    condition_raw = "event_type:PRIVILEGE_CHANGE"
    severity = "CRITICAL"
    points = 25
    description = "Detects privilege escalation actions performed on server or sensitive endpoints."

    def evaluate(self, logs: List[SecurityLogModel]) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        for log in logs:
            if log.event_type == "PRIVILEGE_CHANGE":
                matches.append(
                    RuleMatch(
                        rule_id=self.rule_id,
                        rule_name=self.name,
                        severity=self.severity,
                        points=self.points,
                        title=f"Privilege Escalation on {log.device} by {log.username or 'admin'}",
                        matching_log_ids=[log.id],
                        matching_summary=f"Privilege elevation event observed: {log.raw_log or 'sudo root execution'}",
                        detection_condition=self.condition,
                        source_ip=log.source_ip,
                        destination_ip=log.destination_ip,
                        username=log.username,
                        device=log.device,
                        first_seen=log.timestamp,
                        last_seen=log.timestamp,
                        tags=["privilege", "sudo", "critical"],
                    )
                )
        return matches


class SuspiciousOutboundConnectionRule(BaseRule):
    rule_id = "rule-004"
    name = "Suspicious External Connection"
    category = "Network"
    condition = "Outbound connection to non-whitelisted external IP on port 443/80 from a server-class device"
    condition_raw = "event_type:NETWORK_CONNECTION AND destination_ip NOT IN whitelist AND device_class:SERVER"
    severity = "HIGH"
    points = 20
    description = "Detects outbound connections from server-class devices to external IP addresses."

    def evaluate(self, logs: List[SecurityLogModel]) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        for log in logs:
            if log.event_type in ("NETWORK_CONNECTION", "CONNECTION_BLOCKED"):
                dst = log.destination_ip
                # Check for public/external IPs (e.g. not 10.x, 192.168.x, 127.x)
                if dst and not (dst.startswith("10.") or dst.startswith("192.168.") or dst.startswith("127.")):
                    matches.append(
                        RuleMatch(
                            rule_id=self.rule_id,
                            rule_name=self.name,
                            severity=self.severity,
                            points=self.points,
                            title=f"Suspicious External Connection from {log.device} to {dst}",
                            matching_log_ids=[log.id],
                            matching_summary=f"Outbound connection from {log.device} to external destination {dst}:{log.destination_port or 443}",
                            detection_condition=self.condition,
                            source_ip=log.source_ip,
                            destination_ip=dst,
                            username=log.username,
                            device=log.device,
                            first_seen=log.timestamp,
                            last_seen=log.timestamp,
                            tags=["c2", "outbound", "network"],
                        )
                    )
        return matches
