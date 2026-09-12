"""
evaluation.py — Scientifically valid detection performance evaluation against ground truth.

Computes:
1. OVERALL DATASET EVALUATION:
   - Evaluates whether dataset-compatible detection rules identified ground-truth positive records.
   - Evaluated strictly over UNIQUE log IDs (a log is never counted twice).
   - TP: unique positive log that triggered at least one compatible rule.
   - FP: unique benign log that triggered at least one compatible rule.
   - FN: unique positive log that triggered no compatible rule.
   - TN: unique benign log that triggered no compatible rule.
   - Precision, Recall, F1.

2. RULE-SPECIFIC EVALUATION:
   - Does NOT assume every positive record is relevant to every rule.
   - No manufactured per-rule FN / Recall / F1 when no defensible rule-specific ground truth subset exists.
   - Reports: rule_id, rule_name, evaluation_status (SUPPORTED/PARTIAL/UNSUPPORTED),
     total alerts, unique logs alerted, unique positives, unique negatives, trigger rate, precision,
     recall (null), f1 (null), and explanatory notes.

3. EVALUATION SCOPE & LIMITATIONS:
   - Explicit categorization of all 13 SIEM rules against the dataset.
   - Documented dataset artifacts (midnight timestamps, lack of auth telemetry, 50 KB byte ceiling).

Usage (from backend/):
    python evaluation.py [--output report.json]
"""

import json
import sys
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set, Any
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).parent))

from app.database.session import SessionLocal
from app.models.log import SecurityLogModel
from app.models.alert import AlertModel
from app.detection.registry import registry
from app.detection.rules import (
    BruteForceRule,
    AccountCompromiseRule,
    PrivilegeEscalationRule,
    SuspiciousOutboundConnectionRule,
    PortScanRule,
    CredentialSprayRule,
    DistributedBruteForceRule,
    OffHoursLoginRule,
)
from app.detection.dataset_rules import (
    HighVolumeBlockedConnectionsRule,
    AdminPathAccessRule,
    FTPDataExfiltrationRule,
    ScannerUserAgentRule,
    ICMPFloodRule,
)


# ---------------------------------------------------------------------------
# Ground-truth semantics
# ---------------------------------------------------------------------------
# "benign"     → negative (no alert expected)
# "suspicious" → positive (alert expected)
# "malicious"  → positive (alert expected)
POSITIVE_LABELS = {"suspicious", "malicious"}


# ---------------------------------------------------------------------------
# Rule Evaluation Scope Categorization for Kaggle Dataset
# ---------------------------------------------------------------------------
RULE_EVALUATION_SCOPE: Dict[str, Dict[str, str]] = {
    "rule-001": {
        "status": "UNSUPPORTED",
        "reason": "Dataset lacks authentication and login telemetry; all timestamps are fixed at midnight.",
    },
    "rule-002": {
        "status": "UNSUPPORTED",
        "reason": "No account compromise state sequences or username tracking available in dataset.",
    },
    "rule-003": {
        "status": "UNSUPPORTED",
        "reason": "No privilege change, sudo, or OS-level audit events available in dataset.",
    },
    "rule-004": {
        "status": "UNSUPPORTED",
        "reason": "100% of destination IPs in dataset are RFC-1918 private (192.168.x.x); outbound condition is unreachable.",
    },
    "rule-005": {
        "status": "UNSUPPORTED",
        "reason": "Dataset contains no port columns; destination ports are inferred 1:1 from protocol.",
    },
    "rule-006": {
        "status": "UNSUPPORTED",
        "reason": "No username column in dataset; credential spray cannot be evaluated.",
    },
    "rule-007": {
        "status": "UNSUPPORTED",
        "reason": "No username column in dataset; distributed brute force cannot be evaluated.",
    },
    "rule-008": {
        "status": "UNSUPPORTED",
        "reason": "No authentication semantics and intra-day timestamps are hardcoded to midnight (00:00:00).",
    },
    "rule-009": {
        "status": "PARTIAL",
        "reason": "Fields available (action, source_ip), but 5-minute sliding window is constrained by day-level timestamps.",
    },
    "rule-010": {
        "status": "SUPPORTED",
        "reason": "Evaluates web application injection and exploit probe patterns (SQLi, directory traversal, probe parameters).",
    },
    "rule-011": {
        "status": "UNSUPPORTED",
        "reason": "Preserved general 5 MB threshold; unsupported for this dataset because transfer sizes cap at 50 KB.",
    },
    "rule-012": {
        "status": "SUPPORTED",
        "reason": "Automated scanner signature detection. High false positive rate due to synthetic dataset label noise.",
    },
    "rule-013": {
        "status": "PARTIAL",
        "reason": "Fields available (ICMP, source_ip), but 60-second window is constrained by day-level timestamps.",
    },
}

# Rules considered dataset-compatible for overall classification scoring
EVALUABLE_RULE_IDS: Set[str] = {"rule-009", "rule-010", "rule-012", "rule-013"}

DATASET_LIMITATIONS: List[str] = [
    "Dataset timestamps are truncated to midnight (00:00:00); rate-based sliding windows operate at calendar-day granularity.",
    "Dataset lacks authentication entities, user accounts, and session identifiers, precluding quantitative evaluation of authentication rules.",
    "100% of destination IPs are private (192.168.x.x), precluding outbound connection rule triggers.",
    "Kaggle synthetic generator assigned scanner user-agents (Nmap, SQLMap) across benign baseline records (~92% benign), inducing elevated false positive rates.",
    "Bytes transferred is bounded to <= 50 KB, rendering general enterprise FTP exfiltration thresholds (5 MB) unreachable under default configuration.",
]


@dataclass
class OverallMetrics:
    total_logs: int = 0
    total_positives: int = 0      # logs labelled suspicious/malicious
    total_negatives: int = 0      # logs labelled benign
    total_alerts: int = 0
    alerted_logs: int = 0         # distinct logs that triggered at least one evaluable rule
    tp: int = 0                   # unique positive log alerted
    fp: int = 0                   # unique benign log alerted
    fn: int = 0                   # unique positive log not alerted
    tn: int = 0                   # unique benign log not alerted

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return round(self.tp / denom, 4) if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return round(self.tp / denom, 4) if denom > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return round(2 * p * r / (p + r), 4) if (p + r) > 0 else 0.0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["precision"] = self.precision
        d["recall"] = self.recall
        d["f1"] = self.f1
        return d


@dataclass
class RuleEvaluationResult:
    rule_id: str
    rule_name: str
    evaluation_status: str        # SUPPORTED / PARTIAL / UNSUPPORTED
    alerts: int = 0               # total alerts generated by rule on dataset
    unique_logs_alerted: int = 0  # distinct logs matching this rule
    unique_positives: int = 0     # distinct ground-truth positive logs
    unique_negatives: int = 0     # distinct ground-truth benign logs
    trigger_rate: float = 0.0     # unique_logs_alerted / total_logs
    precision: float = 0.0        # unique_positives / unique_logs_alerted
    recall: Optional[float] = None
    f1: Optional[float] = None
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def ensure_rules_registered():
    """Ensure all 13 rules are in the registry."""
    rules_to_register = [
        BruteForceRule(),
        AccountCompromiseRule(),
        PrivilegeEscalationRule(),
        SuspiciousOutboundConnectionRule(),
        PortScanRule(),
        CredentialSprayRule(),
        DistributedBruteForceRule(),
        OffHoursLoginRule(),
        HighVolumeBlockedConnectionsRule(),
        AdminPathAccessRule(),
        FTPDataExfiltrationRule(),
        ScannerUserAgentRule(),
        ICMPFloodRule(),
    ]
    for r in rules_to_register:
        try:
            registry.register(r)
        except Exception:
            pass


def run_evaluation(output_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Run scientifically valid evaluation comparing detection results against ground truth.
    Strictly evaluates unique log IDs and avoids manufactured per-rule FN/recall.
    """
    ensure_rules_registered()
    db = SessionLocal()
    try:
        print("[EVAL] Loading dataset logs with ground truth labels...")
        # Only consider dataset logs (ID prefix 'ds-')
        logs_q = db.query(SecurityLogModel).filter(
            SecurityLogModel.id.like("ds-%")
        ).all()

        total_logs = len(logs_q)
        print(f"[EVAL] Found {total_logs:,} dataset logs in database.")

        if total_logs == 0:
            return {
                "overall": OverallMetrics().to_dict(),
                "per_rule": [],
                "evaluation_scope": {
                    "supported": [k for k, v in RULE_EVALUATION_SCOPE.items() if v["status"] == "SUPPORTED"],
                    "partial": [k for k, v in RULE_EVALUATION_SCOPE.items() if v["status"] == "PARTIAL"],
                    "unsupported": [k for k, v in RULE_EVALUATION_SCOPE.items() if v["status"] == "UNSUPPORTED"],
                },
                "limitations": DATASET_LIMITATIONS,
                "message": "No dataset logs found in database. Please seed dataset first.",
            }

        # Build unique log -> ground truth boolean lookup (True = positive, False = negative)
        log_is_positive: Dict[str, bool] = {}
        for log in logs_q:
            pf = log.parsed_fields or {}
            gt_label = (pf.get("_ground_truth") or "benign").strip().lower()
            log_is_positive[log.id] = (gt_label in POSITIVE_LABELS)

        # Load all alerts
        alerts_q = db.query(AlertModel).all()

        # Deduplication data structures:
        # 1. log_id -> set of rule_ids that alerted it
        alerted_log_rules: Dict[str, Set[str]] = defaultdict(set)
        # 2. rule_id -> alert count for dataset logs
        rule_alert_count: Dict[str, int] = defaultdict(int)
        # 3. rule_id -> set of unique log_ids alerted
        rule_alerted_logs: Dict[str, Set[str]] = defaultdict(set)

        total_dataset_alerts = 0

        for alert in alerts_q:
            matching_ids = alert.matching_log_ids or []
            # Filter to log IDs actually in dataset
            dataset_matching_ids = [lid for lid in matching_ids if lid in log_is_positive]
            if not dataset_matching_ids:
                continue

            total_dataset_alerts += 1
            rule_id = alert.detection_rule_id
            rule_alert_count[rule_id] += 1

            for lid in dataset_matching_ids:
                # Deduplicated: rule_id + log_id
                alerted_log_rules[lid].add(rule_id)
                rule_alerted_logs[rule_id].add(lid)

        # -------------------------------------------------------------------
        # 1. OVERALL DATASET EVALUATION (Unique Log IDs)
        # -------------------------------------------------------------------
        overall = OverallMetrics()
        overall.total_logs = total_logs
        overall.total_alerts = total_dataset_alerts

        # A log is alerted if any active evaluable rule (SUPPORTED or PARTIAL) fired on it
        for log_id, is_pos in log_is_positive.items():
            if is_pos:
                overall.total_positives += 1
            else:
                overall.total_negatives += 1

            rules_fired = alerted_log_rules.get(log_id, set())
            is_alerted = bool(rules_fired & EVALUABLE_RULE_IDS)

            if is_alerted:
                overall.alerted_logs += 1
                if is_pos:
                    overall.tp += 1
                else:
                    overall.fp += 1
            else:
                if is_pos:
                    overall.fn += 1
                else:
                    overall.tn += 1

        # -------------------------------------------------------------------
        # 2. RULE-SPECIFIC EVALUATION (No manufactured FNs)
        # -------------------------------------------------------------------
        per_rule_results: List[RuleEvaluationResult] = []

        # Get all registered rules from registry to enumerate all 13 rules
        all_rules = registry.get_all_rules()

        for rule in all_rules:
            rid = rule.rule_id
            rname = rule.name
            scope_info = RULE_EVALUATION_SCOPE.get(rid, {
                "status": "UNSUPPORTED",
                "reason": "Rule not calibrated for Kaggle dataset schema.",
            })
            status = scope_info["status"]
            reason = scope_info["reason"]

            alerts_cnt = rule_alert_count.get(rid, 0)
            alerted_logs_set = rule_alerted_logs.get(rid, set())
            unique_logs_alerted = len(alerted_logs_set)

            unique_pos = sum(1 for lid in alerted_logs_set if log_is_positive.get(lid, False))
            unique_neg = unique_logs_alerted - unique_pos

            trigger_rate = round(unique_logs_alerted / total_logs, 4) if total_logs > 0 else 0.0
            prec = round(unique_pos / unique_logs_alerted, 4) if unique_logs_alerted > 0 else 0.0

            # Explanatory note
            note = f"[{status}] {reason}"
            if status in ("SUPPORTED", "PARTIAL"):
                note += " Rule-specific recall is not calculated because the dataset does not provide a ground-truth attack category that maps uniquely to this rule."

            res = RuleEvaluationResult(
                rule_id=rid,
                rule_name=rname,
                evaluation_status=status,
                alerts=alerts_cnt,
                unique_logs_alerted=unique_logs_alerted,
                unique_positives=unique_pos,
                unique_negatives=unique_neg,
                trigger_rate=trigger_rate,
                precision=prec,
                recall=None,  # null in JSON — no manufactured per-rule recall
                f1=None,      # null in JSON
                note=note,
            )
            per_rule_results.append(res)

        # Sort rules: SUPPORTED first, then PARTIAL, then UNSUPPORTED, then by precision
        status_rank = {"SUPPORTED": 0, "PARTIAL": 1, "UNSUPPORTED": 2}
        per_rule_results.sort(key=lambda r: (status_rank.get(r.evaluation_status, 3), -r.precision, -r.alerts))

        report: Dict[str, Any] = {
            "overall": overall.to_dict(),
            "per_rule": [r.to_dict() for r in per_rule_results],
            "evaluation_scope": {
                "supported": [k for k, v in RULE_EVALUATION_SCOPE.items() if v["status"] == "SUPPORTED"],
                "partial": [k for k, v in RULE_EVALUATION_SCOPE.items() if v["status"] == "PARTIAL"],
                "unsupported": [k for k, v in RULE_EVALUATION_SCOPE.items() if v["status"] == "UNSUPPORTED"],
            },
            "limitations": DATASET_LIMITATIONS,
        }

        # Terminal Printout
        print("\n" + "=" * 65)
        print("  SIEM COPILOT — DATASET EVALUATION REPORT")
        print("=" * 65)
        o = overall
        print(f"  Total Logs Evaluated : {o.total_logs:,} (Unique Records)")
        pos_pct = (o.total_positives / o.total_logs * 100) if o.total_logs > 0 else 0
        print(f"  Ground Truth Positives: {o.total_positives:,} ({pos_pct:.1f}%)")
        print(f"  Ground Truth Negatives: {o.total_negatives:,}")
        print(f"  Alerted Logs (Evaluable Rules): {o.alerted_logs:,}")
        print(f"  Classification Matrix: TP={o.tp:,}  FP={o.fp:,}  FN={o.fn:,}  TN={o.tn:,}")
        print(f"  Overall Precision    : {o.precision:.4f}")
        print(f"  Overall Recall       : {o.recall:.4f}")
        print(f"  Overall F1 Score     : {o.f1:.4f}")
        print("=" * 65)

        print("\n  Per-Rule Metrics (Unique Logs Deduplicated):")
        print(f"  {'Rule ID':<10} {'Rule Name':<32} {'Status':<12} {'Logs':<8} {'TP':<6} {'FP':<6} {'Precision':<10}")
        print("  " + "-" * 86)
        for r in per_rule_results:
            prec_str = f"{r.precision:.4f}" if r.unique_logs_alerted > 0 else "N/A"
            print(f"  {r.rule_id:<10} {r.rule_name[:31]:<32} {r.evaluation_status:<12} {r.unique_logs_alerted:<8} {r.unique_positives:<6} {r.unique_negatives:<6} {prec_str:<10}")
        print("=" * 65 + "\n")

        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            print(f"[EVAL] Report saved to {output_path}")

        return report

    finally:
        db.close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Evaluate SIEM detection against ground truth")
    parser.add_argument("--output", default=None, help="Save report JSON to this path")
    args = parser.parse_args()
    run_evaluation(args.output)
