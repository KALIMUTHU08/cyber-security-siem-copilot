from typing import Dict, List, Optional, Set
from app.detection.base import BaseRule, RuleMatch
from app.detection.rules import (
    BruteForceRule,
    AccountCompromiseRule,
    PortScanRule,
    CredentialSprayRule,
    DistributedBruteForceRule,
    OffHoursLoginRule,
    PrivilegeEscalationRule,
    SuspiciousOutboundConnectionRule,
)
from app.detection.dataset_rules import (
    HighVolumeBlockedConnectionsRule,
    AdminPathAccessRule,
    FTPDataExfiltrationRule,
    ScannerUserAgentRule,
    ICMPFloodRule,
)
from app.models.log import SecurityLogModel


class RuleRegistry:
    def __init__(self):
        self._rules: Dict[str, BaseRule] = {}
        self._register_default_rules()

    def register(self, rule: BaseRule):
        self._rules[rule.rule_id] = rule

    def get_rule(self, rule_id: str) -> Optional[BaseRule]:
        return self._rules.get(rule_id)

    def get_all_rules(self) -> List[BaseRule]:
        return list(self._rules.values())

    def _register_default_rules(self):
        default_rules = [
            # Original 8 rules
            BruteForceRule(),
            AccountCompromiseRule(),
            PrivilegeEscalationRule(),
            SuspiciousOutboundConnectionRule(),
            PortScanRule(),
            CredentialSprayRule(),
            DistributedBruteForceRule(),
            OffHoursLoginRule(),
            # Dataset-specific rules (rule-009 to rule-013)
            HighVolumeBlockedConnectionsRule(),
            AdminPathAccessRule(),
            FTPDataExfiltrationRule(),
            ScannerUserAgentRule(),
            ICMPFloodRule(),
        ]
        for r in default_rules:
            self.register(r)

    def evaluate_all(
        self,
        logs: List[SecurityLogModel],
        enabled_rule_ids: Optional[Set[str]] = None,
    ) -> List[RuleMatch]:
        matches: List[RuleMatch] = []
        for rule_id, rule in self._rules.items():
            if enabled_rule_ids is not None and rule_id not in enabled_rule_ids:
                continue
            rule_matches = rule.evaluate(logs)
            matches.extend(rule_matches)
        return matches


# Global instance
registry = RuleRegistry()
