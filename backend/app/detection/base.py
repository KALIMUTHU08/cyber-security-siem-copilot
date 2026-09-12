from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional
from app.models.log import SecurityLogModel


@dataclass
class RuleMatch:
    rule_id: str
    rule_name: str
    severity: str
    points: int
    title: str
    matching_log_ids: List[str]
    matching_summary: str
    detection_condition: str
    source_ip: str
    destination_ip: Optional[str]
    username: str
    device: str
    first_seen: datetime
    last_seen: datetime
    tags: List[str] = field(default_factory=list)


class BaseRule(ABC):
    rule_id: str
    name: str
    category: str
    condition: str
    condition_raw: str
    severity: str
    points: int
    description: str

    @abstractmethod
    def evaluate(self, logs: List[SecurityLogModel]) -> List[RuleMatch]:
        """Evaluate the rule against a collection of logs and return any matches."""
        pass
