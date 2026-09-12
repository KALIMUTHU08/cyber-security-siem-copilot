from typing import Optional
from app.schemas.common import CamelModel


class DetectionRule(CamelModel):
    id: str
    name: str
    category: str
    condition: str
    condition_raw: Optional[str] = None
    severity: str
    enabled: bool
    trigger_count: int = 0
    description: str = ""


class RuleToggleRequest(CamelModel):
    enabled: bool
