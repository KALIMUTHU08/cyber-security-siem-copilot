from typing import Optional, List
from app.schemas.common import CamelModel


class TimeSeriesPoint(CamelModel):
    timestamp: str
    value: int
    label: Optional[str] = None


class SeverityDistribution(CamelModel):
    severity: str
    count: int


class TopSourceIp(CamelModel):
    ip: str
    count: int
    severity: str


class TopTargetUser(CamelModel):
    username: str
    count: int
    severity: str


class DetectionTypeStat(CamelModel):
    rule_name: str
    count: int


class LoginStats(CamelModel):
    timestamp: str
    failed: int
    successful: int


class AnalyticsData(CamelModel):
    events_over_time: List[TimeSeriesPoint] = []
    alerts_over_time: List[TimeSeriesPoint] = []
    severity_distribution: List[SeverityDistribution] = []
    top_source_ips: List[TopSourceIp] = []
    top_target_users: List[TopTargetUser] = []
    top_detection_types: List[DetectionTypeStat] = []
    login_stats: List[LoginStats] = []
    incident_trends: List[TimeSeriesPoint] = []
