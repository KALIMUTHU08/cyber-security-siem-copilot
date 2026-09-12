from typing import Optional, List
from app.schemas.common import CamelModel


class SystemHealthComponent(CamelModel):
    name: str
    status: str  # 'operational' | 'degraded' | 'offline'
    latency_ms: Optional[int] = None
    detail: Optional[str] = None


class SystemHealth(CamelModel):
    overall: str  # 'operational' | 'degraded' | 'offline'
    components: List[SystemHealthComponent] = []


class DashboardStats(CamelModel):
    total_events: int
    total_events_change: int
    active_alerts: int
    active_alerts_change: int
    high_risk_events: int
    high_risk_change: int
    critical_incidents: int
    critical_incidents_change: int
    system_health: SystemHealth
