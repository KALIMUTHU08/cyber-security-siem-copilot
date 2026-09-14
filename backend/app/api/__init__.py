from fastapi import APIRouter
from app.api.auth import router as auth_router
from app.api.dashboard import router as dashboard_router
from app.api.logs import router as logs_router
from app.api.alerts import router as alerts_router
from app.api.incidents import router as incidents_router
from app.api.threat_hunting import router as threat_hunting_router
from app.api.copilot import router as copilot_router
from app.api.analytics import router as analytics_router
from app.api.settings import router as settings_router
from app.api.dataset import router as dataset_router
from app.api.response_actions import router as response_actions_router
from app.api.audit import router as audit_router
from app.api.blocklist import router as blocklist_router

api_router = APIRouter()
api_router.include_router(auth_router)
api_router.include_router(dashboard_router)
api_router.include_router(logs_router)
api_router.include_router(alerts_router)
api_router.include_router(incidents_router)
api_router.include_router(threat_hunting_router)
api_router.include_router(copilot_router)
api_router.include_router(analytics_router)
api_router.include_router(settings_router)
api_router.include_router(dataset_router)
api_router.include_router(response_actions_router)
api_router.include_router(audit_router)
api_router.include_router(blocklist_router)

__all__ = ["api_router"]
