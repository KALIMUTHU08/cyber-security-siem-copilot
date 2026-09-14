from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.permissions import Permission, require_permission
from app.database.session import get_db
from app.models.user import UserModel
from app.schemas.dashboard import DashboardStats
from app.services.analytics_service import get_dashboard_stats as _get_stats

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("", response_model=DashboardStats)
def read_dashboard_stats(
    _: UserModel = Depends(require_permission(Permission.DASHBOARD_VIEW)),
    db: Session = Depends(get_db),
):
    return _get_stats(db)
