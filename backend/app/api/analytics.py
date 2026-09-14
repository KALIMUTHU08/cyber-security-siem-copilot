from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.permissions import Permission, require_permission
from app.database.session import get_db
from app.models.user import UserModel
from app.schemas.analytics import AnalyticsData
from app.services.analytics_service import get_analytics_data

router = APIRouter(prefix="/analytics", tags=["Analytics"])


@router.get("", response_model=AnalyticsData)
def get_analytics(
    days: int = Query(7, ge=1, le=90),
    _: UserModel = Depends(require_permission(Permission.ANALYTICS_VIEW)),
    db: Session = Depends(get_db),
):
    return get_analytics_data(db, days)
