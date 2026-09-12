from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.schemas.analytics import AnalyticsData
from app.services.analytics_service import get_analytics_data

router = APIRouter(prefix="/analytics", tags=["Analytics"])


@router.get("", response_model=AnalyticsData)
def get_analytics(
    days: int = Query(7, ge=1, le=90),
    db: Session = Depends(get_db),
):
    return get_analytics_data(db, days)
