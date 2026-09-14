from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.permissions import Permission, require_permission
from app.database.session import get_db
from app.models.rule import DetectionRuleModel
from app.models.user import UserModel
from app.schemas.rule import DetectionRule, RuleToggleRequest
from app.services.siem_pipeline import seed_default_rules_if_empty

router = APIRouter(prefix="/settings", tags=["Settings"])


@router.get("/detection-rules", response_model=List[DetectionRule])
def list_detection_rules(
    _: UserModel = Depends(require_permission(Permission.RULES_VIEW)),
    db: Session = Depends(get_db),
):
    seed_default_rules_if_empty(db)
    rules = db.query(DetectionRuleModel).all()
    return [DetectionRule.model_validate(r) for r in rules]


@router.patch("/detection-rules/{rule_id}", response_model=DetectionRule)
def toggle_detection_rule(
    rule_id: str,
    request: RuleToggleRequest,
    _: UserModel = Depends(require_permission(Permission.RULES_MANAGE)),
    db: Session = Depends(get_db),
):
    rule = db.query(DetectionRuleModel).filter(DetectionRuleModel.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    rule.enabled = request.enabled
    db.commit()
    db.refresh(rule)
    return DetectionRule.model_validate(rule)
