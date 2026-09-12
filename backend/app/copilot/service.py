import uuid
from datetime import datetime
from typing import List, Optional
from sqlalchemy.orm import Session

from app.copilot.provider import LLMProvider
from app.copilot.openai_provider import OpenAIProvider
from app.copilot.template_provider import DeterministicTemplateProvider
from app.models.copilot import CopilotMessageModel
from app.models.incident import IncidentModel
from app.models.log import SecurityLogModel
from app.schemas.copilot import CopilotMessage, CopilotResponse
from app.core.config import settings


class CopilotService:
    def __init__(self):
        self.template_provider = DeterministicTemplateProvider()
        self.llm_provider: Optional[LLMProvider] = None
        if settings.OPENAI_API_KEY:
            self.llm_provider = OpenAIProvider(
                api_key=settings.OPENAI_API_KEY,
                base_url=settings.OPENAI_BASE_URL or None,
                model=settings.LLM_MODEL,
            )

    def process_chat(
        self,
        db: Session,
        message: str,
        incident_id: Optional[str] = None,
    ) -> CopilotMessage:
        # 1. Save Analyst message
        analyst_id = f"msg-{int(datetime.utcnow().timestamp() * 1000)}"
        analyst_msg = CopilotMessageModel(
            id=analyst_id,
            role="analyst",
            content=message,
            timestamp=datetime.utcnow(),
            incident_id=incident_id,
        )
        db.add(analyst_msg)
        db.flush()

        # 2. Fetch context if incident_id provided
        incident = None
        evidence_logs = None
        if incident_id:
            incident = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
            if incident and incident.related_log_ids:
                evidence_logs = (
                    db.query(SecurityLogModel)
                    .filter(SecurityLogModel.id.in_(incident.related_log_ids[:8]))
                    .all()
                )

        # 3. Generate response via LLM or graceful fallback
        response: Optional[CopilotResponse] = None
        if self.llm_provider:
            try:
                response = self.llm_provider.generate_response(message, incident, evidence_logs)
            except Exception as e:
                # Log or note LLM error and fall back gracefully
                pass

        if not response:
            response = self.template_provider.generate_response(message, incident, evidence_logs)

        # 4. Save Copilot response message
        copilot_id = f"msg-{int(datetime.utcnow().timestamp() * 1000) + 1}"
        copilot_msg = CopilotMessageModel(
            id=copilot_id,
            role="copilot",
            content=response.lead_in,
            timestamp=datetime.utcnow(),
            incident_id=incident_id,
            response_lead_in=response.lead_in,
            response_event_count=response.event_count,
            response_observed_evidence=response.observed_evidence,
            response_ai_assessment=response.ai_assessment,
            response_recommended_next_steps=response.recommended_next_steps,
        )
        db.add(copilot_msg)
        db.commit()

        return CopilotMessage(
            id=copilot_msg.id,
            role=copilot_msg.role,
            content=copilot_msg.content,
            timestamp=copilot_msg.timestamp,
            incident_id=copilot_msg.incident_id,
            response=response,
        )

    def get_history(self, db: Session, incident_id: Optional[str] = None) -> List[CopilotMessage]:
        query = db.query(CopilotMessageModel)
        if incident_id:
            query = query.filter(
                (CopilotMessageModel.incident_id == incident_id) | (CopilotMessageModel.incident_id.is_(None))
            )
        msgs = query.order_by(CopilotMessageModel.timestamp.asc()).all()

        results: List[CopilotMessage] = []
        for m in msgs:
            resp = None
            if m.role == "copilot" and m.response_lead_in:
                resp = CopilotResponse(
                    lead_in=m.response_lead_in,
                    event_count=m.response_event_count,
                    observed_evidence=m.response_observed_evidence or [],
                    ai_assessment=m.response_ai_assessment or "",
                    recommended_next_steps=m.response_recommended_next_steps or [],
                )
            results.append(
                CopilotMessage(
                    id=m.id,
                    role=m.role,
                    content=m.content,
                    timestamp=m.timestamp,
                    incident_id=m.incident_id,
                    response=resp,
                )
            )
        return results


copilot_service = CopilotService()
