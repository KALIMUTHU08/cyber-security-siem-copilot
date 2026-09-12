from abc import ABC, abstractmethod
from typing import List, Optional
from app.schemas.copilot import CopilotResponse
from app.models.incident import IncidentModel
from app.models.log import SecurityLogModel


class LLMProvider(ABC):
    @abstractmethod
    def generate_response(
        self,
        question: str,
        incident: Optional[IncidentModel] = None,
        evidence_logs: Optional[List[SecurityLogModel]] = None,
    ) -> CopilotResponse:
        pass
