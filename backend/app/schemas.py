from pydantic import BaseModel, Field
from typing import Literal

class ScanRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    plan_path: str = Field(min_length=1, max_length=1000)

class FindingStatusUpdate(BaseModel):
    status: Literal["open", "in_progress", "accepted_risk", "resolved"]

class ExplainResponse(BaseModel):
    finding_id: str
    explanation: str
    evidence: str
    proposed_fix: str
    requires_approval: bool = True
