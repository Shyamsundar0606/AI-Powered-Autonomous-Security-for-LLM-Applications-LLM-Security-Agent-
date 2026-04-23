from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AnalyzeRequest(BaseModel):
    input: str = Field(..., min_length=1, max_length=5000, description="Prompt text to analyze.")


class AnalyzeResponse(BaseModel):
    risk_score: int
    label: str
    reason: str
    safe_response: str


class AttackTestRequest(BaseModel):
    topic: str | None = Field(default=None, max_length=200)
    count: int = Field(default=3, ge=1, le=10)


class AttackTestResponse(BaseModel):
    attacks: list[str]


class LogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_input: str
    risk_score: int
    label: str
    reason: str
    created_at: datetime


class PaginatedLogsResponse(BaseModel):
    items: list[LogResponse]
    page: int
    page_size: int
    total: int
    total_pages: int


class LabelStatsResponse(BaseModel):
    SAFE: int
    SUSPICIOUS: int
    MALICIOUS: int


class AdminStatsResponse(BaseModel):
    total_requests: int
    labels: LabelStatsResponse
    average_risk_score: float
