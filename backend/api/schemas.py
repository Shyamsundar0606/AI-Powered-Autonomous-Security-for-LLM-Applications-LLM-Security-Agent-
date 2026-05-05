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
    attack_type: str
    incident_status: str
    incident_notes: str
    created_at: datetime
    updated_at: datetime | None = None


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


class TrendPointResponse(BaseModel):
    date: str
    total: int
    SAFE: int
    SUSPICIOUS: int
    MALICIOUS: int


class AttackDistributionEntryResponse(BaseModel):
    count: int
    percentage: float


class AttackDistributionResponse(BaseModel):
    total: int
    distribution: dict[str, AttackDistributionEntryResponse]


class AttackTypeEntryResponse(BaseModel):
    type: str
    count: int


class RiskBucketResponse(BaseModel):
    range: str
    count: int


class AdminAnalyticsResponse(BaseModel):
    trends: list[TrendPointResponse]
    distribution: AttackDistributionResponse
    attack_types: list[AttackTypeEntryResponse]
    histogram: list[RiskBucketResponse]


class IncidentUpdateRequest(BaseModel):
    incident_status: str = Field(..., min_length=2, max_length=32)
    incident_notes: str = Field(default="", max_length=1000)


class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source_log_id: int
    prompt_summary: str
    attack_type: str
    label: str
    risk_score: int
    severity: str
    status: str
    assignee: str
    notes: str
    repeated_count: int
    alert_count: int
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None = None


class PaginatedIncidentsResponse(BaseModel):
    items: list[IncidentResponse]
    page: int
    page_size: int
    total: int
    total_pages: int


class IncidentTimelineEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    incident_id: int
    event_type: str
    previous_status: str | None = None
    new_status: str | None = None
    previous_severity: str | None = None
    new_severity: str | None = None
    actor: str
    notes: str
    created_at: datetime


class IncidentTimelineResponse(BaseModel):
    incident_id: int
    events: list[IncidentTimelineEventResponse]


class IncidentPatchRequest(BaseModel):
    status: str | None = Field(default=None, min_length=2, max_length=32)
    severity: str | None = Field(default=None, min_length=2, max_length=16)
    assignee: str | None = Field(default=None, max_length=128)
    notes: str | None = Field(default=None, max_length=2000)
