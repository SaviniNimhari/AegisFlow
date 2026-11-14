from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ExecutiveReportRequest(BaseModel):
    title: str | None = Field(default=None, max_length=255)
    time_window_days: int = Field(default=30, ge=1, le=365)
    include_compliance_summary: bool = True
    include_ai_intelligence: bool = True


class IncidentPostmortemRequest(BaseModel):
    incident_id: str
    include_timeline: bool = True
    include_forensics: bool = True
    executive_summary: str | None = None
    root_cause_analysis: str | None = None
    corrective_actions: list[str] | None = None


class SecurityReportResponse(BaseModel):
    id: str
    report_type: str
    title: str
    summary: str
    posture_score: float | None = None
    incident_id: str | None = None
    generated_by_id: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    content: dict[str, Any] = Field(default_factory=dict)
    rendered_html: str | None = None
    rendered_markdown: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SecurityPostureOverview(BaseModel):
    posture_score: float = Field(ge=0.0, le=100.0)
    posture_grade: str
    total_assets: int
    vulnerabilities_count: dict[str, int]
    open_incidents_count: int
    critical_incidents_count: int
    total_alerts_count: int
    mean_time_to_detect_hours: float
    mean_time_to_remediate_hours: float
    mitre_tactics_breakdown: list[dict[str, Any]]
    ai_anomalies_count: int
    compliance_scores: dict[str, float]
