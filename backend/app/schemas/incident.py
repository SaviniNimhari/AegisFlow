from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class IncidentTimelineResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    incident_id: str
    event_type: str
    description: str
    source: str
    timestamp: datetime


class IncidentCommentCreate(BaseModel):
    content: str = Field(..., min_length=1, description="Analyst investigation notes or findings")


class IncidentCommentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    incident_id: str
    author: str
    content: str
    created_at: datetime


class IncidentCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=255)
    description: str = Field(..., min_length=5)
    severity: str = Field(default="medium", description="critical, high, medium, low")
    category: str = Field(default="unauthorized_access")
    assigned_to: str | None = None
    asset_id: str | None = None
    alert_ids: list[str] = Field(default_factory=list)
    artifact_ids: list[str] = Field(default_factory=list)


class IncidentUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    severity: str | None = None
    status: str | None = None
    category: str | None = None
    assigned_to: str | None = None
    lead_analyst: str | None = None
    root_cause: str | None = None
    containment_actions: str | None = None
    lessons_learned: str | None = None
    sla_breach: bool | None = None


class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    incident_number: str
    title: str
    description: str
    severity: str
    status: str
    category: str
    assigned_to: str | None = None
    lead_analyst: str | None = None
    root_cause: str | None = None
    containment_actions: str | None = None
    lessons_learned: str | None = None
    sla_breach: bool
    asset_id: str | None = None
    created_at: datetime
    updated_at: datetime
    closed_at: datetime | None = None

    alert_count: int = 0
    artifact_count: int = 0
    timeline_events: list[IncidentTimelineResponse] = Field(default_factory=list)
    comments: list[IncidentCommentResponse] = Field(default_factory=list)


class IncidentListResponse(BaseModel):
    items: list[IncidentResponse]
    total: int


class CorrelationTriggerResponse(BaseModel):
    incidents_created: int
    alerts_correlated: int
    incident_ids: list[str] = Field(default_factory=list)


class LinkAlertRequest(BaseModel):
    alert_id: str


class LinkArtifactRequest(BaseModel):
    artifact_id: str


class IncidentStatsResponse(BaseModel):
    total_incidents: int
    open_incidents: int
    critical_count: int
    in_containment_count: int
    closed_count: int
    average_resolution_hours: float
