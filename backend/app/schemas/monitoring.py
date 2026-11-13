from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from backend.app.models.monitoring import AlertSeverity, AlertStatus, EventType


class SecurityEventBase(BaseModel):
    event_type: EventType
    source: str = Field(..., min_length=1, max_length=64)
    source_ip: str | None = Field(None, max_length=45)
    source_port: int | None = Field(None, ge=1, le=65535)
    destination_ip: str | None = Field(None, max_length=45)
    destination_port: int | None = Field(None, ge=1, le=65535)
    username: str | None = Field(None, max_length=64)
    asset_id: str | None = None
    raw_log: str | None = None
    details: dict[str, Any] | None = Field(default_factory=dict)
    timestamp: datetime | None = None


class SecurityEventCreate(SecurityEventBase):
    pass


class SecurityEventResponse(SecurityEventBase):
    id: str
    timestamp: datetime
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class EventListResponse(BaseModel):
    items: list[SecurityEventResponse]
    total: int
    page: int
    limit: int
    total_pages: int


class DetectionRuleBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    description: str | None = None
    rule_type: str = Field(..., min_length=2, max_length=32)
    severity: AlertSeverity = AlertSeverity.MEDIUM
    is_enabled: bool = True
    condition_config: dict[str, Any] = Field(default_factory=dict)
    mitre_attack_id: str | None = Field(None, max_length=32)


class DetectionRuleCreate(DetectionRuleBase):
    pass


class DetectionRuleResponse(DetectionRuleBase):
    id: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SecurityAlertBase(BaseModel):
    title: str = Field(..., min_length=2, max_length=255)
    description: str | None = None
    severity: AlertSeverity = AlertSeverity.MEDIUM
    status: AlertStatus = AlertStatus.OPEN
    confidence_score: float = Field(0.85, ge=0.0, le=1.0)
    rule_id: str | None = None
    rule_name: str | None = None
    mitre_attack_id: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    target_user: str | None = None
    asset_id: str | None = None
    evidence: dict[str, Any] | None = Field(default_factory=dict)
    assigned_to: str | None = None
    resolution_notes: str | None = None


class SecurityAlertUpdate(BaseModel):
    status: AlertStatus | None = None
    assigned_to: str | None = None
    resolution_notes: str | None = None


class SecurityAlertResponse(SecurityAlertBase):
    id: str
    resolved_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AlertListResponse(BaseModel):
    items: list[SecurityAlertResponse]
    total: int
    page: int
    limit: int
    total_pages: int


class EventIngestResponse(BaseModel):
    events_ingested: int
    alerts_triggered: int
    alerts: list[SecurityAlertResponse]


class AlertStatsResponse(BaseModel):
    total_alerts: int
    open_alerts: int
    critical_alerts: int
    high_alerts: int
    investigating_alerts: int
    resolved_alerts: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    top_mitre_tactics: dict[str, int]
