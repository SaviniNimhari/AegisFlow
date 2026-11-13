from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class FeatureAttribution(BaseModel):
    feature_name: str
    feature_value: float
    importance_score: float = Field(..., description="SHAP attribution value or weight contribution")
    impact_direction: str = Field(..., description="'increases_risk' | 'decreases_risk' | 'neutral'")
    human_readable: str = Field(..., description="Plain-language explanation for security analysts")


class AIEventAnalysisRequest(BaseModel):
    event_type: str = Field(default="auth_failure")
    source: str = Field(default="security_sensor")
    source_ip: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    username: str | None = None
    raw_log: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    asset_id: str | None = None
    event_id: str | None = None


class BatchAIAnalysisRequest(BaseModel):
    events: list[AIEventAnalysisRequest] = Field(..., min_length=1, max_length=100)


class AnalystFeedbackUpdate(BaseModel):
    analyst_feedback: str = Field(
        ..., description="One of: 'true_positive', 'false_positive', 'benign_suspicious'"
    )
    analyst_notes: str | None = None


class AIThreatPredictionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    risk_score: float
    risk_level: str
    anomaly_score: float
    threat_category: str
    model_name: str
    model_version: str
    feature_vector: dict[str, Any]
    shap_explanations: dict[str, Any]
    attributions: list[FeatureAttribution] = Field(default_factory=list)
    analyst_feedback: str
    analyst_notes: str | None = None
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None
    event_id: str | None = None
    alert_id: str | None = None
    asset_id: str | None = None
    created_at: datetime
    updated_at: datetime


class AIModelMetadata(BaseModel):
    model_name: str
    model_version: str
    algorithm: str
    feature_names: list[str]
    sample_count: int
    auc_roc: float
    accuracy: float
    status: str
    last_trained_at: str


class AIRiskSummary(BaseModel):
    total_predictions: int
    critical_risk_count: int
    high_risk_count: int
    medium_risk_count: int
    low_or_benign_count: int
    average_risk_score: float
    feedback_breakdown: dict[str, int]
