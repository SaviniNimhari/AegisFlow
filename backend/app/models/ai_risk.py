from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, DateTime, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AIRiskLevel(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    BENIGN = "benign"


class AIThreatCategory(StrEnum):
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"
    CREDENTIAL_ACCESS = "credential_access"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ABUSE = "privilege_abuse"
    COMMAND_CONTROL = "command_control"


class AnalystFeedback(StrEnum):
    UNREVIEWED = "unreviewed"
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN_SUSPICIOUS = "benign_suspicious"


class AIThreatPrediction(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "ai_threat_predictions"

    risk_score: Mapped[float] = mapped_column(Float, index=True, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    threat_category: Mapped[str] = mapped_column(
        String(64), default=AIThreatCategory.ANOMALOUS_BEHAVIOR.value, nullable=False
    )
    model_name: Mapped[str] = mapped_column(String(64), default="AegisFlow-Ensemble-v1", nullable=False)
    model_version: Mapped[str] = mapped_column(String(32), default="1.0.0", nullable=False)

    feature_vector: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    shap_explanations: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    analyst_feedback: Mapped[str] = mapped_column(
        String(32), default=AnalystFeedback.UNREVIEWED.value, index=True, nullable=False
    )
    analyst_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    event_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("security_events.id", ondelete="SET NULL"), nullable=True, index=True
    )
    alert_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("security_alerts.id", ondelete="SET NULL"), nullable=True, index=True
    )
    asset_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Relationships
    event = relationship("SecurityEvent", foreign_keys=[event_id], lazy="joined")
    alert = relationship("SecurityAlert", foreign_keys=[alert_id], lazy="joined")
    asset = relationship("Asset", foreign_keys=[asset_id], lazy="joined")

    def __repr__(self) -> str:
        return f"<AIThreatPrediction {self.id} (Score={self.risk_score:.2f}, Level={self.risk_level})>"
