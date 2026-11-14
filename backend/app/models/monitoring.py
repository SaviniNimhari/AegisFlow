from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class EventType(StrEnum):
    AUTH_FAILURE = "auth_failure"
    AUTH_SUCCESS = "auth_success"
    NETWORK_CONNECTION = "network_connection"
    FILE_ACCESS = "file_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SYSTEM_COMMAND = "system_command"
    MALWARE_INDICATOR = "malware_indicator"


class AlertSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(StrEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"
    ESCALATED = "escalated"


class SecurityEvent(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "security_events"

    event_type: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    username: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)

    asset_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("assets.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    incident_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("incidents.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )

    raw_log: Mapped[str | None] = mapped_column(Text, nullable=True)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=dict, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        index=True,
        nullable=False
    )

    # Relationship to asset
    asset = relationship("Asset", backref="security_events")

    def __repr__(self) -> str:
        return f"<SecurityEvent id={self.id} type={self.event_type} src={self.source_ip} user={self.username}>"


class DetectionRule(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "detection_rules"

    name: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    rule_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), default=AlertSeverity.MEDIUM.value, nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    condition_config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    mitre_attack_id: Mapped[str | None] = mapped_column(String(32), nullable=True)

    def __repr__(self) -> str:
        return f"<DetectionRule name={self.name} severity={self.severity} enabled={self.is_enabled}>"


class SecurityAlert(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "security_alerts"

    title: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(
        String(16),
        default=AlertSeverity.MEDIUM.value,
        index=True,
        nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(20),
        default=AlertStatus.OPEN.value,
        index=True,
        nullable=False
    )
    confidence_score: Mapped[float] = mapped_column(Float, default=0.85, nullable=False)

    rule_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("detection_rules.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    rule_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    mitre_attack_id: Mapped[str | None] = mapped_column(String(32), nullable=True)

    source_ip: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    target_user: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)

    asset_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("assets.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    incident_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("incidents.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )

    evidence: Mapped[dict[str, Any] | None] = mapped_column(JSON, default=dict, nullable=True)
    assigned_to: Mapped[str | None] = mapped_column(String(128), nullable=True)
    resolution_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    rule = relationship("DetectionRule", backref="alerts")
    asset = relationship("Asset", backref="alerts")

    def __repr__(self) -> str:
        return f"<SecurityAlert id={self.id} title={self.title} severity={self.severity} status={self.status}>"
