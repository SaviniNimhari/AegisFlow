from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class IncidentSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class IncidentStatus(StrEnum):
    NEW = "new"
    TRIAGED = "triaged"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERED = "recovered"
    CLOSED = "closed"


class IncidentCategory(StrEnum):
    MALWARE_INFECTION = "malware_infection"
    CREDENTIAL_COMPROMISE = "credential_compromise"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_EXFILTRATION = "data_exfiltration"
    DENIAL_OF_SERVICE = "denial_of_service"
    INSIDER_THREAT = "insider_threat"
    POLICY_VIOLATION = "policy_violation"


class Incident(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "incidents"

    incident_number: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(
        String(16), default=IncidentSeverity.MEDIUM.value, index=True, nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(20), default=IncidentStatus.NEW.value, index=True, nullable=False
    )
    category: Mapped[str] = mapped_column(
        String(64), default=IncidentCategory.UNAUTHORIZED_ACCESS.value, nullable=False
    )

    assigned_to: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lead_analyst: Mapped[str | None] = mapped_column(String(128), nullable=True)
    root_cause: Mapped[str | None] = mapped_column(Text, nullable=True)
    containment_actions: Mapped[str | None] = mapped_column(Text, nullable=True)
    lessons_learned: Mapped[str | None] = mapped_column(Text, nullable=True)
    sla_breach: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    asset_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    asset = relationship("Asset", lazy="joined")
    timeline_events = relationship(
        "IncidentTimeline",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentTimeline.timestamp.asc()",
    )
    comments = relationship(
        "IncidentComment",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentComment.created_at.asc()",
    )
    alerts = relationship(
        "SecurityAlert",
        backref="incident",
        lazy="selectin",
        foreign_keys="[SecurityAlert.incident_id]",
    )
    artifacts = relationship(
        "ForensicArtifact",
        backref="incident",
        lazy="selectin",
        foreign_keys="[ForensicArtifact.incident_id]",
    )

    def __repr__(self) -> str:
        return f"<Incident {self.incident_number} title='{self.title}' status={self.status}>"


class IncidentTimeline(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "incident_timeline"

    incident_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(128), default="AegisFlow Engine", nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    incident = relationship("Incident", back_populates="timeline_events")

    def __repr__(self) -> str:
        return f"<IncidentTimeline {self.event_type} on {self.incident_id[:8]}>"


class IncidentComment(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "incident_comments"

    incident_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    author: Mapped[str] = mapped_column(String(128), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)

    incident = relationship("Incident", back_populates="comments")

    def __repr__(self) -> str:
        return f"<IncidentComment by {self.author} on {self.incident_id[:8]}>"
