from enum import StrEnum
from typing import Any

from sqlalchemy import Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from backend.app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

# Use JSONB for Postgres when available, JSON otherwise (e.g. SQLite tests)
JSONType = JSON().with_variant(JSONB, "postgresql")


class ReportType(StrEnum):
    EXECUTIVE_POSTURE = "executive_posture"
    INCIDENT_POSTMORTEM = "incident_postmortem"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    FORENSICS_SUMMARY = "forensics_summary"


class ReportFormat(StrEnum):
    JSON = "json"
    HTML = "html"
    MARKDOWN = "markdown"


class SecurityReport(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "security_reports"

    report_type: Mapped[str] = mapped_column(
        String(32), default=ReportType.EXECUTIVE_POSTURE.value, index=True, nullable=False
    )
    title: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    posture_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    incident_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True
    )
    generated_by_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    parameters: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)
    content: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)
    rendered_html: Mapped[str | None] = mapped_column(Text, nullable=True)
    rendered_markdown: Mapped[str | None] = mapped_column(Text, nullable=True)

    incident = relationship("Incident", lazy="joined")
    generated_by = relationship("User", lazy="joined")
