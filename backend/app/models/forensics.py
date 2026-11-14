from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ForensicVerdict(StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class CustodyAction(StrEnum):
    COLLECTED = "collected"
    ACQUIRED = "acquired"
    ANALYZED = "analyzed"
    VERIFIED = "verified"
    TRANSFERRED = "transferred"
    DISPOSED = "disposed"


class ForensicArtifact(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "forensic_artifacts"

    filename: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    original_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    file_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    mime_type: Mapped[str] = mapped_column(String(128), default="application/octet-stream", nullable=False)
    magic_header: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Cryptographic hashes for chain of custody and threat lookup
    sha256: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    md5: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    sha1: Mapped[str] = mapped_column(String(40), nullable=False)

    entropy: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    verdict: Mapped[str] = mapped_column(
        String(32), default=ForensicVerdict.UNKNOWN.value, index=True, nullable=False
    )
    severity: Mapped[str] = mapped_column(String(32), default="info", index=True, nullable=False)

    # Static analysis findings
    extracted_strings_sample: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    yara_matches: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)

    # Metadata & Relations
    asset_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    uploaded_by: Mapped[str] = mapped_column(String(128), nullable=False)

    # Relationships
    asset = relationship("Asset", lazy="joined")
    custody_logs = relationship(
        "ChainOfCustodyLog",
        back_populates="artifact",
        cascade="all, delete-orphan",
        order_by="ChainOfCustodyLog.timestamp.asc()",
    )

    def __repr__(self) -> str:
        return f"<ForensicArtifact {self.filename} ({self.sha256[:12]}..., Verdict={self.verdict})>"


class ChainOfCustodyLog(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "chain_of_custody_logs"

    artifact_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("forensic_artifacts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    performed_by: Mapped[str] = mapped_column(String(128), nullable=False)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    sha256_at_action: Mapped[str] = mapped_column(String(64), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )

    artifact = relationship("ForensicArtifact", back_populates="custody_logs")

    def __repr__(self) -> str:
        return f"<ChainOfCustodyLog {self.action} on {self.artifact_id[:8]} by {self.performed_by}>"


class YaraRule(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "yara_rules"

    name: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    rule_source: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    threat_type: Mapped[str] = mapped_column(String(64), default="malware", nullable=False)
    severity: Mapped[str] = mapped_column(String(32), default="high", nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    author: Mapped[str | None] = mapped_column(String(128), default="AegisFlow SOC Team", nullable=True)

    def __repr__(self) -> str:
        return f"<YaraRule {self.name} (Threat={self.threat_type}, Enabled={self.is_enabled})>"
