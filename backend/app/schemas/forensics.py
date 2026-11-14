from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ChainOfCustodyLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    artifact_id: str
    action: str
    performed_by: str
    details: str | None = None
    sha256_at_action: str
    timestamp: datetime


class ForensicArtifactResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    filename: str
    original_path: str | None = None
    file_size_bytes: int
    mime_type: str
    magic_header: str | None = None
    sha256: str
    md5: str
    sha1: str
    entropy: float
    verdict: str
    severity: str
    extracted_strings_sample: dict[str, Any] = Field(default_factory=dict)
    yara_matches: list[dict[str, Any]] = Field(default_factory=list)
    asset_id: str | None = None
    uploaded_by: str
    created_at: datetime
    updated_at: datetime
    custody_logs: list[ChainOfCustodyLogResponse] = Field(default_factory=list)


class ArtifactListResponse(BaseModel):
    items: list[ForensicArtifactResponse]
    total: int


class ArtifactTextAnalyzeRequest(BaseModel):
    filename: str = Field(default="payload_snippet.txt", min_length=1, max_length=255)
    content: str = Field(..., min_length=1, description="Raw text, script, or base64 to analyze")
    asset_id: str | None = None


class CustodyVerificationRequest(BaseModel):
    action: str = Field(default="verified", description="Action performed, e.g. 'verified', 'transferred'")
    details: str | None = Field(default=None, description="Custody transfer notes or verification observation")


class YaraRuleCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=128)
    rule_source: str = Field(..., min_length=10, description="Valid YARA rule source text")
    description: str | None = None
    threat_type: str = Field(default="malware", max_length=64)
    severity: str = Field(default="high", max_length=32)


class YaraRuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    rule_source: str
    description: str | None = None
    threat_type: str
    severity: str
    is_enabled: bool
    author: str | None = None
    created_at: datetime


class ForensicStatsResponse(BaseModel):
    total_artifacts: int
    malicious_count: int
    suspicious_count: int
    benign_count: int
    average_entropy: float
    total_yara_rules: int
