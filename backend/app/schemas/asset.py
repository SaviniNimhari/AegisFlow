from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from backend.app.models.asset import (
    AssetCriticality,
    AssetEnvironment,
    AssetStatus,
    AssetType,
)


class PortInfo(BaseModel):
    port: int = Field(..., ge=1, le=65535)
    service: str | None = Field(None, max_length=64)
    protocol: str = Field("tcp", max_length=16)
    state: str = Field("open", max_length=16)


class AssetBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    hostname: str | None = Field(None, max_length=255)
    ip_address: str | None = Field(None, max_length=45)
    mac_address: str | None = Field(None, max_length=17, pattern=r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
    asset_type: AssetType = AssetType.SERVER
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    status: AssetStatus = AssetStatus.ACTIVE
    environment: AssetEnvironment = AssetEnvironment.PRODUCTION
    os_family: str | None = Field(None, max_length=64)
    os_version: str | None = Field(None, max_length=64)
    open_ports: list[PortInfo] | None = Field(default_factory=list)
    tags: list[str] | None = Field(default_factory=list)
    description: str | None = None
    owner: str | None = Field(None, max_length=128)


class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=128)
    hostname: str | None = Field(None, max_length=255)
    ip_address: str | None = Field(None, max_length=45)
    mac_address: str | None = Field(None, max_length=17, pattern=r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
    asset_type: AssetType | None = None
    criticality: AssetCriticality | None = None
    status: AssetStatus | None = None
    environment: AssetEnvironment | None = None
    os_family: str | None = Field(None, max_length=64)
    os_version: str | None = Field(None, max_length=64)
    open_ports: list[PortInfo] | None = None
    tags: list[str] | None = None
    description: str | None = None
    owner: str | None = Field(None, max_length=128)
    last_seen_at: datetime | None = None


class AssetResponse(BaseModel):
    id: str
    name: str
    hostname: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    asset_type: str
    criticality: str
    status: str
    environment: str
    os_family: str | None = None
    os_version: str | None = None
    open_ports: list[dict[str, Any]] | None = None
    tags: list[str] | None = None
    description: str | None = None
    owner: str | None = None
    last_seen_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AssetListResponse(BaseModel):
    items: list[AssetResponse]
    total: int
    page: int
    limit: int
    total_pages: int


class AssetStatsResponse(BaseModel):
    total_assets: int
    active_assets: int
    critical_assets: int
    high_risk_assets: int
    by_type: dict[str, int]
    by_environment: dict[str, int]
    by_criticality: dict[str, int]
