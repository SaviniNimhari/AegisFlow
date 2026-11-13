from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import JSON, DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class AssetType(StrEnum):
    SERVER = "server"
    WORKSTATION = "workstation"
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    CLOUD_INSTANCE = "cloud_instance"
    IOT = "iot"
    OTHER = "other"


class AssetCriticality(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AssetStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DECOMMISSIONED = "decommissioned"
    MAINTENANCE = "maintenance"


class AssetEnvironment(StrEnum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    DMZ = "dmz"
    INTERNAL = "internal"


class Asset(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "assets"

    name: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255), index=True, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), index=True, nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)

    asset_type: Mapped[str] = mapped_column(
        String(32),
        default=AssetType.SERVER.value,
        nullable=False,
        index=True
    )
    criticality: Mapped[str] = mapped_column(
        String(16),
        default=AssetCriticality.MEDIUM.value,
        nullable=False,
        index=True
    )
    status: Mapped[str] = mapped_column(
        String(16),
        default=AssetStatus.ACTIVE.value,
        nullable=False,
        index=True
    )
    environment: Mapped[str] = mapped_column(
        String(32),
        default=AssetEnvironment.PRODUCTION.value,
        nullable=False,
        index=True
    )

    os_family: Mapped[str | None] = mapped_column(String(64), nullable=True)
    os_version: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Structured metadata: ports, services, tags
    open_ports: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, default=list, nullable=True)
    tags: Mapped[list[str] | None] = mapped_column(JSON, default=list, nullable=True)

    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self) -> str:
        return f"<Asset id={self.id} name={self.name} ip={self.ip_address} type={self.asset_type}>"
