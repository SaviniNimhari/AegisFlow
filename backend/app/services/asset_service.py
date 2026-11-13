from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from backend.app.models.asset import Asset, AssetCriticality, AssetStatus
from backend.app.schemas.asset import AssetCreate, AssetUpdate


class AssetService:
    @staticmethod
    def get_by_id(db: Session, asset_id: str) -> Asset | None:
        return db.get(Asset, asset_id)

    @staticmethod
    def get_by_ip(db: Session, ip_address: str) -> Asset | None:
        stmt = select(Asset).where(Asset.ip_address == ip_address.strip())
        return db.scalars(stmt).first()

    @staticmethod
    def get_by_name(db: Session, name: str) -> Asset | None:
        stmt = select(Asset).where(Asset.name == name.strip())
        return db.scalars(stmt).first()

    @classmethod
    def create_asset(cls, db: Session, asset_in: AssetCreate) -> Asset:
        ports_data = (
            [p.model_dump() for p in asset_in.open_ports]
            if asset_in.open_ports is not None
            else []
        )
        asset = Asset(
            name=asset_in.name.strip(),
            hostname=asset_in.hostname.strip() if asset_in.hostname else None,
            ip_address=asset_in.ip_address.strip() if asset_in.ip_address else None,
            mac_address=asset_in.mac_address.strip() if asset_in.mac_address else None,
            asset_type=asset_in.asset_type.value,
            criticality=asset_in.criticality.value,
            status=asset_in.status.value,
            environment=asset_in.environment.value,
            os_family=asset_in.os_family,
            os_version=asset_in.os_version,
            open_ports=ports_data,
            tags=asset_in.tags or [],
            description=asset_in.description,
            owner=asset_in.owner,
            last_seen_at=datetime.now(UTC),
        )
        db.add(asset)
        db.commit()
        db.refresh(asset)
        return asset

    @classmethod
    def update_asset(cls, db: Session, asset: Asset, asset_in: AssetUpdate) -> Asset:
        update_data = asset_in.model_dump(exclude_unset=True)

        if "open_ports" in update_data and update_data["open_ports"] is not None:
            update_data["open_ports"] = [
                p.model_dump() if hasattr(p, "model_dump") else p
                for p in update_data["open_ports"]
            ]

        for field, value in update_data.items():
            if hasattr(value, "value"):
                value = value.value
            setattr(asset, field, value)

        db.commit()
        db.refresh(asset)
        return asset

    @classmethod
    def delete_asset(cls, db: Session, asset: Asset) -> None:
        db.delete(asset)
        db.commit()

    @classmethod
    def list_assets(
        cls,
        db: Session,
        skip: int = 0,
        limit: int = 50,
        search: str | None = None,
        asset_type: str | None = None,
        criticality: str | None = None,
        status: str | None = None,
        environment: str | None = None,
    ) -> tuple[list[Asset], int]:
        stmt = select(Asset)

        if search:
            term = f"%{search.strip().lower()}%"
            stmt = stmt.where(
                or_(
                    func.lower(Asset.name).like(term),
                    func.lower(Asset.hostname).like(term),
                    func.lower(Asset.ip_address).like(term),
                    func.lower(Asset.description).like(term),
                )
            )

        if asset_type:
            stmt = stmt.where(Asset.asset_type == asset_type)
        if criticality:
            stmt = stmt.where(Asset.criticality == criticality)
        if status:
            stmt = stmt.where(Asset.status == status)
        if environment:
            stmt = stmt.where(Asset.environment == environment)

        # Count total matching query
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = db.scalar(count_stmt) or 0

        # Apply ordering and pagination
        stmt = stmt.order_by(Asset.created_at.desc()).offset(skip).limit(limit)
        items = list(db.scalars(stmt).all())

        return items, total

    @classmethod
    def get_statistics(cls, db: Session) -> dict[str, Any]:
        total_assets = db.scalar(select(func.count(Asset.id))) or 0
        active_assets = db.scalar(
            select(func.count(Asset.id)).where(Asset.status == AssetStatus.ACTIVE.value)
        ) or 0
        critical_assets = db.scalar(
            select(func.count(Asset.id)).where(Asset.criticality == AssetCriticality.CRITICAL.value)
        ) or 0
        high_risk_assets = db.scalar(
            select(func.count(Asset.id)).where(
                or_(
                    Asset.criticality == AssetCriticality.CRITICAL.value,
                    Asset.criticality == AssetCriticality.HIGH.value,
                )
            )
        ) or 0

        # Group by type
        by_type_rows = db.execute(
            select(Asset.asset_type, func.count(Asset.id)).group_by(Asset.asset_type)
        ).all()
        by_type = {row[0]: row[1] for row in by_type_rows}

        # Group by environment
        by_env_rows = db.execute(
            select(Asset.environment, func.count(Asset.id)).group_by(Asset.environment)
        ).all()
        by_environment = {row[0]: row[1] for row in by_env_rows}

        # Group by criticality
        by_crit_rows = db.execute(
            select(Asset.criticality, func.count(Asset.id)).group_by(Asset.criticality)
        ).all()
        by_criticality = {row[0]: row[1] for row in by_crit_rows}

        return {
            "total_assets": total_assets,
            "active_assets": active_assets,
            "critical_assets": critical_assets,
            "high_risk_assets": high_risk_assets,
            "by_type": by_type,
            "by_environment": by_environment,
            "by_criticality": by_criticality,
        }
