from math import ceil

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.core.permissions import require_admin, require_analyst, require_authenticated
from backend.app.database.session import get_db
from backend.app.models.asset import AssetCriticality, AssetEnvironment, AssetStatus, AssetType
from backend.app.models.user import User
from backend.app.schemas.asset import (
    AssetCreate,
    AssetListResponse,
    AssetResponse,
    AssetStatsResponse,
    AssetUpdate,
)
from backend.app.services.asset_service import AssetService

router = APIRouter(prefix="/assets", tags=["Asset Inventory & Attack Surface"])


@router.get(
    "/stats",
    response_model=AssetStatsResponse,
    summary="Get asset inventory summary statistics"
)
def get_asset_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated),
):
    """Return high-level metrics for dashboard (total assets, active, critical count, breakdowns)."""
    stats = AssetService.get_statistics(db)
    return stats


@router.get(
    "",
    response_model=AssetListResponse,
    summary="List, search, and filter registered digital assets"
)
def list_assets(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    search: str | None = Query(None, description="Search term for name, IP, hostname, or description"),
    asset_type: AssetType | None = Query(None, description="Filter by asset type"),
    criticality: AssetCriticality | None = Query(None, description="Filter by criticality level"),
    status_filter: AssetStatus | None = Query(None, alias="status", description="Filter by operational status"),
    environment: AssetEnvironment | None = Query(None, description="Filter by deployment environment"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated),
):
    """Retrieve paginated assets with multi-parameter filtering and keyword search."""
    skip = (page - 1) * limit
    type_val = asset_type.value if asset_type else None
    crit_val = criticality.value if criticality else None
    stat_val = status_filter.value if status_filter else None
    env_val = environment.value if environment else None

    items, total = AssetService.list_assets(
        db=db,
        skip=skip,
        limit=limit,
        search=search,
        asset_type=type_val,
        criticality=crit_val,
        status=stat_val,
        environment=env_val,
    )

    total_pages = ceil(total / limit) if total > 0 else 1

    return AssetListResponse(
        items=[AssetResponse.model_validate(item) for item in items],
        total=total,
        page=page,
        limit=limit,
        total_pages=total_pages,
    )


@router.post(
    "",
    response_model=AssetResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new authorized asset (Analyst / Admin)"
)
def create_asset(
    asset_in: AssetCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Register a new digital asset in the platform inventory."""
    if asset_in.ip_address and AssetService.get_by_ip(db, asset_in.ip_address):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"An asset with IP address {asset_in.ip_address} is already registered."
        )

    asset = AssetService.create_asset(db, asset_in)
    return asset


@router.get(
    "/{asset_id}",
    response_model=AssetResponse,
    summary="Get asset details by ID"
)
def get_asset(
    asset_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated),
):
    """Retrieve detailed metadata, open ports, and configuration of an asset."""
    asset = AssetService.get_by_id(db, asset_id)
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found."
        )
    return asset


@router.put(
    "/{asset_id}",
    response_model=AssetResponse,
    summary="Update asset details (Analyst / Admin)"
)
def update_asset(
    asset_id: str,
    asset_in: AssetUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Update asset specifications, operating system, network ports, or status."""
    asset = AssetService.get_by_id(db, asset_id)
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found."
        )

    if asset_in.ip_address and asset_in.ip_address != asset.ip_address:
        existing = AssetService.get_by_ip(db, asset_in.ip_address)
        if existing and existing.id != asset.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"An asset with IP address {asset_in.ip_address} already exists."
            )

    updated = AssetService.update_asset(db, asset, asset_in)
    return updated


@router.delete(
    "/{asset_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an asset from inventory (Admin only)"
)
def delete_asset(
    asset_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Permanently remove an asset from the inventory. Restricted to Administrators."""
    asset = AssetService.get_by_id(db, asset_id)
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found."
        )
    AssetService.delete_asset(db, asset)
    return None
