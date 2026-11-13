from math import ceil

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.core.permissions import require_analyst, require_authenticated
from backend.app.database.session import get_db
from backend.app.models.user import User
from backend.app.models.vulnerability import RemediationStatus, VulnerabilitySeverity
from backend.app.schemas.vulnerability import (
    AssetVulnerabilityResponse,
    AssetVulnerabilityUpdate,
    FindingListResponse,
    VulnerabilityCreate,
    VulnerabilityListResponse,
    VulnerabilityResponse,
    VulnerabilityScanResult,
    VulnerabilityStatsResponse,
    VulnerabilityUpdate,
)
from backend.app.services.asset_service import AssetService
from backend.app.services.vuln_service import VulnerabilityService

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerability Management & CVEs"])


@router.get(
    "/stats",
    response_model=VulnerabilityStatsResponse,
    summary="Get vulnerability management metrics and remediation posture"
)
def get_vulnerability_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated),
):
    """Retrieve high-level CVE counts, open findings, unpatched criticals, and CISA KEV count."""
    return VulnerabilityService.get_statistics(db)


@router.get(
    "",
    response_model=VulnerabilityListResponse,
    summary="List, search, and filter known CVEs & vulnerability definitions"
)
def list_vulnerabilities(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    search: str | None = Query(None, description="Search term for CVE, title, component, or description"),
    severity: VulnerabilitySeverity | None = Query(None, description="Filter by CVSS severity level"),
    component: str | None = Query(None, description="Filter by affected software/package component"),
    is_exploited: bool | None = Query(None, description="Filter by actively exploited in the wild (CISA KEV)"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated),
):
    """Retrieve paginated vulnerability catalog with multi-factor filtering."""
    skip = (page - 1) * limit
    sev_val = severity.value if severity else None

    items, total = VulnerabilityService.list_vulnerabilities(
        db=db,
        skip=skip,
        limit=limit,
        search=search,
        severity=sev_val,
        component=component,
        is_exploited=is_exploited,
    )

    total_pages = ceil(total / limit) if total > 0 else 1

    return VulnerabilityListResponse(
        items=[VulnerabilityResponse.model_validate(item) for item in items],
        total=total,
        page=page,
        limit=limit,
        total_pages=total_pages,
    )


@router.post(
    "",
    response_model=VulnerabilityResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest or create a vulnerability/CVE definition (Analyst / Admin)"
)
def create_vulnerability(
    vuln_in: VulnerabilityCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Ingest a new CVE advisory with CVSS score and component version matching patterns."""
    if vuln_in.cve_id and VulnerabilityService.get_by_cve(db, vuln_in.cve_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Vulnerability advisory with identifier {vuln_in.cve_id} already exists."
        )

    vuln = VulnerabilityService.create_vulnerability(db, vuln_in)
    return vuln


@router.get(
    "/findings/all",
    response_model=FindingListResponse,
    summary="List asset vulnerability findings across the entire platform"
)
def list_asset_findings(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    asset_id: str | None = Query(None, description="Filter findings for a specific asset"),
    finding_status: RemediationStatus | None = Query(None, alias="status", description="Filter by status"),
    severity: VulnerabilitySeverity | None = Query(None, description="Filter by severity"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated),
):
    """Retrieve tracked asset vulnerabilities with remediation status and assignment."""
    skip = (page - 1) * limit
    stat_val = finding_status.value if finding_status else None
    sev_val = severity.value if severity else None

    findings, total = VulnerabilityService.list_findings(
        db=db,
        skip=skip,
        limit=limit,
        asset_id=asset_id,
        status=stat_val,
        severity=sev_val,
    )

    total_pages = ceil(total / limit) if total > 0 else 1

    formatted_items = []
    for f in findings:
        formatted_items.append(
            AssetVulnerabilityResponse(
                id=f.id,
                asset_id=f.asset_id,
                vulnerability_id=f.vulnerability_id,
                status=f.status,
                detected_version=f.detected_version,
                detected_port=f.detected_port,
                detected_at=f.detected_at,
                resolved_at=f.resolved_at,
                remediation_notes=f.remediation_notes,
                assigned_to=f.assigned_to,
                created_at=f.created_at,
                updated_at=f.updated_at,
                asset_name=f.asset.name if f.asset else None,
                vulnerability=VulnerabilityResponse.model_validate(f.vulnerability) if f.vulnerability else None,
            )
        )

    return FindingListResponse(
        items=formatted_items,
        total=total,
        page=page,
        limit=limit,
        total_pages=total_pages,
    )


@router.post(
    "/scan/{asset_id}",
    response_model=VulnerabilityScanResult,
    summary="Trigger a vulnerability assessment scan on an asset (Analyst / Admin)"
)
def scan_asset(
    asset_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Inspect asset services, ports, and OS against the CVE database and flag findings."""
    asset = AssetService.get_by_id(db, asset_id)
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found."
        )

    scan_result = VulnerabilityService.scan_asset_for_vulnerabilities(db, asset)
    return scan_result


@router.patch(
    "/findings/{finding_id}",
    response_model=AssetVulnerabilityResponse,
    summary="Update vulnerability finding remediation status & notes (Analyst / Admin)"
)
def update_finding_remediation(
    finding_id: str,
    update_in: AssetVulnerabilityUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Update finding remediation progress (e.g. mark RESOLVED or RISK_ACCEPTED)."""
    finding = VulnerabilityService.get_finding_by_id(db, finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found."
        )

    updated = VulnerabilityService.update_remediation(db, finding, update_in)
    v_obj = updated.vulnerability
    return AssetVulnerabilityResponse(
        id=updated.id,
        asset_id=updated.asset_id,
        vulnerability_id=updated.vulnerability_id,
        status=updated.status,
        detected_version=updated.detected_version,
        detected_port=updated.detected_port,
        detected_at=updated.detected_at,
        resolved_at=updated.resolved_at,
        remediation_notes=updated.remediation_notes,
        assigned_to=updated.assigned_to,
        created_at=updated.created_at,
        updated_at=updated.updated_at,
        asset_name=updated.asset.name if updated.asset else None,
        vulnerability=VulnerabilityResponse.model_validate(v_obj) if v_obj else None,
    )


@router.get(
    "/{vuln_id}",
    response_model=VulnerabilityResponse,
    summary="Get vulnerability advisory details by ID"
)
def get_vulnerability(
    vuln_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated),
):
    """Retrieve detailed vulnerability specifications, CVSS vector, and remediation guidance."""
    vuln = VulnerabilityService.get_by_id(db, vuln_id)
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found."
        )
    return vuln


@router.put(
    "/{vuln_id}",
    response_model=VulnerabilityResponse,
    summary="Update vulnerability details (Analyst / Admin)"
)
def update_vulnerability(
    vuln_id: str,
    vuln_in: VulnerabilityUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Update advisory details or remediation instructions."""
    vuln = VulnerabilityService.get_by_id(db, vuln_id)
    if not vuln:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vulnerability not found."
        )

    updated = VulnerabilityService.update_vulnerability(db, vuln, vuln_in)
    return updated
