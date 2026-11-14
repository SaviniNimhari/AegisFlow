from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from backend.app.core.permissions import require_analyst, require_authenticated
from backend.app.database.session import get_db
from backend.app.models.user import User
from backend.app.schemas.report import (
    ExecutiveReportRequest,
    IncidentPostmortemRequest,
    SecurityPostureOverview,
    SecurityReportResponse,
)
from backend.app.services.report_service import (
    compute_security_posture,
    generate_executive_posture_report,
    generate_incident_postmortem_report,
    get_report_by_id,
    list_reports,
)

router = APIRouter(prefix="/reports", tags=["Reporting & Executive Analytics"])


@router.get(
    "/posture",
    response_model=SecurityPostureOverview,
    summary="Get enterprise security posture analytics",
)
def get_posture_overview(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(require_authenticated)],
) -> SecurityPostureOverview:
    """Computes real-time enterprise security posture score, compliance status, and MTTD/MTTR."""
    return compute_security_posture(db)


@router.post(
    "/executive",
    response_model=SecurityReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate executive security posture report",
)
def create_executive_report(
    request: ExecutiveReportRequest,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
) -> SecurityReportResponse:
    """Compiles and renders an executive security posture report."""
    report = generate_executive_posture_report(
        db=db, request=request, generated_by_id=current_user.id
    )
    return SecurityReportResponse.model_validate(report)


@router.post(
    "/incident",
    response_model=SecurityReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate incident post-mortem dossier",
)
def create_incident_postmortem(
    request: IncidentPostmortemRequest,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
) -> SecurityReportResponse:
    """Compiles and renders an incident post-mortem investigation report."""
    try:
        report = generate_incident_postmortem_report(
            db=db, request=request, generated_by_id=current_user.id
        )
        return SecurityReportResponse.model_validate(report)
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(err),
        ) from err


@router.get(
    "/",
    response_model=list[SecurityReportResponse],
    summary="List generated security reports",
)
def get_reports(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(require_authenticated)],
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    report_type: Annotated[str | None, Query()] = None,
) -> list[SecurityReportResponse]:
    """Lists saved security reports with optional pagination and filtering."""
    reports = list_reports(db=db, skip=skip, limit=limit, report_type=report_type)
    return [SecurityReportResponse.model_validate(r) for r in reports]


@router.get(
    "/{report_id}",
    response_model=SecurityReportResponse,
    summary="Get security report details",
)
def get_report(
    report_id: str,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(require_authenticated)],
) -> SecurityReportResponse:
    """Retrieves full metadata and content for a specific report."""
    report = get_report_by_id(db=db, report_id=report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report with id '{report_id}' not found.",
        )
    return SecurityReportResponse.model_validate(report)


@router.get(
    "/{report_id}/export",
    summary="Export security report formatted content",
)
def export_report(
    report_id: str,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(require_authenticated)],
    export_format: Annotated[str, Query()] = "html",
) -> Response:
    """Exports a security report as HTML, Markdown, or JSON."""
    report = get_report_by_id(db=db, report_id=report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report with id '{report_id}' not found.",
        )

    fmt = export_format.lower()
    if fmt == "html":
        content = report.rendered_html or "<p>No HTML content available.</p>"
        return Response(content=content, media_type="text/html")
    elif fmt == "markdown" or fmt == "md":
        content = report.rendered_markdown or "# No markdown content"
        return Response(content=content, media_type="text/markdown")
    elif fmt == "json":
        import json
        return Response(
            content=json.dumps(report.content, indent=2),
            media_type="application/json",
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported export format '{export_format}'. Supported: html, markdown, json.",
        )
