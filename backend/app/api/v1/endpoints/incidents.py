from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.core.permissions import require_analyst, require_authenticated
from backend.app.database.session import get_db
from backend.app.models.user import User
from backend.app.schemas.incident import (
    CorrelationTriggerResponse,
    IncidentCommentCreate,
    IncidentCommentResponse,
    IncidentCreate,
    IncidentListResponse,
    IncidentResponse,
    IncidentStatsResponse,
    IncidentUpdate,
    LinkAlertRequest,
    LinkArtifactRequest,
)
from backend.app.services.incident_service import IncidentService

router = APIRouter(prefix="/incidents", tags=["Incident Management"])


def _format_incident_response(incident) -> IncidentResponse:
    """Format an Incident model instance including alert and artifact counts."""
    resp = IncidentResponse.model_validate(incident)
    resp.alert_count = len(incident.alerts) if incident.alerts else 0
    resp.artifact_count = len(incident.artifacts) if incident.artifacts else 0
    return resp


@router.post(
    "",
    response_model=IncidentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new security incident case",
)
def create_incident(
    incident_in: IncidentCreate,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
) -> IncidentResponse:
    """Create a new incident case file, attach initial alerts/artifacts, and start audit timeline."""
    incident = IncidentService.create_incident(
        db=db, incident_in=incident_in, creator=current_user.email
    )
    return _format_incident_response(incident)


@router.post(
    "/correlate",
    response_model=CorrelationTriggerResponse,
    summary="Trigger automated alert correlation engine across unassigned alerts",
)
def run_alert_correlation(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
) -> CorrelationTriggerResponse:
    """
    Evaluates all unassigned SIEM alerts.
    Clusters related events by asset or threat actor into coordinated Incident cases.
    """
    inc_count, alert_count, incidents = IncidentService.correlate_unassigned_alerts(
        db, author=current_user.email
    )
    return CorrelationTriggerResponse(
        incidents_created=inc_count,
        alerts_correlated=alert_count,
        incident_ids=[i.id for i in incidents],
    )


@router.get(
    "",
    response_model=IncidentListResponse,
    summary="List security incidents with filtering and search",
)
def list_incidents(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_authenticated)],
    status_filter: str | None = Query(None, alias="status", description="Filter by status"),
    severity: str | None = Query(None, description="Filter by severity: critical, high, medium, low"),
    search: str | None = Query(None, description="Search by title, number, or description"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
) -> IncidentListResponse:
    """Retrieve catalog of incidents with pagination."""
    items, total = IncidentService.list_incidents(
        db, status=status_filter, severity=severity, search=search, skip=skip, limit=limit
    )
    return IncidentListResponse(
        items=[_format_incident_response(i) for i in items],
        total=total,
    )


@router.get(
    "/stats",
    response_model=IncidentStatsResponse,
    summary="Get incident metrics and MTTR statistics",
)
def get_incident_stats(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_authenticated)],
) -> IncidentStatsResponse:
    """Retrieve summary counts for active cases, critical threats, and resolution times."""
    return IncidentService.get_stats(db)


@router.get(
    "/{incident_id}",
    response_model=IncidentResponse,
    summary="Get detailed incident case file, timeline, and analyst notes",
)
def get_incident(
    incident_id: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_authenticated)],
) -> IncidentResponse:
    """Retrieve complete incident record including timeline progression and correlated evidence."""
    incident = IncidentService.get_incident(db, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )
    return _format_incident_response(incident)


@router.patch(
    "/{incident_id}",
    response_model=IncidentResponse,
    summary="Update incident lifecycle, containment notes, or assignments",
)
def update_incident(
    incident_id: str,
    update_in: IncidentUpdate,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
) -> IncidentResponse:
    """Update status, assign lead analyst, log containment actions, and update root cause."""
    incident = IncidentService.update_incident(
        db, incident_id=incident_id, update_in=update_in, author=current_user.email
    )
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )
    return _format_incident_response(incident)


@router.post(
    "/{incident_id}/link-alert",
    response_model=IncidentResponse,
    summary="Associate a security alert with this incident",
)
def link_alert_to_incident(
    incident_id: str,
    request: LinkAlertRequest,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
) -> IncidentResponse:
    """Link an alert and record a timeline event."""
    incident = IncidentService.link_alert(
        db, incident_id=incident_id, alert_id=request.alert_id, author=current_user.email
    )
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident or Alert not found.",
        )
    return _format_incident_response(incident)


@router.post(
    "/{incident_id}/link-artifact",
    response_model=IncidentResponse,
    summary="Associate a forensic evidence artifact with this incident",
)
def link_artifact_to_incident(
    incident_id: str,
    request: LinkArtifactRequest,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
) -> IncidentResponse:
    """Link a forensic artifact and record a timeline event."""
    incident = IncidentService.link_artifact(
        db, incident_id=incident_id, artifact_id=request.artifact_id, author=current_user.email
    )
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident or Artifact not found.",
        )
    return _format_incident_response(incident)


@router.post(
    "/{incident_id}/comments",
    response_model=IncidentCommentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Post collaborative analyst investigation comment",
)
def post_incident_comment(
    incident_id: str,
    comment_in: IncidentCommentCreate,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
) -> IncidentCommentResponse:
    """Add collaborative investigation notes to the case file."""
    comment = IncidentService.add_comment(
        db, incident_id=incident_id, author=current_user.email, content=comment_in.content
    )
    if not comment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found.",
        )
    return IncidentCommentResponse.model_validate(comment)
