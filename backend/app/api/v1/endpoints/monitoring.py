from math import ceil

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.core.permissions import require_analyst, require_authenticated
from backend.app.database.session import get_db
from backend.app.models.monitoring import AlertSeverity, AlertStatus, EventType
from backend.app.models.user import User
from backend.app.schemas.monitoring import (
    AlertListResponse,
    AlertStatsResponse,
    DetectionRuleCreate,
    DetectionRuleResponse,
    EventIngestResponse,
    EventListResponse,
    SecurityAlertResponse,
    SecurityAlertUpdate,
    SecurityEventCreate,
    SecurityEventResponse,
)
from backend.app.services.monitoring_service import MonitoringService

router = APIRouter(prefix="/monitoring", tags=["Security Monitoring & Rule-Based Detection"])


@router.post(
    "/events",
    response_model=EventIngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest a security event log and evaluate real-time detection rules"
)
def ingest_event(
    event_in: SecurityEventCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated),
):
    """Ingest a security event (auth, network, file, privilege, or system command) and run detection rules."""
    _, triggered_alerts = MonitoringService.ingest_event(db, event_in)

    return EventIngestResponse(
        events_ingested=1,
        alerts_triggered=len(triggered_alerts),
        alerts=[SecurityAlertResponse.model_validate(a) for a in triggered_alerts],
    )


@router.get(
    "/events",
    response_model=EventListResponse,
    summary="List and filter ingested security logs & telemetry"
)
def list_events(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    event_type: EventType | None = Query(None, description="Filter by event type"),
    source_ip: str | None = Query(None, description="Filter by source IP"),
    username: str | None = Query(None, description="Filter by username"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated),
):
    """Query ingested security logs with multi-parameter filtering."""
    skip = (page - 1) * limit
    type_val = event_type.value if event_type else None

    items, total = MonitoringService.list_events(
        db=db,
        skip=skip,
        limit=limit,
        event_type=type_val,
        source_ip=source_ip,
        username=username,
    )

    total_pages = ceil(total / limit) if total > 0 else 1

    return EventListResponse(
        items=[SecurityEventResponse.model_validate(item) for item in items],
        total=total,
        page=page,
        limit=limit,
        total_pages=total_pages,
    )


@router.get(
    "/alerts/stats",
    response_model=AlertStatsResponse,
    summary="Get security alert statistics & MITRE ATT&CK telemetry"
)
def get_alert_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated),
):
    """Retrieve active alert counts by severity, status, and top MITRE ATT&CK tactics."""
    return MonitoringService.get_statistics(db)


@router.get(
    "/alerts",
    response_model=AlertListResponse,
    summary="List and filter triggered security alerts"
)
def list_alerts(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    severity: AlertSeverity | None = Query(None, description="Filter by alert severity"),
    alert_status: AlertStatus | None = Query(None, alias="status", description="Filter by alert status"),
    search: str | None = Query(None, description="Search term matching title, description, or IP"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated),
):
    """Retrieve security alerts triggered by the rule detection engine with status filtering."""
    skip = (page - 1) * limit
    sev_val = severity.value if severity else None
    stat_val = alert_status.value if alert_status else None

    items, total = MonitoringService.list_alerts(
        db=db,
        skip=skip,
        limit=limit,
        severity=sev_val,
        status=stat_val,
        search=search,
    )

    total_pages = ceil(total / limit) if total > 0 else 1

    return AlertListResponse(
        items=[SecurityAlertResponse.model_validate(item) for item in items],
        total=total,
        page=page,
        limit=limit,
        total_pages=total_pages,
    )


@router.get(
    "/alerts/{alert_id}",
    response_model=SecurityAlertResponse,
    summary="Get alert details & forensic evidence by ID"
)
def get_alert(
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated),
):
    """Inspect full alert details including forensic evidence payload and MITRE ATT&CK mapping."""
    alert = MonitoringService.get_alert_by_id(db, alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security alert not found."
        )
    return alert


@router.patch(
    "/alerts/{alert_id}",
    response_model=SecurityAlertResponse,
    summary="Triage and update security alert status (Analyst / Admin)"
)
def update_alert(
    alert_id: str,
    update_in: SecurityAlertUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Triage security alert (transition to investigating, resolved, dismissed, or escalated)."""
    alert = MonitoringService.get_alert_by_id(db, alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security alert not found."
        )

    updated = MonitoringService.update_alert(db, alert, update_in)
    return updated


@router.get(
    "/rules",
    response_model=list[DetectionRuleResponse],
    summary="List active detection rules"
)
def list_rules(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_authenticated),
):
    """Retrieve all active rule signatures currently loaded in the detection engine."""
    rules = MonitoringService.list_rules(db)
    return [DetectionRuleResponse.model_validate(r) for r in rules]


@router.post(
    "/rules",
    response_model=DetectionRuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a custom detection rule (Analyst / Admin)"
)
def create_rule(
    rule_in: DetectionRuleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Register a new detection rule signature with thresholds and MITRE technique tag."""
    rule = MonitoringService.create_rule(db, rule_in)
    return rule
