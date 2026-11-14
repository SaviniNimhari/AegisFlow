from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from sqlalchemy.orm import Session

from backend.app.core.permissions import require_analyst, require_authenticated
from backend.app.database.session import get_db
from backend.app.models.user import User
from backend.app.schemas.forensics import (
    ArtifactListResponse,
    ArtifactTextAnalyzeRequest,
    ChainOfCustodyLogResponse,
    CustodyVerificationRequest,
    ForensicArtifactResponse,
    ForensicStatsResponse,
    YaraRuleCreate,
    YaraRuleResponse,
)
from backend.app.services.forensics_service import ForensicsService

router = APIRouter(prefix="/forensics", tags=["Digital Forensics"])


@router.post(
    "/artifacts/upload",
    response_model=ForensicArtifactResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload binary or suspicious file for static forensic analysis and YARA scanning",
)
async def upload_forensic_artifact(
    file: Annotated[UploadFile, File(...)],
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
    asset_id: Annotated[str | None, Form()] = None,
) -> ForensicArtifactResponse:
    """
    Upload a suspicious binary, payload, or file artifact.
    Computes cryptographic hashes, calculates Shannon entropy, extracts strings/APIs,
    executes YARA rule matching, and creates an initial Chain of Custody entry.
    """
    contents = await file.read()
    if not contents:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot analyze an empty file.",
        )

    filename = file.filename or "unknown_artifact.bin"
    artifact = ForensicsService.analyze_artifact(
        db=db,
        filename=filename,
        data=contents,
        uploaded_by=current_user.email,
        asset_id=asset_id,
    )
    return ForensicArtifactResponse.model_validate(artifact)


@router.post(
    "/artifacts/analyze-text",
    response_model=ForensicArtifactResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Analyze suspicious command, script snippet, or text payload",
)
def analyze_text_snippet(
    request: ArtifactTextAnalyzeRequest,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
) -> ForensicArtifactResponse:
    """
    Submits a raw text/script snippet (e.g. PowerShell, PHP, Shell script) for static analysis,
    entropy assessment, string extraction, and YARA rule matching.
    """
    data_bytes = request.content.encode("utf-8")
    artifact = ForensicsService.analyze_artifact(
        db=db,
        filename=request.filename,
        data=data_bytes,
        uploaded_by=current_user.email,
        asset_id=request.asset_id,
    )
    return ForensicArtifactResponse.model_validate(artifact)


@router.get(
    "/artifacts",
    response_model=ArtifactListResponse,
    summary="List forensic artifacts with filters",
)
def list_forensic_artifacts(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_authenticated)],
    verdict: str | None = Query(None, description="Filter by verdict: malicious, suspicious, benign, unknown"),
    severity: str | None = Query(None, description="Filter by severity: critical, high, medium, low, info"),
    search: str | None = Query(None, description="Search by filename or SHA-256 hash"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
) -> ArtifactListResponse:
    """Retrieve catalog of analyzed forensic artifacts."""
    items, total = ForensicsService.list_artifacts(
        db, verdict=verdict, severity=severity, search=search, skip=skip, limit=limit
    )
    return ArtifactListResponse(
        items=[ForensicArtifactResponse.model_validate(i) for i in items],
        total=total,
    )


@router.get(
    "/artifacts/{artifact_id}",
    response_model=ForensicArtifactResponse,
    summary="Get detailed forensic artifact inspection and chain of custody",
)
def get_forensic_artifact(
    artifact_id: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_authenticated)],
) -> ForensicArtifactResponse:
    """Retrieve complete artifact record including YARA matches, extracted strings, and custody history."""
    artifact = ForensicsService.get_artifact(db, artifact_id)
    if not artifact:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Forensic artifact '{artifact_id}' not found.",
        )
    return ForensicArtifactResponse.model_validate(artifact)


@router.post(
    "/artifacts/{artifact_id}/custody",
    response_model=ChainOfCustodyLogResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Append a verified custody action or integrity check",
)
def add_custody_action(
    artifact_id: str,
    request: CustodyVerificationRequest,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
) -> ChainOfCustodyLogResponse:
    """
    Records an immutable Chain of Custody event verifying the artifact's SHA-256 hash
    during evidence transfer, laboratory checkout, or judicial presentation.
    """
    try:
        log = ForensicsService.verify_custody_integrity(
            db=db,
            artifact_id=artifact_id,
            performed_by=current_user.email,
            action=request.action,
            details=request.details,
        )
        return ChainOfCustodyLogResponse.model_validate(log)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        ) from e


@router.get(
    "/artifacts/{artifact_id}/custody",
    response_model=list[ChainOfCustodyLogResponse],
    summary="Get chain of custody audit logs for an artifact",
)
def get_artifact_custody_timeline(
    artifact_id: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_authenticated)],
) -> list[ChainOfCustodyLogResponse]:
    """Retrieve full chronological chain of custody log for an evidence item."""
    artifact = ForensicsService.get_artifact(db, artifact_id)
    if not artifact:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Forensic artifact '{artifact_id}' not found.",
        )
    return [ChainOfCustodyLogResponse.model_validate(log_entry) for log_entry in artifact.custody_logs]


@router.get(
    "/yara/rules",
    response_model=list[YaraRuleResponse],
    summary="List registered YARA threat rules",
)
def list_yara_rules(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_authenticated)],
) -> list[YaraRuleResponse]:
    """List all registered and default YARA threat rules."""
    rules = ForensicsService.list_yara_rules(db)
    return [YaraRuleResponse.model_validate(r) for r in rules]


@router.post(
    "/yara/rules",
    response_model=YaraRuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register and compile a new YARA threat signature",
)
def create_custom_yara_rule(
    rule_in: YaraRuleCreate,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
) -> YaraRuleResponse:
    """Validate, test-compile, and persist a new custom YARA detection signature."""
    try:
        rule = ForensicsService.create_yara_rule(
            db=db, rule_in=rule_in, author=current_user.email
        )
        return YaraRuleResponse.model_validate(rule)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e


@router.get(
    "/stats",
    response_model=ForensicStatsResponse,
    summary="Get digital forensics overview metrics",
)
def get_forensics_stats(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_authenticated)],
) -> ForensicStatsResponse:
    """Retrieve summary metrics for evidence vault and YARA engine."""
    return ForensicsService.get_stats(db)
