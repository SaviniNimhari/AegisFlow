from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.core.permissions import require_analyst, require_authenticated
from backend.app.database.session import get_db
from backend.app.models.user import User
from backend.app.schemas.ai_risk import (
    AIEventAnalysisRequest,
    AIModelMetadata,
    AIRiskSummary,
    AIThreatPredictionResponse,
    AnalystFeedbackUpdate,
    BatchAIAnalysisRequest,
    FeatureAttribution,
)
from backend.app.services.ai_risk_service import AIRiskService

router = APIRouter()


def _format_prediction_response(prediction) -> AIThreatPredictionResponse:
    """Format an AIThreatPrediction model instance with computed attributions list."""
    shap_dict = prediction.shap_explanations or {}
    attributions = [
        FeatureAttribution(
            feature_name=fname,
            feature_value=data.get("value", 0.0),
            importance_score=data.get("shap_value", 0.0),
            impact_direction=data.get("direction", "neutral"),
            human_readable=data.get("explanation", ""),
        )
        for fname, data in shap_dict.items()
    ]
    attributions.sort(key=lambda a: abs(a.importance_score), reverse=True)

    resp = AIThreatPredictionResponse.model_validate(prediction)
    resp.attributions = attributions
    return resp


@router.post(
    "/analyze",
    response_model=AIThreatPredictionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Analyze event telemetry with ML threat intelligence and SHAP explanations",
)
def analyze_telemetry_event(
    request: AIEventAnalysisRequest,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
) -> AIThreatPredictionResponse:
    """
    Evaluate incoming security telemetry or raw event against the trained ML model.
    Returns calculated risk score, anomaly score, threat category, and SHAP feature attributions.
    """
    prediction = AIRiskService.analyze_event(db, request, reviewer=current_user.email)
    return _format_prediction_response(prediction)


@router.post(
    "/batch-analyze",
    response_model=list[AIThreatPredictionResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Batch analyze multiple telemetry events",
)
def batch_analyze_events(
    request: BatchAIAnalysisRequest,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
) -> list[AIThreatPredictionResponse]:
    """Analyze a batch of up to 100 security events with ML threat scoring."""
    results = []
    for event_req in request.events:
        prediction = AIRiskService.analyze_event(db, event_req, reviewer=current_user.email)
        results.append(_format_prediction_response(prediction))
    return results


@router.get(
    "/predictions",
    response_model=list[AIThreatPredictionResponse],
    summary="List recent AI threat predictions",
)
def list_ai_predictions(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_authenticated)],
    risk_level: str | None = Query(None, description="Filter by risk level (critical, high, medium, low)"),
    feedback: str | None = Query(None, description="Filter by feedback (unreviewed, true_positive, false_positive)"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
) -> list[AIThreatPredictionResponse]:
    """Retrieve historical AI threat predictions with optional filtering and pagination."""
    items, _ = AIRiskService.list_predictions(
        db, risk_level=risk_level, feedback=feedback, skip=skip, limit=limit
    )
    return [_format_prediction_response(p) for p in items]


@router.get(
    "/predictions/{prediction_id}",
    response_model=AIThreatPredictionResponse,
    summary="Get single AI threat prediction details with SHAP attributions",
)
def get_prediction_detail(
    prediction_id: str,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_authenticated)],
) -> AIThreatPredictionResponse:
    """Retrieve full details of an AI threat prediction by UUID."""
    pred = AIRiskService.get_prediction_by_id(db, prediction_id)
    if not pred:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat prediction '{prediction_id}' not found.",
        )
    return _format_prediction_response(pred)


@router.patch(
    "/predictions/{prediction_id}/feedback",
    response_model=AIThreatPredictionResponse,
    summary="Submit analyst feedback for model reinforcement",
)
def update_prediction_feedback(
    prediction_id: str,
    update: AnalystFeedbackUpdate,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(require_analyst)],
) -> AIThreatPredictionResponse:
    """
    Analysts can label predictions as True Positive, False Positive, or Benign Suspicious
    to track model performance and guide continuous active learning.
    """
    pred = AIRiskService.update_feedback(
        db,
        prediction_id=prediction_id,
        feedback=update.analyst_feedback,
        notes=update.analyst_notes,
        reviewed_by=current_user.email,
    )
    if not pred:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat prediction '{prediction_id}' not found.",
        )
    return _format_prediction_response(pred)


@router.get(
    "/summary",
    response_model=AIRiskSummary,
    summary="Get AI threat intelligence summary metrics",
)
def get_ai_risk_summary(
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[User, Depends(require_authenticated)],
) -> AIRiskSummary:
    """Aggregate risk tier breakdown and feedback statistics."""
    return AIRiskService.get_summary(db)


@router.get(
    "/model-metadata",
    response_model=AIModelMetadata,
    summary="Get active ML model metadata, architecture, and accuracy",
)
def get_ai_model_metadata(
    _: Annotated[User, Depends(require_authenticated)],
) -> AIModelMetadata:
    """Returns details on the loaded model, AUC-ROC, feature list, and training state."""
    return AIRiskService.get_model_metadata()
