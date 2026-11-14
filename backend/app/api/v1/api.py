from fastapi import APIRouter

from backend.app.api.v1.endpoints import (
    ai_risk,
    assets,
    auth,
    forensics,
    incidents,
    monitoring,
    reports,
    vulnerabilities,
)

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(assets.router)
api_router.include_router(vulnerabilities.router)
api_router.include_router(monitoring.router)
api_router.include_router(ai_risk.router, prefix="/ai-risk", tags=["AI Risk Intelligence"])
api_router.include_router(forensics.router)
api_router.include_router(incidents.router)
api_router.include_router(reports.router)
