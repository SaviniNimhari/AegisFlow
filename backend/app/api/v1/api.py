from fastapi import APIRouter

from backend.app.api.v1.endpoints import assets, auth, monitoring, vulnerabilities

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(assets.router)
api_router.include_router(vulnerabilities.router)
api_router.include_router(monitoring.router)
