from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.v1.api import api_router
from backend.app.core.config import settings
from backend.app.database.session import check_db_connected

app = FastAPI(
    title="AegisFlow API",
    description="Cybersecurity Defense and Digital Forensics Platform",
    version="1.0.0",
    openapi_url="/api/v1/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Allow the React frontend to communicate with the Python backend during development
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# Include v1 endpoints
app.include_router(api_router, prefix=settings.API_V1_PREFIX)


@app.get("/")
async def root():
    return {
        "application": settings.APP_NAME,
        "message": "Cybersecurity platform API is running",
        "version": "1.0.0",
        "environment": settings.APP_ENV
    }


@app.get("/api/v1/health")
async def health_check():
    db_ok = check_db_connected()
    return {
        "status": "healthy" if db_ok else "degraded",
        "service": "AegisFlow API",
        "version": "1.0.0",
        "database": "connected" if db_ok else "disconnected",
    }
