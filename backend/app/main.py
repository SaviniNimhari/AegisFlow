from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.core.config import settings

app = FastAPI(
    title="AegisFlow API",
    description="Cybersecurity Defense and Digital Forensics Platform",
    version="1.0.0"
)

# Allow the React frontend to communicate with the Python backend during development
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


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
    return {
        "status": "healthy",
        "service": "AegisFlow API",
        "version": "1.0.0"
    }
