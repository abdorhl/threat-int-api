"""API Routes"""
from fastapi import APIRouter

from app.api import auth, threat_intel, cache

api_router = APIRouter()

# Include sub-routers
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(threat_intel.router, prefix="/api/v1", tags=["Threat Intelligence"])
api_router.include_router(cache.router, prefix="/api/v1/cache", tags=["Cache Management"])
