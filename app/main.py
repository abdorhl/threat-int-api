"""
Threat Intelligence API - Main Application
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import logging

from app.core.config import settings
from app.core.auth import initialize_default_users
from app.core.cache import cache_manager
from app.api.routes import api_router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title=settings.API_TITLE,
    version=settings.API_VERSION,
    description="A comprehensive threat intelligence aggregation API",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Include API routes
app.include_router(api_router)


@app.on_event("startup")
async def startup_event():
    """Initialize on startup"""
    logger.info(f"Starting {settings.API_TITLE} v{settings.API_VERSION}")
    
    # Security validation
    if settings.SECRET_KEY == "your-secret-key-change-this-in-production":
        logger.warning("⚠️  WARNING: Using default SECRET_KEY! Generate a secure key for production!")
        logger.warning("   Generate with: python -c 'import secrets; print(secrets.token_urlsafe(32))'")
    
    # Initialize users
    initialize_default_users()
    logger.info("✓ Default users initialized")
    
    # Check cache connectivity
    cache_stats = cache_manager.get_stats()
    if cache_stats.get("connected"):
        logger.info(f"✓ Redis connected: {cache_stats}")
    else:
        logger.warning("⚠️  Redis not connected - caching will be disabled")
    
    # Check API keys
    api_keys_status = {
        "VirusTotal": bool(settings.VIRUSTOTAL_API_KEY),
        "OTX": bool(settings.OTX_API_KEY),
        "AbuseIPDB": bool(settings.ABUSEIPDB_API_KEY),
        "Shodan": bool(settings.SHODAN_API_KEY)
    }
    configured_sources = sum(api_keys_status.values())
    logger.info(f"✓ Threat Intel Sources: {configured_sources}/4 configured")
    for source, configured in api_keys_status.items():
        if not configured:
            logger.info(f"  - {source}: Not configured (optional)")


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": settings.API_TITLE,
        "version": settings.API_VERSION,
        "status": "operational",
        "docs": "/docs",
        "redoc": "/redoc"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint with detailed system status"""
    cache_stats = cache_manager.get_stats()
    
    # Check Redis connectivity
    redis_healthy = cache_stats.get("connected", False)
    
    # Check configured API sources
    api_sources = {
        "virustotal": bool(settings.VIRUSTOTAL_API_KEY),
        "otx": bool(settings.OTX_API_KEY),
        "abuseipdb": bool(settings.ABUSEIPDB_API_KEY),
        "shodan": bool(settings.SHODAN_API_KEY)
    }
    
    # Overall health status
    overall_status = "healthy" if redis_healthy else "degraded"
    
    return {
        "status": overall_status,
        "version": settings.API_VERSION,
        "components": {
            "redis": {
                "status": "up" if redis_healthy else "down",
                "stats": cache_stats
            },
            "threat_intel_sources": {
                "configured": sum(api_sources.values()),
                "total": len(api_sources),
                "sources": api_sources
            }
        },
        "environment": "production" if settings.SECRET_KEY != "your-secret-key-change-this-in-production" else "development"
    }


# Exception handlers
@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions"""
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": str(exc)
        }
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=True,
        log_level="info"
    )
