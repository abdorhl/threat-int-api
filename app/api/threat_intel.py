"""Threat Intelligence endpoints"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.models.schemas import ThreatQueryRequest, ThreatQueryResponse, User
from app.core.auth import get_current_active_user
from app.core.config import settings
from app.services.threat_intel import ThreatIntelAggregator
from app.core.risk_scoring import RiskScorer
from app.core.cache import cache_manager
import logging

logger = logging.getLogger(__name__)

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)
threat_intel_aggregator = ThreatIntelAggregator()


@router.post("/query", response_model=ThreatQueryResponse)
@limiter.limit(f"{settings.RATE_LIMIT_PER_MINUTE}/minute")
async def query_threat_intel(
    request: Request,
    query_request: ThreatQueryRequest,
    current_user: User = Depends(get_current_active_user)
):
    """
    Query threat intelligence for an indicator
    
    Supports:
    - IP addresses (IPv4 and IPv6)
    - Domains
    - URLs
    - File hashes (MD5, SHA1, SHA256)
    
    Returns unified risk score and data from multiple sources.
    """
    try:
        indicator = query_request.indicator
        indicator_type = query_request.indicator_type
        
        logger.info(f"User {current_user.username} querying {indicator_type}: {indicator}")
        
        # Check cache first (unless force_refresh is True)
        if not query_request.force_refresh:
            cached_result = cache_manager.get(indicator, indicator_type.value)
            if cached_result:
                logger.info(f"Returning cached result for {indicator}")
                cached_result["cached"] = True
                return ThreatQueryResponse(**cached_result)
        
        # Query all threat intelligence sources
        source_results = await threat_intel_aggregator.query_all(indicator, indicator_type)
        
        # Calculate unified risk score
        risk_score = RiskScorer.calculate_unified_score(source_results)
        risk_level = RiskScorer.get_risk_level(risk_score)
        
        # Generate summary
        summary = RiskScorer.generate_summary(source_results)
        
        # Build response
        response_data = {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "sources": source_results,
            "summary": summary,
            "cached": False
        }
        
        # Cache the result
        cache_manager.set(indicator, indicator_type.value, response_data)
        
        return ThreatQueryResponse(**response_data)
    
    except Exception as e:
        logger.error(f"Query error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Query failed: {str(e)}"
        )


@router.post("/batch-query")
@limiter.limit(f"{settings.RATE_LIMIT_PER_MINUTE}/minute")
async def batch_query_threat_intel(
    request: Request,
    queries: list[ThreatQueryRequest],
    current_user: User = Depends(get_current_active_user)
):
    """
    Batch query multiple indicators
    
    Limited to 10 indicators per request to prevent abuse.
    """
    if len(queries) > 10:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 10 indicators per batch request"
        )
    
    results = []
    for query_request in queries:
        try:
            result = await query_threat_intel(request, query_request, current_user)
            results.append({
                "indicator": query_request.indicator,
                "success": True,
                "data": result
            })
        except Exception as e:
            results.append({
                "indicator": query_request.indicator,
                "success": False,
                "error": str(e)
            })
    
    return {
        "results": results,
        "total": len(queries),
        "successful": sum(1 for r in results if r["success"])
    }
