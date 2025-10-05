"""Cache management endpoints"""
from fastapi import APIRouter, Depends

from app.models.schemas import User
from app.core.auth import get_current_active_user
from app.core.cache import cache_manager

router = APIRouter()


@router.get("/stats")
async def get_cache_stats(current_user: User = Depends(get_current_active_user)):
    """Get cache statistics"""
    return cache_manager.get_stats()


@router.delete("/{indicator_type}/{indicator}")
async def clear_cache_entry(
    indicator: str,
    indicator_type: str,
    current_user: User = Depends(get_current_active_user)
):
    """Clear cache for a specific indicator"""
    cache_manager.delete(indicator, indicator_type)
    return {"message": f"Cache cleared for {indicator_type}: {indicator}"}


@router.delete("")
async def clear_all_cache(current_user: User = Depends(get_current_active_user)):
    """Clear all cached results"""
    cache_manager.clear_all()
    return {"message": "All cache cleared"}
