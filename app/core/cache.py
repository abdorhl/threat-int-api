import redis
import json
import hashlib
from typing import Optional, Dict, Any
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)


class CacheManager:
    """Redis-based cache manager for threat intelligence queries"""
    
    def __init__(self):
        self.redis_client = None
        self.enabled = False
        self._connect()
    
    def _connect(self):
        """Connect to Redis"""
        try:
            self.redis_client = redis.Redis(
                host=settings.REDIS_HOST,
                port=settings.REDIS_PORT,
                db=settings.REDIS_DB,
                password=settings.REDIS_PASSWORD if settings.REDIS_PASSWORD else None,
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2
            )
            # Test connection
            self.redis_client.ping()
            self.enabled = True
            logger.info("Redis cache connected successfully")
        except Exception as e:
            logger.warning(f"Redis connection failed: {str(e)}. Caching disabled.")
            self.enabled = False
    
    def _generate_key(self, indicator: str, indicator_type: str) -> str:
        """Generate cache key from indicator and type"""
        # Create a hash to ensure consistent key format
        key_string = f"{indicator_type}:{indicator.lower()}"
        key_hash = hashlib.md5(key_string.encode()).hexdigest()
        return f"threat_intel:{key_hash}"
    
    def get(self, indicator: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        """Get cached result"""
        if not self.enabled:
            return None
        
        try:
            key = self._generate_key(indicator, indicator_type)
            cached_data = self.redis_client.get(key)
            
            if cached_data:
                logger.info(f"Cache hit for {indicator}")
                return json.loads(cached_data)
            
            logger.debug(f"Cache miss for {indicator}")
            return None
        except Exception as e:
            logger.error(f"Cache get error: {str(e)}")
            return None
    
    def set(self, indicator: str, indicator_type: str, data: Dict[str, Any], ttl: Optional[int] = None):
        """Set cached result"""
        if not self.enabled:
            return
        
        try:
            key = self._generate_key(indicator, indicator_type)
            ttl = ttl or settings.CACHE_TTL
            
            self.redis_client.setex(
                key,
                ttl,
                json.dumps(data, default=str)  # default=str handles datetime serialization
            )
            logger.debug(f"Cached result for {indicator} (TTL: {ttl}s)")
        except Exception as e:
            logger.error(f"Cache set error: {str(e)}")
    
    def delete(self, indicator: str, indicator_type: str):
        """Delete cached result"""
        if not self.enabled:
            return
        
        try:
            key = self._generate_key(indicator, indicator_type)
            self.redis_client.delete(key)
            logger.debug(f"Deleted cache for {indicator}")
        except Exception as e:
            logger.error(f"Cache delete error: {str(e)}")
    
    def clear_all(self):
        """Clear all cached results"""
        if not self.enabled:
            return
        
        try:
            keys = self.redis_client.keys("threat_intel:*")
            if keys:
                self.redis_client.delete(*keys)
                logger.info(f"Cleared {len(keys)} cached results")
        except Exception as e:
            logger.error(f"Cache clear error: {str(e)}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        if not self.enabled:
            return {"enabled": False, "connected": False}
        
        try:
            info = self.redis_client.info()
            keys_count = len(self.redis_client.keys("threat_intel:*"))
            
            return {
                "enabled": True,
                "connected": True,
                "total_keys": keys_count,
                "used_memory": info.get("used_memory_human"),
                "connected_clients": info.get("connected_clients"),
                "uptime_days": info.get("uptime_in_days")
            }
        except Exception as e:
            logger.error(f"Cache stats error: {str(e)}")
            return {"enabled": False, "connected": False, "error": str(e)}


# Global cache instance
cache_manager = CacheManager()
