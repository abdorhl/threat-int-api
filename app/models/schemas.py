from pydantic import BaseModel, Field, validator
from typing import Optional, Dict, Any, List
from enum import Enum
from datetime import datetime
import validators
import re


class IndicatorType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatQueryRequest(BaseModel):
    indicator: str = Field(..., description="The indicator to query (IP, domain, URL, or hash)")
    indicator_type: IndicatorType = Field(..., description="Type of indicator")
    force_refresh: bool = Field(False, description="Force refresh cache")
    
    @validator('indicator')
    def validate_indicator(cls, v, values):
        if 'indicator_type' not in values:
            return v
            
        indicator_type = values['indicator_type']
        
        if indicator_type == IndicatorType.IP:
            if not validators.ipv4(v) and not validators.ipv6(v):
                raise ValueError(f"Invalid IP address: {v}")
        elif indicator_type == IndicatorType.DOMAIN:
            if not validators.domain(v):
                raise ValueError(f"Invalid domain: {v}")
        elif indicator_type == IndicatorType.URL:
            if not validators.url(v):
                raise ValueError(f"Invalid URL: {v}")
        elif indicator_type == IndicatorType.HASH:
            # Support MD5, SHA1, SHA256
            if not re.match(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$', v):
                raise ValueError(f"Invalid hash format (must be MD5, SHA1, or SHA256): {v}")
        
        return v


class SourceResult(BaseModel):
    available: bool = Field(..., description="Whether the source was available")
    data: Optional[Dict[str, Any]] = Field(None, description="Raw data from source")
    error: Optional[str] = Field(None, description="Error message if query failed")
    score: Optional[float] = Field(None, description="Normalized score from this source (0-100)")
    malicious: Optional[bool] = Field(None, description="Whether source flagged as malicious")


class ThreatQueryResponse(BaseModel):
    indicator: str = Field(..., description="The queried indicator")
    indicator_type: IndicatorType = Field(..., description="Type of indicator")
    risk_score: float = Field(..., description="Unified risk score (0-100)")
    risk_level: RiskLevel = Field(..., description="Risk level classification")
    sources: Dict[str, SourceResult] = Field(..., description="Results from each source")
    summary: Dict[str, Any] = Field(..., description="Summary statistics")
    cached: bool = Field(..., description="Whether result was from cache")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Query timestamp")
    
    class Config:
        json_schema_extra = {
            "example": {
                "indicator": "8.8.8.8",
                "indicator_type": "ip",
                "risk_score": 15.5,
                "risk_level": "low",
                "sources": {
                    "virustotal": {
                        "available": True,
                        "score": 10.0,
                        "malicious": False,
                        "data": {"detections": 0, "total_scans": 90}
                    }
                },
                "summary": {
                    "total_sources": 4,
                    "sources_with_data": 3,
                    "malicious_count": 0,
                    "suspicious_count": 1
                },
                "cached": False,
                "timestamp": "2025-10-04T22:52:36Z"
            }
        }


class User(BaseModel):
    username: str
    disabled: Optional[bool] = None


class UserInDB(User):
    hashed_password: str


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None
