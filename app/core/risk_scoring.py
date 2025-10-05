from typing import Dict, Any
from app.models.schemas import SourceResult, RiskLevel
import logging

logger = logging.getLogger(__name__)


class RiskScorer:
    """Custom risk scoring algorithm that combines results from multiple sources"""
    
    # Source weights based on reliability and coverage
    SOURCE_WEIGHTS = {
        "virustotal": 0.35,  # Highest weight - most comprehensive
        "otx": 0.25,         # Good threat intelligence
        "abuseipdb": 0.25,   # Reliable for IP reputation
        "shodan": 0.15       # Useful but less direct threat indicator
    }
    
    # Minimum score threshold for each risk level
    RISK_THRESHOLDS = {
        "low": 0,
        "medium": 21,
        "high": 51,
        "critical": 76
    }
    
    @classmethod
    def calculate_unified_score(cls, sources: Dict[str, SourceResult]) -> float:
        """
        Calculate unified risk score from multiple sources
        
        Algorithm:
        1. Normalize all source scores to 0-100 scale
        2. Apply weighted averaging based on source reliability
        3. Apply malicious flag boost
        4. Return final score (0-100)
        """
        total_weight = 0.0
        weighted_score = 0.0
        malicious_count = 0
        available_sources = 0
        
        for source_name, result in sources.items():
            if not result.available or result.score is None:
                continue
            
            available_sources += 1
            weight = cls.SOURCE_WEIGHTS.get(source_name, 0.1)
            
            # Add weighted score
            weighted_score += result.score * weight
            total_weight += weight
            
            # Count malicious flags
            if result.malicious:
                malicious_count += 1
        
        # If no sources available, return 0
        if total_weight == 0:
            return 0.0
        
        # Calculate base score
        base_score = weighted_score / total_weight
        
        # Apply malicious flag boost
        # If multiple sources flag as malicious, increase score
        if malicious_count > 0:
            malicious_boost = min(malicious_count * 10, 25)  # Max 25 point boost
            base_score = min(base_score + malicious_boost, 100.0)
        
        # Apply consensus penalty
        # If sources disagree significantly, reduce confidence
        if available_sources > 1:
            scores = [r.score for r in sources.values() if r.available and r.score is not None]
            if scores:
                score_variance = cls._calculate_variance(scores)
                # High variance (>30) reduces score slightly
                if score_variance > 30:
                    variance_penalty = min((score_variance - 30) / 10, 10)
                    base_score = max(base_score - variance_penalty, 0)
        
        return round(base_score, 2)
    
    @classmethod
    def _calculate_variance(cls, scores: list) -> float:
        """Calculate variance of scores"""
        if len(scores) < 2:
            return 0.0
        
        mean = sum(scores) / len(scores)
        variance = sum((x - mean) ** 2 for x in scores) / len(scores)
        return variance ** 0.5  # Standard deviation
    
    @classmethod
    def get_risk_level(cls, score: float) -> RiskLevel:
        """Determine risk level from score"""
        if score >= cls.RISK_THRESHOLDS["critical"]:
            return RiskLevel.CRITICAL
        elif score >= cls.RISK_THRESHOLDS["high"]:
            return RiskLevel.HIGH
        elif score >= cls.RISK_THRESHOLDS["medium"]:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    @classmethod
    def generate_summary(cls, sources: Dict[str, SourceResult]) -> Dict[str, Any]:
        """Generate summary statistics from source results"""
        total_sources = len(sources)
        sources_with_data = sum(1 for r in sources.values() if r.available and r.data)
        malicious_count = sum(1 for r in sources.values() if r.malicious)
        
        # Count suspicious (score > 30 but not flagged as malicious)
        suspicious_count = sum(
            1 for r in sources.values() 
            if r.available and r.score and r.score > 30 and not r.malicious
        )
        
        # Get average score from available sources
        available_scores = [r.score for r in sources.values() if r.available and r.score is not None]
        avg_source_score = round(sum(available_scores) / len(available_scores), 2) if available_scores else 0.0
        
        # List sources that failed
        failed_sources = [name for name, r in sources.items() if not r.available]
        
        return {
            "total_sources": total_sources,
            "sources_with_data": sources_with_data,
            "malicious_count": malicious_count,
            "suspicious_count": suspicious_count,
            "average_source_score": avg_source_score,
            "failed_sources": failed_sources,
            "source_agreement": cls._calculate_agreement(sources)
        }
    
    @classmethod
    def _calculate_agreement(cls, sources: Dict[str, SourceResult]) -> str:
        """Calculate how much sources agree on the assessment"""
        malicious_flags = [r.malicious for r in sources.values() if r.available and r.malicious is not None]
        
        if not malicious_flags:
            return "unknown"
        
        malicious_ratio = sum(malicious_flags) / len(malicious_flags)
        
        if malicious_ratio >= 0.75:
            return "high_agreement_malicious"
        elif malicious_ratio >= 0.5:
            return "moderate_agreement_malicious"
        elif malicious_ratio >= 0.25:
            return "low_agreement_malicious"
        else:
            return "agreement_benign"
