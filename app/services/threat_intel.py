import aiohttp
import asyncio
from typing import Dict, Any, Optional
from app.models.schemas import IndicatorType, SourceResult
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)


class ThreatIntelService:
    """Base class for threat intelligence services"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.timeout = aiohttp.ClientTimeout(total=10)
    
    async def query(self, indicator: str, indicator_type: IndicatorType) -> SourceResult:
        """Query the threat intelligence service"""
        raise NotImplementedError


class VirusTotalService(ThreatIntelService):
    """VirusTotal API integration"""
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    async def query(self, indicator: str, indicator_type: IndicatorType) -> SourceResult:
        if not self.api_key:
            return SourceResult(available=False, error="API key not configured")
        
        try:
            headers = {"x-apikey": self.api_key}
            
            # Determine endpoint based on indicator type
            if indicator_type == IndicatorType.IP:
                url = f"{self.BASE_URL}/ip_addresses/{indicator}"
            elif indicator_type == IndicatorType.DOMAIN:
                url = f"{self.BASE_URL}/domains/{indicator}"
            elif indicator_type == IndicatorType.URL:
                # URL needs to be base64 encoded without padding
                import base64
                url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
                url = f"{self.BASE_URL}/urls/{url_id}"
            elif indicator_type == IndicatorType.HASH:
                url = f"{self.BASE_URL}/files/{indicator}"
            else:
                return SourceResult(available=False, error="Unsupported indicator type")
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 404:
                        return SourceResult(
                            available=True,
                            data={"message": "Not found in VirusTotal"},
                            score=0.0,
                            malicious=False
                        )
                    elif response.status == 429:
                        return SourceResult(available=False, error="Rate limit exceeded")
                    elif response.status != 200:
                        return SourceResult(available=False, error=f"HTTP {response.status}")
                    
                    data = await response.json()
                    return self._parse_response(data)
        
        except asyncio.TimeoutError:
            return SourceResult(available=False, error="Request timeout")
        except Exception as e:
            logger.error(f"VirusTotal query error: {str(e)}")
            return SourceResult(available=False, error=str(e))
    
    def _parse_response(self, data: Dict[str, Any]) -> SourceResult:
        """Parse VirusTotal response and calculate score"""
        try:
            attributes = data.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})
            
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            
            total = malicious + suspicious + harmless + undetected
            
            if total == 0:
                score = 0.0
            else:
                # Calculate score: malicious counts full, suspicious counts half
                score = ((malicious * 100) + (suspicious * 50)) / total
            
            is_malicious = malicious > 0
            
            return SourceResult(
                available=True,
                data={
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "total": total,
                    "reputation": attributes.get("reputation", 0)
                },
                score=min(score, 100.0),
                malicious=is_malicious
            )
        except Exception as e:
            logger.error(f"VirusTotal parse error: {str(e)}")
            return SourceResult(available=False, error=f"Parse error: {str(e)}")


class OTXService(ThreatIntelService):
    """AlienVault OTX API integration"""
    
    BASE_URL = "https://otx.alienvault.com/api/v1"
    
    async def query(self, indicator: str, indicator_type: IndicatorType) -> SourceResult:
        if not self.api_key:
            return SourceResult(available=False, error="API key not configured")
        
        try:
            headers = {"X-OTX-API-KEY": self.api_key}
            
            # Determine endpoint based on indicator type
            if indicator_type == IndicatorType.IP:
                url = f"{self.BASE_URL}/indicators/IPv4/{indicator}/general"
            elif indicator_type == IndicatorType.DOMAIN:
                url = f"{self.BASE_URL}/indicators/domain/{indicator}/general"
            elif indicator_type == IndicatorType.URL:
                url = f"{self.BASE_URL}/indicators/url/{indicator}/general"
            elif indicator_type == IndicatorType.HASH:
                url = f"{self.BASE_URL}/indicators/file/{indicator}/general"
            else:
                return SourceResult(available=False, error="Unsupported indicator type")
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(url, headers=headers) as response:
                    if response.status == 404:
                        return SourceResult(
                            available=True,
                            data={"message": "Not found in OTX"},
                            score=0.0,
                            malicious=False
                        )
                    elif response.status == 429:
                        return SourceResult(available=False, error="Rate limit exceeded")
                    elif response.status != 200:
                        return SourceResult(available=False, error=f"HTTP {response.status}")
                    
                    data = await response.json()
                    return self._parse_response(data)
        
        except asyncio.TimeoutError:
            return SourceResult(available=False, error="Request timeout")
        except Exception as e:
            logger.error(f"OTX query error: {str(e)}")
            return SourceResult(available=False, error=str(e))
    
    def _parse_response(self, data: Dict[str, Any]) -> SourceResult:
        """Parse OTX response and calculate score"""
        try:
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            pulses = data.get("pulse_info", {}).get("pulses", [])
            
            # Calculate score based on pulse count and tags
            if pulse_count == 0:
                score = 0.0
                is_malicious = False
            else:
                # More pulses = higher risk, cap at 100
                score = min(pulse_count * 10, 100.0)
                is_malicious = pulse_count > 0
            
            # Check for malicious tags
            malicious_tags = ["malware", "phishing", "ransomware", "trojan", "botnet"]
            tags_found = []
            for pulse in pulses[:5]:  # Check first 5 pulses
                tags = pulse.get("tags", [])
                tags_found.extend([tag for tag in tags if tag.lower() in malicious_tags])
            
            if tags_found:
                score = min(score + 20, 100.0)
                is_malicious = True
            
            return SourceResult(
                available=True,
                data={
                    "pulse_count": pulse_count,
                    "malicious_tags": list(set(tags_found)),
                    "validation": data.get("validation", [])
                },
                score=score,
                malicious=is_malicious
            )
        except Exception as e:
            logger.error(f"OTX parse error: {str(e)}")
            return SourceResult(available=False, error=f"Parse error: {str(e)}")


class AbuseIPDBService(ThreatIntelService):
    """AbuseIPDB API integration (IP addresses only)"""
    
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    async def query(self, indicator: str, indicator_type: IndicatorType) -> SourceResult:
        if indicator_type != IndicatorType.IP:
            return SourceResult(available=False, error="AbuseIPDB only supports IP addresses")
        
        if not self.api_key:
            return SourceResult(available=False, error="API key not configured")
        
        try:
            headers = {
                "Key": self.api_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": indicator,
                "maxAgeInDays": 90,
                "verbose": ""
            }
            
            url = f"{self.BASE_URL}/check"
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(url, headers=headers, params=params) as response:
                    if response.status == 429:
                        return SourceResult(available=False, error="Rate limit exceeded")
                    elif response.status != 200:
                        return SourceResult(available=False, error=f"HTTP {response.status}")
                    
                    data = await response.json()
                    return self._parse_response(data)
        
        except asyncio.TimeoutError:
            return SourceResult(available=False, error="Request timeout")
        except Exception as e:
            logger.error(f"AbuseIPDB query error: {str(e)}")
            return SourceResult(available=False, error=str(e))
    
    def _parse_response(self, data: Dict[str, Any]) -> SourceResult:
        """Parse AbuseIPDB response and calculate score"""
        try:
            ip_data = data.get("data", {})
            abuse_score = ip_data.get("abuseConfidenceScore", 0)
            total_reports = ip_data.get("totalReports", 0)
            is_whitelisted = ip_data.get("isWhitelisted", False)
            
            # AbuseIPDB score is already 0-100
            score = float(abuse_score)
            
            # Whitelisted IPs get lower score
            if is_whitelisted:
                score = max(0, score - 50)
            
            is_malicious = abuse_score > 50 and not is_whitelisted
            
            return SourceResult(
                available=True,
                data={
                    "abuse_score": abuse_score,
                    "total_reports": total_reports,
                    "is_whitelisted": is_whitelisted,
                    "country": ip_data.get("countryCode"),
                    "isp": ip_data.get("isp")
                },
                score=score,
                malicious=is_malicious
            )
        except Exception as e:
            logger.error(f"AbuseIPDB parse error: {str(e)}")
            return SourceResult(available=False, error=f"Parse error: {str(e)}")


class ShodanService(ThreatIntelService):
    """Shodan API integration (IP addresses only)"""
    
    BASE_URL = "https://api.shodan.io"
    
    async def query(self, indicator: str, indicator_type: IndicatorType) -> SourceResult:
        if indicator_type != IndicatorType.IP:
            return SourceResult(available=False, error="Shodan only supports IP addresses")
        
        if not self.api_key:
            return SourceResult(available=False, error="API key not configured")
        
        try:
            url = f"{self.BASE_URL}/shodan/host/{indicator}"
            params = {"key": self.api_key}
            
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                async with session.get(url, params=params) as response:
                    if response.status == 404:
                        return SourceResult(
                            available=True,
                            data={"message": "Not found in Shodan"},
                            score=0.0,
                            malicious=False
                        )
                    elif response.status == 429:
                        return SourceResult(available=False, error="Rate limit exceeded")
                    elif response.status != 200:
                        return SourceResult(available=False, error=f"HTTP {response.status}")
                    
                    data = await response.json()
                    return self._parse_response(data)
        
        except asyncio.TimeoutError:
            return SourceResult(available=False, error="Request timeout")
        except Exception as e:
            logger.error(f"Shodan query error: {str(e)}")
            return SourceResult(available=False, error=str(e))
    
    def _parse_response(self, data: Dict[str, Any]) -> SourceResult:
        """Parse Shodan response and calculate score"""
        try:
            # Shodan doesn't provide direct malicious score
            # Score based on open ports, vulnerabilities, and tags
            ports = data.get("ports", [])
            vulns = data.get("vulns", [])
            tags = data.get("tags", [])
            
            score = 0.0
            
            # High number of open ports increases score
            if len(ports) > 10:
                score += 20
            elif len(ports) > 5:
                score += 10
            
            # Vulnerabilities significantly increase score
            if vulns:
                score += min(len(vulns) * 15, 50)
            
            # Suspicious tags
            suspicious_tags = ["malware", "honeypot", "scanner", "compromised"]
            if any(tag in suspicious_tags for tag in tags):
                score += 30
            
            score = min(score, 100.0)
            is_malicious = len(vulns) > 0 or score > 50
            
            return SourceResult(
                available=True,
                data={
                    "ports": ports[:10],  # Limit to first 10
                    "vulnerabilities": list(vulns)[:5],  # Limit to first 5
                    "tags": tags,
                    "organization": data.get("org"),
                    "country": data.get("country_name")
                },
                score=score,
                malicious=is_malicious
            )
        except Exception as e:
            logger.error(f"Shodan parse error: {str(e)}")
            return SourceResult(available=False, error=f"Parse error: {str(e)}")


class ThreatIntelAggregator:
    """Aggregates results from multiple threat intelligence services"""
    
    def __init__(self):
        self.services = {
            "virustotal": VirusTotalService(settings.VIRUSTOTAL_API_KEY),
            "otx": OTXService(settings.OTX_API_KEY),
            "abuseipdb": AbuseIPDBService(settings.ABUSEIPDB_API_KEY),
            "shodan": ShodanService(settings.SHODAN_API_KEY)
        }
    
    async def query_all(self, indicator: str, indicator_type: IndicatorType) -> Dict[str, SourceResult]:
        """Query all available services concurrently"""
        tasks = {}
        
        for name, service in self.services.items():
            tasks[name] = service.query(indicator, indicator_type)
        
        # Execute all queries concurrently
        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        
        # Map results back to service names
        output = {}
        for (name, _), result in zip(tasks.items(), results):
            if isinstance(result, Exception):
                output[name] = SourceResult(available=False, error=str(result))
            else:
                output[name] = result
        
        return output
