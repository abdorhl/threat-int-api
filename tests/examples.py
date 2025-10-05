"""
Example usage of the Threat Intelligence API
This demonstrates how to use the API programmatically
"""
import requests
import json
from typing import Optional, Dict, Any


class ThreatIntelClient:
    """Client for interacting with the Threat Intelligence API"""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url
        self.token: Optional[str] = None
    
    def register(self, username: str, password: str) -> Dict[str, Any]:
        """Register a new user"""
        response = requests.post(
            f"{self.base_url}/auth/register",
            json={"username": username, "password": password}
        )
        return response.json()
    
    def login(self, username: str, password: str) -> bool:
        """Login and store token"""
        response = requests.post(
            f"{self.base_url}/auth/token",
            data={"username": username, "password": password}
        )
        
        if response.status_code == 200:
            data = response.json()
            self.token = data["access_token"]
            return True
        return False
    
    def _get_headers(self) -> Dict[str, str]:
        """Get authorization headers"""
        if not self.token:
            raise ValueError("Not authenticated. Please login first.")
        return {"Authorization": f"Bearer {self.token}"}
    
    def query(self, indicator: str, indicator_type: str, force_refresh: bool = False) -> Dict[str, Any]:
        """Query threat intelligence for an indicator"""
        response = requests.post(
            f"{self.base_url}/api/v1/query",
            headers=self._get_headers(),
            json={
                "indicator": indicator,
                "indicator_type": indicator_type,
                "force_refresh": force_refresh
            }
        )
        return response.json()
    
    def batch_query(self, indicators: list) -> Dict[str, Any]:
        """Batch query multiple indicators"""
        response = requests.post(
            f"{self.base_url}/api/v1/batch-query",
            headers=self._get_headers(),
            json=indicators
        )
        return response.json()
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        response = requests.get(
            f"{self.base_url}/api/v1/cache/stats",
            headers=self._get_headers()
        )
        return response.json()
    
    def clear_cache(self) -> Dict[str, Any]:
        """Clear all cache"""
        response = requests.delete(
            f"{self.base_url}/api/v1/cache",
            headers=self._get_headers()
        )
        return response.json()


def example_basic_usage():
    """Example: Basic usage"""
    print("\n" + "="*60)
    print("Example 1: Basic Usage")
    print("="*60)
    
    # Create client
    client = ThreatIntelClient()
    
    # Login with default credentials
    print("\n1. Logging in...")
    if client.login("admin", "admin123"):
        print("✓ Login successful")
    else:
        print("✗ Login failed")
        return
    
    # Query an IP address
    print("\n2. Querying IP address 8.8.8.8...")
    result = client.query("8.8.8.8", "ip")
    
    print(f"\nRisk Score: {result['risk_score']}")
    print(f"Risk Level: {result['risk_level']}")
    print(f"Cached: {result['cached']}")
    print(f"\nSummary:")
    print(f"  - Total Sources: {result['summary']['total_sources']}")
    print(f"  - Sources with Data: {result['summary']['sources_with_data']}")
    print(f"  - Malicious Count: {result['summary']['malicious_count']}")
    print(f"  - Source Agreement: {result['summary']['source_agreement']}")
    
    # Show source results
    print(f"\nSource Results:")
    for source_name, source_data in result['sources'].items():
        status = "✓" if source_data['available'] else "✗"
        score = source_data.get('score', 'N/A')
        print(f"  {status} {source_name}: Score={score}")


def example_batch_query():
    """Example: Batch query multiple indicators"""
    print("\n" + "="*60)
    print("Example 2: Batch Query")
    print("="*60)
    
    client = ThreatIntelClient()
    
    # Login
    print("\n1. Logging in...")
    if not client.login("admin", "admin123"):
        print("✗ Login failed")
        return
    
    # Batch query
    print("\n2. Querying multiple indicators...")
    indicators = [
        {"indicator": "8.8.8.8", "indicator_type": "ip"},
        {"indicator": "1.1.1.1", "indicator_type": "ip"},
        {"indicator": "google.com", "indicator_type": "domain"},
    ]
    
    result = client.batch_query(indicators)
    
    print(f"\nTotal queries: {result['total']}")
    print(f"Successful: {result['successful']}")
    
    print("\nResults:")
    for item in result['results']:
        if item['success']:
            data = item['data']
            print(f"\n  {item['indicator']}:")
            print(f"    Risk Score: {data['risk_score']}")
            print(f"    Risk Level: {data['risk_level']}")
        else:
            print(f"\n  {item['indicator']}: Failed - {item['error']}")


def example_different_indicator_types():
    """Example: Query different indicator types"""
    print("\n" + "="*60)
    print("Example 3: Different Indicator Types")
    print("="*60)
    
    client = ThreatIntelClient()
    
    # Login
    if not client.login("admin", "admin123"):
        print("✗ Login failed")
        return
    
    # Test different indicator types
    test_cases = [
        ("8.8.8.8", "ip", "IP Address"),
        ("google.com", "domain", "Domain"),
        ("https://www.google.com", "url", "URL"),
        ("44d88612fea8a8f36de82e1278abb02f", "hash", "File Hash (MD5)"),
    ]
    
    for indicator, indicator_type, description in test_cases:
        print(f"\n{description}: {indicator}")
        try:
            result = client.query(indicator, indicator_type)
            print(f"  Risk Score: {result['risk_score']}")
            print(f"  Risk Level: {result['risk_level']}")
            print(f"  Sources Available: {result['summary']['sources_with_data']}/{result['summary']['total_sources']}")
        except Exception as e:
            print(f"  Error: {str(e)}")


def example_cache_management():
    """Example: Cache management"""
    print("\n" + "="*60)
    print("Example 4: Cache Management")
    print("="*60)
    
    client = ThreatIntelClient()
    
    # Login
    if not client.login("admin", "admin123"):
        print("✗ Login failed")
        return
    
    # First query (not cached)
    print("\n1. First query (will hit external APIs)...")
    result1 = client.query("8.8.8.8", "ip")
    print(f"   Cached: {result1['cached']}")
    print(f"   Risk Score: {result1['risk_score']}")
    
    # Second query (should be cached)
    print("\n2. Second query (should be cached)...")
    result2 = client.query("8.8.8.8", "ip")
    print(f"   Cached: {result2['cached']}")
    print(f"   Risk Score: {result2['risk_score']}")
    
    # Get cache stats
    print("\n3. Cache statistics...")
    stats = client.get_cache_stats()
    print(f"   Cache Enabled: {stats.get('enabled', False)}")
    if stats.get('enabled'):
        print(f"   Total Keys: {stats.get('total_keys', 0)}")
        print(f"   Used Memory: {stats.get('used_memory', 'N/A')}")
    
    # Force refresh (bypass cache)
    print("\n4. Force refresh (bypass cache)...")
    result3 = client.query("8.8.8.8", "ip", force_refresh=True)
    print(f"   Cached: {result3['cached']}")
    print(f"   Risk Score: {result3['risk_score']}")


def example_risk_analysis():
    """Example: Analyzing risk scores"""
    print("\n" + "="*60)
    print("Example 5: Risk Analysis")
    print("="*60)
    
    client = ThreatIntelClient()
    
    # Login
    if not client.login("admin", "admin123"):
        print("✗ Login failed")
        return
    
    # Query multiple IPs and analyze
    test_ips = [
        "8.8.8.8",      # Google DNS - should be low risk
        "1.1.1.1",      # Cloudflare DNS - should be low risk
        "127.0.0.1",    # Localhost
    ]
    
    print("\nAnalyzing multiple IP addresses...\n")
    
    results = []
    for ip in test_ips:
        try:
            result = client.query(ip, "ip")
            results.append({
                "ip": ip,
                "risk_score": result['risk_score'],
                "risk_level": result['risk_level'],
                "malicious_count": result['summary']['malicious_count'],
                "sources_with_data": result['summary']['sources_with_data']
            })
        except Exception as e:
            print(f"Error querying {ip}: {str(e)}")
    
    # Sort by risk score
    results.sort(key=lambda x: x['risk_score'], reverse=True)
    
    # Display results
    print(f"{'IP Address':<15} {'Risk Score':<12} {'Risk Level':<12} {'Malicious':<12} {'Sources'}")
    print("-" * 70)
    for r in results:
        print(f"{r['ip']:<15} {r['risk_score']:<12.2f} {r['risk_level']:<12} {r['malicious_count']:<12} {r['sources_with_data']}")


def main():
    """Run all examples"""
    print("\n" + "="*60)
    print("Threat Intelligence API - Usage Examples")
    print("="*60)
    print("\nMake sure the API server is running at http://localhost:8000")
    print("Default credentials: admin / admin123")
    
    try:
        # Run examples
        example_basic_usage()
        example_batch_query()
        example_different_indicator_types()
        example_cache_management()
        example_risk_analysis()
        
        print("\n" + "="*60)
        print("All examples completed successfully!")
        print("="*60 + "\n")
        
    except requests.exceptions.ConnectionError:
        print("\n✗ Cannot connect to API. Make sure the server is running.")
    except Exception as e:
        print(f"\n✗ Error: {str(e)}")


if __name__ == "__main__":
    main()
