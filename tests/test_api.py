"""
Simple test script to verify API functionality
Run this after starting the API server
"""
import requests
import json

BASE_URL = "http://localhost:8000"

def test_health():
    """Test health endpoint"""
    print("\n=== Testing Health Endpoint ===")
    response = requests.get(f"{BASE_URL}/health")
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    return response.status_code == 200

def test_register():
    """Test user registration"""
    print("\n=== Testing User Registration ===")
    data = {
        "username": "testuser",
        "password": "testpass123"
    }
    response = requests.post(f"{BASE_URL}/auth/register", json=data)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    return response.status_code in [200, 400]  # 400 if user already exists

def test_login():
    """Test login and get token"""
    print("\n=== Testing Login ===")
    # Try default admin user
    params = {
        "username": "admin",
        "password": "admin123"
    }
    response = requests.post(f"{BASE_URL}/auth/token", params=params)
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"Token received: {data['access_token'][:50]}...")
        return data['access_token']
    else:
        print(f"Response: {response.json()}")
        return None

def test_query_ip(token):
    """Test IP address query"""
    print("\n=== Testing IP Query ===")
    headers = {"Authorization": f"Bearer {token}"}
    data = {
        "indicator": "8.8.8.8",
        "indicator_type": "ip",
        "force_refresh": False
    }
    response = requests.post(f"{BASE_URL}/api/v1/query", json=data, headers=headers)
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        result = response.json()
        print(f"Indicator: {result['indicator']}")
        print(f"Risk Score: {result['risk_score']}")
        print(f"Risk Level: {result['risk_level']}")
        print(f"Cached: {result['cached']}")
        print(f"Sources: {list(result['sources'].keys())}")
        print(f"Summary: {json.dumps(result['summary'], indent=2)}")
    else:
        print(f"Response: {response.json()}")
    return response.status_code == 200

def test_query_domain(token):
    """Test domain query"""
    print("\n=== Testing Domain Query ===")
    headers = {"Authorization": f"Bearer {token}"}
    data = {
        "indicator": "google.com",
        "indicator_type": "domain",
        "force_refresh": False
    }
    response = requests.post(f"{BASE_URL}/api/v1/query", json=data, headers=headers)
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        result = response.json()
        print(f"Indicator: {result['indicator']}")
        print(f"Risk Score: {result['risk_score']}")
        print(f"Risk Level: {result['risk_level']}")
    else:
        print(f"Response: {response.json()}")
    return response.status_code == 200

def test_cache_stats(token):
    """Test cache statistics"""
    print("\n=== Testing Cache Stats ===")
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(f"{BASE_URL}/api/v1/cache/stats", headers=headers)
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    return response.status_code == 200

def run_all_tests():
    """Run all tests"""
    print("=" * 60)
    print("Threat Intelligence API - Test Suite")
    print("=" * 60)
    
    # Test health
    if not test_health():
        print("\n❌ Health check failed. Is the server running?")
        return
    
    # Test registration
    test_register()
    
    # Test login
    token = test_login()
    if not token:
        print("\n❌ Login failed. Cannot continue tests.")
        return
    
    # Test queries
    test_query_ip(token)
    test_query_domain(token)
    
    # Test cache
    test_cache_stats(token)
    
    print("\n" + "=" * 60)
    print("✅ Test suite completed!")
    print("=" * 60)

if __name__ == "__main__":
    try:
        run_all_tests()
    except requests.exceptions.ConnectionError:
        print("\n❌ Cannot connect to API. Make sure the server is running on http://localhost:8000")
    except Exception as e:
        print(f"\n❌ Test failed with error: {str(e)}")
