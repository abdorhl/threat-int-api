"""
Comprehensive pytest tests for Threat Intelligence API
"""
import pytest
from fastapi import status


class TestHealthEndpoints:
    """Test health check and root endpoints"""
    
    def test_root_endpoint(self, client):
        """Test root endpoint returns basic info"""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "name" in data
        assert "version" in data
        assert "status" in data
        assert data["status"] == "operational"
    
    def test_health_check(self, client):
        """Test health check endpoint"""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert "cache" in data
        assert "version" in data


class TestAuthentication:
    """Test authentication endpoints"""
    
    def test_register_new_user(self, client):
        """Test user registration"""
        response = client.post(
            "/auth/register",
            json={"username": "newuser", "password": "newpass123"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "newuser"
        assert "hashed_password" not in data
    
    def test_register_duplicate_user(self, client):
        """Test registering duplicate username fails"""
        response = client.post(
            "/auth/register",
            json={"username": "admin", "password": "password123"}
        )
        assert response.status_code == 400
        assert "already registered" in response.json()["detail"]
    
    def test_login_success(self, client):
        """Test successful login"""
        response = client.post(
            "/auth/token",
            data={"username": "admin", "password": "admin123"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "token_type" in data
        assert data["token_type"] == "bearer"
    
    def test_login_invalid_password(self, client):
        """Test login with invalid password"""
        response = client.post(
            "/auth/token",
            data={"username": "admin", "password": "wrongpassword"}
        )
        assert response.status_code == 401
    
    def test_login_invalid_username(self, client):
        """Test login with invalid username"""
        response = client.post(
            "/auth/token",
            data={"username": "nonexistent", "password": "password"}
        )
        assert response.status_code == 401
    
    def test_get_current_user(self, client, auth_headers):
        """Test getting current user info"""
        response = client.get("/auth/me", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "admin"
    
    def test_unauthorized_access(self, client):
        """Test accessing protected endpoint without token"""
        response = client.post(
            "/api/v1/query",
            json={"indicator": "8.8.8.8", "indicator_type": "ip"}
        )
        assert response.status_code == 403


class TestThreatIntelligence:
    """Test threat intelligence query endpoints"""
    
    def test_query_ip_address(self, client, auth_headers, sample_indicators):
        """Test querying an IP address"""
        response = client.post(
            "/api/v1/query",
            headers=auth_headers,
            json={
                "indicator": sample_indicators["ip"],
                "indicator_type": "ip",
                "force_refresh": False
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["indicator"] == sample_indicators["ip"]
        assert data["indicator_type"] == "ip"
        assert "risk_score" in data
        assert "risk_level" in data
        assert "sources" in data
        assert "summary" in data
        assert isinstance(data["cached"], bool)
    
    def test_query_domain(self, client, auth_headers, sample_indicators):
        """Test querying a domain"""
        response = client.post(
            "/api/v1/query",
            headers=auth_headers,
            json={
                "indicator": sample_indicators["domain"],
                "indicator_type": "domain",
                "force_refresh": False
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["indicator"] == sample_indicators["domain"]
        assert data["indicator_type"] == "domain"
    
    def test_query_invalid_ip(self, client, auth_headers):
        """Test querying an invalid IP address"""
        response = client.post(
            "/api/v1/query",
            headers=auth_headers,
            json={
                "indicator": "999.999.999.999",
                "indicator_type": "ip"
            }
        )
        assert response.status_code == 422  # Validation error
    
    def test_query_invalid_domain(self, client, auth_headers):
        """Test querying an invalid domain"""
        response = client.post(
            "/api/v1/query",
            headers=auth_headers,
            json={
                "indicator": "not a domain!@#",
                "indicator_type": "domain"
            }
        )
        assert response.status_code == 422
    
    def test_query_cache_hit(self, client, auth_headers, sample_indicators):
        """Test that second query returns cached result"""
        # First query
        response1 = client.post(
            "/api/v1/query",
            headers=auth_headers,
            json={
                "indicator": sample_indicators["ip"],
                "indicator_type": "ip"
            }
        )
        assert response1.status_code == 200
        assert response1.json()["cached"] is False
        
        # Second query should be cached
        response2 = client.post(
            "/api/v1/query",
            headers=auth_headers,
            json={
                "indicator": sample_indicators["ip"],
                "indicator_type": "ip"
            }
        )
        assert response2.status_code == 200
        assert response2.json()["cached"] is True
    
    def test_query_force_refresh(self, client, auth_headers, sample_indicators):
        """Test force refresh bypasses cache"""
        # First query to cache it
        client.post(
            "/api/v1/query",
            headers=auth_headers,
            json={
                "indicator": sample_indicators["ip"],
                "indicator_type": "ip"
            }
        )
        
        # Force refresh should not use cache
        response = client.post(
            "/api/v1/query",
            headers=auth_headers,
            json={
                "indicator": sample_indicators["ip"],
                "indicator_type": "ip",
                "force_refresh": True
            }
        )
        assert response.status_code == 200
        assert response.json()["cached"] is False
    
    def test_batch_query(self, client, auth_headers, sample_indicators):
        """Test batch query endpoint"""
        response = client.post(
            "/api/v1/batch-query",
            headers=auth_headers,
            json=[
                {"indicator": sample_indicators["ip"], "indicator_type": "ip"},
                {"indicator": sample_indicators["domain"], "indicator_type": "domain"}
            ]
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data["results"]) == 2
    
    def test_batch_query_limit(self, client, auth_headers):
        """Test batch query respects limit"""
        queries = [
            {"indicator": f"192.168.1.{i}", "indicator_type": "ip"}
            for i in range(15)
        ]
        response = client.post(
            "/api/v1/batch-query",
            headers=auth_headers,
            json=queries
        )
        assert response.status_code == 400
        assert "maximum" in response.json()["detail"].lower()


class TestCacheManagement:
    """Test cache management endpoints"""
    
    def test_get_cache_stats(self, client, auth_headers):
        """Test getting cache statistics"""
        response = client.get("/api/v1/cache/stats", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "total_keys" in data or "connected" in data
    
    def test_clear_cache(self, client, auth_headers):
        """Test clearing cache"""
        response = client.post("/api/v1/cache/clear", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "message" in data


class TestValidation:
    """Test input validation"""
    
    def test_missing_indicator(self, client, auth_headers):
        """Test request with missing indicator"""
        response = client.post(
            "/api/v1/query",
            headers=auth_headers,
            json={"indicator_type": "ip"}
        )
        assert response.status_code == 422
    
    def test_missing_indicator_type(self, client, auth_headers):
        """Test request with missing indicator type"""
        response = client.post(
            "/api/v1/query",
            headers=auth_headers,
            json={"indicator": "8.8.8.8"}
        )
        assert response.status_code == 422
    
    def test_invalid_indicator_type(self, client, auth_headers):
        """Test request with invalid indicator type"""
        response = client.post(
            "/api/v1/query",
            headers=auth_headers,
            json={"indicator": "8.8.8.8", "indicator_type": "invalid"}
        )
        assert response.status_code == 422


@pytest.mark.asyncio
class TestAsyncOperations:
    """Test async operations"""
    
    async def test_concurrent_queries(self, client, auth_headers, sample_indicators):
        """Test handling concurrent queries"""
        # This would require async test client, demonstrating structure
        pass
