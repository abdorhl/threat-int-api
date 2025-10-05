# API Reference

Complete API endpoint reference for the Threat Intelligence API.

## Base URL

```
http://localhost:8000
```

## Authentication

All API endpoints (except `/auth/*` and `/health`) require authentication using JWT Bearer tokens.

Include the token in the `Authorization` header:
```
Authorization: Bearer <your_token>
```

---

## Endpoints

### Health & Status

#### GET `/`
Root endpoint with API information.

**Response:**
```json
{
  "name": "Threat Intelligence API",
  "version": "1.0.0",
  "status": "operational",
  "docs": "/docs",
  "redoc": "/redoc"
}
```

#### GET `/health`
Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "cache": {
    "enabled": true,
    "total_keys": 5,
    "used_memory": "1.2M"
  },
  "version": "1.0.0"
}
```

---

### Authentication

#### POST `/auth/register`
Register a new user account.

**Request Body:**
```json
{
  "username": "string (min 3, max 50 chars)",
  "password": "string (min 8 chars)"
}
```

**Response:**
```json
{
  "message": "User username created successfully"
}
```

**Status Codes:**
- `200` - Success
- `400` - Username already exists or validation error
- `500` - Internal server error

---

#### POST `/auth/token`
Login and receive JWT access token.

**Request (Form Data):**
```
username=your_username
password=your_password
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

**Status Codes:**
- `200` - Success
- `401` - Invalid credentials

---

#### GET `/auth/me`
Get current authenticated user information.

**Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "username": "string",
  "disabled": false
}
```

**Status Codes:**
- `200` - Success
- `401` - Unauthorized

---

### Threat Intelligence

#### POST `/api/v1/query`
Query threat intelligence for a single indicator.

**Headers:**
```
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "indicator": "string",
  "indicator_type": "ip|domain|url|hash",
  "force_refresh": false
}
```

**Indicator Types:**
- `ip` - IPv4 or IPv6 address
- `domain` - Domain name
- `url` - Full URL
- `hash` - File hash (MD5, SHA1, or SHA256)

**Response:**
```json
{
  "indicator": "8.8.8.8",
  "indicator_type": "ip",
  "risk_score": 15.5,
  "risk_level": "low|medium|high|critical",
  "sources": {
    "virustotal": {
      "available": true,
      "data": {},
      "error": null,
      "score": 10.0,
      "malicious": false
    },
    "otx": {...},
    "abuseipdb": {...},
    "shodan": {...}
  },
  "summary": {
    "total_sources": 4,
    "sources_with_data": 3,
    "malicious_count": 0,
    "suspicious_count": 1,
    "average_source_score": 12.5,
    "failed_sources": [],
    "source_agreement": "agreement_benign"
  },
  "cached": false,
  "timestamp": "2025-10-04T22:52:36Z"
}
```

**Status Codes:**
- `200` - Success
- `400` - Invalid indicator or validation error
- `401` - Unauthorized
- `429` - Rate limit exceeded
- `500` - Internal server error

**Rate Limit:** 10 requests per minute (configurable)

---

#### POST `/api/v1/batch-query`
Query multiple indicators in a single request.

**Headers:**
```
Authorization: Bearer <token>
Content-Type: application/json
```

**Request Body:**
```json
[
  {
    "indicator": "8.8.8.8",
    "indicator_type": "ip",
    "force_refresh": false
  },
  {
    "indicator": "example.com",
    "indicator_type": "domain"
  }
]
```

**Limits:** Maximum 10 indicators per request

**Response:**
```json
{
  "results": [
    {
      "indicator": "8.8.8.8",
      "success": true,
      "data": {
        "indicator": "8.8.8.8",
        "risk_score": 15.5,
        ...
      }
    },
    {
      "indicator": "example.com",
      "success": true,
      "data": {...}
    }
  ],
  "total": 2,
  "successful": 2
}
```

**Status Codes:**
- `200` - Success (individual results may have errors)
- `400` - Too many indicators or validation error
- `401` - Unauthorized
- `429` - Rate limit exceeded

---

### Cache Management

#### GET `/api/v1/cache/stats`
Get cache statistics.

**Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "enabled": true,
  "total_keys": 42,
  "used_memory": "2.5M",
  "connected_clients": 3,
  "uptime_days": 5
}
```

**Status Codes:**
- `200` - Success
- `401` - Unauthorized

---

#### DELETE `/api/v1/cache/{indicator_type}/{indicator}`
Clear cache for a specific indicator.

**Headers:**
```
Authorization: Bearer <token>
```

**Path Parameters:**
- `indicator_type` - Type of indicator (ip, domain, url, hash)
- `indicator` - The indicator value

**Example:**
```
DELETE /api/v1/cache/ip/8.8.8.8
```

**Response:**
```json
{
  "message": "Cache cleared for ip: 8.8.8.8"
}
```

**Status Codes:**
- `200` - Success
- `401` - Unauthorized

---

#### DELETE `/api/v1/cache`
Clear all cached results.

**Headers:**
```
Authorization: Bearer <token>
```

**Response:**
```json
{
  "message": "All cache cleared"
}
```

**Status Codes:**
- `200` - Success
- `401` - Unauthorized

---

## Data Models

### Risk Levels

| Level | Score Range | Description |
|-------|-------------|-------------|
| `low` | 0-20 | Minimal or no threat detected |
| `medium` | 21-50 | Some suspicious activity |
| `high` | 51-75 | Significant threat indicators |
| `critical` | 76-100 | Confirmed malicious activity |

### Source Agreement Values

- `high_agreement_malicious` - 75%+ sources flag as malicious
- `moderate_agreement_malicious` - 50-74% sources flag as malicious
- `low_agreement_malicious` - 25-49% sources flag as malicious
- `agreement_benign` - <25% sources flag as malicious
- `unknown` - No consensus data available

### Indicator Validation

**IP Address:**
- Valid IPv4 or IPv6 format
- Examples: `8.8.8.8`, `2001:4860:4860::8888`

**Domain:**
- Valid domain name format
- Examples: `example.com`, `subdomain.example.org`

**URL:**
- Valid URL format with protocol
- Examples: `https://example.com`, `http://example.com/path`

**Hash:**
- MD5 (32 hex characters)
- SHA1 (40 hex characters)
- SHA256 (64 hex characters)
- Examples: `44d88612fea8a8f36de82e1278abb02f`

---

## Error Responses

All error responses follow this format:

```json
{
  "error": "Error message",
  "status_code": 400,
  "detail": "Detailed error information"
}
```

### Common Error Codes

| Code | Description |
|------|-------------|
| `400` | Bad Request - Invalid input |
| `401` | Unauthorized - Missing or invalid token |
| `429` | Too Many Requests - Rate limit exceeded |
| `500` | Internal Server Error |

---

## Rate Limiting

- **Default Limit:** 10 requests per minute per user
- **Applies to:** All `/api/v1/*` endpoints
- **Cached Results:** Do not count against external API rate limits
- **Response Header:** `X-RateLimit-Remaining` shows remaining requests

When rate limit is exceeded:
```json
{
  "error": "Rate limit exceeded: 10 per 1 minute"
}
```

---

## Caching Behavior

- **Default TTL:** 3600 seconds (1 hour)
- **Cache Key:** Based on indicator + indicator_type
- **Force Refresh:** Use `force_refresh: true` to bypass cache
- **Cache Backend:** Redis

Cached responses include `"cached": true` in the response.

---

## External API Sources

The API aggregates data from these sources:

| Source | Supports | Weight | Notes |
|--------|----------|--------|-------|
| VirusTotal | IP, Domain, URL, Hash | 35% | Most comprehensive |
| AlienVault OTX | IP, Domain, URL, Hash | 25% | Good threat intel |
| AbuseIPDB | IP only | 25% | IP reputation |
| Shodan | IP only | 15% | Infrastructure data |

**Note:** API works with any available API keys. Missing keys will skip those sources.

---

## Examples

### cURL Examples

**Login:**
```bash
curl -X POST "http://localhost:8000/auth/token" \
  -d "username=admin&password=admin123"
```

**Query IP:**
```bash
curl -X POST "http://localhost:8000/api/v1/query" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"indicator": "8.8.8.8", "indicator_type": "ip"}'
```

**Batch Query:**
```bash
curl -X POST "http://localhost:8000/api/v1/batch-query" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '[
    {"indicator": "8.8.8.8", "indicator_type": "ip"},
    {"indicator": "google.com", "indicator_type": "domain"}
  ]'
```

### Python Example

```python
import requests

# Login
response = requests.post(
    "http://localhost:8000/auth/token",
    data={"username": "admin", "password": "admin123"}
)
token = response.json()["access_token"]

# Query
headers = {"Authorization": f"Bearer {token}"}
response = requests.post(
    "http://localhost:8000/api/v1/query",
    headers=headers,
    json={"indicator": "8.8.8.8", "indicator_type": "ip"}
)
result = response.json()
print(f"Risk Score: {result['risk_score']}")
```

---

## Interactive Documentation

- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc

Both provide interactive API testing and complete schema documentation.
