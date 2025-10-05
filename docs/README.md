# Threat Intelligence API

A comprehensive threat intelligence aggregation API that queries multiple public threat intelligence services and provides unified risk scoring.

## Features

- **Multi-Source Intelligence**: Integrates with VirusTotal, AlienVault OTX, AbuseIPDB, and Shodan
- **Unified Risk Scoring**: Custom algorithm that combines results from multiple sources
- **Smart Caching**: Redis-based caching for repeated queries
- **Rate Limiting**: Built-in rate limit handling for external APIs
- **Authentication**: JWT-based authentication system
- **Input Validation**: Supports IP addresses, domains, URLs, and file hashes

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set up Redis (required for caching):
```bash
# Using Docker
docker run -d -p 6379:6379 redis:latest

# Or install Redis locally
# Windows: https://redis.io/docs/getting-started/installation/install-redis-on-windows/
# Linux: sudo apt-get install redis-server
# macOS: brew install redis
```

3. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your API keys and configuration
```

4. Generate a secure secret key:
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

## Configuration

Edit `.env` file with your settings:

- **API Keys**: Add your threat intelligence service API keys (optional, API works with available keys)
- **Secret Key**: Set a strong secret key for JWT authentication
- **Redis**: Configure Redis connection settings
- **Rate Limiting**: Adjust rate limits as needed

## Running the API

```bash
python main.py
```

Or with uvicorn directly:
```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

The API will be available at `http://localhost:8000`

## API Documentation

Interactive API documentation is available at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## Authentication

### Create an API Key

```bash
POST /auth/register
{
  "username": "your_username",
  "password": "your_password"
}
```

### Login to get JWT token

```bash
POST /auth/token
{
  "username": "your_username",
  "password": "your_password"
}
```

### Use the token in requests

```bash
Authorization: Bearer <your_token>
```

## Usage Examples

### Query an IP Address

```bash
curl -X POST "http://localhost:8000/api/v1/query" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"indicator": "8.8.8.8", "indicator_type": "ip"}'
```

### Query a Domain

```bash
curl -X POST "http://localhost:8000/api/v1/query" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"indicator": "example.com", "indicator_type": "domain"}'
```

### Query a URL

```bash
curl -X POST "http://localhost:8000/api/v1/query" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"indicator": "https://example.com/page", "indicator_type": "url"}'
```

### Query a File Hash

```bash
curl -X POST "http://localhost:8000/api/v1/query" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"indicator": "44d88612fea8a8f36de82e1278abb02f", "indicator_type": "hash"}'
```

## Risk Scoring

The API uses a custom risk scoring algorithm that:

1. Normalizes scores from different sources (0-100 scale)
2. Applies weighted averaging based on source reliability
3. Considers detection ratios, reputation scores, and threat categories
4. Provides a final unified risk score (0-100)

**Risk Levels**:
- 0-20: Low Risk
- 21-50: Medium Risk
- 51-75: High Risk
- 76-100: Critical Risk

## Response Format

```json
{
  "indicator": "8.8.8.8",
  "indicator_type": "ip",
  "risk_score": 15,
  "risk_level": "low",
  "sources": {
    "virustotal": {...},
    "otx": {...},
    "abuseipdb": {...},
    "shodan": {...}
  },
  "summary": {
    "total_sources": 4,
    "sources_with_data": 3,
    "malicious_count": 0,
    "suspicious_count": 1
  },
  "cached": false,
  "timestamp": "2025-10-04T22:52:36Z"
}
```

## Rate Limiting

- Default: 10 requests per minute per user
- Rate limits apply per authenticated user
- Cached results don't count against external API rate limits

## Error Handling

The API includes comprehensive error handling:
- Invalid input validation
- External API failures (graceful degradation)
- Rate limit exceeded responses
- Authentication errors

## Security Best Practices

1. Always use HTTPS in production
2. Keep your `.env` file secure and never commit it
3. Rotate API keys regularly
4. Use strong passwords for user accounts
5. Monitor API usage and set appropriate rate limits

## License

MIT License
