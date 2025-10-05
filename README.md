# Threat Intelligence API

A production-ready REST API that aggregates threat intelligence from multiple sources (VirusTotal, AlienVault OTX, AbuseIPDB, Shodan) with unified risk scoring, caching, and authentication.

## Features

- **Multi-Source Intelligence** - VirusTotal, OTX, AbuseIPDB, Shodan
- **Unified Risk Scoring** - Custom weighted algorithm (0-100 scale)
- **Smart Caching** - Redis-based with configurable TTL
- **Rate Limiting** - Per-user limits with graceful handling
- **JWT Authentication** - Secure token-based auth
- **Input Support** - IP, Domain, URL, File Hash (MD5/SHA1/SHA256)

## Quick Start

### Docker (Recommended)

```bash
# 1. Copy environment file
cp .env.example .env

# 2. Start services
docker-compose up -d

# 3. Access API
open http://localhost:8000/docs
```

### Manual Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start Redis
docker run -d -p 6379:6379 redis:latest

# 3. Configure environment
cp .env.example .env
# Edit .env with your API keys

# 4. Run API
python -m app.main
```

## Usage

### Authentication

```bash
# Login (default: admin/admin123)
curl -X POST "http://localhost:8000/auth/token" \
  -d "username=admin&password=admin123"
```

### Query Threat Intelligence

```bash
# Query IP address
curl -X POST "http://localhost:8000/api/v1/query" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"indicator": "8.8.8.8", "indicator_type": "ip"}'
```

## API Documentation

- **Interactive Docs**: http://localhost:8000/docs
- **API Reference**: [docs/API_REFERENCE.md](docs/API_REFERENCE.md)

## Configuration

Edit `.env` file:

```env
# Security (REQUIRED - generate secure key!)
SECRET_KEY=your-secret-key-here

# External API Keys (Optional)
VIRUSTOTAL_API_KEY=your_key
OTX_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
SHODAN_API_KEY=your_key

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
CACHE_TTL=3600

# Rate Limiting
RATE_LIMIT_PER_MINUTE=10
```

## Project Structure

```
threat-intel-api/
├── app/
│   ├── main.py              # Application entry point
│   ├── api/                 # API routes
│   ├── core/                # Core functionality
│   ├── models/              # Data models
│   └── services/            # External integrations
├── tests/                   # Tests and examples
├── docs/                    # Documentation
├── scripts/                 # Utility scripts
├── requirements.txt
├── docker-compose.yml
└── Dockerfile
```

## Risk Scoring

- **Low (0-20)** - Minimal threat
- **Medium (21-50)** - Suspicious activity
- **High (51-75)** - Significant threat
- **Critical (76-100)** - Confirmed malicious

Algorithm uses weighted sources:
- VirusTotal: 35%
- OTX: 25%
- AbuseIPDB: 25%
- Shodan: 15%

## Testing

```bash
# Run tests
python tests/test_api.py

# Run examples
python tests/examples.py
```

## Production Deployment

1. **Generate secure SECRET_KEY**
   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

2. **Add API keys** to `.env`

3. **Deploy with Docker**
   ```bash
   docker-compose up -d
   ```

4. **Use reverse proxy** (nginx/Caddy) for HTTPS

## License

MIT License - See LICENSE file

## Support

- Documentation: [docs/](docs/)
- Interactive API: http://localhost:8000/docs
- Health Check: http://localhost:8000/health
