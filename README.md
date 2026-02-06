# Threat Intelligence API

One API to query multiple threat intelligence sources (VirusTotal, AlienVault OTX, AbuseIPDB, Shodan). Check IPs, domains, URLs, and file hashes. Get a unified risk score instead of juggling 4 different APIs.

## What It Does

Aggregates threat intel from 4 sources into one simple REST API. You send an IP/domain/URL/hash, you get back a risk score (0-100) and detailed results. Built-in caching, authentication, and rate limiting.

Works without API keys for testing. Add keys later for real data.

## Get Started

```bash
# Start it
docker-compose up -d

# Use it
curl http://localhost:8000/docs
```

Default login: `admin` / `admin123`

That's it. API is running on port 8000.

## Example Usage

```bash
# Get a token
curl -X POST "http://localhost:8000/auth/token" \
  -d "username=admin&password=admin123"

# Query an IP
curl -X POST "http://localhost:8000/api/v1/query" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"indicator": "8.8.8.8", "indicator_type": "ip"}'
```

Returns unified risk score + detailed data from all sources.

## Configuration

Edit `.env` file (created from `.env.example`):

```env
SECRET_KEY=generate-a-secure-key-here

# Optional - add these to get real threat intel data
VIRUSTOTAL_API_KEY=your_key
OTX_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
SHODAN_API_KEY=your_key
```

Generate secure key: `python -c "import secrets; print(secrets.token_urlsafe(32))"`

See [docs/API_KEYS_GUIDE.md](docs/API_KEYS_GUIDE.md) for how to get free API keys.

## Testing

```bash
# Run the test suite
python tests/test_api.py

# Or use pytest
pytest tests/ -v
```

## Documentation

- **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)** - Production deployment guide
- **[docs/API_KEYS_GUIDE.md](docs/API_KEYS_GUIDE.md)** - How to get API keys (free options available)
- **[docs/API_REFERENCE.md](docs/API_REFERENCE.md)** - Full API endpoint documentation

Interactive docs at http://localhost:8000/docs after starting the server.

## Why This Exists

Instead of integrating with 4 different threat intel APIs (different auth, different response formats, different rate limits), you get one consistent API. Saves time, reduces complexity, includes smart caching to stay within free tier limits.

Good for security tools, SIEM integrations, incident response, or anything that needs threat intelligence.

## Stack

FastAPI + Redis + Docker. Python 3.11+. JWT auth. Works standalone or as a microservice.

## License

MIT
