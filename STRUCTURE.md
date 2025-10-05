# Project Structure

```
threat-intel-api/
│
├── app/                          # Main application package
│   ├── __init__.py
│   ├── main.py                   # Application entry point
│   │
│   ├── api/                      # API routes and endpoints
│   │   ├── __init__.py
│   │   ├── routes.py             # Route aggregator
│   │   ├── auth.py               # Authentication endpoints
│   │   ├── threat_intel.py       # Threat intelligence endpoints
│   │   └── cache.py              # Cache management endpoints
│   │
│   ├── core/                     # Core business logic
│   │   ├── __init__.py
│   │   ├── config.py             # Configuration & settings
│   │   ├── auth.py               # Authentication logic
│   │   ├── cache.py              # Redis cache manager
│   │   └── risk_scoring.py       # Risk scoring algorithm
│   │
│   ├── models/                   # Data models and schemas
│   │   ├── __init__.py
│   │   └── schemas.py            # Pydantic models
│   │
│   └── services/                 # External service integrations
│       ├── __init__.py
│       └── threat_intel.py       # VirusTotal, OTX, AbuseIPDB, Shodan
│
├── tests/                        # Tests and examples
│   ├── __init__.py
│   ├── test_api.py               # API test suite
│   └── examples.py               # Usage examples
│
├── docs/                         # Documentation
│   ├── __init__.py
│   ├── README.md                 # Detailed documentation
│   └── API_REFERENCE.md          # API endpoint reference
│
├── scripts/                      # Utility scripts
│   ├── __init__.py
│   ├── start.bat                 # Windows startup script
│   └── start.sh                  # Linux/macOS startup script
│
├── README.md                     # Main project README
├── STRUCTURE.md                  # This file
├── LICENSE                       # MIT License
│
├── requirements.txt              # Python dependencies
├── .env.example                  # Environment variables template
├── .gitignore                    # Git ignore rules
│
├── Dockerfile                    # Docker container definition
└── docker-compose.yml            # Docker Compose configuration
```

## Module Descriptions

### `app/main.py`
- FastAPI application initialization
- Middleware configuration (CORS, rate limiting)
- Startup/shutdown events
- Root and health check endpoints

### `app/api/`
**routes.py** - Aggregates all API routers
**auth.py** - User registration, login, token management
**threat_intel.py** - Query endpoints (single & batch)
**cache.py** - Cache statistics and management

### `app/core/`
**config.py** - Pydantic settings, environment variables
**auth.py** - JWT token creation/validation, password hashing, user management
**cache.py** - Redis connection, cache operations (get/set/delete)
**risk_scoring.py** - Unified risk score calculation, source weighting

### `app/models/`
**schemas.py** - All Pydantic models:
- Request/Response models
- User models
- Enums (IndicatorType, RiskLevel)
- Validation logic

### `app/services/`
**threat_intel.py** - External API integrations:
- ThreatIntelService (base class)
- VirusTotalService
- OTXService
- AbuseIPDBService
- ShodanService
- ThreatIntelAggregator (orchestrator)

## Running the Application

### Development
```bash
python -m app.main
```

### Production (Docker)
```bash
docker-compose up -d
```

### Tests
```bash
python tests/test_api.py
python tests/examples.py
```

## Import Structure

All imports use absolute paths from the `app` package:

```python
from app.core.config import settings
from app.models.schemas import User, ThreatQueryRequest
from app.services.threat_intel import ThreatIntelAggregator
from app.core.auth import get_current_active_user
```

## Design Principles

1. **Separation of Concerns** - Each module has a single responsibility
2. **Dependency Injection** - Services are injected where needed
3. **Clean Architecture** - Business logic separated from API layer
4. **Modular Design** - Easy to add new features or services
5. **Type Safety** - Pydantic models for validation
6. **Async/Await** - Non-blocking I/O for performance

## Adding New Features

### New Threat Intelligence Source
1. Add service class in `app/services/threat_intel.py`
2. Register in `ThreatIntelAggregator`
3. Update source weights in `app/core/risk_scoring.py`

### New API Endpoint
1. Create route in appropriate file in `app/api/`
2. Add to `app/api/routes.py` router
3. Update `docs/API_REFERENCE.md`

### New Data Model
1. Add Pydantic model to `app/models/schemas.py`
2. Use in API endpoints and services

## Configuration

All configuration is in `app/core/config.py` using Pydantic Settings.
Environment variables are loaded from `.env` file.

## Testing

Tests are in `tests/` directory:
- `test_api.py` - Automated API tests
- `examples.py` - Usage examples and client library

## Documentation

- `README.md` - Quick start and overview
- `docs/README.md` - Detailed documentation
- `docs/API_REFERENCE.md` - Complete API reference
- `STRUCTURE.md` - This file
