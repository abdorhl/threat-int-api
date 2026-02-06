# Production Deployment Guide

This guide covers deploying the Threat Intelligence API in production environments with best practices for security, scalability, and reliability.

## 📋 Pre-Deployment Checklist

### Security
- [ ] Generate secure `SECRET_KEY` (32+ characters)
- [ ] Change default admin password
- [ ] Configure HTTPS/TLS certificates
- [ ] Set up firewall rules
- [ ] Enable API rate limiting
- [ ] Configure CORS for specific origins only
- [ ] Rotate API keys regularly
- [ ] Set up monitoring and alerting
- [ ] Enable audit logging
- [ ] Review and restrict file permissions

### Infrastructure
- [ ] Set up Redis with persistence
- [ ] Configure backup strategy
- [ ] Set up load balancer (if needed)
- [ ] Configure health check endpoints
- [ ] Set up log aggregation
- [ ] Configure resource limits
- [ ] Plan for high availability
- [ ] Set up staging environment

### Configuration
- [ ] Obtain production API keys for threat intel sources
- [ ] Configure production environment variables
- [ ] Set appropriate cache TTL values
- [ ] Configure rate limits based on expected load
- [ ] Set up database persistence (if moving beyond in-memory users)
- [ ] Configure timezone and locale
- [ ] Set up email notifications (if needed)

## 🔐 Security Configuration

### Generate Secure SECRET_KEY

```bash
# Generate a cryptographically secure secret key
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Add to your `.env` file:
```env
SECRET_KEY=your-generated-secure-key-here
```

### Environment Variables for Production

Create a production `.env` file with secure values:

```env
# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
API_TITLE=Threat Intelligence API
API_VERSION=1.0.0

# Security (CRITICAL - Use secure values!)
SECRET_KEY=<GENERATED_SECURE_KEY>
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# External API Keys
VIRUSTOTAL_API_KEY=<your_production_key>
OTX_API_KEY=<your_production_key>
ABUSEIPDB_API_KEY=<your_production_key>
SHODAN_API_KEY=<your_production_key>

# Redis Configuration (Production values)
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_DB=0
REDIS_PASSWORD=<strong_password>
CACHE_TTL=3600

# Rate Limiting (Adjust based on your needs)
RATE_LIMIT_ENABLED=true
RATE_LIMIT_PER_MINUTE=60
```

### CORS Configuration

Update [app/main.py](app/main.py) for production:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://yourdomain.com",
        "https://app.yourdomain.com"
    ],  # Specific origins only
    allow_credentials=True,
    allow_methods=["GET", "POST"],  # Limit to needed methods
    allow_headers=["Authorization", "Content-Type"],
)
```

## 🚀 Deployment Options

### Option 1: Docker Compose (Recommended for Small-Medium Scale)

#### Production docker-compose.yml

```yaml
version: '3.8'

services:
  redis:
    image: redis:7-alpine
    container_name: threat-intel-redis
    restart: always
    command: redis-server --requirepass ${REDIS_PASSWORD} --appendonly yes
    volumes:
      - redis_data:/data
    networks:
      - internal
    healthcheck:
      test: ["CMD", "redis-cli", "--raw", "incr", "ping"]
      interval: 10s
      timeout: 3s
      retries: 3

  api:
    build: .
    container_name: threat-intel-api
    restart: always
    ports:
      - "8000:8000"
    environment:
      - REDIS_HOST=redis
      - REDIS_PORT=6379
      - REDIS_PASSWORD=${REDIS_PASSWORD}
    env_file:
      - .env
    depends_on:
      redis:
        condition: service_healthy
    networks:
      - internal
      - web
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

networks:
  internal:
    driver: bridge
  web:
    driver: bridge

volumes:
  redis_data:
    driver: local
```

#### Deploy

```bash
# Pull latest code
git pull origin main

# Build and start services
docker-compose -f docker-compose.prod.yml up -d --build

# Verify services are running
docker-compose ps

# Check logs
docker-compose logs -f api
```

### Option 2: Kubernetes (For Large Scale)

#### deployment.yaml

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: threat-intel-api
  labels:
    app: threat-intel-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: threat-intel-api
  template:
    metadata:
      labels:
        app: threat-intel-api
    spec:
      containers:
      - name: api
        image: your-registry/threat-intel-api:latest
        ports:
        - containerPort: 8000
        env:
        - name: REDIS_HOST
          value: redis-service
        - name: SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: api-secrets
              key: secret-key
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
---
apiVersion: v1
kind: Service
metadata:
  name: threat-intel-service
spec:
  selector:
    app: threat-intel-api
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8000
  type: LoadBalancer
```

### Option 3: Cloud Services (AWS, Azure, GCP)

#### AWS Elastic Beanstalk

```bash
# Install EB CLI
pip install awsebcli

# Initialize
eb init -p docker threat-intel-api

# Create environment
eb create production-env

# Deploy
eb deploy
```

#### Azure Container Instances

```bash
# Create resource group
az group create --name threat-intel-rg --location eastus

# Create container
az container create \
  --resource-group threat-intel-rg \
  --name threat-intel-api \
  --image your-registry/threat-intel-api:latest \
  --dns-name-label threat-intel-api \
  --ports 8000 \
  --environment-variables SECRET_KEY=<your-key>
```

## 🔧 Production Optimization

### Gunicorn with Multiple Workers

Update Dockerfile for production:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Copy application
COPY . .

# Create non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8000

# Run with Gunicorn
CMD ["gunicorn", "app.main:app", "-k", "uvicorn.workers.UvicornWorker", "-w", "4", "-b", "0.0.0.0:8000", "--access-logfile", "-", "--error-logfile", "-"]
```

### Nginx Reverse Proxy

```nginx
upstream threat_intel_api {
    server localhost:8000;
}

server {
    listen 80;
    server_name api.yourdomain.com;
    
    # Redirect to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;
    
    ssl_certificate /etc/ssl/certs/your-cert.crt;
    ssl_certificate_key /etc/ssl/private/your-key.key;
    
    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
    
    location / {
        limit_req zone=api_limit burst=20 nodelay;
        
        proxy_pass http://threat_intel_api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

### Redis Configuration for Production

Create `redis.conf`:

```conf
# Persistence
appendonly yes
appendfsync everysec

# Memory management
maxmemory 2gb
maxmemory-policy allkeys-lru

# Security
requirepass your-strong-password

# Performance
tcp-backlog 511
timeout 300

# Logging
loglevel notice
logfile /var/log/redis/redis.log
```

## 📊 Monitoring and Logging

### Application Metrics

Add Prometheus metrics:

```python
# requirements.txt
prometheus-fastapi-instrumentator==6.1.0

# app/main.py
from prometheus_fastapi_instrumentator import Instrumentator

app = FastAPI(...)

Instrumentator().instrument(app).expose(app)
```

### Health Checks

The `/health` endpoint provides comprehensive status:

```bash
curl https://api.yourdomain.com/health
```

Monitor:
- Redis connectivity
- API source availability
- Application version
- Cache statistics

### Logging Strategy

```python
# app/main.py
import logging
from logging.handlers import RotatingFileHandler

# File logging
file_handler = RotatingFileHandler(
    'logs/app.log',
    maxBytes=10485760,  # 10MB
    backupCount=5
)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
))

logging.basicConfig(
    level=logging.INFO,
    handlers=[
        file_handler,
        logging.StreamHandler()
    ]
)
```

### Centralized Logging (ELK Stack)

```yaml
# docker-compose with logging
services:
  api:
    # ... other config ...
    logging:
      driver: "fluentd"
      options:
        fluentd-address: localhost:24224
        tag: threat-intel-api
```

## 🔄 Backup and Recovery

### Redis Backup

```bash
# Manual backup
docker exec threat-intel-redis redis-cli --rdb /data/dump.rdb

# Automated daily backup script
#!/bin/bash
BACKUP_DIR="/backups/redis"
DATE=$(date +%Y%m%d_%H%M%S)

docker exec threat-intel-redis redis-cli save
docker cp threat-intel-redis:/data/dump.rdb $BACKUP_DIR/dump_$DATE.rdb

# Keep only last 7 days
find $BACKUP_DIR -name "dump_*.rdb" -mtime +7 -delete
```

### Database Backup (When Using Real DB)

When migrating from in-memory users to a real database:

```bash
# PostgreSQL example
docker exec postgres pg_dump -U user threat_intel > backup_$(date +%Y%m%d).sql
```

## 📈 Scaling Strategies

### Horizontal Scaling

1. **Load Balancer**: Deploy multiple API instances behind a load balancer
2. **Redis Cluster**: Use Redis Cluster for distributed caching
3. **API Gateway**: Consider Kong or AWS API Gateway
4. **CDN**: Use CloudFlare or AWS CloudFront for static content

### Vertical Scaling

```yaml
# Increase resources in docker-compose
services:
  api:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G
```

### Caching Strategy

```python
# Longer TTL for less critical data
CACHE_TTL_CRITICAL = 300     # 5 minutes
CACHE_TTL_STANDARD = 3600    # 1 hour
CACHE_TTL_HISTORICAL = 86400 # 24 hours
```

## 🛡️ Security Hardening

### 1. API Key Rotation

```bash
# Rotate keys monthly
# Update .env with new keys
# Restart services
docker-compose restart api
```

### 2. User Management

Move from in-memory to database:

```python
# Use PostgreSQL or MongoDB for production
# Implement proper user management
# Add email verification
# Implement MFA (Multi-Factor Authentication)
```

### 3. Network Security

```bash
# Firewall rules
# Allow only specific IPs
sudo ufw allow from <your-ip> to any port 8000

# Restrict Redis access
sudo ufw deny 6379
sudo ufw allow from 172.18.0.0/16 to any port 6379  # Docker network
```

### 4. Regular Updates

```bash
# Update dependencies
pip list --outdated
pip install -U <package>

# Update base images
docker-compose pull
docker-compose up -d --build
```

## 📊 Performance Tuning

### Database Connection Pooling

```python
# For future DB implementation
from sqlalchemy.pool import QueuePool

engine = create_engine(
    DATABASE_URL,
    poolclass=QueuePool,
    pool_size=10,
    max_overflow=20
)
```

### Async Optimization

```python
# Use connection pooling for external APIs
connector = aiohttp.TCPConnector(
    limit=100,
    limit_per_host=10
)
```

### Redis Optimization

```python
# Use pipeline for batch operations
pipe = redis.pipeline()
for key, value in items:
    pipe.set(key, value)
pipe.execute()
```

## 🚨 Incident Response

### Common Issues

**High Memory Usage**
```bash
# Check container stats
docker stats

# Restart if needed
docker-compose restart api
```

**Redis Connection Loss**
```bash
# Check Redis
docker logs threat-intel-redis

# Restart Redis
docker-compose restart redis
```

**High Response Times**
```bash
# Check API logs
docker logs threat-intel-api --tail=100

# Monitor external API latency
# Consider increasing cache TTL
```

## 📞 Support and Maintenance

### Regular Maintenance Tasks

- **Daily**: Check logs for errors
- **Weekly**: Review metrics and performance
- **Monthly**: Update dependencies, rotate keys
- **Quarterly**: Security audit, load testing

### Monitoring Alerts

Set up alerts for:
- API response time > 2s
- Error rate > 1%
- Redis memory usage > 80%
- Disk usage > 85%
- CPU usage > 80% for 5+ minutes

## 📚 Additional Resources

- [FastAPI Deployment](https://fastapi.tiangolo.com/deployment/)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)
- [Redis Production Checklist](https://redis.io/topics/admin)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)

---

**Last Updated**: February 2026  
**Maintained By**: Development Team
