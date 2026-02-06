# 🔑 Obtaining Threat Intelligence API Keys

This guide explains how to obtain API keys for the external threat intelligence services supported by this API.

## Overview

The Threat Intelligence API integrates with four major threat intelligence sources:

| Service | Required | Free Tier | Rate Limits | Best For |
|---------|----------|-----------|-------------|----------|
| **VirusTotal** | No | Yes | 4 req/min | Files, URLs, IPs, Domains |
| **AlienVault OTX** | No | Yes | Good limits | IP reputation, indicators |
| **AbuseIPDB** | No | Yes | 1,000 req/day | IP abuse reports |
| **Shodan** | No | Paid | Varies | Internet-connected devices |

**Note**: The API works without any keys, but results will be limited. You can add keys one at a time as needed.

---

## 1. VirusTotal

**What it provides**: Malware scanning, URL/file/IP/domain reputation

### Get Your API Key

1. **Sign up**: https://www.virustotal.com/gui/join-us
2. **Verify email**
3. **Get API key**: https://www.virustotal.com/gui/my-apikey
4. **Copy the key**

### Free Tier
- ✅ 4 requests per minute
- ✅ 500 requests per day
- ✅ All indicator types (IP, domain, URL, hash)

### Add to .env
```env
VIRUSTOTAL_API_KEY=your_actual_api_key_here
```

### API Documentation
- https://developers.virustotal.com/reference/overview

---

## 2. AlienVault OTX (Open Threat Exchange)

**What it provides**: Community-driven threat intelligence, pulse feeds

### Get Your API Key

1. **Sign up**: https://otx.alienvault.com/accounts/signup/
2. **Verify email**
3. **Get API key**: https://otx.alienvault.com/settings
   - Click on "Settings" (top right)
   - Find "OTX Key" section
4. **Copy the key**

### Free Tier
- ✅ Unlimited API requests (reasonable use)
- ✅ Community threat feeds
- ✅ Historical data
- ✅ All indicator types

### Add to .env
```env
OTX_API_KEY=your_actual_api_key_here
```

### API Documentation
- https://otx.alienvault.com/api

---

## 3. AbuseIPDB

**What it provides**: IP address abuse reports, blacklists

### Get Your API Key

1. **Sign up**: https://www.abuseipdb.com/register
2. **Verify email**
3. **Get API key**: https://www.abuseipdb.com/account/api
   - Go to "API" section
   - Find or create API key
4. **Copy the key**

### Free Tier
- ✅ 1,000 requests per day
- ✅ IP address lookups
- ✅ 60 days of reports
- ⚠️ IP addresses only (no domains/URLs)

### Add to .env
```env
ABUSEIPDB_API_KEY=your_actual_api_key_here
```

### API Documentation
- https://docs.abuseipdb.com/

---

## 4. Shodan

**What it provides**: Internet-connected device search, vulnerability data

### Get Your API Key

1. **Sign up**: https://account.shodan.io/register
2. **Verify email**
3. **Subscribe** (requires payment):
   - Free account: Limited features
   - Freelancer ($59/month): Full API access
   - Small Business ($299/month): Higher limits
4. **Get API key**: https://account.shodan.io/
   - Find "API Key" on account page
5. **Copy the key**

### Plans
- ⚠️ Free: Very limited (1 query credit, no API access)
- 💰 Freelancer: 100 query credits/month, full API
- 💰 Small Business: 5,000 query credits/month

### Add to .env
```env
SHODAN_API_KEY=your_actual_api_key_here
```

### API Documentation
- https://developer.shodan.io/api

---

## 🔧 Configuration Steps

### 1. Create/Edit .env file

```bash
# Copy template if not exists
cp .env.example .env

# Edit with your favorite editor
nano .env  # or vim, code, notepad, etc.
```

### 2. Add Your Keys

```env
# Security
SECRET_KEY=<GENERATE_SECURE_KEY>

# API Keys (add the ones you have)
VIRUSTOTAL_API_KEY=your_virustotal_key_here
OTX_API_KEY=your_otx_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
SHODAN_API_KEY=your_shodan_key_here

# Leave blank if you don't have a key
# SHODAN_API_KEY=
```

### 3. Restart the API

```bash
# If using Docker
docker-compose restart api

# If running manually
# Stop (Ctrl+C) and restart:
python -m app.main
```

### 4. Verify Configuration

Check the startup logs or health endpoint:

```bash
# Check logs
docker-compose logs api | grep "Threat Intel Sources"

# Or check health endpoint
curl http://localhost:8000/health
```

Should show:
```json
{
  "threat_intel_sources": {
    "configured": 4,  // number of sources with keys
    "sources": {
      "virustotal": true,
      "otx": true,
      "abuseipdb": true,
      "shodan": false
    }
  }
}
```

---

## 📊 Recommended Setup

### Minimum (Free)
Start with these for full free coverage:

1. **AlienVault OTX** - Best free tier, no limits
2. **AbuseIPDB** - Good for IP reputation (1,000/day)
3. **VirusTotal** - Essential for malware/URL checks (500/day)

**Total cost**: $0/month  
**Coverage**: Excellent for development and small deployments

### Recommended (Small Production)
Add Shodan for complete coverage:

1. **AlienVault OTX** - Free
2. **AbuseIPDB** - Free  
3. **VirusTotal** - Free or Premium ($20/month for 15,000 req/day)
4. **Shodan** - Freelancer ($59/month)

**Total cost**: $59-79/month  
**Coverage**: Complete threat intelligence

### Enterprise
Consider paid tiers for all services:

1. **VirusTotal Premium** - $20-200+/month
2. **AlienVault USM** - Enterprise pricing
3. **AbuseIPDB Premium** - Custom pricing
4. **Shodan Business** - $299+/month

**Total cost**: $500+/month  
**Coverage**: High-volume, priority support

---

## 🔒 Security Best Practices

### Protect Your API Keys

1. **Never commit** keys to version control
   ```bash
   # .gitignore already includes .env
   git status  # should not show .env
   ```

2. **Use environment variables** in production
   ```bash
   export VIRUSTOTAL_API_KEY=your_key
   ```

3. **Rotate keys regularly** (monthly recommended)

4. **Monitor usage** for unauthorized access
   - Check each provider's dashboard
   - Set up alerts for unusual activity

5. **Use separate keys** for dev/staging/production

### Secure Storage

**Development:**
- Store in `.env` file (gitignored)
- Use local environment variables

**Production:**
- Use secrets management (AWS Secrets Manager, HashiCorp Vault)
- Use container secrets (Docker secrets, Kubernetes secrets)
- Never hardcode in application code

---

## 🧪 Testing Without API Keys

The API works without keys! You'll get:

- ✅ Authentication and authorization
- ✅ Caching and rate limiting
- ✅ Risk scoring (based on available sources)
- ⚠️ Limited threat intelligence data
- ⚠️ "API key not configured" in source results

### Test Mode

For development/testing without real keys:

```env
# Leave keys empty or use placeholders
VIRUSTOTAL_API_KEY=
OTX_API_KEY=
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=
```

The API will:
- Start successfully
- Accept queries
- Return results from available sources
- Mark unavailable sources appropriately

---

## 📈 Rate Limit Management

### Built-in Protection

The API includes rate limiting to prevent exceeding provider limits:

```env
# Adjust based on your API tier
RATE_LIMIT_PER_MINUTE=10
CACHE_TTL=3600  # Cache for 1 hour
```

### Caching Strategy

Reduce API calls with smart caching:

```python
# Query with caching (default)
{
  "indicator": "8.8.8.8",
  "indicator_type": "ip",
  "force_refresh": false  // Use cache if available
}

# Force fresh data
{
  "indicator": "8.8.8.8",
  "indicator_type": "ip",
  "force_refresh": true  // Bypass cache
}
```

---

## 🆘 Troubleshooting

### "API key not configured"

**Solution**: Add the API key to your `.env` file and restart

### "Rate limit exceeded"

**Solutions**:
1. Wait for rate limit reset
2. Increase `CACHE_TTL` to cache longer
3. Upgrade to paid tier
4. Add more API sources

### "Invalid API key"

**Solutions**:
1. Verify key is correct (check for spaces)
2. Regenerate key in provider dashboard
3. Check key is active (not expired)

### "Connection timeout"

**Solutions**:
1. Check internet connectivity
2. Verify firewall allows outbound connections
3. Check provider status pages

---

## 📞 Support

### API Provider Support

- **VirusTotal**: support@virustotal.com
- **AlienVault OTX**: https://otx.alienvault.com/forums/
- **AbuseIPDB**: https://www.abuseipdb.com/contact
- **Shodan**: https://help.shodan.io/

### This Project

- Create GitHub issue for API integration problems
- Check logs: `docker-compose logs api`
- Review [CONTRIBUTING.md](CONTRIBUTING.md) for debugging tips

---

## 🎯 Quick Reference

```bash
# Check which sources are configured
curl http://localhost:8000/health | jq '.components.threat_intel_sources'

# Test a query
curl -X POST "http://localhost:8000/api/v1/query" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"indicator": "8.8.8.8", "indicator_type": "ip"}'

# View API key status in startup logs
docker-compose logs api | grep -i "source"
```

---

**Last Updated**: February 2026  
**Maintained By**: Development Team
