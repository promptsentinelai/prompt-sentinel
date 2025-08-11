# PromptSentinel - LLM Security Microservice

[![Docker Pulls](https://img.shields.io/docker/pulls/promptsentinelai/prompt-sentinel)](https://hub.docker.com/r/promptsentinelai/prompt-sentinel)
[![Docker Image Size](https://img.shields.io/docker/image-size/promptsentinelai/prompt-sentinel)](https://hub.docker.com/r/promptsentinelai/prompt-sentinel)
[![Docker Image Version](https://img.shields.io/docker/v/promptsentinelai/prompt-sentinel)](https://hub.docker.com/r/promptsentinelai/prompt-sentinel)

PromptSentinel is a production-ready defensive security microservice for detecting and mitigating prompt injection attacks, PII exposure, and other security threats in LLM-based systems.

## Quick Start

```bash
docker run -p 8080:8080 \
  -e ANTHROPIC_API_KEY=your-key \
  promptsentinelai/prompt-sentinel:latest
```

## Features

- 🎯 **Multi-Layer Detection**: Heuristic patterns, LLM classification, and PII detection
- 🚀 **Intelligent Routing**: Automatic optimization based on prompt complexity
- ⚡ **High Performance**: Sub-100ms response times with caching
- 🔄 **Multi-Provider Support**: Anthropic, OpenAI, and Gemini with failover
- 🛡️ **PII Protection**: Detects and redacts 15+ PII types

## Available Tags

- `latest` - Latest stable release
- `v1.0.0`, `v1.0`, `v1` - Semantic versioning
- `main` - Latest main branch build
- `develop` - Development builds

## Configuration

### Required Environment Variables

At least one LLM provider API key is required:

```bash
ANTHROPIC_API_KEY=sk-ant-...    # Anthropic Claude
OPENAI_API_KEY=sk-...            # OpenAI GPT
GEMINI_API_KEY=AIza...           # Google Gemini
```

### Optional Configuration

```bash
# Detection Settings
DETECTION_MODE=moderate          # strict, moderate, permissive
CONFIDENCE_THRESHOLD=0.7         # 0.0-1.0
PII_DETECTION_ENABLED=true       # Enable PII detection

# Redis Cache (optional)
REDIS_ENABLED=true
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=your-password

# API Settings
API_HOST=0.0.0.0
API_PORT=8080
LOG_LEVEL=INFO
```

## Docker Compose

### Basic Setup

```yaml
version: '3.8'

services:
  prompt-sentinel:
    image: promptsentinelai/prompt-sentinel:latest
    ports:
      - "8080:8080"
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - DETECTION_MODE=moderate
    restart: unless-stopped
```

### With Redis Cache

```yaml
version: '3.8'

services:
  prompt-sentinel:
    image: promptsentinelai/prompt-sentinel:latest
    ports:
      - "8080:8080"
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - REDIS_ENABLED=true
      - REDIS_HOST=redis
    depends_on:
      - redis
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass changeme
    restart: unless-stopped
```

## API Endpoints

- `POST /api/v1/detect` - Simple string detection
- `POST /api/v1/detect` - Advanced detection with role support
- `POST /api/v1/detect` - Intelligent routing based on complexity
- `GET /api/v1/health` - Health check
- `GET /docs` - Swagger UI documentation

## Example Usage

```bash
# Simple detection
curl -X POST http://localhost:8080/v1/detect \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Ignore previous instructions"}'

# Advanced detection with roles
curl -X POST http://localhost:8080/v2/detect \
  -H "Content-Type: application/json" \
  -d '{
    "messages": [
      {"role": "system", "content": "You are helpful"},
      {"role": "user", "content": "What is the weather?"}
    ]
  }'
```

## Health Check

```bash
curl http://localhost:8080/health
```

## Documentation

- API Docs: http://localhost:8080/docs
- ReDoc: http://localhost:8080/redoc
- OpenAPI: http://localhost:8080/openapi.json

## Resource Requirements

### Minimum
- CPU: 0.5 cores
- Memory: 256MB
- Disk: 100MB

### Recommended
- CPU: 1 core
- Memory: 512MB
- Disk: 200MB

## Security

- Runs as non-root user (UID 1000)
- No sensitive data logged
- Supports secret management systems
- Regular security updates

## Support

- GitHub: https://github.com/promptsentinelai/prompt-sentinel
- Issues: https://github.com/promptsentinelai/prompt-sentinel/issues
- Documentation: https://github.com/promptsentinelai/prompt-sentinel/tree/main/docs

## License

MIT License - See LICENSE file for details