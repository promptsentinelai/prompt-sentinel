# PromptSentinel

Production-ready defensive security microservice for detecting and mitigating prompt injection attacks in LLM systems.

## Quick Start

```bash
# Minimal configuration - only requires one LLM provider key
docker run -p 8080:8080 \
  -e ANTHROPIC_API_KEY=your-key \
  promptsentinelai/prompt-sentinel:latest
```

## Required Configuration

At least **ONE** LLM provider API key is required:

| Variable | Description | Example |
|----------|-------------|---------|
| `ANTHROPIC_API_KEY` | Anthropic Claude API key (recommended) | `sk-ant-...` |
| `OPENAI_API_KEY` | OpenAI GPT API key | `sk-...` |
| `GEMINI_API_KEY` | Google Gemini API key | `AIza...` |

## Common Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| **Service Configuration** | | |
| `API_HOST` | `0.0.0.0` | Network interface (`0.0.0.0` for all, `127.0.0.1` for local only) |
| `API_PORT` | `8080` | Service port |
| `API_ENV` | `development` | Environment: `development`, `staging`, or `production` |
| `DEBUG` | `true` | Debug mode (⚠️ set `false` in production) |
| **Detection Settings** | | |
| `DETECTION_MODE` | `strict` | Detection sensitivity: `strict`, `moderate`, or `permissive` |
| `HEURISTIC_ENABLED` | `true` | Enable pattern-based detection |
| `LLM_CLASSIFICATION_ENABLED` | `true` | Enable LLM-based detection |
| `PII_DETECTION_ENABLED` | `true` | Enable PII detection |
| `PII_REDACTION_MODE` | `mask` | PII handling: `mask`, `remove`, `hash`, or `reject` |
| **Performance** | | |
| `REDIS_ENABLED` | `false` | Enable Redis caching for 30-40% fewer API calls |
| `REDIS_HOST` | `localhost` | Redis server host |
| `REDIS_PORT` | `6379` | Redis server port |
| **Authentication** | | |
| `AUTH_MODE` | `optional` | Auth mode: `none` (sidecar), `optional`, or `required` |
| `AUTH_ALLOW_LOCALHOST` | `true` | Allow unauthenticated localhost access |
| **Rate Limiting** | | |
| `RATE_LIMIT_REQUESTS_PER_MINUTE` | `60` | Global rate limit |
| `RATE_LIMIT_CLIENT_REQUESTS_PER_MINUTE` | `20` | Per-client rate limit |
| **Budget Control** | | |
| `BUDGET_DAILY_LIMIT` | `100.0` | Daily spending limit in USD |
| `BUDGET_BLOCK_ON_EXCEEDED` | `true` | Block requests when budget exceeded |

## Docker Compose Example

```yaml
version: '3.8'
services:
  promptsentinel:
    image: promptsentinelai/prompt-sentinel:latest
    ports:
      - "8080:8080"
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - DETECTION_MODE=moderate
      - REDIS_ENABLED=true
      - REDIS_HOST=redis
    depends_on:
      - redis
  
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
```

## Production Deployment

For production, we recommend:
- Set `API_ENV=production` and `DEBUG=false`
- Enable Redis for caching (`REDIS_ENABLED=true`)
- Configure authentication (`AUTH_MODE=required`)
- Set budget limits to control costs
- Use strict detection mode for maximum security

## Full Documentation

- **Complete configuration guide**: See `.env.example` in the repository
- **GitHub**: https://github.com/promptsentinelai/prompt-sentinel
- **SDKs**: Python, JavaScript, and Go clients available

## Tags

- `latest` - Most recent stable release
- `1.0.0`, `1.0`, `1` - Version tags
- `sha-*` - Commit-specific builds

## License

Elastic License 2.0