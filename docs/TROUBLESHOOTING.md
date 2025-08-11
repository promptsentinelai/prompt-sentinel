# Troubleshooting Guide

This guide helps you diagnose and resolve common issues with PromptSentinel.

## Table of Contents
- [Quick Diagnostics](#quick-diagnostics)
- [Common Issues](#common-issues)
- [API Errors](#api-errors)
- [Performance Issues](#performance-issues)
- [Integration Problems](#integration-problems)
- [Docker & Deployment Issues](#docker--deployment-issues)
- [LLM Provider Issues](#llm-provider-issues)
- [Redis & Caching Issues](#redis--caching-issues)
- [SDK-Specific Issues](#sdk-specific-issues)
- [Debugging Tools](#debugging-tools)
- [FAQ](#frequently-asked-questions)

## Quick Diagnostics

### Health Check Script

Run this script to quickly diagnose common issues:

```bash
#!/bin/bash
# healthcheck.sh

echo "🔍 PromptSentinel Diagnostics"
echo "=============================="

# Check if service is running
echo -n "1. Service Status: "
if curl -s http://localhost:8080/api/v1/health > /dev/null; then
    echo "✅ Running"
    curl -s http://localhost:8080/api/v1/health | jq .
else
    echo "❌ Not responding"
fi

# Check Redis connection
echo -n "2. Redis Connection: "
if redis-cli ping > /dev/null 2>&1; then
    echo "✅ Connected"
else
    echo "⚠️  Not connected (optional)"
fi

# Check environment variables
echo "3. Environment Variables:"
for var in ANTHROPIC_API_KEY OPENAI_API_KEY GEMINI_API_KEY; do
    if [ -z "${!var}" ]; then
        echo "   ❌ $var not set"
    else
        echo "   ✅ $var configured"
    fi
done

# Check Docker
echo -n "4. Docker Status: "
if docker ps | grep promptsentinel > /dev/null; then
    echo "✅ Container running"
    docker ps | grep promptsentinel
else
    echo "❌ Container not found"
fi

# Test detection endpoint
echo "5. Testing Detection API:"
response=$(curl -s -X POST http://localhost:8080/api/v1/detect \
    -H "Content-Type: application/json" \
    -d '{"prompt": "test"}')
    
if echo "$response" | grep -q "verdict"; then
    echo "   ✅ API responding correctly"
else
    echo "   ❌ API error: $response"
fi
```

## Common Issues

### Issue: Service Won't Start

**Symptoms:**
- Container exits immediately
- Port 8080 not accessible
- Health check fails

**Solutions:**

1. **Check logs first:**
```bash
# Docker logs
docker logs promptsentinel

# Docker Compose logs
docker-compose logs -f promptsentinel

# System logs
journalctl -u promptsentinel -f
```

2. **Verify API keys:**
```bash
# At least one LLM provider key must be set
export ANTHROPIC_API_KEY="sk-ant-..."
# OR
export OPENAI_API_KEY="sk-..."
# OR
export GEMINI_API_KEY="..."
```

3. **Check port conflicts:**
```bash
# Check if port 8080 is already in use
lsof -i :8080
# or
netstat -tulpn | grep 8080

# Use a different port
docker run -p 8081:8080 promptsentinel/promptsentinel
```

4. **Memory issues:**
```bash
# Increase Docker memory allocation
docker run -m 2g promptsentinel/promptsentinel

# Check system memory
free -h
```

### Issue: Authentication Errors

**Symptoms:**
- 401 Unauthorized responses
- "API key invalid" errors
- "Authentication failed" messages

**Solutions:**

1. **Check authentication mode:**
```bash
# Check current mode
curl http://localhost:8080/api/v1/health | jq .authentication_mode

# Set authentication mode
export AUTHENTICATION_MODE=optional  # or "none", "required"
```

2. **Verify API key format:**
```bash
# Correct format for request
curl -H "Authorization: Bearer psk_your_key" \
     -H "Content-Type: application/json" \
     -X POST http://localhost:8080/api/v1/detect \
     -d '{"prompt": "test"}'

# Or use X-API-Key header
curl -H "X-API-Key: psk_your_key" ...
```

3. **Generate new API key:**
```python
# Generate a secure API key
import secrets
api_key = f"psk_{secrets.token_urlsafe(32)}"
print(api_key)
```

### Issue: Slow Response Times

**Symptoms:**
- Detection takes >1 second
- Timeouts on API calls
- High latency in responses

**Solutions:**

1. **Enable Redis caching:**
```bash
# Start with Redis
docker-compose -f docker-compose.redis.yml up

# Verify Redis is connected
curl http://localhost:8080/api/v1/health | jq .cache_enabled
```

2. **Check cache hit rate:**
```bash
# Monitor cache performance
curl http://localhost:8080/api/v1/monitoring/metrics | jq '.cache_hit_rate'

# Should be > 50% for repeated prompts
```

3. **Use intelligent routing:**
```python
# Python - Use V3 intelligent routing
result = client.detect(
    prompt="simple greeting",
    use_intelligent_routing=True  # Automatically optimizes
)
```

4. **Optimize detection mode:**
```bash
# Use permissive mode for better performance
export DETECTION_MODE=permissive  # vs "moderate" or "strict"
```

### Issue: High False Positive Rate

**Symptoms:**
- Legitimate prompts being blocked
- Too many "review" verdicts
- Business users complaining

**Solutions:**

1. **Adjust detection mode:**
```python
# Use appropriate mode for your use case
result = client.detect(
    prompt=user_input,
    detection_mode="permissive"  # For creative applications
    # detection_mode="moderate"  # Balanced (default)
    # detection_mode="strict"    # High security
)
```

2. **Customize thresholds:**
```yaml
# config/detection.yaml
thresholds:
  strict:
    block_threshold: 0.7
    review_threshold: 0.5
  moderate:
    block_threshold: 0.8
    review_threshold: 0.6
  permissive:
    block_threshold: 0.9
    review_threshold: 0.8
```

3. **Implement allowlisting:**
```python
# Bypass detection for known-safe patterns
SAFE_PATTERNS = [
    r"^(hello|hi|hey)",
    r"^what is the weather",
    r"^translate .+ to .+"
]

def should_skip_detection(prompt):
    return any(re.match(pattern, prompt.lower()) 
              for pattern in SAFE_PATTERNS)
```

## API Errors

### 400 Bad Request

**Cause:** Invalid request format or parameters

```json
{
  "detail": "Either 'prompt' or 'messages' is required"
}
```

**Fix:**
```python
# Correct - provide prompt
result = client.detect(prompt="test")

# Or provide messages
messages = [
    {"role": "user", "content": "test"}
]
result = client.detect(messages=messages)

# Wrong - both or neither
result = client.detect()  # ❌ Missing input
result = client.detect(prompt="test", messages=messages)  # ❌ Both provided
```

### 401 Unauthorized

**Cause:** Missing or invalid API key when required

**Fix:**
```bash
# Set API key in environment
export PROMPTSENTINEL_API_KEY="psk_your_key"

# Or pass in request
curl -H "Authorization: Bearer psk_your_key" ...
```

### 422 Validation Error

**Cause:** Request validation failed

**Common issues:**
- Prompt exceeds maximum length (10,000 chars default)
- Invalid role in messages (must be system/user/assistant)
- Invalid detection mode

**Fix:**
```python
# Check prompt length
if len(prompt) > 10000:
    prompt = prompt[:10000]

# Use valid roles
from promptsentinel import Role
message = {"role": Role.USER, "content": "text"}

# Use valid detection mode
detection_mode = "moderate"  # not "medium" or other values
```

### 429 Rate Limited

**Cause:** Too many requests

**Fix:**
```python
import time
from promptsentinel import RateLimitError

try:
    result = client.detect(prompt=prompt)
except RateLimitError as e:
    # Wait and retry
    time.sleep(e.retry_after or 60)
    result = client.detect(prompt=prompt)
```

### 503 Service Unavailable

**Causes:**
- All LLM providers are down
- Redis connection lost (if required)
- Service overloaded

**Fix:**
```python
# Implement retry with backoff
import time

def detect_with_retry(prompt, max_retries=3):
    for i in range(max_retries):
        try:
            return client.detect(prompt=prompt)
        except ServiceUnavailableError:
            if i < max_retries - 1:
                time.sleep(2 ** i)  # Exponential backoff
            else:
                raise
```

## Performance Issues

### Issue: Memory Leaks

**Symptoms:**
- Increasing memory usage over time
- Container restarts due to OOM
- Degrading performance

**Solutions:**

1. **Monitor memory usage:**
```bash
# Check container memory
docker stats promptsentinel

# Inside container
ps aux | grep python
cat /proc/meminfo
```

2. **Limit cache size:**
```yaml
# config/cache.yaml
cache:
  max_size: 10000  # Limit number of cached items
  ttl: 3600        # Expire after 1 hour
  max_memory: 1gb  # Redis max memory
```

3. **Enable garbage collection:**
```python
# Force garbage collection periodically
import gc
gc.collect()
```

### Issue: High CPU Usage

**Symptoms:**
- CPU constantly at 100%
- Slow response times
- System unresponsive

**Solutions:**

1. **Check for infinite loops:**
```bash
# Profile CPU usage
py-spy top --pid $(pgrep -f promptsentinel)
```

2. **Limit worker processes:**
```yaml
# config/server.yaml
server:
  workers: 2  # Reduce from 4
  worker_connections: 100  # Reduce concurrent connections
```

3. **Optimize regex patterns:**
```python
# Compile regex patterns once
import re
PATTERNS = [re.compile(p) for p in pattern_list]

# Not in every request
def detect(prompt):
    patterns = [re.compile(p) for p in pattern_list]  # ❌ Bad
```

## Integration Problems

### SDK Connection Issues

**Python SDK:**
```python
# Debug connection
import logging
logging.basicConfig(level=logging.DEBUG)

from promptsentinel import PromptSentinel

# Test connection
client = PromptSentinel(
    base_url="http://localhost:8080",
    timeout=30.0
)

try:
    health = client.health_check()
    print(f"Status: {health.status}")
except Exception as e:
    print(f"Connection failed: {e}")
```

**JavaScript SDK:**
```javascript
// Enable debug mode
const client = new PromptSentinel({
  baseUrl: 'http://localhost:8080',
  debug: true  // Show detailed logs
});

// Test connection
client.healthCheck()
  .then(health => console.log('Status:', health.status))
  .catch(err => console.error('Connection failed:', err));
```

**Go SDK:**
```go
// Enable verbose logging
client := promptsentinel.New(&promptsentinel.Config{
    BaseURL: "http://localhost:8080",
    Debug:   true,
})

// Test connection
health, err := client.HealthCheck()
if err != nil {
    log.Printf("Connection failed: %v", err)
}
```

### CORS Issues

**Symptom:** Browser requests blocked

**Fix:**
```python
# Enable CORS in FastAPI
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)
```

Or use environment variable:
```bash
export CORS_ORIGINS="http://localhost:3000,https://app.example.com"
```

## Docker & Deployment Issues

### Container Won't Start

```bash
# Check logs
docker logs promptsentinel

# Common fixes:
# 1. Ensure image is pulled
docker pull promptsentinel/promptsentinel:latest

# 2. Check resource constraints
docker run -m 2g -c 2 promptsentinel/promptsentinel

# 3. Verify network
docker run --network host promptsentinel/promptsentinel

# 4. Debug interactively
docker run -it --entrypoint /bin/bash promptsentinel/promptsentinel
```

### Docker Compose Issues

```bash
# Validate compose file
docker-compose config

# Force rebuild
docker-compose build --no-cache
docker-compose up --force-recreate

# Clean up
docker-compose down -v  # Remove volumes
docker system prune -a  # Clean everything
```

### Kubernetes Deployment Issues

```bash
# Check pod status
kubectl get pods -n promptsentinel
kubectl describe pod promptsentinel-xxx

# Check logs
kubectl logs -f deployment/promptsentinel

# Debug with shell
kubectl exec -it deployment/promptsentinel -- /bin/bash

# Check events
kubectl get events -n promptsentinel --sort-by='.lastTimestamp'
```

## LLM Provider Issues

### Anthropic API Errors

```python
# Test Anthropic directly
import anthropic

client = anthropic.Anthropic(api_key="sk-ant-...")
try:
    response = client.messages.create(
        model="claude-3-opus-20240229",
        messages=[{"role": "user", "content": "test"}],
        max_tokens=10
    )
    print("Anthropic API working")
except Exception as e:
    print(f"Anthropic error: {e}")
```

### OpenAI API Errors

```python
# Test OpenAI directly
import openai

openai.api_key = "sk-..."
try:
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "test"}],
        max_tokens=10
    )
    print("OpenAI API working")
except Exception as e:
    print(f"OpenAI error: {e}")
```

### Provider Failover Not Working

```bash
# Check provider order
export LLM_PROVIDER_ORDER="anthropic,openai,gemini"

# Enable fallback logging
export LOG_LEVEL=DEBUG

# Test specific provider
curl -X POST http://localhost:8080/api/v1/detect \
  -H "X-Force-Provider: openai" \
  -d '{"prompt": "test"}'
```

## Redis & Caching Issues

### Redis Connection Failed

```bash
# Test Redis connection
redis-cli ping

# Check Redis is running
docker ps | grep redis

# Start Redis
docker run -d -p 6379:6379 redis:7-alpine

# Test with Redis URL
export REDIS_URL="redis://localhost:6379"
```

### Cache Not Working

```python
# Verify cache is enabled
result = client.detect(prompt="test", use_cache=True)
print(f"Cached: {result.cached}")  # Should be True on second call

# Clear cache if needed
import redis
r = redis.Redis(host='localhost', port=6379)
r.flushall()
```

### Redis Memory Issues

```bash
# Check Redis memory
redis-cli INFO memory

# Set max memory
redis-cli CONFIG SET maxmemory 2gb
redis-cli CONFIG SET maxmemory-policy allkeys-lru

# Monitor memory usage
redis-cli --stat
```

## SDK-Specific Issues

### Python SDK Issues

**Import errors:**
```bash
# Reinstall
pip uninstall promptsentinel
pip install promptsentinel --no-cache-dir

# Check version
python -c "import promptsentinel; print(promptsentinel.__version__)"
```

**Async issues:**
```python
# Use async client correctly
import asyncio
from promptsentinel import AsyncPromptSentinel

async def main():
    async with AsyncPromptSentinel() as client:
        result = await client.detect(prompt="test")
        print(result.verdict)

asyncio.run(main())
```

### JavaScript SDK Issues

**TypeScript errors:**
```typescript
// Ensure types are installed
npm install --save-dev @types/node

// Import correctly
import { PromptSentinel, DetectionResponse, Verdict } from 'promptsentinel';

// Use proper types
const result: DetectionResponse = await client.detect({
  prompt: 'test'
});
```

**Promise handling:**
```javascript
// Use async/await
async function checkPrompt(prompt) {
  try {
    const result = await client.detect({ prompt });
    return result.verdict === 'allow';
  } catch (error) {
    console.error('Detection failed:', error);
    return false;
  }
}

// Or use promises
client.detect({ prompt: 'test' })
  .then(result => console.log(result))
  .catch(error => console.error(error));
```

### Go SDK Issues

**Module errors:**
```bash
# Update module
go get -u github.com/promptsentinel/sdk-go

# Clear cache
go clean -modcache

# Vendor dependencies
go mod vendor
```

**Context handling:**
```go
// Use context for timeouts
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

result, err := client.DetectWithContext(ctx, prompt)
```

## Debugging Tools

### Enable Debug Logging

```bash
# Set log level
export LOG_LEVEL=DEBUG

# Or in config
echo "log_level: DEBUG" >> config/app.yaml

# View logs
docker logs -f promptsentinel 2>&1 | grep -E "DEBUG|ERROR"
```

### API Request Tracing

```bash
# Trace curl request
curl -v -X POST http://localhost:8080/api/v1/detect \
  -H "Content-Type: application/json" \
  -d '{"prompt": "test"}'

# Use httpie for better output
http POST localhost:8080/api/v1/detect prompt="test"
```

### Performance Profiling

```python
# Profile detection performance
import time
import statistics

times = []
for i in range(100):
    start = time.time()
    client.detect(prompt="test prompt")
    times.append(time.time() - start)

print(f"Average: {statistics.mean(times):.3f}s")
print(f"Median: {statistics.median(times):.3f}s")
print(f"P95: {statistics.quantiles(times, n=20)[18]:.3f}s")
```

### Network Debugging

```bash
# Test connectivity
ping localhost
telnet localhost 8080
nc -zv localhost 8080

# Check DNS
nslookup promptsentinel
dig promptsentinel

# Trace network path
traceroute promptsentinel

# Monitor network traffic
tcpdump -i any -n port 8080
```

## Frequently Asked Questions

### Q: Why is detection taking so long?

**A:** First time detection calls can take 500-700ms due to LLM API latency. Enable Redis caching to get sub-20ms response times for repeated prompts:

```bash
docker-compose -f docker-compose.redis.yml up
```

### Q: How do I reduce false positives?

**A:** Adjust the detection mode based on your use case:
- `permissive` - Creative applications, low false positives
- `moderate` - Balanced for general use (default)
- `strict` - High security, more false positives

### Q: Can I use PromptSentinel without any LLM API keys?

**A:** No, at least one LLM provider API key is required. PromptSentinel uses LLMs for advanced threat classification. You can use heuristics-only mode for testing:

```bash
export DETECTION_STRATEGY=heuristics_only
```

### Q: How do I handle intermittent failures?

**A:** Implement retry logic with exponential backoff:

```python
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10)
)
def detect_with_retry(prompt):
    return client.detect(prompt=prompt)
```

### Q: Why am I getting CORS errors?

**A:** Configure CORS origins:

```bash
export CORS_ORIGINS="http://localhost:3000,https://yourapp.com"
```

### Q: How do I debug production issues?

**A:** Use structured logging and monitoring:

```bash
# Enable JSON logging
export LOG_FORMAT=json

# Send to logging service
docker logs promptsentinel | jq '.'

# Use OpenTelemetry
export OTEL_EXPORTER_OTLP_ENDPOINT="http://jaeger:4317"
```

### Q: Can I run PromptSentinel offline?

**A:** No, PromptSentinel requires internet access to call LLM provider APIs. For air-gapped environments, consider:
1. Running LLM models locally (not currently supported)
2. Using heuristics-only mode (limited protection)
3. Implementing a proxy server for API calls

## Getting Help

If you're still experiencing issues:

1. **Check the logs** - Most issues are apparent in the logs
2. **Search existing issues** - [GitHub Issues](https://github.com/promptsentinel/promptsentinel/issues)
3. **Ask the community** - [Discord Server](https://discord.gg/promptsentinel)
4. **Contact support** - support@promptsentinel.com (Enterprise customers)

When reporting issues, include:
- PromptSentinel version
- Deployment method (Docker, Kubernetes, etc.)
- Error messages and logs
- Steps to reproduce
- Environment details (OS, versions)