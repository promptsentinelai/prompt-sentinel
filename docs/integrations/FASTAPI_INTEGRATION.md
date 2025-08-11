# FastAPI Integration Guide

This guide demonstrates how to integrate PromptSentinel with FastAPI applications for robust prompt injection detection and security.

## Table of Contents
- [Installation](#installation)
- [Basic Setup](#basic-setup)
- [Middleware Integration](#middleware-integration)
- [Advanced Patterns](#advanced-patterns)
- [Async Support](#async-support)
- [Error Handling](#error-handling)
- [Performance Optimization](#performance-optimization)
- [Production Deployment](#production-deployment)

## Installation

```bash
# Install FastAPI and PromptSentinel
pip install fastapi uvicorn promptsentinel

# Or with UV (recommended)
uv pip install fastapi uvicorn promptsentinel
```

## Basic Setup

### Simple Integration

```python
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from promptsentinel import PromptSentinel

app = FastAPI(title="Secure AI Application")

# Initialize PromptSentinel client
sentinel = PromptSentinel(
    api_key="psk_your_api_key",
    base_url="http://localhost:8080"  # Or your deployment URL
)

class PromptRequest(BaseModel):
    prompt: str
    
class PromptResponse(BaseModel):
    result: str
    safe: bool

@app.post("/api/generate", response_model=PromptResponse)
async def generate_text(request: PromptRequest):
    """Generate text with prompt injection protection."""
    
    # Detect threats before processing
    detection = sentinel.detect(prompt=request.prompt)
    
    if detection.verdict == "block":
        raise HTTPException(
            status_code=400,
            detail=f"Potential security threat detected: {detection.reasons[0].description}"
        )
    
    # Process safe prompt
    result = await process_with_llm(request.prompt)
    
    return PromptResponse(
        result=result,
        safe=detection.verdict == "allow"
    )
```

## Middleware Integration

### Custom Security Middleware

Create reusable middleware for automatic prompt validation:

```python
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import json

class PromptSentinelMiddleware(BaseHTTPMiddleware):
    """Middleware for automatic prompt injection detection."""
    
    def __init__(self, app, sentinel_client: PromptSentinel, 
                 protected_paths: list = None):
        super().__init__(app)
        self.sentinel = sentinel_client
        self.protected_paths = protected_paths or ["/api/"]
        
    async def dispatch(self, request: Request, call_next):
        # Check if path needs protection
        if not any(request.url.path.startswith(p) for p in self.protected_paths):
            return await call_next(request)
        
        # Only check POST requests with JSON body
        if request.method == "POST" and request.headers.get("content-type") == "application/json":
            # Read and validate body
            body = await request.body()
            try:
                data = json.loads(body)
                
                # Check for prompt fields
                prompt_fields = ["prompt", "query", "input", "message", "text"]
                for field in prompt_fields:
                    if field in data:
                        detection = self.sentinel.detect(prompt=data[field])
                        
                        if detection.verdict == "block":
                            return JSONResponse(
                                status_code=400,
                                content={
                                    "error": "Security threat detected",
                                    "category": detection.reasons[0].category,
                                    "description": detection.reasons[0].description
                                }
                            )
                        
                        # Add sanitized version if available
                        if detection.modified_prompt:
                            data[f"{field}_sanitized"] = detection.modified_prompt
                
                # Reconstruct request with validated data
                async def receive():
                    return {"type": "http.request", "body": json.dumps(data).encode()}
                
                request._receive = receive
                
            except json.JSONDecodeError:
                pass  # Let the endpoint handle invalid JSON
        
        response = await call_next(request)
        return response

# Apply middleware
app.add_middleware(
    PromptSentinelMiddleware,
    sentinel_client=sentinel,
    protected_paths=["/api/", "/v1/"]
)
```

## Advanced Patterns

### Dependency Injection

Use FastAPI's dependency injection for cleaner code:

```python
from fastapi import Depends
from typing import Annotated

async def get_sentinel():
    """Dependency for PromptSentinel client."""
    return PromptSentinel(api_key="psk_your_api_key")

async def validate_prompt(
    prompt: str,
    sentinel: Annotated[PromptSentinel, Depends(get_sentinel)]
) -> str:
    """Validate and sanitize prompt."""
    detection = sentinel.detect(prompt=prompt)
    
    if detection.verdict == "block":
        raise HTTPException(
            status_code=400,
            detail="Prompt contains security threats"
        )
    
    # Return sanitized version if available
    return detection.modified_prompt or prompt

@app.post("/api/chat")
async def chat(
    prompt: str,
    safe_prompt: Annotated[str, Depends(validate_prompt)]
):
    """Chat endpoint with automatic validation."""
    # safe_prompt is already validated
    response = await llm.generate(safe_prompt)
    return {"response": response}
```

### Role-Based Conversation Handling

```python
from promptsentinel import Message, Role
from typing import List

class ConversationMessage(BaseModel):
    role: str
    content: str

class ConversationRequest(BaseModel):
    messages: List[ConversationMessage]
    system_prompt: str = None

@app.post("/api/conversation")
async def handle_conversation(
    request: ConversationRequest,
    sentinel: Annotated[PromptSentinel, Depends(get_sentinel)]
):
    """Handle multi-turn conversations with role separation."""
    
    # Convert to PromptSentinel messages
    messages = []
    
    if request.system_prompt:
        messages.append(Message(role=Role.SYSTEM, content=request.system_prompt))
    
    for msg in request.messages:
        messages.append(Message(
            role=Role(msg.role.lower()),
            content=msg.content
        ))
    
    # Detect with role context
    detection = sentinel.detect(
        messages=messages,
        check_format=True,
        detection_mode="strict"
    )
    
    if detection.verdict == "block":
        return {
            "error": "Security threat detected",
            "threats": [r.description for r in detection.reasons],
            "recommendations": detection.format_recommendations
        }
    
    # Process conversation
    response = await process_conversation(messages)
    
    return {
        "response": response,
        "safety_score": detection.confidence,
        "pii_detected": len(detection.pii_detected) > 0 if detection.pii_detected else False
    }
```

## Async Support

### Using AsyncPromptSentinel

```python
from promptsentinel import AsyncPromptSentinel
import asyncio

# Initialize async client
async_sentinel = AsyncPromptSentinel(
    api_key="psk_your_api_key",
    timeout=10.0
)

@app.on_event("startup")
async def startup_event():
    """Initialize async resources."""
    app.state.sentinel = async_sentinel
    
    # Verify connection
    health = await async_sentinel.health_check()
    if health.status != "healthy":
        print(f"Warning: PromptSentinel status: {health.status}")

@app.on_event("shutdown")
async def shutdown_event():
    """Clean up async resources."""
    await app.state.sentinel.close()

@app.post("/api/async-generate")
async def async_generate(prompt: str):
    """Async endpoint with detection."""
    
    # Async detection
    detection = await app.state.sentinel.detect(prompt=prompt)
    
    if detection.verdict == "block":
        raise HTTPException(status_code=400, detail="Unsafe prompt")
    
    # Process concurrently
    result, usage = await asyncio.gather(
        process_with_llm(prompt),
        app.state.sentinel.get_usage(1)  # Last hour usage
    )
    
    return {
        "result": result,
        "api_usage": {
            "requests": usage.total_requests,
            "cost": usage.estimated_cost
        }
    }
```

### Batch Processing

```python
from concurrent.futures import ThreadPoolExecutor
import asyncio

@app.post("/api/batch-analyze")
async def batch_analyze(prompts: List[str]):
    """Analyze multiple prompts efficiently."""
    
    # Prepare batch request
    batch_prompts = [
        {"id": f"prompt_{i}", "prompt": p} 
        for i, p in enumerate(prompts)
    ]
    
    # Batch detection
    batch_result = await app.state.sentinel.batch_detect(batch_prompts)
    
    # Process results
    safe_prompts = []
    blocked_prompts = []
    
    for result in batch_result.results:
        if result.verdict == "allow":
            safe_prompts.append({
                "id": result.id,
                "prompt": prompts[int(result.id.split("_")[1])]
            })
        else:
            blocked_prompts.append({
                "id": result.id,
                "reason": result.reasons[0].description
            })
    
    # Process safe prompts in parallel
    if safe_prompts:
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor(max_workers=5) as executor:
            tasks = [
                loop.run_in_executor(executor, process_prompt_sync, p["prompt"])
                for p in safe_prompts
            ]
            results = await asyncio.gather(*tasks)
    else:
        results = []
    
    return {
        "processed": len(safe_prompts),
        "blocked": len(blocked_prompts),
        "results": results,
        "blocked_details": blocked_prompts
    }
```

## Error Handling

### Comprehensive Error Management

```python
from promptsentinel import (
    AuthenticationError,
    RateLimitError,
    ValidationError,
    ServiceUnavailableError
)
import time
from functools import wraps

def with_retry(max_retries=3, backoff_factor=2):
    """Decorator for automatic retry with exponential backoff."""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_retries):
                try:
                    return await func(*args, **kwargs)
                except RateLimitError as e:
                    wait_time = e.retry_after or (backoff_factor ** attempt)
                    print(f"Rate limited, waiting {wait_time}s...")
                    await asyncio.sleep(wait_time)
                    last_exception = e
                except ServiceUnavailableError as e:
                    wait_time = backoff_factor ** attempt
                    print(f"Service unavailable, retrying in {wait_time}s...")
                    await asyncio.sleep(wait_time)
                    last_exception = e
                except (AuthenticationError, ValidationError) as e:
                    # Don't retry these errors
                    raise
            
            raise last_exception
        return wrapper
    return decorator

@app.post("/api/secure-generate")
@with_retry(max_retries=3)
async def secure_generate(prompt: str):
    """Generate with automatic retry and error handling."""
    try:
        detection = await app.state.sentinel.detect(prompt=prompt)
        
        if detection.verdict == "block":
            return {
                "error": "Blocked for security",
                "threats": [r.category for r in detection.reasons]
            }
        
        result = await generate_with_timeout(prompt, timeout=30)
        return {"result": result}
        
    except AuthenticationError:
        raise HTTPException(
            status_code=401,
            detail="API key authentication failed"
        )
    except ValidationError as e:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid request: {str(e)}"
        )
    except Exception as e:
        # Log unexpected errors
        print(f"Unexpected error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Internal server error"
        )
```

## Performance Optimization

### Caching Strategy

```python
from fastapi_cache import FastAPICache
from fastapi_cache.decorator import cache
from fastapi_cache.backends.redis import RedisBackend
import hashlib

@app.on_event("startup")
async def startup():
    redis = aioredis.from_url("redis://localhost")
    FastAPICache.init(RedisBackend(redis), prefix="promptsentinel")

def cache_key_builder(prompt: str, mode: str = "moderate"):
    """Generate cache key for detection results."""
    return hashlib.md5(f"{prompt}:{mode}".encode()).hexdigest()

@app.post("/api/cached-generate")
@cache(expire=3600, key_builder=cache_key_builder)
async def cached_generate(prompt: str, mode: str = "moderate"):
    """Generate with cached detection results."""
    
    # Check cache first (handled by decorator)
    detection = await app.state.sentinel.detect(
        prompt=prompt,
        detection_mode=mode,
        use_cache=True  # Use PromptSentinel's cache too
    )
    
    if detection.verdict == "block":
        raise HTTPException(status_code=400, detail="Unsafe prompt")
    
    # Generate response
    result = await generate_response(prompt)
    
    return {
        "result": result,
        "cached": False,  # Will be true on cache hit
        "latency_ms": detection.processing_time_ms
    }
```

### Connection Pooling

```python
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle with connection pooling."""
    
    # Create connection pool
    app.state.sentinel_pool = [
        AsyncPromptSentinel(api_key="psk_your_api_key")
        for _ in range(5)  # Pool size
    ]
    app.state.pool_index = 0
    
    yield
    
    # Cleanup
    for client in app.state.sentinel_pool:
        await client.close()

app = FastAPI(lifespan=lifespan)

async def get_sentinel_from_pool():
    """Get client from connection pool."""
    pool = app.state.sentinel_pool
    index = app.state.pool_index
    app.state.pool_index = (index + 1) % len(pool)
    return pool[index]

@app.post("/api/pooled-detection")
async def pooled_detection(
    prompt: str,
    sentinel: Annotated[AsyncPromptSentinel, Depends(get_sentinel_from_pool)]
):
    """Use connection pool for better performance."""
    detection = await sentinel.detect(prompt=prompt)
    return {"verdict": detection.verdict}
```

## Production Deployment

### Environment Configuration

```python
from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    """Application settings from environment."""
    
    # API Configuration
    app_name: str = "Secure AI Service"
    debug: bool = False
    
    # PromptSentinel Configuration
    promptsentinel_api_key: str
    promptsentinel_base_url: str = "http://localhost:8080"
    promptsentinel_timeout: float = 30.0
    
    # Security Settings
    detection_mode: str = "moderate"
    enable_pii_detection: bool = True
    max_prompt_length: int = 10000
    
    # Performance
    enable_caching: bool = True
    cache_ttl: int = 3600
    connection_pool_size: int = 10
    
    class Config:
        env_file = ".env"

@lru_cache()
def get_settings():
    return Settings()

# Use settings
settings = get_settings()
sentinel = PromptSentinel(
    api_key=settings.promptsentinel_api_key,
    base_url=settings.promptsentinel_base_url,
    timeout=settings.promptsentinel_timeout
)
```

### Health Checks and Monitoring

```python
from datetime import datetime
import psutil

@app.get("/health")
async def health_check():
    """Comprehensive health check endpoint."""
    
    # Check PromptSentinel
    try:
        sentinel_health = await app.state.sentinel.health_check()
        sentinel_status = sentinel_health.status
    except Exception as e:
        sentinel_status = f"error: {str(e)}"
    
    # Check system resources
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    
    return {
        "status": "healthy" if sentinel_status == "healthy" else "degraded",
        "timestamp": datetime.utcnow().isoformat(),
        "services": {
            "promptsentinel": sentinel_status,
            "api": "healthy"
        },
        "resources": {
            "cpu_percent": cpu_percent,
            "memory_percent": memory.percent
        }
    }

@app.get("/metrics")
async def get_metrics():
    """Get usage metrics for monitoring."""
    
    usage = await app.state.sentinel.get_usage(24)  # Last 24 hours
    budget = await app.state.sentinel.get_budget_status()
    
    return {
        "usage": {
            "total_requests": usage.total_requests,
            "total_tokens": usage.total_tokens,
            "estimated_cost": usage.estimated_cost,
            "cache_hit_rate": usage.cache_hit_rate
        },
        "budget": {
            "current_spend": budget.current_spend,
            "limit": budget.budget_limit,
            "percentage_used": budget.percentage_used
        }
    }
```

### Docker Deployment

```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Run with Uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - PROMPTSENTINEL_API_KEY=${PROMPTSENTINEL_API_KEY}
      - PROMPTSENTINEL_BASE_URL=http://promptsentinel:8080
    depends_on:
      - promptsentinel
      - redis
    
  promptsentinel:
    image: promptsentinel/promptsentinel:latest
    ports:
      - "8080:8080"
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - OPENAI_API_KEY=${OPENAI_API_KEY}
      - REDIS_URL=redis://redis:6379
    
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
```

### Example Application

Complete example application with all patterns:

```python
# main.py
from fastapi import FastAPI, HTTPException, Depends
from contextlib import asynccontextmanager
from promptsentinel import AsyncPromptSentinel, Message, Role
from typing import Annotated
import os

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management."""
    
    # Initialize PromptSentinel
    app.state.sentinel = AsyncPromptSentinel(
        api_key=os.getenv("PROMPTSENTINEL_API_KEY"),
        base_url=os.getenv("PROMPTSENTINEL_BASE_URL", "http://localhost:8080")
    )
    
    # Verify connection
    health = await app.state.sentinel.health_check()
    print(f"PromptSentinel status: {health.status}")
    
    yield
    
    # Cleanup
    await app.state.sentinel.close()

app = FastAPI(
    title="Secure AI Application",
    lifespan=lifespan
)

async def get_sentinel():
    """Dependency for PromptSentinel client."""
    return app.state.sentinel

# Validation dependency
async def validate_and_sanitize(
    prompt: str,
    sentinel: Annotated[AsyncPromptSentinel, Depends(get_sentinel)]
) -> str:
    """Validate prompt and return sanitized version."""
    
    if len(prompt) > 10000:
        raise HTTPException(status_code=400, detail="Prompt too long")
    
    detection = await sentinel.detect(
        prompt=prompt,
        detection_mode="strict"
    )
    
    if detection.verdict == "block":
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Security threat detected",
                "threats": [r.category for r in detection.reasons]
            }
        )
    
    # Return sanitized version if available
    return detection.modified_prompt or prompt

@app.post("/api/generate")
async def generate(
    prompt: str,
    safe_prompt: Annotated[str, Depends(validate_and_sanitize)]
):
    """Generate AI response with security validation."""
    
    # Process the validated prompt
    # safe_prompt is guaranteed to be safe
    response = f"Processing: {safe_prompt[:50]}..."
    
    return {
        "prompt": safe_prompt,
        "response": response,
        "status": "success"
    }

@app.get("/health")
async def health():
    """Health check endpoint."""
    sentinel_health = await app.state.sentinel.health_check()
    return {
        "status": sentinel_health.status,
        "version": "1.0.0"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

## Best Practices

1. **Always validate prompts before processing** - Never send unvalidated user input to LLMs
2. **Use role separation** - Clearly separate system instructions from user input
3. **Implement proper error handling** - Handle all PromptSentinel error types gracefully
4. **Enable caching** - Use both application-level and PromptSentinel caching
5. **Monitor usage and budgets** - Track API usage to prevent unexpected costs
6. **Use async clients** - Leverage FastAPI's async capabilities for better performance
7. **Implement retry logic** - Handle transient failures with exponential backoff
8. **Sanitize PII** - Use modified prompts when PII is detected
9. **Log security events** - Track blocked prompts for security analysis
10. **Test thoroughly** - Include security tests in your test suite

## Additional Resources

- [PromptSentinel Documentation](https://github.com/promptsentinel/promptsentinel)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [API Examples](../API_EXAMPLES.md)
- [Security Best Practices](../../README.md#security-best-practices)