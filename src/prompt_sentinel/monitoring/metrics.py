# Elastic License 2.0
#
# Copyright (c) 2024-present, PromptSentinel
#
# This source code is licensed under the Elastic License 2.0 found in the
# LICENSE file in the root directory of this source tree.

"""Prometheus metrics for PromptSentinel monitoring."""

import time
from collections.abc import Callable
from functools import wraps

import structlog
from prometheus_client import REGISTRY, Counter, Gauge, Histogram, Info, generate_latest

logger = structlog.get_logger()

# =============================================================================
# Core RED Metrics (Rate, Errors, Duration)
# =============================================================================

# Request metrics
REQUEST_COUNT = Counter(
    "prompt_sentinel_requests_total",
    "Total number of requests",
    ["method", "endpoint", "status", "detection_mode"],
)

REQUEST_DURATION = Histogram(
    "prompt_sentinel_request_duration_seconds",
    "Request duration in seconds",
    ["method", "endpoint"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

ERROR_COUNT = Counter(
    "prompt_sentinel_errors_total", "Total number of errors", ["error_type", "endpoint", "severity"]
)

# =============================================================================
# Security Detection Metrics
# =============================================================================

DETECTION_COUNT = Counter(
    "prompt_sentinel_detections_total",
    "Total number of threat detections",
    ["attack_type", "severity", "detection_method", "confidence_range"],
)

DETECTION_DURATION = Histogram(
    "prompt_sentinel_detection_duration_seconds",
    "Time taken for threat detection",
    ["detection_method"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
)

FALSE_POSITIVE_COUNT = Counter(
    "prompt_sentinel_false_positives_total",
    "Total false positive detections reported",
    ["attack_type"],
)

TRUE_POSITIVE_COUNT = Counter(
    "prompt_sentinel_true_positives_total",
    "Total confirmed true positive detections",
    ["attack_type"],
)

ATTACK_SEVERITY = Histogram(
    "prompt_sentinel_attack_severity",
    "Distribution of attack severity scores",
    ["attack_type"],
    buckets=(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0),
)

# =============================================================================
# LLM Provider Metrics
# =============================================================================

LLM_REQUEST_COUNT = Counter(
    "prompt_sentinel_llm_requests_total", "Total LLM API requests", ["provider", "model", "status"]
)

LLM_REQUEST_DURATION = Histogram(
    "prompt_sentinel_llm_request_duration_seconds",
    "LLM API request duration",
    ["provider", "model"],
    buckets=(0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
)

TOKEN_USAGE = Counter(
    "prompt_sentinel_tokens_used_total",
    "Total tokens consumed",
    ["provider", "model", "token_type"],  # token_type: input/output
)

API_COST = Counter(
    "prompt_sentinel_api_cost_usd_total", "Total API costs in USD", ["provider", "model"]
)

PROVIDER_FAILOVER = Counter(
    "prompt_sentinel_provider_failover_total",
    "Provider failover events",
    ["from_provider", "to_provider", "reason"],
)

# =============================================================================
# Cache Metrics
# =============================================================================

CACHE_HITS = Counter(
    "prompt_sentinel_cache_hits_total",
    "Cache hit count",
    ["cache_type"],  # detection, llm, pii
)

CACHE_MISSES = Counter("prompt_sentinel_cache_misses_total", "Cache miss count", ["cache_type"])

CACHE_SIZE = Gauge(
    "prompt_sentinel_cache_size_bytes", "Current cache size in bytes", ["cache_type"]
)

CACHE_EVICTIONS = Counter(
    "prompt_sentinel_cache_evictions_total", "Cache eviction count", ["cache_type", "reason"]
)

# =============================================================================
# Pattern & Feed Metrics
# =============================================================================

PATTERN_MATCHES = Counter(
    "prompt_sentinel_pattern_matches_total",
    "Pattern match count",
    ["pattern_category", "pattern_id", "confidence_range"],
)

FEED_UPDATE_COUNT = Counter(
    "prompt_sentinel_feed_updates_total", "Threat feed update count", ["feed_id", "status"]
)

FEED_INDICATOR_COUNT = Gauge(
    "prompt_sentinel_feed_indicators_active", "Active threat indicators from feeds", ["feed_id"]
)

# =============================================================================
# System & Resource Metrics
# =============================================================================

ACTIVE_REQUESTS = Gauge("prompt_sentinel_active_requests", "Currently active requests")

QUEUE_SIZE = Gauge("prompt_sentinel_queue_size", "Current queue size", ["queue_name"])

RATE_LIMIT_HITS = Counter(
    "prompt_sentinel_rate_limit_hits_total", "Rate limit hit count", ["client_id", "limit_type"]
)

# =============================================================================
# Business Metrics
# =============================================================================

COST_PER_DETECTION = Histogram(
    "prompt_sentinel_cost_per_detection_usd",
    "Cost per detection in USD",
    ["detection_method"],
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
)

DETECTION_CONFIDENCE = Histogram(
    "prompt_sentinel_detection_confidence",
    "Detection confidence score distribution",
    ["attack_type"],
    buckets=(0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0),
)

# Service info
SERVICE_INFO = Info("prompt_sentinel_service", "Service information")

# =============================================================================
# Decorators and Helpers
# =============================================================================


def track_request_metrics(endpoint: str):
    """Decorator to track request metrics."""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            ACTIVE_REQUESTS.inc()

            try:
                result = await func(*args, **kwargs)
                status = "success"
                return result
            except Exception as e:
                status = "error"
                ERROR_COUNT.labels(
                    error_type=type(e).__name__, endpoint=endpoint, severity="high"
                ).inc()
                raise
            finally:
                duration = time.time() - start_time
                REQUEST_DURATION.labels(
                    method=kwargs.get("request", {}).get("method", "UNKNOWN"), endpoint=endpoint
                ).observe(duration)
                REQUEST_COUNT.labels(
                    method=kwargs.get("request", {}).get("method", "UNKNOWN"),
                    endpoint=endpoint,
                    status=status,
                    detection_mode=kwargs.get("detection_mode", "default"),
                ).inc()
                ACTIVE_REQUESTS.dec()

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            ACTIVE_REQUESTS.inc()

            try:
                result = func(*args, **kwargs)
                status = "success"
                return result
            except Exception as e:
                status = "error"
                ERROR_COUNT.labels(
                    error_type=type(e).__name__, endpoint=endpoint, severity="high"
                ).inc()
                raise
            finally:
                duration = time.time() - start_time
                REQUEST_DURATION.labels(method="UNKNOWN", endpoint=endpoint).observe(duration)
                REQUEST_COUNT.labels(
                    method="UNKNOWN", endpoint=endpoint, status=status, detection_mode="default"
                ).inc()
                ACTIVE_REQUESTS.dec()

        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper

    return decorator


def track_detection_metrics(attack_type: str, severity: str, method: str, confidence: float):
    """Track detection-related metrics."""
    # Determine confidence range
    if confidence >= 0.9:
        confidence_range = "0.9-1.0"
    elif confidence >= 0.7:
        confidence_range = "0.7-0.9"
    elif confidence >= 0.5:
        confidence_range = "0.5-0.7"
    else:
        confidence_range = "0.0-0.5"

    DETECTION_COUNT.labels(
        attack_type=attack_type,
        severity=severity,
        detection_method=method,
        confidence_range=confidence_range,
    ).inc()

    DETECTION_CONFIDENCE.labels(attack_type=attack_type).observe(confidence)
    ATTACK_SEVERITY.labels(attack_type=attack_type).observe(
        {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}.get(severity, 0.5)
    )


def track_llm_metrics(
    provider: str,
    model: str,
    duration: float,
    input_tokens: int,
    output_tokens: int,
    cost: float,
    success: bool,
):
    """Track LLM provider metrics."""
    status = "success" if success else "error"

    LLM_REQUEST_COUNT.labels(provider=provider, model=model, status=status).inc()
    LLM_REQUEST_DURATION.labels(provider=provider, model=model).observe(duration)

    if input_tokens > 0:
        TOKEN_USAGE.labels(provider=provider, model=model, token_type="input").inc(input_tokens)
    if output_tokens > 0:
        TOKEN_USAGE.labels(provider=provider, model=model, token_type="output").inc(output_tokens)

    if cost > 0:
        API_COST.labels(provider=provider, model=model).inc(cost)


def track_cache_metrics(cache_type: str, hit: bool, size_bytes: int = None):
    """Track cache-related metrics."""
    if hit:
        CACHE_HITS.labels(cache_type=cache_type).inc()
    else:
        CACHE_MISSES.labels(cache_type=cache_type).inc()

    if size_bytes is not None:
        CACHE_SIZE.labels(cache_type=cache_type).set(size_bytes)


def get_metrics() -> bytes:
    """Generate Prometheus metrics output."""
    return generate_latest(REGISTRY)


def initialize_metrics(version: str):
    """Initialize service info metrics."""
    SERVICE_INFO.info(
        {"version": version, "service": "prompt-sentinel", "environment": "production"}
    )
    logger.info("Metrics initialized", version=version)


# Import asyncio only when needed to avoid issues
import asyncio
