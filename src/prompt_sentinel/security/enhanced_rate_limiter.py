# Elastic License 2.0
#
# Copyright (c) 2024-present, PromptSentinel
#
# This source code is licensed under the Elastic License 2.0 found in the
# LICENSE file in the root directory of this source tree.

"""Enhanced rate limiting with multiple algorithms and DDoS protection."""

import asyncio
import time
from dataclasses import dataclass
from enum import Enum

import structlog
from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware

from prompt_sentinel.cache.cache_manager import cache_manager
from prompt_sentinel.monitoring.rate_limiter import Priority, RateLimiter
from prompt_sentinel.security.audit_logger import SecurityEventType, security_audit_logger

logger = structlog.get_logger()


class ThreatLevel(str, Enum):
    """Threat levels for DDoS detection."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SlidingWindowConfig:
    """Configuration for sliding window rate limiter."""

    window_size_seconds: int = 60
    max_requests: int = 100
    sub_window_count: int = 6  # 6 sub-windows of 10 seconds each
    redis_key_prefix: str = "sw_limit"


@dataclass
class DDoSConfig:
    """Configuration for DDoS protection."""

    rapid_request_threshold: int = 100  # Requests per minute
    burst_request_threshold: int = 30  # Requests per 10 seconds
    temporary_block_duration: int = 300  # 5 minutes
    extended_block_duration: int = 3600  # 1 hour
    suspicious_user_agents: list[str] | None = None
    suspicious_patterns: list[str] | None = None

    def __post_init__(self):
        """Initialize default values for suspicious patterns."""
        if self.suspicious_user_agents is None:
            self.suspicious_user_agents = [
                "python-requests",
                "curl",
                "wget",
                "bot",
                "crawler",
                "scanner",
                "scraper",
            ]

        if self.suspicious_patterns is None:
            self.suspicious_patterns = [
                "admin",
                "wp-admin",
                ".env",
                "config",
                "backup",
                "sql",
                "database",
            ]


class SlidingWindowLimiter:
    """Redis-based sliding window rate limiter."""

    def __init__(self, config: SlidingWindowConfig):
        """
        Initialize sliding window rate limiter.

        Args:
            config: Sliding window configuration
        """
        self.config = config
        self.sub_window_size = config.window_size_seconds // config.sub_window_count

        # Lua script for atomic sliding window operations
        self.lua_script = """
        local key = KEYS[1]
        local window_size = tonumber(ARGV[1])
        local max_requests = tonumber(ARGV[2])
        local current_time = tonumber(ARGV[3])
        local sub_window_size = tonumber(ARGV[4])

        -- Calculate the current sub-window
        local current_window = math.floor(current_time / sub_window_size)
        local window_key = key .. ":" .. current_window

        -- Clean up old windows
        local oldest_window = current_window - math.ceil(window_size / sub_window_size)
        for i = oldest_window, current_window - 1 do
            redis.call('DEL', key .. ":" .. i)
        end

        -- Count requests in the sliding window
        local total_requests = 0
        for i = current_window - math.ceil(window_size / sub_window_size) + 1, current_window do
            local count = redis.call('GET', key .. ":" .. i)
            if count then
                total_requests = total_requests + tonumber(count)
            end
        end

        -- Check if request is allowed
        if total_requests >= max_requests then
            return {0, total_requests, max_requests - total_requests}
        end

        -- Increment current window counter
        redis.call('INCR', window_key)
        redis.call('EXPIRE', window_key, window_size)

        return {1, total_requests + 1, max_requests - total_requests - 1}
        """

    async def check_rate_limit(self, identifier: str) -> tuple[bool, int, int]:
        """Check if request is within sliding window limit."""
        if not cache_manager.connected:
            return True, 0, self.config.max_requests  # Fail open if Redis unavailable

        try:
            key = f"{self.config.redis_key_prefix}:{identifier}"
            current_time = time.time()

            if cache_manager.client is None:
                return True, 0, self.config.max_requests  # Allow if cache is not available

            result = await cache_manager.client.eval(
                self.lua_script,
                1,
                key,
                self.config.window_size_seconds,
                self.config.max_requests,
                current_time,
                self.sub_window_size,
            )

            allowed = bool(result[0])
            current_count = int(result[1])
            remaining = int(result[2])

            return allowed, current_count, remaining

        except Exception as e:
            logger.error("Sliding window rate limit check failed", error=str(e))
            return True, 0, self.config.max_requests  # Fail open


class DDoSProtectionMiddleware:
    """DDoS protection with pattern recognition and automatic blocking."""

    def __init__(self, config: DDoSConfig):
        """
        Initialize DDoS protection middleware.

        Args:
            config: DDoS protection configuration
        """
        self.config = config
        self.request_patterns: dict[str, list[float]] = {}
        self.suspicious_ips: dict[str, float] = {}

        # Start background cleanup task
        asyncio.create_task(self._cleanup_old_data())

    async def check_request(self, request: Request) -> tuple[bool, str | None, ThreatLevel]:
        """Check if request should be allowed."""
        client_ip = self._get_client_ip(request)

        # Check if IP is already blocked
        if await self._is_blocked(client_ip):
            return False, "IP temporarily blocked", ThreatLevel.HIGH

        # Analyze request patterns
        threat_level = await self._analyze_request_patterns(client_ip, request)

        if threat_level == ThreatLevel.CRITICAL:
            await self._block_ip(client_ip, self.config.extended_block_duration)
            return False, "Malicious activity detected", threat_level

        if threat_level == ThreatLevel.HIGH:
            # Increase suspicion score
            await self._increase_suspicion(client_ip, 0.3)

            # Check if should be temporarily blocked
            suspicion = await self._get_suspicion_score(client_ip)
            if suspicion >= 0.8:
                await self._block_ip(client_ip, self.config.temporary_block_duration)
                return False, "Suspicious activity threshold exceeded", threat_level

        return True, None, threat_level

    async def _analyze_request_patterns(self, client_ip: str, request: Request) -> ThreatLevel:
        """Analyze request patterns for DDoS detection."""
        current_time = time.time()
        threat_level = ThreatLevel.LOW

        # Track request timestamps
        if client_ip not in self.request_patterns:
            self.request_patterns[client_ip] = []

        self.request_patterns[client_ip].append(current_time)

        # Keep only recent requests (last 10 minutes)
        cutoff_time = current_time - 600
        self.request_patterns[client_ip] = [
            ts for ts in self.request_patterns[client_ip] if ts > cutoff_time
        ]

        recent_requests = self.request_patterns[client_ip]

        # Check for rapid requests (last minute)
        last_minute = [ts for ts in recent_requests if ts > current_time - 60]
        if len(last_minute) > self.config.rapid_request_threshold:
            threat_level = ThreatLevel.CRITICAL
            logger.warning(
                "Rapid request pattern detected",
                client_ip=client_ip,
                requests_per_minute=len(last_minute),
            )

        # Check for burst requests (last 10 seconds)
        last_10_seconds = [ts for ts in recent_requests if ts > current_time - 10]
        if len(last_10_seconds) > self.config.burst_request_threshold:
            threat_level = max(threat_level, ThreatLevel.HIGH)
            logger.warning(
                "Burst request pattern detected",
                client_ip=client_ip,
                requests_per_10s=len(last_10_seconds),
            )

        # Analyze User-Agent
        user_agent = request.headers.get("user-agent", "").lower()
        if self.config.suspicious_user_agents:
            for suspicious_agent in self.config.suspicious_user_agents:
                if suspicious_agent in user_agent:
                    threat_level = max(threat_level, ThreatLevel.MEDIUM)
                    break

        # Analyze request path for suspicious patterns
        path = request.url.path.lower()
        if self.config.suspicious_patterns:
            for pattern in self.config.suspicious_patterns:
                if pattern in path:
                    threat_level = max(threat_level, ThreatLevel.MEDIUM)
                    break

        # Check for missing common headers
        if not request.headers.get("accept") or not request.headers.get("user-agent"):
            threat_level = max(threat_level, ThreatLevel.MEDIUM)

        return threat_level

    async def _is_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked."""
        if not cache_manager.connected:
            return False

        try:
            block_key = f"ddos_block:{ip}"
            blocked = await cache_manager.get(block_key)
            return blocked is not None
        except Exception:
            return False

    async def _block_ip(self, ip: str, duration: int):
        """
        Block IP for specified duration.

        Args:
            ip: IP address to block
            duration: Block duration in seconds
        """
        if not cache_manager.connected:
            logger.warning("Cannot block IP - Redis not available", ip=ip)
            return

        try:
            block_key = f"ddos_block:{ip}"
            await cache_manager.set(
                block_key,
                {"blocked_at": time.time(), "duration": duration, "reason": "DDoS protection"},
                ttl=duration,
            )

            logger.warning(f"Blocked IP {ip} for {duration} seconds")

            # Log security event
            await security_audit_logger.log_security_event(
                event_type=SecurityEventType.DDOS_DETECTED,
                description=f"IP blocked for {duration} seconds",
                severity="high",
                additional_data={
                    "blocked_ip": ip,
                    "duration": duration,
                    "reason": "DDoS protection",
                },
            )

        except Exception as e:
            logger.error(f"Failed to block IP in Redis: {e}")

    async def _increase_suspicion(self, ip: str, amount: float):
        """Increase suspicion score for an IP."""
        if not cache_manager.connected:
            return

        try:
            suspicion_key = f"ddos_suspicion:{ip}"
            current_score = await cache_manager.get(suspicion_key) or 0.0
            new_score = min(1.0, current_score + amount)
            await cache_manager.set(suspicion_key, new_score, ttl=3600)
        except Exception:
            # Fallback to in-memory
            self.suspicious_ips[ip] = min(1.0, self.suspicious_ips.get(ip, 0.0) + amount)

    async def _get_suspicion_score(self, ip: str) -> float:
        """Get current suspicion score for an IP."""
        if not cache_manager.connected:
            return self.suspicious_ips.get(ip, 0.0)

        try:
            suspicion_key = f"ddos_suspicion:{ip}"
            return await cache_manager.get(suspicion_key) or 0.0
        except Exception:
            return self.suspicious_ips.get(ip, 0.0)

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request."""
        # Check for forwarded headers first
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip

        return request.client.host if request.client else "unknown"

    async def _cleanup_old_data(self):
        """Periodic cleanup of old tracking data."""
        while True:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes

                current_time = time.time()
                cutoff_time = current_time - 3600  # Keep data for 1 hour

                # Clean up request patterns
                for ip in list(self.request_patterns.keys()):
                    self.request_patterns[ip] = [
                        ts for ts in self.request_patterns[ip] if ts > cutoff_time
                    ]
                    if not self.request_patterns[ip]:
                        del self.request_patterns[ip]

                # Clean up in-memory suspicious IPs (Redis entries expire automatically)
                for ip in list(self.suspicious_ips.keys()):
                    if self.suspicious_ips[ip] < 0.1:  # Very low suspicion
                        del self.suspicious_ips[ip]

                logger.debug("Completed DDoS protection data cleanup")

            except Exception as e:
                logger.error(f"DDoS cleanup error: {e}")


class EnhancedRateLimitingMiddleware(BaseHTTPMiddleware):
    """Enhanced rate limiting middleware with multiple algorithms."""

    def __init__(
        self,
        app,
        token_bucket_limiter: RateLimiter,
        enable_sliding_window: bool = True,
        enable_ddos_protection: bool = True,
        enable_adaptive_limits: bool = True,
    ):
        """
        Initialize enhanced rate limiting middleware.

        Args:
            app: FastAPI application instance
            token_bucket_limiter: Token bucket rate limiter instance
            enable_sliding_window: Enable sliding window algorithm
            enable_ddos_protection: Enable DDoS protection
            enable_adaptive_limits: Enable adaptive rate limits
        """
        super().__init__(app)
        self.token_bucket = token_bucket_limiter
        self.enable_sliding_window = enable_sliding_window
        self.enable_ddos = enable_ddos_protection
        self.enable_adaptive = enable_adaptive_limits

        # Initialize sliding window limiter if enabled
        self.sliding_window: SlidingWindowLimiter | None
        if enable_sliding_window and cache_manager.connected:
            self.sliding_window = SlidingWindowLimiter(
                SlidingWindowConfig(
                    window_size_seconds=60,
                    max_requests=120,  # Slightly higher than token bucket for burst tolerance
                    sub_window_count=6,
                )
            )
        else:
            self.sliding_window = None

        # Initialize DDoS protection
        self.ddos_protection: DDoSProtectionMiddleware | None
        if enable_ddos_protection:
            self.ddos_protection = DDoSProtectionMiddleware(DDoSConfig())
        else:
            self.ddos_protection = None

        # Endpoint sensitivity mapping
        self.endpoint_configs = {
            "/api/v1/detect": {
                "sensitivity": "high",
                "base_rpm": 60,
                "burst_multiplier": 1.2,
                "priority_weight": 1.5,
            },
            "/api/v1/analyze": {
                "sensitivity": "critical",
                "base_rpm": 30,
                "burst_multiplier": 1.1,
                "priority_weight": 2.0,
            },
            "/api/v1/batch": {
                "sensitivity": "medium",
                "base_rpm": 10,
                "burst_multiplier": 1.3,
                "priority_weight": 1.0,
            },
            "/api/v1/health": {
                "sensitivity": "low",
                "base_rpm": 300,
                "burst_multiplier": 2.0,
                "priority_weight": 0.5,
            },
        }

    async def dispatch(self, request: Request, call_next):
        """Enhanced rate limiting with multiple algorithms."""

        # Skip rate limiting for health checks and internal requests
        if request.url.path in ["/health", "/metrics", "/docs", "/openapi.json"]:
            return await call_next(request)

        # Get client information
        client = getattr(request.state, "client", None)
        client_id = client.client_id if client else self._get_client_identifier(request)

        # Get endpoint configuration
        endpoint_config = self._get_endpoint_config(request.url.path)

        try:
            # 1. DDoS Protection (first line of defense)
            if self.ddos_protection:
                allowed, reason, threat_level = await self.ddos_protection.check_request(request)
                if not allowed:
                    await security_audit_logger.log_security_event(
                        event_type=SecurityEventType.DDOS_DETECTED,
                        description=reason or "DDoS protection triggered",
                        request=request,
                        client_id=client_id,
                        severity="high" if threat_level == ThreatLevel.CRITICAL else "medium",
                        additional_data={"threat_level": threat_level.value},
                    )
                    raise HTTPException(
                        status_code=429, detail=reason, headers={"Retry-After": "300"}
                    )

            # 2. Token Bucket Rate Limiting (your existing system)
            allowed, wait_time = await self._check_token_bucket(request, client_id, endpoint_config)

            if not allowed:
                await security_audit_logger.log_rate_limit_event(
                    request=request,
                    client_id=client_id,
                    limit_type="token_bucket",
                    current_count=0,
                    limit=endpoint_config["base_rpm"],
                )
                raise HTTPException(
                    status_code=429,
                    detail="Rate limit exceeded",
                    headers={"Retry-After": str(int(wait_time))},
                )

            # 3. Sliding Window Rate Limiting (additional protection)
            if self.sliding_window:
                sw_allowed, current_count, remaining = await self.sliding_window.check_rate_limit(
                    f"{client_id}:{request.url.path}"
                )

                if not sw_allowed:
                    await security_audit_logger.log_rate_limit_event(
                        request=request,
                        client_id=client_id,
                        limit_type="sliding_window",
                        current_count=current_count,
                        limit=self.sliding_window.config.max_requests,
                    )
                    raise HTTPException(
                        status_code=429,
                        detail="Rate limit exceeded (sliding window)",
                        headers={"Retry-After": "60", "X-RateLimit-Remaining": str(remaining)},
                    )

            # 4. Adaptive Rate Limiting based on system load
            if self.enable_adaptive:
                adaptive_allowed = await self._check_adaptive_limits(request, client_id)
                if not adaptive_allowed:
                    raise HTTPException(
                        status_code=503,
                        detail="System under high load",
                        headers={"Retry-After": "30"},
                    )

            # Consume tokens if all checks pass
            consumed = await self.token_bucket.consume_tokens(
                client_id=client_id, tokens=self._calculate_token_cost(request, endpoint_config)
            )

            if not consumed:
                raise HTTPException(
                    status_code=429,
                    detail="Token consumption failed",
                    headers={"Retry-After": "60"},
                )

            # Process request
            start_time = time.time()
            response = await call_next(request)
            time.time() - start_time

            # Add rate limiting headers
            self._add_rate_limit_headers(response, client_id, endpoint_config)

            return response

        except HTTPException:
            raise
        except Exception as e:
            logger.error("Rate limiting middleware error", error=str(e), path=request.url.path)
            # Fail open for middleware errors
            return await call_next(request)

    async def _check_token_bucket(self, request: Request, client_id: str, config: dict) -> tuple:
        """Check token bucket rate limiting with endpoint-specific configuration."""

        # Calculate priority based on client and endpoint
        priority = Priority.NORMAL
        if hasattr(request.state, "client") and request.state.client:
            if hasattr(request.state.client, "usage_tier"):
                if request.state.client.usage_tier == "premium":
                    priority = Priority.HIGH
                elif request.state.client.usage_tier == "internal":
                    priority = Priority.CRITICAL

        # Calculate token cost based on endpoint sensitivity
        token_cost = self._calculate_token_cost(request, config)

        return await self.token_bucket.check_rate_limit(
            client_id=client_id, tokens=token_cost, priority=priority
        )

    def _calculate_token_cost(self, request: Request, config: dict) -> int:
        """Calculate token cost based on request complexity and endpoint sensitivity."""
        base_cost = 1

        # Adjust based on endpoint sensitivity
        sensitivity_multiplier = {"low": 1, "medium": 2, "high": 3, "critical": 5}

        cost = base_cost * sensitivity_multiplier.get(config["sensitivity"], 1)

        # Adjust based on request body size for POST requests
        if request.method == "POST":
            content_length = int(request.headers.get("content-length", 0))
            if content_length > 10000:  # Large requests cost more
                cost *= 2
            elif content_length > 50000:
                cost *= 3

        return cost

    async def _check_adaptive_limits(self, request: Request, client_id: str) -> bool:
        """Implement adaptive rate limiting based on system load."""
        try:
            # Get current system metrics
            metrics = self.token_bucket.get_metrics()
            current_load = metrics.get("current_load", 0)

            # If system load is high, apply stricter limits
            if current_load > 0.8:
                # Check if this client has exceeded adaptive threshold
                adaptive_key = f"adaptive:{client_id}"
                recent_requests = await cache_manager.get(adaptive_key) or 0

                if recent_requests > 10:  # Adaptive threshold
                    return False

                # Increment adaptive counter
                await cache_manager.set(adaptive_key, recent_requests + 1, ttl=60)

            return True

        except Exception as e:
            logger.error("Adaptive rate limiting check failed", error=str(e))
            return True  # Fail open

    def _get_client_identifier(self, request: Request) -> str:
        """Get client identifier for rate limiting."""
        # Try to get from forwarded headers first (for proxy setups)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        # Fall back to direct client IP
        return request.client.host if request.client else "unknown"

    def _get_endpoint_config(self, path: str) -> dict:
        """Get configuration for specific endpoint."""
        # Exact match first
        if path in self.endpoint_configs:
            return self.endpoint_configs[path]

        # Pattern matching for versioned APIs
        for pattern, config in self.endpoint_configs.items():
            if path.startswith(pattern.replace("/v1/", "/v")):
                return config

        # Default configuration
        return {
            "sensitivity": "medium",
            "base_rpm": 60,
            "burst_multiplier": 1.5,
            "priority_weight": 1.0,
        }

    def _add_rate_limit_headers(self, response, client_id: str, config: dict):
        """Add rate limiting headers to successful responses."""
        try:
            # Get current token bucket status
            metrics = self.token_bucket.get_metrics()

            response.headers["X-RateLimit-Limit"] = str(config["base_rpm"])
            response.headers["X-RateLimit-Remaining"] = str(
                int(metrics.get("global_tokens_available", 0))
            )
            response.headers["X-RateLimit-Reset"] = str(int(time.time() + 60))
            response.headers["X-RateLimit-Window"] = "60"
            response.headers["X-RateLimit-Type"] = "token-bucket"

        except Exception as e:
            logger.debug("Failed to add rate limit headers", error=str(e))


# Global instances
rate_limiter: RateLimiter | None = None
ddos_protection: DDoSProtectionMiddleware | None = None
