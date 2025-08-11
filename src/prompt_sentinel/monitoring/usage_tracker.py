# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Track API usage, costs, and performance metrics.

This module provides comprehensive tracking of LLM API usage including:
- Request counts and token usage
- Cost calculation per provider
- Performance metrics
- Usage patterns and trends
"""

import asyncio
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

import structlog

from prompt_sentinel.cache.cache_manager import cache_manager

logger = structlog.get_logger()


class Provider(Enum):
    """LLM provider enumeration."""

    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    GEMINI = "gemini"
    HEURISTIC = "heuristic"  # No API cost
    CACHE = "cache"  # Cached response


@dataclass
class TokenUsage:
    """Token usage for a single API call."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

    def __post_init__(self) -> None:
        if self.total_tokens == 0:
            self.total_tokens = self.prompt_tokens + self.completion_tokens


@dataclass
class ApiCall:
    """Record of a single API call."""

    provider: Provider
    model: str
    timestamp: datetime
    tokens: TokenUsage
    latency_ms: float
    cost_usd: float
    success: bool
    endpoint: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class UsageMetrics:
    """Aggregated usage metrics."""

    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_tokens: int = 0
    total_cost_usd: float = 0.0
    avg_latency_ms: float = 0.0
    cache_hits: int = 0
    cache_hit_rate: float = 0.0

    # Per-provider breakdown
    by_provider: dict[str, dict[str, Any]] = field(default_factory=dict)

    # Time-based metrics
    requests_per_minute: float = 0.0
    tokens_per_minute: float = 0.0
    cost_per_hour: float = 0.0

    # Current period (for rate limiting)
    current_minute_requests: int = 0
    current_hour_cost: float = 0.0
    current_day_cost: float = 0.0
    current_month_cost: float = 0.0


class UsageTracker:
    """Track and analyze API usage across all providers.

    Provides real-time tracking of API calls, token usage, costs,
    and performance metrics. Supports multiple providers and models
    with configurable cost calculations.
    """

    # Cost per 1K tokens (approximate, should be configured)
    COST_PER_1K_TOKENS = {
        Provider.ANTHROPIC: {
            "claude-3-haiku-20240307": {"input": 0.00025, "output": 0.00125},
            "claude-3-sonnet-20240229": {"input": 0.003, "output": 0.015},
            "claude-3-opus-20240229": {"input": 0.015, "output": 0.075},
        },
        Provider.OPENAI: {
            "gpt-4-turbo-preview": {"input": 0.01, "output": 0.03},
            "gpt-4": {"input": 0.03, "output": 0.06},
            "gpt-3.5-turbo": {"input": 0.0005, "output": 0.0015},
        },
        Provider.GEMINI: {
            "gemini-1.5-flash": {"input": 0.00035, "output": 0.0021},
            "gemini-1.5-pro": {"input": 0.007, "output": 0.021},
            "gemini-pro": {"input": 0.0005, "output": 0.0015},
        },
    }

    def __init__(
        self, persist_to_cache: bool = True, retention_hours: int = 24 * 7
    ):  # 1 week default
        """Initialize usage tracker.

        Args:
            persist_to_cache: Whether to persist metrics to Redis
            retention_hours: How long to retain detailed usage data
        """
        self.persist_to_cache = persist_to_cache
        self.retention_hours = retention_hours

        # In-memory storage
        self.api_calls: list[ApiCall] = []
        self.metrics = UsageMetrics()

        # Time windows for rate limiting
        self.current_minute = datetime.now().replace(second=0, microsecond=0)
        self.current_hour = datetime.now().replace(minute=0, second=0, microsecond=0)
        self.current_day = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        self.current_month = datetime.now().replace(
            day=1, hour=0, minute=0, second=0, microsecond=0
        )

        # Provider-specific metrics
        self.provider_metrics: defaultdict[str, dict[str, Any]] = defaultdict(
            lambda: {
                "requests": 0,
                "tokens": 0,
                "cost": 0.0,
                "avg_latency": 0.0,
                "success_rate": 0.0,
            }
        )

        # Load persisted metrics if available
        asyncio.create_task(self._load_persisted_metrics())

    async def track_api_call(
        self,
        provider: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        latency_ms: float,
        success: bool = True,
        endpoint: str = "",
        metadata: dict | None = None,
    ) -> ApiCall:
        """Track a single API call.

        Args:
            provider: Provider name (anthropic, openai, gemini)
            model: Model identifier
            prompt_tokens: Input token count
            completion_tokens: Output token count
            latency_ms: Call latency in milliseconds
            success: Whether the call succeeded
            endpoint: API endpoint called
            metadata: Additional metadata

        Returns:
            ApiCall record
        """
        # Create provider enum
        try:
            provider_enum = Provider(provider.lower())
        except ValueError:
            provider_enum = Provider.HEURISTIC

        # Calculate cost
        tokens = TokenUsage(prompt_tokens=prompt_tokens, completion_tokens=completion_tokens)
        cost = self._calculate_cost(provider_enum, model, tokens)

        # Create API call record
        api_call = ApiCall(
            provider=provider_enum,
            model=model,
            timestamp=datetime.now(),
            tokens=tokens,
            latency_ms=latency_ms,
            cost_usd=cost,
            success=success,
            endpoint=endpoint,
            metadata=metadata or {},
        )

        # Store and update metrics
        self.api_calls.append(api_call)
        await self._update_metrics(api_call)

        # Persist if configured
        if self.persist_to_cache:
            await self._persist_call(api_call)

        # Log high-cost calls
        if cost > 0.10:  # More than 10 cents
            logger.warning(
                "High cost API call",
                provider=provider,
                model=model,
                cost_usd=cost,
                tokens=tokens.total_tokens,
            )

        return api_call

    async def track_cache_hit(self, endpoint: str, latency_ms: float) -> None:
        """Track a cache hit (no API cost).

        Args:
            endpoint: Endpoint that was cached
            latency_ms: Cache retrieval latency
        """
        api_call = ApiCall(
            provider=Provider.CACHE,
            model="cache",
            timestamp=datetime.now(),
            tokens=TokenUsage(),
            latency_ms=latency_ms,
            cost_usd=0.0,
            success=True,
            endpoint=endpoint,
            metadata={"cache_hit": True},
        )

        self.api_calls.append(api_call)
        self.metrics.cache_hits += 1
        await self._update_metrics(api_call)

    async def track_request(
        self,
        endpoint: str,
        latency_ms: float,
        success: bool = True,
        metadata: dict | None = None,
        client_id: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Track a generic request (heuristic detection, etc).

        Args:
            endpoint: Endpoint that was called
            latency_ms: Request latency in milliseconds
            success: Whether the request succeeded
            metadata: Additional metadata
            client_id: Optional client identifier
            **kwargs: Additional keyword arguments
        """
        # Merge metadata with client_id if provided
        request_metadata = metadata or {}
        if client_id:
            request_metadata["client_id"] = client_id

        api_call = ApiCall(
            provider=Provider.HEURISTIC,
            model="heuristic",
            timestamp=datetime.now(),
            tokens=TokenUsage(),
            latency_ms=latency_ms,
            cost_usd=0.0,
            success=success,
            endpoint=endpoint,
            metadata=request_metadata,
        )

        self.api_calls.append(api_call)
        await self._update_metrics(api_call)

    def _calculate_cost(self, provider: Provider, model: str, tokens: TokenUsage) -> float:
        """Calculate cost for API call.

        Args:
            provider: Provider enum
            model: Model identifier
            tokens: Token usage

        Returns:
            Cost in USD
        """
        if provider in [Provider.HEURISTIC, Provider.CACHE]:
            return 0.0

        # Get pricing for provider/model
        provider_costs = self.COST_PER_1K_TOKENS.get(provider, {})
        model_costs = provider_costs.get(model, None)

        if not model_costs:
            # Use default pricing if model not found
            logger.warning(f"No pricing found for {provider.value}/{model}")
            model_costs = {"input": 0.001, "output": 0.002}  # Default conservative pricing

        # Calculate cost
        input_cost = (tokens.prompt_tokens / 1000) * model_costs["input"]
        output_cost = (tokens.completion_tokens / 1000) * model_costs["output"]

        return round(input_cost + output_cost, 6)

    async def _update_metrics(self, api_call: ApiCall) -> None:
        """Update aggregated metrics.

        Args:
            api_call: New API call to include in metrics
        """
        now = datetime.now()

        # Check time window resets
        if now.minute != self.current_minute.minute:
            self.metrics.current_minute_requests = 0
            self.current_minute = now.replace(second=0, microsecond=0)

        if now.hour != self.current_hour.hour:
            self.metrics.current_hour_cost = 0.0
            self.current_hour = now.replace(minute=0, second=0, microsecond=0)

        if now.day != self.current_day.day:
            self.metrics.current_day_cost = 0.0
            self.current_day = now.replace(hour=0, minute=0, second=0, microsecond=0)

        if now.month != self.current_month.month:
            self.metrics.current_month_cost = 0.0
            self.current_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        # Update counts
        self.metrics.total_requests += 1
        self.metrics.current_minute_requests += 1

        if api_call.success:
            self.metrics.successful_requests += 1
        else:
            self.metrics.failed_requests += 1

        # Update tokens and cost
        self.metrics.total_tokens += api_call.tokens.total_tokens
        self.metrics.total_cost_usd += api_call.cost_usd
        self.metrics.current_hour_cost += api_call.cost_usd
        self.metrics.current_day_cost += api_call.cost_usd
        self.metrics.current_month_cost += api_call.cost_usd

        # Update latency (running average)
        total = self.metrics.total_requests
        self.metrics.avg_latency_ms = (
            self.metrics.avg_latency_ms * (total - 1) + api_call.latency_ms
        ) / total

        # Update cache hit rate
        if self.metrics.total_requests > 0:
            self.metrics.cache_hit_rate = self.metrics.cache_hits / self.metrics.total_requests

        # Update per-provider metrics
        if api_call.provider != Provider.CACHE:
            provider_key = api_call.provider.value
            pm = self.provider_metrics[provider_key]
            pm["requests"] += 1
            pm["tokens"] += api_call.tokens.total_tokens
            pm["cost"] += api_call.cost_usd

            # Update provider average latency
            pm["avg_latency"] = (
                pm["avg_latency"] * (pm["requests"] - 1) + api_call.latency_ms
            ) / pm["requests"]

            # Calculate success rate
            if api_call.success:
                pm["success_rate"] = (pm["success_rate"] * (pm["requests"] - 1) + 1) / pm[
                    "requests"
                ]
            else:
                pm["success_rate"] = (pm["success_rate"] * (pm["requests"] - 1)) / pm["requests"]

        # Calculate rate metrics
        time_since_start = (
            (now - self.api_calls[0].timestamp).total_seconds() if self.api_calls else 1
        )
        minutes_elapsed = max(time_since_start / 60, 1)
        hours_elapsed = max(time_since_start / 3600, 1)

        self.metrics.requests_per_minute = self.metrics.total_requests / minutes_elapsed
        self.metrics.tokens_per_minute = self.metrics.total_tokens / minutes_elapsed
        self.metrics.cost_per_hour = self.metrics.total_cost_usd / hours_elapsed

        # Update by_provider in metrics
        self.metrics.by_provider = dict(self.provider_metrics)

    async def _persist_call(self, api_call: ApiCall) -> None:
        """Persist API call to cache.

        Args:
            api_call: API call to persist
        """
        if not cache_manager.connected:
            return

        # Create cache key with timestamp
        timestamp = api_call.timestamp.isoformat()
        key = f"usage:calls:{timestamp}"

        # Serialize call data
        call_data = {
            "provider": api_call.provider.value,
            "model": api_call.model,
            "timestamp": timestamp,
            "tokens": asdict(api_call.tokens),
            "latency_ms": api_call.latency_ms,
            "cost_usd": api_call.cost_usd,
            "success": api_call.success,
            "endpoint": api_call.endpoint,
            "metadata": api_call.metadata,
        }

        # Store with retention period
        ttl = self.retention_hours * 3600
        await cache_manager.set(key, call_data, ttl=ttl)

        # Also update aggregated daily metrics
        day_key = f"usage:daily:{self.current_day.strftime('%Y-%m-%d')}"
        daily_metrics = await cache_manager.get(day_key) or {
            "requests": 0,
            "tokens": 0,
            "cost": 0.0,
        }

        daily_metrics["requests"] += 1
        daily_metrics["tokens"] += api_call.tokens.total_tokens
        daily_metrics["cost"] += api_call.cost_usd

        await cache_manager.set(day_key, daily_metrics, ttl=30 * 24 * 3600)  # 30 days

    async def _load_persisted_metrics(self) -> None:
        """Load persisted metrics from cache on startup."""
        if not cache_manager.connected:
            return

        try:
            # Load today's metrics
            day_key = f"usage:daily:{self.current_day.strftime('%Y-%m-%d')}"
            daily_metrics = await cache_manager.get(day_key)

            if daily_metrics:
                self.metrics.current_day_cost = daily_metrics.get("cost", 0.0)
                logger.info(
                    "Loaded persisted daily metrics",
                    requests=daily_metrics.get("requests", 0),
                    cost=daily_metrics.get("cost", 0.0),
                )

            # Load current month metrics
            month_start = self.current_month.strftime("%Y-%m-01")
            month_key = f"usage:monthly:{month_start}"
            monthly_metrics = await cache_manager.get(month_key)

            if monthly_metrics:
                self.metrics.current_month_cost = monthly_metrics.get("cost", 0.0)

        except Exception as e:
            logger.error("Failed to load persisted metrics", error=str(e))

    def get_metrics(self, time_window: timedelta | None = None) -> UsageMetrics:
        """Get usage metrics for time window.

        Args:
            time_window: Optional time window (default: all time)

        Returns:
            UsageMetrics for the period
        """
        if not time_window:
            return self.metrics

        # Filter calls within time window
        cutoff = datetime.now() - time_window
        recent_calls = [c for c in self.api_calls if c.timestamp > cutoff]

        if not recent_calls:
            return UsageMetrics()

        # Calculate metrics for window
        metrics = UsageMetrics()
        metrics.total_requests = len(recent_calls)
        metrics.successful_requests = sum(1 for c in recent_calls if c.success)
        metrics.failed_requests = metrics.total_requests - metrics.successful_requests
        metrics.total_tokens = sum(c.tokens.total_tokens for c in recent_calls)
        metrics.total_cost_usd = sum(c.cost_usd for c in recent_calls)
        metrics.avg_latency_ms = sum(c.latency_ms for c in recent_calls) / len(recent_calls)
        metrics.cache_hits = sum(1 for c in recent_calls if c.provider == Provider.CACHE)
        metrics.cache_hit_rate = metrics.cache_hits / metrics.total_requests

        # Calculate rates
        time_span = (recent_calls[-1].timestamp - recent_calls[0].timestamp).total_seconds()
        if time_span > 0:
            metrics.requests_per_minute = metrics.total_requests / (time_span / 60)
            metrics.tokens_per_minute = metrics.total_tokens / (time_span / 60)
            metrics.cost_per_hour = metrics.total_cost_usd / (time_span / 3600)

        return metrics

    def get_provider_breakdown(self) -> dict[str, dict[str, Any]]:
        """Get detailed breakdown by provider.

        Returns:
            Dictionary with per-provider metrics
        """
        return dict(self.provider_metrics)

    def get_cost_breakdown(self, group_by: str = "provider") -> dict[str, float]:
        """Get cost breakdown by provider or model.

        Args:
            group_by: "provider" or "model"

        Returns:
            Dictionary mapping provider/model to cost
        """
        breakdown: defaultdict[str, float] = defaultdict(float)

        for call in self.api_calls:
            if group_by == "provider":
                key = call.provider.value
            elif group_by == "model":
                key = f"{call.provider.value}/{call.model}"
            else:
                key = "unknown"

            breakdown[key] += call.cost_usd

        return dict(breakdown)

    def get_usage_trend(self, period: str = "hour", limit: int = 24) -> list[dict[str, Any]]:
        """Get usage trend over time.

        Args:
            period: "minute", "hour", or "day"
            limit: Number of periods to return

        Returns:
            List of period metrics
        """
        if not self.api_calls:
            return []

        # Group calls by period
        periods: defaultdict[str, dict[str, float]] = defaultdict(
            lambda: {"requests": 0, "tokens": 0, "cost": 0.0, "avg_latency": 0.0}
        )

        for call in self.api_calls:
            if period == "minute":
                key = call.timestamp.strftime("%Y-%m-%d %H:%M")
            elif period == "hour":
                key = call.timestamp.strftime("%Y-%m-%d %H:00")
            elif period == "day":
                key = call.timestamp.strftime("%Y-%m-%d")
            else:
                continue

            p = periods[key]
            p["requests"] += 1
            p["tokens"] += call.tokens.total_tokens
            p["cost"] += call.cost_usd
            p["avg_latency"] = (p["avg_latency"] * (p["requests"] - 1) + call.latency_ms) / p[
                "requests"
            ]

        # Convert to list and sort
        trend = [{"period": k, **v} for k, v in sorted(periods.items(), reverse=True)[:limit]]

        return list(reversed(trend))

    def clear_old_data(self, retention_hours: int | None = None) -> None:
        """Clear data older than retention period.

        Args:
            retention_hours: Hours to retain (default: self.retention_hours)
        """
        retention = retention_hours or self.retention_hours
        cutoff = datetime.now() - timedelta(hours=retention)

        # Filter recent calls
        self.api_calls = [c for c in self.api_calls if c.timestamp > cutoff]

        logger.info(
            "Cleared old usage data", retention_hours=retention, remaining_calls=len(self.api_calls)
        )
