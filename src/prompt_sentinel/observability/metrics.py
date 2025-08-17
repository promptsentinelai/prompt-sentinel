# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Metrics collection for observability.

Deprecated: Prefer Prometheus-backed metrics in `prompt_sentinel.monitoring.metrics`.
This module remains for test and in-memory scenarios (no external deps).

For compatibility, this module also re-exports Prometheus metrics and helpers
from `prompt_sentinel.monitoring.metrics` when available, so existing imports
like `from prompt_sentinel.observability.metrics import get_metrics` continue
to work while the codebase migrates to the monitoring module.
"""

import time
from collections import defaultdict
from typing import Any

# Re-export Prometheus-backed metrics and helpers for compatibility
try:  # Best-effort shim; tests that rely on in-memory collector will still work
    from prompt_sentinel.monitoring.metrics import (
        ACTIVE_REQUESTS,
        API_COST,
        ATTACK_SEVERITY,
        CACHE_EVICTIONS,
        CACHE_HITS,
        CACHE_MISSES,
        CACHE_SIZE,
        COST_PER_DETECTION,
        DETECTION_CONFIDENCE,
        DETECTION_COUNT,
        DETECTION_DURATION,
        ERROR_COUNT,
        FEED_INDICATOR_COUNT,
        FEED_UPDATE_COUNT,
        LLM_REQUEST_COUNT,
        LLM_REQUEST_DURATION,
        PATTERN_MATCHES,
        QUEUE_SIZE,
        RATE_LIMIT_HITS,
        REQUEST_COUNT,
        REQUEST_DURATION,
        SERVICE_INFO,
        TOKEN_USAGE,
        get_metrics,
        initialize_metrics,
        track_cache_metrics,
        track_detection_metrics,
        track_llm_metrics,
    )

    __all__ = [
        # Prometheus symbols
        "ACTIVE_REQUESTS",
        "API_COST",
        "ATTACK_SEVERITY",
        "CACHE_EVICTIONS",
        "CACHE_HITS",
        "CACHE_MISSES",
        "CACHE_SIZE",
        "COST_PER_DETECTION",
        "DETECTION_CONFIDENCE",
        "DETECTION_COUNT",
        "DETECTION_DURATION",
        "ERROR_COUNT",
        "FEED_INDICATOR_COUNT",
        "FEED_UPDATE_COUNT",
        "LLM_REQUEST_COUNT",
        "LLM_REQUEST_DURATION",
        "PATTERN_MATCHES",
        "QUEUE_SIZE",
        "RATE_LIMIT_HITS",
        "REQUEST_COUNT",
        "REQUEST_DURATION",
        "SERVICE_INFO",
        "TOKEN_USAGE",
        "get_metrics",
        "initialize_metrics",
        "track_cache_metrics",
        "track_detection_metrics",
        "track_llm_metrics",
        # In-memory collector (below)
        "MetricsCollector",
    ]
except Exception:  # pragma: no cover - only triggered in constrained envs
    __all__ = ["MetricsCollector"]


class MetricsCollector:
    """Collect and aggregate metrics (test/in-memory use only)."""

    def __init__(self, namespace: str = "prompt_sentinel"):
        """Initialize metrics collector."""
        self.namespace = namespace
        self.counters: dict[str, int] = defaultdict(int)
        self.gauges: dict[str, float] = {}
        self.histograms: dict[str, list[float]] = defaultdict(list)
        self.timers: dict[str, float] = {}

    def increment(self, name: str, value: int = 1, tags: dict[str, str] | None = None) -> None:
        """Increment a counter metric."""
        key = self._format_key(name, tags)
        self.counters[key] += value

    def gauge(self, name: str, value: float, tags: dict[str, str] | None = None) -> None:
        """Set a gauge metric."""
        key = self._format_key(name, tags)
        self.gauges[key] = value

    def histogram(self, name: str, value: float, tags: dict[str, str] | None = None) -> None:
        """Record a histogram value."""
        key = self._format_key(name, tags)
        self.histograms[key].append(value)

    def timer_start(self, name: str) -> None:
        """Start a timer."""
        self.timers[name] = time.time()

    def timer_end(self, name: str, tags: dict[str, str] | None = None) -> float:
        """End a timer and record duration."""
        if name not in self.timers:
            return 0.0

        duration = time.time() - self.timers[name]
        self.histogram(f"{name}.duration", duration, tags)
        del self.timers[name]
        return duration

    def _format_key(self, name: str, tags: dict[str, str] | None) -> str:
        """Format metric key with tags."""
        key = f"{self.namespace}.{name}"
        if tags:
            tag_str = ",".join(f"{k}={v}" for k, v in sorted(tags.items()))
            key = f"{key},{tag_str}"
        return key

    def get_counter(self, name: str, tags: dict[str, str] | None = None) -> int:
        """Get counter value."""
        key = self._format_key(name, tags)
        return self.counters.get(key, 0)

    def get_gauge(self, name: str, tags: dict[str, str] | None = None) -> float:
        """Get gauge value."""
        key = self._format_key(name, tags)
        return self.gauges.get(key, 0.0)

    def get_histogram_stats(
        self, name: str, tags: dict[str, str] | None = None
    ) -> dict[str, float]:
        """Get histogram statistics."""
        key = self._format_key(name, tags)
        values = self.histograms.get(key, [])

        if not values:
            return {"count": 0, "min": 0, "max": 0, "avg": 0, "p50": 0, "p95": 0, "p99": 0}

        sorted_values = sorted(values)
        count = len(values)

        return {
            "count": count,
            "min": min(values),
            "max": max(values),
            "avg": sum(values) / count,
            "p50": sorted_values[count // 2],
            "p95": sorted_values[int(count * 0.95)] if count > 1 else sorted_values[0],
            "p99": sorted_values[int(count * 0.99)] if count > 1 else sorted_values[0],
        }

    def get_all_metrics(self) -> dict[str, Any]:
        """Get all metrics."""
        return {
            "counters": dict(self.counters),
            "gauges": dict(self.gauges),
            "histograms": {
                k: self.get_histogram_stats(k.split(",")[0].split(".")[-1], self._parse_tags(k))
                for k in self.histograms.keys()
            },
        }

    def _parse_tags(self, key: str) -> dict[str, str] | None:
        """Parse tags from metric key."""
        if "," not in key:
            return None

        tags = {}
        tag_str = key.split(",", 1)[1]
        for tag in tag_str.split(","):
            if "=" in tag:
                k, v = tag.split("=", 1)
                tags[k] = v
        return tags if tags else None

    def reset(self) -> None:
        """Reset all metrics."""
        self.counters.clear()
        self.gauges.clear()
        self.histograms.clear()
        self.timers.clear()
