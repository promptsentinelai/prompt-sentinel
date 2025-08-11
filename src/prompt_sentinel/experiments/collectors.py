# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Metrics collection for A/B testing experiments.

This module provides enhanced metrics collection specifically for experiment
analysis, building on the existing monitoring infrastructure.
"""

import json
import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import structlog

from prompt_sentinel.cache.cache_manager import cache_manager
from prompt_sentinel.monitoring.usage_tracker import UsageTracker

logger = structlog.get_logger()


@dataclass
class ExperimentMetric:
    """A single experiment metric measurement."""

    experiment_id: str
    variant_id: str
    user_id: str
    metric_name: str
    value: float
    timestamp: datetime
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AggregatedMetrics:
    """Aggregated metrics for a variant."""

    variant_id: str
    metric_name: str
    count: int
    sum_value: float
    mean: float
    min_value: float
    max_value: float
    std_dev: float
    percentiles: dict[int, float]  # {50: median, 95: p95, etc.}


class MetricsCollector:
    """Enhanced metrics collection for experiments.

    Extends the base monitoring system with experiment-specific
    functionality for detailed A/B testing analysis.
    """

    def __init__(self, usage_tracker: UsageTracker | None = None):
        """Initialize metrics collector.

        Args:
            usage_tracker: Base usage tracking service
        """
        self.usage_tracker = usage_tracker
        self.experiment_metrics: dict[str, list[ExperimentMetric]] = defaultdict(list)
        self.aggregation_cache: dict[str, dict[str, AggregatedMetrics]] = {}
        self.cache_ttl = 300  # 5 minutes

    async def record_experiment_metric(
        self,
        experiment_id: str,
        variant_id: str,
        metric_name: str,
        value: float,
        user_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ):
        """Record a metric for experiment analysis.

        Args:
            experiment_id: Experiment identifier
            variant_id: Variant identifier
            metric_name: Name of the metric
            value: Metric value
            user_id: User identifier (optional)
            metadata: Additional metadata
        """
        metric = ExperimentMetric(
            experiment_id=experiment_id,
            variant_id=variant_id,
            user_id=user_id or "anonymous",
            metric_name=metric_name,
            value=value,
            timestamp=datetime.utcnow(),
            metadata=metadata or {},
        )

        # Store in memory buffer
        self.experiment_metrics[experiment_id].append(metric)

        # Invalidate aggregation cache for this experiment
        if experiment_id in self.aggregation_cache:
            cache_key = f"{variant_id}:{metric_name}"
            if cache_key in self.aggregation_cache[experiment_id]:
                del self.aggregation_cache[experiment_id][cache_key]

        # Cache in Redis if available
        await self._cache_metric(metric)

        logger.debug(
            "Experiment metric recorded",
            experiment_id=experiment_id,
            variant_id=variant_id,
            metric=metric_name,
            value=value,
        )

    async def get_experiment_metrics(
        self,
        experiment_id: str,
        time_window_hours: int | None = None,
        variant_ids: list[str] | None = None,
        metric_names: list[str] | None = None,
    ) -> dict[str, dict[str, list[float]]]:
        """Get raw metrics for experiment analysis.

        Args:
            experiment_id: Experiment identifier
            time_window_hours: Time window for metrics (None for all)
            variant_ids: Filter by variant IDs
            metric_names: Filter by metric names

        Returns:
            Nested dict {metric_name: {variant_id: [values]}}
        """
        # Try cache first
        cache_key = f"experiment_metrics:{experiment_id}"
        if cache_manager and cache_manager.connected:
            try:
                cached_data = await cache_manager.get(cache_key)
                if cached_data:
                    return self._filter_metrics_data(
                        cached_data, variant_ids, metric_names, time_window_hours
                    )
            except Exception as e:
                logger.warning("Failed to get cached metrics", error=str(e))

        # Get from memory buffer
        metrics = self.experiment_metrics.get(experiment_id, [])

        # Apply time window filter
        if time_window_hours:
            cutoff_time = datetime.utcnow() - timedelta(hours=time_window_hours)
            metrics = [m for m in metrics if m.timestamp > cutoff_time]

        # Apply variant filter
        if variant_ids:
            metrics = [m for m in metrics if m.variant_id in variant_ids]

        # Apply metric name filter
        if metric_names:
            metrics = [m for m in metrics if m.metric_name in metric_names]

        # Organize data
        data = defaultdict(lambda: defaultdict(list))
        for metric in metrics:
            data[metric.metric_name][metric.variant_id].append(metric.value)

        # Convert to regular dict
        result = {k: dict(v) for k, v in data.items()}

        # Cache result
        if cache_manager and cache_manager.connected:
            try:
                await cache_manager.set(cache_key, result, ttl=self.cache_ttl)
            except Exception as e:
                logger.warning("Failed to cache metrics", error=str(e))

        return result

    async def get_aggregated_metrics(
        self,
        experiment_id: str,
        variant_id: str,
        metric_name: str,
        time_window_hours: int | None = None,
    ) -> AggregatedMetrics | None:
        """Get aggregated metrics for a variant.

        Args:
            experiment_id: Experiment identifier
            variant_id: Variant identifier
            metric_name: Metric name
            time_window_hours: Time window for aggregation

        Returns:
            Aggregated metrics or None if no data
        """
        # Check cache
        cache_key = f"{variant_id}:{metric_name}"
        if (
            experiment_id in self.aggregation_cache
            and cache_key in self.aggregation_cache[experiment_id]
        ):
            return self.aggregation_cache[experiment_id][cache_key]

        # Get raw metrics
        metrics_data = await self.get_experiment_metrics(
            experiment_id, time_window_hours, [variant_id], [metric_name]
        )

        if metric_name not in metrics_data or variant_id not in metrics_data[metric_name]:
            return None

        values = metrics_data[metric_name][variant_id]
        if not values:
            return None

        # Calculate aggregations
        aggregated = self._calculate_aggregations(variant_id, metric_name, values)

        # Cache result
        if experiment_id not in self.aggregation_cache:
            self.aggregation_cache[experiment_id] = {}
        self.aggregation_cache[experiment_id][cache_key] = aggregated

        return aggregated

    async def get_variant_performance(
        self, experiment_id: str, variant_id: str, time_window_hours: int = 24
    ) -> dict[str, Any]:
        """Get comprehensive performance metrics for a variant.

        Args:
            experiment_id: Experiment identifier
            variant_id: Variant identifier
            time_window_hours: Time window for analysis

        Returns:
            Performance metrics
        """
        # Get all metrics for the variant
        metrics_data = await self.get_experiment_metrics(
            experiment_id, time_window_hours, [variant_id]
        )

        performance = {
            "variant_id": variant_id,
            "time_window_hours": time_window_hours,
            "metrics": {},
            "summary": {
                "total_events": 0,
                "unique_users": set(),
                "avg_events_per_user": 0,
                "first_event": None,
                "last_event": None,
            },
        }

        # Get all metrics for the variant within the time window
        all_experiment_metrics = self.experiment_metrics.get(experiment_id, [])

        # Apply time window filter if specified
        if time_window_hours:
            cutoff_time = datetime.utcnow() - timedelta(hours=time_window_hours)
            filtered_metrics = [
                m
                for m in all_experiment_metrics
                if m.timestamp > cutoff_time and m.variant_id == variant_id
            ]
        else:
            filtered_metrics = [m for m in all_experiment_metrics if m.variant_id == variant_id]

        for metric_name, variant_data in metrics_data.items():
            if variant_id in variant_data:
                # Get aggregated metrics
                aggregated = await self.get_aggregated_metrics(
                    experiment_id, variant_id, metric_name, time_window_hours
                )

                if aggregated:
                    performance["metrics"][metric_name] = {
                        "count": aggregated.count,
                        "mean": aggregated.mean,
                        "min": aggregated.min_value,
                        "max": aggregated.max_value,
                        "std_dev": aggregated.std_dev,
                        "percentiles": aggregated.percentiles,
                    }

        # Calculate summary statistics using filtered metrics
        variant_metrics = filtered_metrics

        if variant_metrics:
            performance["summary"]["total_events"] = len(variant_metrics)
            performance["summary"]["unique_users"] = len({m.user_id for m in variant_metrics})
            performance["summary"]["avg_events_per_user"] = len(variant_metrics) / len(
                {m.user_id for m in variant_metrics}
            )
            performance["summary"]["first_event"] = min(
                m.timestamp for m in variant_metrics
            ).isoformat()
            performance["summary"]["last_event"] = max(
                m.timestamp for m in variant_metrics
            ).isoformat()

        return performance

    async def record_detection_metrics(
        self,
        experiment_id: str,
        variant_id: str,
        user_id: str,
        response_time_ms: float,
        confidence: float,
        verdict: str,
        provider_used: str,
        cache_hit: bool,
        pii_detected: bool = False,
    ):
        """Record detection-specific metrics for experiments.

        Args:
            experiment_id: Experiment identifier
            variant_id: Variant identifier
            user_id: User identifier
            response_time_ms: Response time in milliseconds
            confidence: Detection confidence
            verdict: Detection verdict
            provider_used: LLM provider used
            cache_hit: Whether result was from cache
            pii_detected: Whether PII was detected
        """
        # Record individual metrics
        await self.record_experiment_metric(
            experiment_id, variant_id, "response_time_ms", response_time_ms, user_id
        )

        await self.record_experiment_metric(
            experiment_id, variant_id, "confidence", confidence, user_id
        )

        # Binary metrics
        await self.record_experiment_metric(
            experiment_id, variant_id, "blocked", 1.0 if verdict == "block" else 0.0, user_id
        )

        await self.record_experiment_metric(
            experiment_id, variant_id, "cache_hit", 1.0 if cache_hit else 0.0, user_id
        )

        await self.record_experiment_metric(
            experiment_id, variant_id, "pii_detected", 1.0 if pii_detected else 0.0, user_id
        )

        # Provider distribution
        await self.record_experiment_metric(
            experiment_id, variant_id, f"provider_{provider_used}", 1.0, user_id
        )

        logger.debug(
            "Detection metrics recorded",
            experiment_id=experiment_id,
            variant_id=variant_id,
            response_time=response_time_ms,
            verdict=verdict,
        )

    async def export_experiment_data(self, experiment_id: str, format_type: str = "json") -> str:
        """Export experiment data for external analysis.

        Args:
            experiment_id: Experiment identifier
            format_type: Export format (json, csv)

        Returns:
            Exported data as string
        """
        metrics = self.experiment_metrics.get(experiment_id, [])

        if format_type.lower() == "json":
            data = []
            for metric in metrics:
                data.append(
                    {
                        "experiment_id": metric.experiment_id,
                        "variant_id": metric.variant_id,
                        "user_id": metric.user_id,
                        "metric_name": metric.metric_name,
                        "value": metric.value,
                        "timestamp": metric.timestamp.isoformat(),
                        "metadata": metric.metadata,
                    }
                )
            return json.dumps(data, indent=2)

        elif format_type.lower() == "csv":
            lines = ["experiment_id,variant_id,user_id,metric_name,value,timestamp"]
            for metric in metrics:
                lines.append(
                    f"{metric.experiment_id},{metric.variant_id},{metric.user_id},"
                    f"{metric.metric_name},{metric.value},{metric.timestamp.isoformat()}"
                )
            return "\n".join(lines)

        else:
            raise ValueError(f"Unsupported format: {format_type}")

    async def clear_experiment_data(self, experiment_id: str):
        """Clear cached experiment data.

        Args:
            experiment_id: Experiment identifier
        """
        # Clear memory buffers
        if experiment_id in self.experiment_metrics:
            del self.experiment_metrics[experiment_id]

        if experiment_id in self.aggregation_cache:
            del self.aggregation_cache[experiment_id]

        # Clear Redis cache
        if cache_manager and cache_manager.connected:
            try:
                pattern = f"experiment_metric:{experiment_id}:*"
                await cache_manager.delete_pattern(pattern)

                cache_key = f"experiment_metrics:{experiment_id}"
                await cache_manager.delete(cache_key)

            except Exception as e:
                logger.warning("Failed to clear cached experiment data", error=str(e))

        logger.info("Experiment data cleared", experiment_id=experiment_id)

    def _calculate_aggregations(
        self, variant_id: str, metric_name: str, values: list[float]
    ) -> AggregatedMetrics:
        """Calculate aggregated statistics for metric values."""
        import statistics

        if not values:
            return AggregatedMetrics(
                variant_id=variant_id,
                metric_name=metric_name,
                count=0,
                sum_value=0.0,
                mean=0.0,
                min_value=0.0,
                max_value=0.0,
                std_dev=0.0,
                percentiles={},
            )

        sorted_values = sorted(values)
        n = len(values)
        mean_val = statistics.mean(values)

        return AggregatedMetrics(
            variant_id=variant_id,
            metric_name=metric_name,
            count=n,
            sum_value=sum(values),
            mean=mean_val,
            min_value=min(values),
            max_value=max(values),
            std_dev=statistics.stdev(values) if n > 1 else 0.0,
            percentiles={
                25: self._percentile(sorted_values, 25),
                50: self._percentile(sorted_values, 50),
                75: self._percentile(sorted_values, 75),
                90: self._percentile(sorted_values, 90),
                95: self._percentile(sorted_values, 95),
                99: self._percentile(sorted_values, 99),
            },
        )

    def _percentile(self, sorted_values: list[float], percentile: int) -> float:
        """Calculate percentile from sorted values."""
        if not sorted_values:
            return 0.0

        n = len(sorted_values)
        k = (n - 1) * percentile / 100.0
        f = math.floor(k)
        c = math.ceil(k)

        if f == c:
            return sorted_values[int(k)]

        d0 = sorted_values[int(f)] * (c - k)
        d1 = sorted_values[int(c)] * (k - f)
        return d0 + d1

    def _filter_metrics_data(
        self,
        data: dict[str, dict[str, list[float]]],
        variant_ids: list[str] | None,
        metric_names: list[str] | None,
        time_window_hours: int | None,
    ) -> dict[str, dict[str, list[float]]]:
        """Filter metrics data based on criteria."""
        filtered = {}

        for metric_name, variant_data in data.items():
            if metric_names and metric_name not in metric_names:
                continue

            filtered_variants = {}
            for variant_id, values in variant_data.items():
                if variant_ids and variant_id not in variant_ids:
                    continue

                # Time filtering would need timestamps, which aren't in this structure
                # This is a simplified version
                filtered_variants[variant_id] = values

            if filtered_variants:
                filtered[metric_name] = filtered_variants

        return filtered

    async def _cache_metric(self, metric: ExperimentMetric):
        """Cache individual metric in Redis."""
        if not cache_manager or not cache_manager.connected:
            return

        try:
            cache_key = (
                f"experiment_metric:{metric.experiment_id}:{metric.variant_id}:{metric.metric_name}"
            )
            metric_data = {
                "value": metric.value,
                "timestamp": metric.timestamp.isoformat(),
                "user_id": metric.user_id,
                "metadata": metric.metadata,
            }

            # Add to a list in Redis (for time-series data)
            await cache_manager.lpush(cache_key, json.dumps(metric_data))

            # Keep only recent data (last 1000 entries)
            await cache_manager.ltrim(cache_key, 0, 999)

            # Set expiration
            await cache_manager.expire(cache_key, 86400)  # 24 hours

        except Exception as e:
            logger.warning("Failed to cache metric", error=str(e))
