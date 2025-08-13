# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Observability pipeline for monitoring and telemetry."""

import asyncio
import time
from typing import Any

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode


class ObservabilityPipeline:
    """Unified observability pipeline."""

    def __init__(self) -> None:
        """Initialize observability pipeline."""
        self.metrics: dict[str, list[dict[str, Any]]] = {}
        self.traces: list[dict[str, Any]] = []
        self.logs: list[dict[str, Any]] = []
        self.tracer = trace.get_tracer(__name__)
        self._initialized = False

    async def initialize(self) -> None:
        """Initialize the pipeline."""
        self._initialized = True
        # Stub initialization
        await asyncio.sleep(0.001)

    async def shutdown(self) -> None:
        """Shutdown the pipeline."""
        self._initialized = False
        # Stub shutdown
        await asyncio.sleep(0.001)

    def record_metric(self, name: str, value: float, tags: dict[str, Any] | None = None) -> None:
        """Record a metric."""
        if name not in self.metrics:
            self.metrics[name] = []
        self.metrics[name].append({"value": value, "timestamp": time.time(), "tags": tags or {}})

    def start_trace(self, name: str) -> Any:
        """Start a trace span."""
        span = self.tracer.start_span(name)
        self.traces.append({"name": name, "start_time": time.time(), "span": span})
        return span

    def end_trace(self, span: Any, status: Status | None = None) -> None:
        """End a trace span."""
        if status:
            span.set_status(status)
        else:
            span.set_status(Status(StatusCode.OK))
        span.end()

    def log_event(self, level: str, message: str, context: dict[str, Any] | None = None) -> None:
        """Log an event."""
        self.logs.append(
            {"level": level, "message": message, "timestamp": time.time(), "context": context or {}}
        )

    async def flush(self) -> None:
        """Flush all pending data."""
        # Stub flush
        await asyncio.sleep(0.001)
        # In real implementation, would send to backend

    def get_metrics_summary(self) -> dict[str, Any]:
        """Get summary of recorded metrics."""
        summary = {}
        for name, values in self.metrics.items():
            if values:
                all_values = [v["value"] for v in values]
                summary[name] = {
                    "count": len(all_values),
                    "min": min(all_values),
                    "max": max(all_values),
                    "avg": sum(all_values) / len(all_values),
                }
        return summary

    def get_trace_summary(self) -> dict[str, Any]:
        """Get summary of traces."""
        return {
            "total_traces": len(self.traces),
            "trace_names": list({t["name"] for t in self.traces}),
        }

    def get_log_summary(self) -> dict[str, Any]:
        """Get summary of logs."""
        levels: dict[str, int] = {}
        for log in self.logs:
            level = log["level"]
            levels[level] = levels.get(level, 0) + 1
        return {"total_logs": len(self.logs), "by_level": levels}

    async def health_check(self) -> bool:
        """Check if pipeline is healthy."""
        return self._initialized
