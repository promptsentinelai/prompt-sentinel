# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Distributed tracing for observability.

Deprecated/Stub: Minimal in-memory tracing utilities for tests. For production
use, prefer OpenTelemetry integration under `prompt_sentinel.monitoring` and
external tracing backends. Not wired by default.
"""

import asyncio
import time
import uuid
from typing import Any


class Span:
    """Represents a trace span."""

    def __init__(self, name: str, parent_id: str | None = None):
        """Initialize span."""
        self.span_id = str(uuid.uuid4())
        self.parent_id = parent_id
        self.name = name
        self.start_time = time.time()
        self.end_time: float | None = None
        self.attributes: dict[str, Any] = {}
        self.events: list[dict[str, Any]] = []
        self.status = "ok"

    def set_attribute(self, key: str, value: Any) -> None:
        """Set span attribute."""
        self.attributes[key] = value

    def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> None:
        """Add event to span."""
        self.events.append({"name": name, "timestamp": time.time(), "attributes": attributes or {}})

    def set_status(self, status: str) -> None:
        """Set span status."""
        self.status = status

    def end(self) -> None:
        """End the span."""
        self.end_time = time.time()

    def get_duration(self) -> float:
        """Get span duration in seconds."""
        if self.end_time:
            return self.end_time - self.start_time
        return time.time() - self.start_time


class Tracer:
    """Distributed tracing implementation."""

    def __init__(self, service_name: str = "prompt_sentinel"):
        """Initialize tracer."""
        self.service_name = service_name
        self.spans: list[Span] = []
        self.current_span: Span | None = None
        self.trace_id = str(uuid.uuid4())

    def start_span(self, name: str, parent: Span | None = None) -> Span:
        """Start a new span."""
        parent_id = parent.span_id if parent else None
        span = Span(name, parent_id)
        self.spans.append(span)
        self.current_span = span
        return span

    def get_current_span(self) -> Span | None:
        """Get current active span."""
        return self.current_span

    async def trace(self, name: str):
        """Context manager for tracing."""

        class TraceContext:
            def __init__(self, tracer, name):
                self.tracer = tracer
                self.name = name
                self.span = None

            async def __aenter__(self):
                self.span = self.tracer.start_span(self.name)
                return self.span

            async def __aexit__(self, exc_type, _exc_val, _exc_tb):
                if self.span:
                    if exc_type:
                        self.span.set_status("error")
                    self.span.end()
                return False

        return TraceContext(self, name)

    def get_trace_context(self) -> dict[str, str | None]:
        """Get trace context for propagation."""
        return {
            "trace_id": self.trace_id,
            "span_id": self.current_span.span_id if self.current_span else None,
            "service": self.service_name,
        }

    def inject_context(self, headers: dict[str, str]) -> None:
        """Inject trace context into headers."""
        context = self.get_trace_context()
        if context["trace_id"]:
            headers["X-Trace-Id"] = context["trace_id"]
        if context["span_id"]:
            headers["X-Span-Id"] = context["span_id"]
        if context["service"]:
            headers["X-Service"] = context["service"]

    def extract_context(self, headers: dict[str, str]) -> dict[str, str | None]:
        """Extract trace context from headers."""
        return {
            "trace_id": headers.get("X-Trace-Id", str(uuid.uuid4())),
            "span_id": headers.get("X-Span-Id"),
            "service": headers.get("X-Service", "unknown"),
        }

    def get_spans(self) -> list[Span]:
        """Get all spans in trace."""
        return self.spans

    async def export(self) -> None:
        """Export spans to backend."""
        # Stub export
        await asyncio.sleep(0.001)
