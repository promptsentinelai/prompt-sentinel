"""Observability tests for logging, tracing, and monitoring."""

import pytest
import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any
from unittest.mock import AsyncMock, MagicMock, patch
import logging
from opentelemetry import trace, metrics
from opentelemetry.trace import Status, StatusCode

from prompt_sentinel.models.schemas import Message, Role, Verdict


class TestStructuredLogging:
    """Test structured logging implementation."""

    @pytest.fixture
    def structured_logger(self):
        """Create structured logger."""
        from prompt_sentinel.observability.logging import StructuredLogger
        return StructuredLogger(
            service_name="prompt_sentinel",
            environment="test"
        )

    def test_log_structure(self, structured_logger):
        """Test log message structure."""
        # Log an event
        structured_logger.info(
            "Detection completed",
            verdict="BLOCK",
            confidence=0.95,
            processing_time_ms=45.2,
            user_id="user123"
        )
        
        # Get last log entry
        log_entry = structured_logger.get_last_entry()
        
        # Check structure
        assert log_entry["level"] == "INFO"
        assert log_entry["message"] == "Detection completed"
        assert log_entry["verdict"] == "BLOCK"
        assert log_entry["confidence"] == 0.95
        assert log_entry["service_name"] == "prompt_sentinel"
        assert log_entry["environment"] == "test"
        assert "timestamp" in log_entry
        assert "trace_id" in log_entry

    def test_error_logging_with_context(self, structured_logger):
        """Test error logging with context."""
        try:
            raise ValueError("Test error")
        except ValueError as e:
            structured_logger.error(
                "Operation failed",
                error=str(e),
                error_type=type(e).__name__,
                stack_trace=True,
                operation="detect",
                request_id="req_123"
            )
        
        log_entry = structured_logger.get_last_entry()
        
        assert log_entry["level"] == "ERROR"
        assert log_entry["error"] == "Test error"
        assert log_entry["error_type"] == "ValueError"
        assert "stack_trace" in log_entry
        assert log_entry["operation"] == "detect"

    def test_log_correlation(self, structured_logger):
        """Test log correlation with trace IDs."""
        trace_id = "abc123def456"
        span_id = "789ghi"
        
        with structured_logger.correlation_context(
            trace_id=trace_id,
            span_id=span_id
        ):
            structured_logger.info("Correlated log")
            log_entry = structured_logger.get_last_entry()
            
            assert log_entry["trace_id"] == trace_id
            assert log_entry["span_id"] == span_id

    def test_log_filtering_and_sampling(self, structured_logger):
        """Test log filtering and sampling."""
        # Configure sampling
        structured_logger.set_sampling_rate(0.1)  # 10% sampling
        
        # Log many messages
        sampled_count = 0
        for i in range(1000):
            if structured_logger.debug(f"Debug message {i}"):
                sampled_count += 1
        
        # Should sample approximately 10%
        assert 50 < sampled_count < 150

    def test_sensitive_data_masking(self, structured_logger):
        """Test sensitive data masking in logs."""
        structured_logger.info(
            "User request",
            email="user@example.com",
            ssn="123-45-6789",
            api_key="sk_live_abcd1234",
            safe_field="This is safe"
        )
        
        log_entry = structured_logger.get_last_entry()
        
        # Sensitive data should be masked
        assert "user@example.com" not in str(log_entry)
        assert "123-45-6789" not in str(log_entry)
        assert "sk_live_abcd1234" not in str(log_entry)
        assert log_entry["email"] == "***MASKED***"
        assert log_entry["ssn"] == "***MASKED***"
        assert log_entry["api_key"] == "***MASKED***"
        assert log_entry["safe_field"] == "This is safe"


class TestDistributedTracing:
    """Test distributed tracing implementation."""

    @pytest.fixture
    def tracer(self):
        """Create tracer instance."""
        from prompt_sentinel.observability.tracing import Tracer
        return Tracer(
            service_name="prompt_sentinel",
            endpoint="http://localhost:4318"
        )

    @pytest.mark.asyncio
    async def test_span_creation(self, tracer):
        """Test creating and managing spans."""
        with tracer.start_span("detect_prompt") as span:
            span.set_attribute("prompt.length", 100)
            span.set_attribute("detection.mode", "strict")
            
            # Nested span
            with tracer.start_span("heuristic_check", parent=span) as child_span:
                child_span.set_attribute("patterns.checked", 50)
                await asyncio.sleep(0.01)
            
            # Another nested span
            with tracer.start_span("llm_check", parent=span) as child_span:
                child_span.set_attribute("model", "gpt-4")
                await asyncio.sleep(0.02)
            
            span.set_attribute("verdict", "BLOCK")
        
        # Get span data
        span_data = tracer.get_span_data(span.span_id)
        
        assert span_data["name"] == "detect_prompt"
        assert span_data["attributes"]["prompt.length"] == 100
        assert len(span_data["children"]) == 2

    @pytest.mark.asyncio
    async def test_span_error_handling(self, tracer):
        """Test span error handling."""
        with tracer.start_span("failing_operation") as span:
            try:
                raise ValueError("Operation failed")
            except ValueError as e:
                span.record_exception(e)
                span.set_status(Status(StatusCode.ERROR, str(e)))
        
        span_data = tracer.get_span_data(span.span_id)
        
        assert span_data["status"]["code"] == "ERROR"
        assert "Operation failed" in span_data["status"]["description"]
        assert len(span_data["events"]) > 0
        assert span_data["events"][0]["name"] == "exception"

    @pytest.mark.asyncio
    async def test_trace_context_propagation(self, tracer):
        """Test trace context propagation across services."""
        # Start root span
        with tracer.start_span("api_request") as root_span:
            trace_context = tracer.get_trace_context()
            
            # Simulate calling another service
            async def downstream_service(context):
                with tracer.start_span(
                    "downstream_operation",
                    context=context
                ) as span:
                    span.set_attribute("service", "downstream")
                    return span.span_id
            
            downstream_span_id = await downstream_service(trace_context)
        
        # Verify trace linkage
        root_data = tracer.get_span_data(root_span.span_id)
        downstream_data = tracer.get_span_data(downstream_span_id)
        
        assert root_data["trace_id"] == downstream_data["trace_id"]
        assert downstream_data["parent_span_id"] == root_span.span_id

    @pytest.mark.asyncio
    async def test_span_sampling(self, tracer):
        """Test span sampling strategies."""
        # Configure sampling
        tracer.set_sampling_strategy("probabilistic", rate=0.1)
        
        sampled_count = 0
        for _ in range(100):
            with tracer.start_span("sampled_operation") as span:
                if span.is_recording():
                    sampled_count += 1
        
        # Should sample approximately 10%
        assert 5 < sampled_count < 15

    @pytest.mark.asyncio
    async def test_baggage_propagation(self, tracer):
        """Test baggage propagation across spans."""
        with tracer.start_span("root") as root_span:
            # Set baggage
            tracer.set_baggage("user_id", "user123")
            tracer.set_baggage("session_id", "sess456")
            
            with tracer.start_span("child") as child_span:
                # Baggage should be available
                baggage = tracer.get_baggage()
                assert baggage["user_id"] == "user123"
                assert baggage["session_id"] == "sess456"


class TestMetricsCollection:
    """Test metrics collection and reporting."""

    @pytest.fixture
    def metrics_collector(self):
        """Create metrics collector."""
        from prompt_sentinel.observability.metrics import MetricsCollector
        return MetricsCollector(
            service_name="prompt_sentinel",
            namespace="prompt_sentinel"
        )

    @pytest.mark.asyncio
    async def test_counter_metrics(self, metrics_collector):
        """Test counter metrics."""
        # Create counter
        detection_counter = metrics_collector.create_counter(
            name="detections_total",
            description="Total number of detections",
            unit="1"
        )
        
        # Increment counter
        detection_counter.add(1, {"verdict": "ALLOW", "mode": "strict"})
        detection_counter.add(1, {"verdict": "BLOCK", "mode": "strict"})
        detection_counter.add(1, {"verdict": "ALLOW", "mode": "moderate"})
        
        # Get metrics
        metrics = metrics_collector.get_metrics("detections_total")
        
        assert metrics["total"] == 3
        assert metrics["by_labels"]["verdict=ALLOW"] == 2
        assert metrics["by_labels"]["verdict=BLOCK"] == 1

    @pytest.mark.asyncio
    async def test_histogram_metrics(self, metrics_collector):
        """Test histogram metrics."""
        # Create histogram
        latency_histogram = metrics_collector.create_histogram(
            name="detection_latency",
            description="Detection latency in milliseconds",
            unit="ms",
            buckets=[10, 25, 50, 100, 250, 500, 1000]
        )
        
        # Record values
        latencies = [15, 23, 45, 67, 89, 120, 230, 450, 23, 34, 56]
        for latency in latencies:
            latency_histogram.record(latency, {"endpoint": "/v1/detect"})
        
        # Get statistics
        stats = metrics_collector.get_histogram_stats("detection_latency")
        
        assert stats["count"] == len(latencies)
        assert stats["min"] == min(latencies)
        assert stats["max"] == max(latencies)
        assert 50 < stats["p50"] < 100
        assert 100 < stats["p95"] < 500

    @pytest.mark.asyncio
    async def test_gauge_metrics(self, metrics_collector):
        """Test gauge metrics."""
        # Create gauge
        queue_size = metrics_collector.create_gauge(
            name="queue_size",
            description="Current queue size",
            unit="1"
        )
        
        # Set gauge values
        queue_size.set(10, {"queue": "detection"})
        queue_size.set(5, {"queue": "analysis"})
        
        # Update values
        queue_size.set(15, {"queue": "detection"})
        
        # Get current values
        values = metrics_collector.get_gauge_values("queue_size")
        
        assert values["queue=detection"] == 15
        assert values["queue=analysis"] == 5

    @pytest.mark.asyncio
    async def test_metric_aggregation(self, metrics_collector):
        """Test metric aggregation."""
        # Create metrics
        counter = metrics_collector.create_counter("requests")
        histogram = metrics_collector.create_histogram("latency")
        
        # Generate data
        for i in range(100):
            counter.add(1, {"status": "success" if i % 10 != 0 else "error"})
            histogram.record(10 + i % 50)
        
        # Get aggregated report
        report = metrics_collector.get_aggregated_report(
            period_minutes=5
        )
        
        assert report["requests"]["total"] == 100
        assert report["requests"]["rate_per_minute"] > 0
        assert report["latency"]["p50"] > 0
        assert report["latency"]["p99"] > 0

    @pytest.mark.asyncio
    async def test_custom_metrics(self, metrics_collector):
        """Test custom business metrics."""
        # Define custom metrics
        metrics_collector.register_custom_metric(
            name="prompt_complexity",
            type="histogram",
            calculator=lambda prompt: len(prompt.split())
        )
        
        metrics_collector.register_custom_metric(
            name="detection_accuracy",
            type="gauge",
            calculator=lambda tp, fp, fn: tp / (tp + fp + fn)
        )
        
        # Record custom metrics
        prompts = ["short", "this is a longer prompt", "very very long prompt here"]
        for prompt in prompts:
            metrics_collector.record_custom("prompt_complexity", prompt)
        
        metrics_collector.record_custom(
            "detection_accuracy",
            tp=95, fp=3, fn=2
        )
        
        # Get custom metrics
        complexity = metrics_collector.get_custom_metric("prompt_complexity")
        accuracy = metrics_collector.get_custom_metric("detection_accuracy")
        
        assert complexity["count"] == 3
        assert accuracy["value"] == 0.95


class TestHealthChecks:
    """Test health check monitoring."""

    @pytest.fixture
    def health_monitor(self):
        """Create health monitor."""
        from prompt_sentinel.observability.health import HealthMonitor
        return HealthMonitor()

    @pytest.mark.asyncio
    async def test_component_health_checks(self, health_monitor):
        """Test component health checks."""
        # Register health checks
        async def database_check():
            # Simulate database check
            return {"status": "healthy", "latency_ms": 5}
        
        async def cache_check():
            # Simulate cache check
            return {"status": "healthy", "latency_ms": 1}
        
        async def llm_check():
            # Simulate LLM provider check
            return {"status": "degraded", "error": "High latency"}
        
        health_monitor.register_check("database", database_check)
        health_monitor.register_check("cache", cache_check)
        health_monitor.register_check("llm", llm_check)
        
        # Run health checks
        results = await health_monitor.check_all()
        
        assert results["database"]["status"] == "healthy"
        assert results["cache"]["status"] == "healthy"
        assert results["llm"]["status"] == "degraded"
        assert results["overall_status"] == "degraded"

    @pytest.mark.asyncio
    async def test_liveness_probe(self, health_monitor):
        """Test liveness probe."""
        # Liveness should always pass if service is running
        liveness = await health_monitor.liveness()
        
        assert liveness["status"] == "alive"
        assert liveness["timestamp"] is not None

    @pytest.mark.asyncio
    async def test_readiness_probe(self, health_monitor):
        """Test readiness probe."""
        # Configure readiness requirements
        health_monitor.set_readiness_requirements([
            "database",
            "cache"
        ])
        
        # Mock component statuses
        health_monitor._component_status = {
            "database": "healthy",
            "cache": "healthy",
            "llm": "unhealthy"
        }
        
        # Should be ready (LLM not required)
        readiness = await health_monitor.readiness()
        assert readiness["ready"] is True
        
        # Make required component unhealthy
        health_monitor._component_status["database"] = "unhealthy"
        
        readiness = await health_monitor.readiness()
        assert readiness["ready"] is False
        assert "database" in readiness["blocking_components"]

    @pytest.mark.asyncio
    async def test_startup_probe(self, health_monitor):
        """Test startup probe."""
        # Simulate startup sequence
        startup_complete = False
        
        async def startup_check():
            return {"initialized": startup_complete}
        
        health_monitor.register_startup_check(startup_check)
        
        # Not ready initially
        result = await health_monitor.startup()
        assert result["ready"] is False
        
        # Complete startup
        startup_complete = True
        
        result = await health_monitor.startup()
        assert result["ready"] is True


class TestLoggingAggregation:
    """Test log aggregation and analysis."""

    @pytest.fixture
    def log_aggregator(self):
        """Create log aggregator."""
        from prompt_sentinel.observability.aggregation import LogAggregator
        return LogAggregator()

    @pytest.mark.asyncio
    async def test_log_pattern_detection(self, log_aggregator):
        """Test detecting patterns in logs."""
        # Generate logs with patterns
        logs = []
        for i in range(100):
            if i % 10 == 0:
                logs.append({
                    "level": "ERROR",
                    "message": "Database connection failed",
                    "error": "Connection timeout"
                })
            elif i % 5 == 0:
                logs.append({
                    "level": "WARN",
                    "message": "Slow query detected",
                    "query_time": 2000
                })
            else:
                logs.append({
                    "level": "INFO",
                    "message": "Request processed",
                    "status": "success"
                })
        
        # Analyze patterns
        patterns = await log_aggregator.analyze_patterns(logs)
        
        assert len(patterns) > 0
        assert any(p["pattern"] == "Database connection failed" for p in patterns)
        assert any(p["frequency"] == 10 for p in patterns)

    @pytest.mark.asyncio
    async def test_error_clustering(self, log_aggregator):
        """Test clustering similar errors."""
        # Generate similar errors
        errors = [
            {"message": "Connection to database failed: timeout"},
            {"message": "Connection to database failed: refused"},
            {"message": "API call failed: 500 Internal Server Error"},
            {"message": "API call failed: 503 Service Unavailable"},
            {"message": "Validation error: invalid email"},
            {"message": "Validation error: missing field"},
        ]
        
        # Cluster errors
        clusters = await log_aggregator.cluster_errors(errors)
        
        assert len(clusters) == 3  # Database, API, Validation
        assert any("database" in c["pattern"].lower() for c in clusters)
        assert any("api" in c["pattern"].lower() for c in clusters)
        assert any("validation" in c["pattern"].lower() for c in clusters)

    @pytest.mark.asyncio
    async def test_anomaly_detection_in_logs(self, log_aggregator):
        """Test detecting anomalies in log patterns."""
        # Normal log pattern
        normal_logs = []
        for i in range(1000):
            normal_logs.append({
                "timestamp": datetime.utcnow() - timedelta(minutes=1000-i),
                "level": "INFO",
                "message": "Normal operation",
                "latency": 50 + random.randint(-10, 10)
            })
        
        # Add anomalies
        anomaly_logs = [
            {
                "timestamp": datetime.utcnow() - timedelta(minutes=500),
                "level": "ERROR",
                "message": "Unexpected error spike",
                "count": 100
            },
            {
                "timestamp": datetime.utcnow() - timedelta(minutes=250),
                "level": "INFO",
                "message": "Normal operation",
                "latency": 500  # Anomalous latency
            }
        ]
        
        all_logs = normal_logs + anomaly_logs
        
        # Detect anomalies
        anomalies = await log_aggregator.detect_anomalies(
            all_logs,
            sensitivity=2.0
        )
        
        assert len(anomalies) >= 2
        assert any(a["type"] == "error_spike" for a in anomalies)
        assert any(a["type"] == "latency_anomaly" for a in anomalies)


class TestTracingVisualization:
    """Test trace visualization and analysis."""

    @pytest.fixture
    def trace_analyzer(self):
        """Create trace analyzer."""
        from prompt_sentinel.observability.trace_analysis import TraceAnalyzer
        return TraceAnalyzer()

    @pytest.mark.asyncio
    async def test_critical_path_analysis(self, trace_analyzer):
        """Test identifying critical path in traces."""
        # Create trace with multiple paths
        trace = {
            "trace_id": "abc123",
            "spans": [
                {"id": "1", "parent": None, "name": "api", "duration": 100},
                {"id": "2", "parent": "1", "name": "auth", "duration": 10},
                {"id": "3", "parent": "1", "name": "detect", "duration": 80},
                {"id": "4", "parent": "3", "name": "heuristic", "duration": 20},
                {"id": "5", "parent": "3", "name": "llm", "duration": 60},
            ]
        }
        
        # Find critical path
        critical_path = await trace_analyzer.find_critical_path(trace)
        
        assert critical_path["total_duration"] == 100
        assert len(critical_path["spans"]) == 3  # api -> detect -> llm
        assert critical_path["spans"][-1]["name"] == "llm"

    @pytest.mark.asyncio
    async def test_span_statistics(self, trace_analyzer):
        """Test calculating span statistics."""
        # Multiple traces
        traces = []
        for i in range(100):
            traces.append({
                "trace_id": f"trace_{i}",
                "spans": [
                    {"name": "api", "duration": 50 + i % 50},
                    {"name": "database", "duration": 10 + i % 20},
                    {"name": "cache", "duration": 1 + i % 5},
                ]
            })
        
        # Calculate statistics
        stats = await trace_analyzer.calculate_statistics(traces)
        
        assert "api" in stats
        assert stats["api"]["count"] == 100
        assert stats["api"]["avg_duration"] > 0
        assert stats["api"]["p50"] > 0
        assert stats["api"]["p99"] > 0

    @pytest.mark.asyncio
    async def test_dependency_graph_generation(self, trace_analyzer):
        """Test generating service dependency graph."""
        # Traces showing service dependencies
        traces = [
            {
                "spans": [
                    {"service": "api", "calls": ["auth", "database"]},
                    {"service": "auth", "calls": ["cache"]},
                    {"service": "database", "calls": []},
                ]
            },
            {
                "spans": [
                    {"service": "api", "calls": ["cache", "llm"]},
                    {"service": "llm", "calls": ["database"]},
                ]
            }
        ]
        
        # Generate dependency graph
        graph = await trace_analyzer.generate_dependency_graph(traces)
        
        assert "api" in graph
        assert set(graph["api"]["dependencies"]) == {"auth", "database", "cache", "llm"}
        assert graph["auth"]["dependencies"] == ["cache"]
        assert graph["database"]["dependencies"] == []


class TestAlertingIntegration:
    """Test alerting integration."""

    @pytest.fixture
    def alert_manager(self):
        """Create alert manager."""
        from prompt_sentinel.observability.alerting import AlertManager
        return AlertManager()

    @pytest.mark.asyncio
    async def test_alert_rule_evaluation(self, alert_manager):
        """Test evaluating alert rules."""
        # Define alert rules
        rules = [
            {
                "name": "high_error_rate",
                "condition": "error_rate > 0.05",
                "severity": "critical",
                "notification": ["email", "slack"]
            },
            {
                "name": "high_latency",
                "condition": "p99_latency > 1000",
                "severity": "warning",
                "notification": ["slack"]
            }
        ]
        
        alert_manager.configure_rules(rules)
        
        # Evaluate with metrics
        metrics = {
            "error_rate": 0.08,
            "p99_latency": 500
        }
        
        alerts = await alert_manager.evaluate(metrics)
        
        assert len(alerts) == 1
        assert alerts[0]["name"] == "high_error_rate"
        assert alerts[0]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_alert_deduplication(self, alert_manager):
        """Test alert deduplication."""
        # Generate same alert multiple times
        for _ in range(10):
            await alert_manager.trigger_alert({
                "name": "database_down",
                "severity": "critical",
                "message": "Database connection failed"
            })
        
        # Should deduplicate
        active_alerts = alert_manager.get_active_alerts()
        
        assert len(active_alerts) == 1
        assert active_alerts[0]["count"] == 10

    @pytest.mark.asyncio
    async def test_alert_escalation(self, alert_manager):
        """Test alert escalation."""
        # Configure escalation policy
        alert_manager.set_escalation_policy({
            "initial_delay": 5,
            "escalation_levels": [
                {"delay": 5, "notify": ["oncall"]},
                {"delay": 15, "notify": ["manager"]},
                {"delay": 30, "notify": ["director"]}
            ]
        })
        
        # Trigger alert
        alert_id = await alert_manager.trigger_alert({
            "name": "service_down",
            "severity": "critical"
        })
        
        # Simulate time passing
        await asyncio.sleep(0.1)  # Simplified for test
        
        # Check escalation status
        escalation = alert_manager.get_escalation_status(alert_id)
        
        assert escalation["level"] >= 0
        assert escalation["next_escalation"] is not None


class TestObservabilityPipeline:
    """Test complete observability pipeline."""

    @pytest.mark.asyncio
    async def test_end_to_end_observability(self):
        """Test end-to-end observability flow."""
        from prompt_sentinel.observability.pipeline import ObservabilityPipeline
        
        pipeline = ObservabilityPipeline()
        
        # Configure pipeline
        await pipeline.configure({
            "logging": {"level": "INFO", "structured": True},
            "tracing": {"sampling_rate": 1.0},
            "metrics": {"interval": 60},
            "alerting": {"enabled": True}
        })
        
        # Start pipeline
        await pipeline.start()
        
        # Simulate request with full observability
        async with pipeline.trace("api_request") as trace:
            # Log
            pipeline.log("Request received", request_id="req_123")
            
            # Metric
            pipeline.metric("request_count", 1)
            
            # Nested operation
            async with pipeline.trace("detection", parent=trace):
                pipeline.log("Running detection")
                pipeline.metric("detection_latency", 45.2)
                
                # Simulate error
                try:
                    raise ValueError("Test error")
                except Exception as e:
                    pipeline.log_error("Detection failed", error=e)
                    pipeline.metric("error_count", 1)
        
        # Get observability data
        data = await pipeline.get_request_data("req_123")
        
        assert "logs" in data
        assert "traces" in data
        assert "metrics" in data
        assert len(data["logs"]) > 0
        assert data["traces"]["duration"] > 0
        assert data["metrics"]["request_count"] == 1
        
        # Stop pipeline
        await pipeline.stop()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])