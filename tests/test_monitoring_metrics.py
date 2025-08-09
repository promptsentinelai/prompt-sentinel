"""Tests for monitoring and metrics collection."""

import pytest
import asyncio
import time
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from prometheus_client import Counter, Histogram, Gauge

from prompt_sentinel.monitoring.metrics import MetricsCollector, MetricsExporter
from prompt_sentinel.monitoring.health import HealthChecker
from prompt_sentinel.monitoring.alerts import AlertManager


class TestMetricsCollector:
    """Test metrics collection functionality."""

    @pytest.fixture
    def metrics_collector(self):
        """Create metrics collector instance."""
        return MetricsCollector(
            namespace="prompt_sentinel",
            enable_prometheus=True
        )

    def test_counter_metrics(self, metrics_collector):
        """Test counter metric recording."""
        # Record detection counts
        metrics_collector.increment("detections_total", labels={"verdict": "ALLOW"})
        metrics_collector.increment("detections_total", labels={"verdict": "ALLOW"})
        metrics_collector.increment("detections_total", labels={"verdict": "BLOCK"})
        
        # Get metrics
        metrics = metrics_collector.get_metrics()
        
        assert metrics["detections_total"]["ALLOW"] == 2
        assert metrics["detections_total"]["BLOCK"] == 1

    def test_histogram_metrics(self, metrics_collector):
        """Test histogram metric recording."""
        # Record latencies
        latencies = [0.025, 0.030, 0.045, 0.050, 0.100]
        
        for latency in latencies:
            metrics_collector.observe("detection_latency_seconds", latency)
        
        # Get statistics
        stats = metrics_collector.get_histogram_stats("detection_latency_seconds")
        
        assert stats["count"] == 5
        assert stats["sum"] == sum(latencies)
        assert 0.025 <= stats["p50"] <= 0.050
        assert stats["p99"] <= 0.100

    def test_gauge_metrics(self, metrics_collector):
        """Test gauge metric recording."""
        # Set current values
        metrics_collector.set_gauge("active_connections", 5)
        metrics_collector.set_gauge("cache_size_bytes", 1024 * 1024)
        
        # Update values
        metrics_collector.set_gauge("active_connections", 8)
        
        # Get current values
        metrics = metrics_collector.get_metrics()
        
        assert metrics["active_connections"] == 8
        assert metrics["cache_size_bytes"] == 1024 * 1024

    def test_labels_and_dimensions(self, metrics_collector):
        """Test metrics with labels."""
        # Record with different labels
        metrics_collector.increment("api_requests", labels={
            "method": "POST",
            "endpoint": "/v1/detect",
            "status": "200"
        })
        
        metrics_collector.increment("api_requests", labels={
            "method": "POST",
            "endpoint": "/v2/analyze",
            "status": "200"
        })
        
        metrics_collector.increment("api_requests", labels={
            "method": "POST",
            "endpoint": "/v1/detect",
            "status": "429"
        })
        
        # Query by labels
        v1_success = metrics_collector.get_metric_by_labels(
            "api_requests",
            {"endpoint": "/v1/detect", "status": "200"}
        )
        
        assert v1_success == 1

    @pytest.mark.asyncio
    async def test_async_metrics_recording(self, metrics_collector):
        """Test async metrics recording."""
        async def process_request():
            start = time.time()
            await asyncio.sleep(0.05)
            elapsed = time.time() - start
            metrics_collector.observe("async_processing_time", elapsed)
            return elapsed
        
        # Process multiple requests concurrently
        tasks = [process_request() for _ in range(10)]
        results = await asyncio.gather(*tasks)
        
        stats = metrics_collector.get_histogram_stats("async_processing_time")
        assert stats["count"] == 10
        assert all(r >= 0.05 for r in results)


class TestPrometheusExporter:
    """Test Prometheus metrics export."""

    @pytest.fixture
    def exporter(self):
        """Create Prometheus exporter."""
        return MetricsExporter(
            port=9090,
            path="/metrics"
        )

    def test_prometheus_format(self, exporter):
        """Test exporting metrics in Prometheus format."""
        # Create sample metrics
        metrics = {
            "http_requests_total": Counter(
                "http_requests_total",
                "Total HTTP requests",
                ["method", "status"]
            ),
            "request_duration_seconds": Histogram(
                "request_duration_seconds",
                "Request duration"
            )
        }
        
        # Record some data
        metrics["http_requests_total"].labels(method="GET", status="200").inc()
        metrics["request_duration_seconds"].observe(0.05)
        
        # Export to Prometheus format
        output = exporter.export_metrics(metrics)
        
        assert "# TYPE http_requests_total counter" in output
        assert "# TYPE request_duration_seconds histogram" in output
        assert 'http_requests_total{method="GET",status="200"}' in output

    @pytest.mark.asyncio
    async def test_metrics_endpoint(self, exporter):
        """Test metrics HTTP endpoint."""
        with patch("aiohttp.web.Application") as mock_app:
            # Start exporter
            await exporter.start()
            
            # Should register metrics route
            mock_app.return_value.router.add_get.assert_called_with(
                "/metrics",
                exporter.handle_metrics
            )
            
            await exporter.stop()


class TestHealthChecker:
    """Test health checking functionality."""

    @pytest.fixture
    def health_checker(self):
        """Create health checker."""
        return HealthChecker(
            check_interval=5,
            timeout=2
        )

    @pytest.mark.asyncio
    async def test_component_health_checks(self, health_checker):
        """Test checking health of components."""
        # Register health checks
        health_checker.register_check(
            "database",
            lambda: {"status": "healthy", "latency_ms": 5}
        )
        
        health_checker.register_check(
            "cache",
            lambda: {"status": "healthy", "hit_rate": 0.95}
        )
        
        health_checker.register_check(
            "llm_provider",
            lambda: {"status": "degraded", "error_rate": 0.1}
        )
        
        # Run health checks
        results = await health_checker.check_all()
        
        assert results["database"]["status"] == "healthy"
        assert results["cache"]["status"] == "healthy"
        assert results["llm_provider"]["status"] == "degraded"
        assert results["overall_status"] == "degraded"

    @pytest.mark.asyncio
    async def test_health_check_timeout(self, health_checker):
        """Test health check timeout handling."""
        async def slow_check():
            await asyncio.sleep(5)  # Longer than timeout
            return {"status": "healthy"}
        
        health_checker.register_check("slow_service", slow_check)
        
        results = await health_checker.check_all(timeout=1)
        
        assert results["slow_service"]["status"] == "unhealthy"
        assert "timeout" in results["slow_service"]["error"]

    @pytest.mark.asyncio
    async def test_health_endpoint(self, health_checker):
        """Test health check HTTP endpoint."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        
        app = FastAPI()
        health_checker.register_routes(app)
        
        client = TestClient(app)
        
        # Test health endpoint
        response = client.get("/health")
        assert response.status_code == 200
        
        data = response.json()
        assert "status" in data
        assert "checks" in data
        assert "timestamp" in data

    @pytest.mark.asyncio
    async def test_liveness_readiness_probes(self, health_checker):
        """Test Kubernetes-style probes."""
        # Liveness - is the service alive?
        liveness = await health_checker.liveness_probe()
        assert liveness["status"] in ["healthy", "unhealthy"]
        
        # Readiness - is the service ready to accept traffic?
        readiness = await health_checker.readiness_probe()
        assert readiness["status"] in ["ready", "not_ready"]
        
        # Startup - has the service finished starting up?
        startup = await health_checker.startup_probe()
        assert startup["status"] in ["started", "starting"]


class TestAlertManager:
    """Test alert management system."""

    @pytest.fixture
    def alert_manager(self):
        """Create alert manager."""
        return AlertManager(
            alert_rules_path="/tmp/alert_rules.yaml"
        )

    @pytest.mark.asyncio
    async def test_alert_rules(self, alert_manager):
        """Test alert rule evaluation."""
        # Define alert rules
        rules = [
            {
                "name": "high_error_rate",
                "condition": "error_rate > 0.05",
                "severity": "warning",
                "message": "Error rate is above 5%"
            },
            {
                "name": "low_cache_hit_rate",
                "condition": "cache_hit_rate < 0.8",
                "severity": "info",
                "message": "Cache hit rate below 80%"
            }
        ]
        
        alert_manager.load_rules(rules)
        
        # Evaluate with metrics
        metrics = {
            "error_rate": 0.07,
            "cache_hit_rate": 0.75
        }
        
        alerts = await alert_manager.evaluate(metrics)
        
        assert len(alerts) == 2
        assert any(a["name"] == "high_error_rate" for a in alerts)
        assert any(a["name"] == "low_cache_hit_rate" for a in alerts)

    @pytest.mark.asyncio
    async def test_alert_notifications(self, alert_manager):
        """Test sending alert notifications."""
        # Configure notification channels
        alert_manager.configure_channel("email", {
            "to": ["admin@example.com"],
            "smtp_host": "smtp.example.com"
        })
        
        alert_manager.configure_channel("slack", {
            "webhook_url": "https://hooks.slack.com/services/XXX"
        })
        
        # Create alert
        alert = {
            "name": "high_latency",
            "severity": "critical",
            "message": "API latency above 1 second",
            "value": 1.5,
            "timestamp": datetime.utcnow()
        }
        
        with patch("smtplib.SMTP") as mock_smtp, \
             patch("httpx.post") as mock_post:
            
            await alert_manager.send_alert(alert)
            
            # Should send to both channels
            mock_smtp.assert_called()
            mock_post.assert_called()

    @pytest.mark.asyncio
    async def test_alert_deduplication(self, alert_manager):
        """Test alert deduplication."""
        alert = {
            "name": "high_cpu",
            "severity": "warning",
            "message": "CPU usage above 80%"
        }
        
        # Send same alert multiple times
        sent = []
        for _ in range(5):
            if await alert_manager.should_send_alert(alert):
                sent.append(alert)
                await alert_manager.send_alert(alert)
        
        # Should only send once within dedup window
        assert len(sent) == 1

    @pytest.mark.asyncio
    async def test_alert_escalation(self, alert_manager):
        """Test alert escalation."""
        # Configure escalation policy
        alert_manager.configure_escalation({
            "initial_delay": 5,
            "escalation_levels": [
                {"notify": ["on-call"], "after_minutes": 5},
                {"notify": ["manager"], "after_minutes": 15},
                {"notify": ["director"], "after_minutes": 30}
            ]
        })
        
        # Create unresolved alert
        alert = {
            "name": "service_down",
            "severity": "critical",
            "created_at": datetime.utcnow() - timedelta(minutes=20)
        }
        
        escalation_level = await alert_manager.get_escalation_level(alert)
        assert escalation_level == 2  # Should escalate to manager


class TestMetricsAggregation:
    """Test metrics aggregation and rollup."""

    @pytest.mark.asyncio
    async def test_time_series_aggregation(self):
        """Test aggregating metrics over time."""
        from prompt_sentinel.monitoring.aggregator import MetricsAggregator
        
        aggregator = MetricsAggregator()
        
        # Record metrics over time
        base_time = datetime.utcnow()
        for i in range(60):
            await aggregator.record(
                "requests_per_second",
                value=100 + (i % 10),
                timestamp=base_time + timedelta(seconds=i)
            )
        
        # Aggregate by minute
        minute_aggregates = await aggregator.aggregate(
            metric="requests_per_second",
            interval="1m",
            function="avg"
        )
        
        assert len(minute_aggregates) == 1
        assert 100 <= minute_aggregates[0]["value"] <= 110

    @pytest.mark.asyncio
    async def test_percentile_aggregation(self):
        """Test percentile aggregation."""
        from prompt_sentinel.monitoring.aggregator import MetricsAggregator
        
        aggregator = MetricsAggregator()
        
        # Record latencies
        latencies = [0.01, 0.02, 0.03, 0.04, 0.05, 0.10, 0.20, 0.30, 0.40, 1.0]
        for latency in latencies:
            await aggregator.record("latency", latency)
        
        # Calculate percentiles
        p50 = await aggregator.percentile("latency", 50)
        p95 = await aggregator.percentile("latency", 95)
        p99 = await aggregator.percentile("latency", 99)
        
        assert 0.05 <= p50 <= 0.10
        assert 0.40 <= p95 <= 1.0
        assert p99 <= 1.0


class TestDistributedTracing:
    """Test distributed tracing functionality."""

    @pytest.mark.asyncio
    async def test_trace_creation(self):
        """Test creating traces."""
        from prompt_sentinel.monitoring.tracing import Tracer
        
        tracer = Tracer()
        
        # Start trace
        trace = tracer.start_trace(
            operation="detect_prompt",
            attributes={"user_id": "user123"}
        )
        
        # Add spans
        span1 = trace.start_span("validate_input")
        await asyncio.sleep(0.01)
        span1.end()
        
        span2 = trace.start_span("run_detection")
        await asyncio.sleep(0.02)
        span2.end()
        
        trace.end()
        
        # Check trace data
        assert trace.duration_ms > 30
        assert len(trace.spans) == 2
        assert trace.spans[0].name == "validate_input"

    @pytest.mark.asyncio
    async def test_trace_context_propagation(self):
        """Test trace context propagation."""
        from prompt_sentinel.monitoring.tracing import Tracer
        
        tracer = Tracer()
        
        # Parent trace
        parent_trace = tracer.start_trace("parent_operation")
        parent_context = parent_trace.get_context()
        
        # Child trace with context
        child_trace = tracer.start_trace(
            "child_operation",
            parent_context=parent_context
        )
        
        assert child_trace.parent_id == parent_trace.trace_id
        assert child_trace.trace_id != parent_trace.trace_id


class TestCustomMetrics:
    """Test custom business metrics."""

    @pytest.mark.asyncio
    async def test_business_metrics(self):
        """Test tracking business-specific metrics."""
        from prompt_sentinel.monitoring.business_metrics import BusinessMetrics
        
        metrics = BusinessMetrics()
        
        # Track detections by verdict
        for verdict in ["ALLOW", "ALLOW", "FLAG", "BLOCK"]:
            await metrics.track_detection(
                verdict=verdict,
                confidence=0.85,
                provider="anthropic"
            )
        
        # Track API usage
        await metrics.track_api_usage(
            endpoint="/v1/detect",
            user_tier="pro",
            response_time_ms=45
        )
        
        # Get business KPIs
        kpis = await metrics.get_kpis()
        
        assert kpis["detection_block_rate"] == 0.25  # 1/4
        assert kpis["api_response_time_p50"] <= 45
        assert "daily_active_users" in kpis


class TestLogging:
    """Test structured logging."""

    def test_structured_logging(self):
        """Test structured log formatting."""
        from prompt_sentinel.monitoring.logging import StructuredLogger
        
        logger = StructuredLogger("test_module")
        
        # Log with context
        logger.info(
            "Detection completed",
            verdict="BLOCK",
            confidence=0.95,
            latency_ms=35,
            user_id="user123"
        )
        
        # Check log format
        with patch("logging.Logger.info") as mock_log:
            logger.info("Test", key="value")
            
            call_args = mock_log.call_args[0][0]
            assert "key" in call_args
            assert "timestamp" in call_args

    def test_log_correlation(self):
        """Test log correlation with trace IDs."""
        from prompt_sentinel.monitoring.logging import StructuredLogger
        
        logger = StructuredLogger("test")
        
        # Set trace context
        logger.set_trace_id("trace_123")
        
        with patch("logging.Logger.info") as mock_log:
            logger.info("Operation", status="success")
            
            call_args = mock_log.call_args[0][0]
            assert "trace_id" in call_args
            assert call_args["trace_id"] == "trace_123"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])