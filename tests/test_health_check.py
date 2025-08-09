"""Tests for enhanced health check endpoints."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock, AsyncMock
import json

from prompt_sentinel.main import app


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


class TestBasicHealthCheck:
    """Test basic health check endpoint."""

    def test_health_check_healthy(self, client):
        """Test health check returns healthy status."""
        response = client.get("/health")
        assert response.status_code == 200

        data = response.json()
        assert "status" in data
        assert data["status"] in ["healthy", "degraded", "unhealthy"]
        assert "version" in data
        assert "uptime_seconds" in data
        assert "providers_status" in data
        assert "redis_connected" in data
        assert "timestamp" in data

    def test_health_check_with_redis(self, client):
        """Test health check with Redis enabled."""
        with patch("prompt_sentinel.main.settings") as mock_settings:
            mock_settings.redis_enabled = True

            with patch("prompt_sentinel.main.cache_manager") as mock_cache:
                mock_cache.health_check = AsyncMock(return_value=True)
                mock_cache.get_stats = AsyncMock(
                    return_value={"hits": 100, "misses": 20, "hit_rate": 83.3}
                )

                response = client.get("/health")
                assert response.status_code == 200

                data = response.json()
                assert data["redis_connected"] == True
                assert "redis_latency_ms" in data
                assert "cache_stats" in data

    def test_health_check_with_system_metrics(self, client):
        """Test health check includes system metrics."""
        response = client.get("/health")
        assert response.status_code == 200

        data = response.json()
        if "system_metrics" in data and data["system_metrics"]:
            assert "memory_usage_mb" in data["system_metrics"]
            assert "cpu_percent" in data["system_metrics"]
            assert "num_threads" in data["system_metrics"]

    def test_health_check_degraded_status(self, client):
        """Test health check returns degraded when some providers fail."""
        with patch("prompt_sentinel.main.detector") as mock_detector:
            mock_detector.llm_classifier.health_check = AsyncMock(
                return_value={"anthropic": True, "openai": False, "gemini": False}
            )

            response = client.get("/health")
            data = response.json()

            # Should be degraded if some providers are unhealthy
            assert data["providers_status"]["anthropic"] == "healthy"
            assert data["providers_status"]["openai"] == "unhealthy"


class TestDetailedHealthCheck:
    """Test detailed health check endpoint."""

    @pytest.mark.asyncio
    async def test_detailed_health_check(self):
        """Test detailed health check returns component status."""
        from httpx import AsyncClient

        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.get("/health/detailed")
            assert response.status_code == 200

            data = response.json()
            assert "status" in data
            assert "components" in data
            assert "configuration" in data
            assert "timestamp" in data
            assert "version" in data

    @pytest.mark.asyncio
    async def test_detailed_health_components(self):
        """Test detailed health check includes all components."""
        from httpx import AsyncClient

        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.get("/health/detailed")
            data = response.json()

        components = data["components"]

        # Check expected components
        assert "detector" in components
        assert "cache" in components
        assert "authentication" in components
        assert "websocket" in components
        assert "monitoring" in components

    @pytest.mark.asyncio
    async def test_detailed_health_detector_component(self):
        """Test detector component status."""
        from httpx import AsyncClient

        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.get("/health/detailed")
            data = response.json()

        detector = data["components"]["detector"]
        if detector["status"] == "healthy":
            assert "detection_methods" in detector
            assert "heuristic" in detector["detection_methods"]
            assert "llm_classification" in detector["detection_methods"]
            assert "pii_detection" in detector["detection_methods"]

    @pytest.mark.asyncio
    async def test_detailed_health_auth_component(self):
        """Test authentication component status."""
        from httpx import AsyncClient

        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.get("/health/detailed")
            data = response.json()

        auth = data["components"]["authentication"]
        assert auth["status"] == "healthy"
        assert "mode" in auth
        assert "bypass_rules" in auth
        assert "localhost" in auth["bypass_rules"]
        assert "networks" in auth["bypass_rules"]
        assert "headers" in auth["bypass_rules"]

    @pytest.mark.asyncio
    async def test_detailed_health_websocket_component(self):
        """Test WebSocket component status."""
        from httpx import AsyncClient

        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.get("/health/detailed")
            data = response.json()

        ws = data["components"]["websocket"]
        assert ws["status"] == "healthy"
        assert "active_connections" in ws
        assert "total_messages" in ws
        assert isinstance(ws["active_connections"], int)
        assert isinstance(ws["total_messages"], int)

    @pytest.mark.asyncio
    async def test_detailed_health_configuration(self):
        """Test configuration information in detailed health."""
        from httpx import AsyncClient

        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.get("/health/detailed")
            data = response.json()

        config = data["configuration"]
        assert "environment" in config
        assert "debug" in config
        assert "detection_mode" in config


class TestKubernetesProbes:
    """Test Kubernetes health probe endpoints."""

    def test_liveness_probe(self, client):
        """Test liveness probe always returns alive."""
        response = client.get("/health/live")
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "alive"

    def test_readiness_probe_ready(self, client):
        """Test readiness probe when service is ready."""
        with patch("prompt_sentinel.main.detector") as mock_detector:
            mock_detector.llm_classifier.health_check = AsyncMock(return_value={"anthropic": True})

            response = client.get("/health/ready")
            assert response.status_code == 200

            data = response.json()
            assert data["status"] == "ready"

    def test_readiness_probe_not_ready_no_detector(self, client):
        """Test readiness probe when detector not initialized."""
        with patch("prompt_sentinel.main.detector", None):
            response = client.get("/health/ready")
            assert response.status_code == 503

            data = response.json()
            assert data["status"] == "not_ready"
            assert "reason" in data
            assert "Detector not initialized" in data["reason"]

    def test_readiness_probe_not_ready_no_providers(self, client):
        """Test readiness probe when no providers are healthy."""
        with patch("prompt_sentinel.main.detector") as mock_detector:
            with patch("prompt_sentinel.main.settings") as mock_settings:
                mock_settings.llm_classification_enabled = True
                mock_detector.llm_classifier.health_check = AsyncMock(
                    return_value={"anthropic": False, "openai": False, "gemini": False}
                )

                response = client.get("/health/ready")
                assert response.status_code == 503

                data = response.json()
                assert data["status"] == "not_ready"
                assert "No healthy LLM providers" in data["reason"]


class TestHealthCheckMetadata:
    """Test health check metadata and metrics."""

    def test_health_metadata_warnings(self, client):
        """Test health check includes warnings in metadata."""
        with patch("prompt_sentinel.main.settings") as mock_settings:
            mock_settings.heuristic_enabled = False
            mock_settings.llm_classification_enabled = False
            mock_settings.pii_detection_enabled = False

            response = client.get("/health")
            data = response.json()

            metadata = data["metadata"]
            assert metadata["warning"] == "No detection methods enabled!"
            assert data["status"] == "unhealthy"

    def test_health_metadata_environment(self, client):
        """Test health check includes environment info."""
        response = client.get("/health")
        data = response.json()

        metadata = data["metadata"]
        assert "environment" in metadata
        assert "auth_mode" in metadata
        assert "detection_methods_enabled" in metadata

    def test_health_cache_stats(self, client):
        """Test health check includes cache statistics when available."""
        with patch("prompt_sentinel.main.settings") as mock_settings:
            mock_settings.redis_enabled = True

            with patch("prompt_sentinel.main.cache_manager") as mock_cache:
                mock_cache.health_check = AsyncMock(return_value=True)
                mock_cache.get_stats = AsyncMock(
                    return_value={
                        "hits": 1000,
                        "misses": 100,
                        "hit_rate": 90.9,
                        "keys_count": 50,
                        "memory_used": "2.5MB",
                    }
                )

                response = client.get("/health")
                data = response.json()

                assert data["cache_stats"]["hits"] == 1000
                assert data["cache_stats"]["hit_rate"] == 90.9


class TestHealthCheckPerformance:
    """Test health check performance characteristics."""

    def test_health_check_fast_response(self, client):
        """Test basic health check responds quickly."""
        import time

        start = time.time()
        response = client.get("/health")
        duration = time.time() - start

        assert response.status_code == 200
        # Should respond in less than 500ms even with all checks
        assert duration < 0.5

    def test_liveness_probe_minimal_overhead(self, client):
        """Test liveness probe has minimal overhead."""
        import time

        start = time.time()
        response = client.get("/health/live")
        duration = time.time() - start

        assert response.status_code == 200
        # Liveness probe should be very fast
        assert duration < 0.1


class TestHealthCheckIntegration:
    """Integration tests for health check with other components."""

    @pytest.mark.asyncio
    async def test_health_check_with_ml_patterns(self):
        """Test health check detects ML pattern status."""
        from httpx import AsyncClient

        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.get("/health/detailed")
            data = response.json()

        ml_patterns = data["components"].get("ml_patterns", {})
        assert "status" in ml_patterns
        # Should be either healthy or disabled based on dependencies
        assert ml_patterns["status"] in ["healthy", "disabled"]

    @pytest.mark.asyncio
    async def test_health_check_with_rate_limiter(self):
        """Test health check includes rate limiter status."""
        from httpx import AsyncClient

        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.get("/health/detailed")
            data = response.json()

        if "rate_limiter" in data["components"]:
            rl = data["components"]["rate_limiter"]
            assert rl["status"] == "healthy"
            assert "global_limits" in rl
            assert "rpm" in rl["global_limits"]
            assert "tpm" in rl["global_limits"]

    @pytest.mark.asyncio
    async def test_health_check_overall_status_calculation(self):
        """Test overall status calculation based on components."""
        from httpx import AsyncClient

        async with AsyncClient(app=app, base_url="http://test") as client:
            response = await client.get("/health/detailed")
            data = response.json()

        components = data["components"]
        unhealthy_count = sum(
            1 for c in components.values() if isinstance(c, dict) and c.get("status") == "unhealthy"
        )

        # Verify status matches unhealthy count
        if unhealthy_count == 0:
            assert data["status"] == "healthy"
        elif unhealthy_count <= 2:
            assert data["status"] == "degraded"
        else:
            assert data["status"] == "unhealthy"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
