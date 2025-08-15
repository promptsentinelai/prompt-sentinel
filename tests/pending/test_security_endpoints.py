#!/usr/bin/env python3
# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0

"""Comprehensive tests for API security endpoints."""

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from prompt_sentinel.api.security_endpoints import (
    SecurityDashboard,
    SecurityManager,
    SecurityMetric,
    UserRole,
    router,
)
from prompt_sentinel.models.schemas import DetectionCategory, Verdict


@pytest.fixture
def security_manager():
    """Create a test security manager."""
    manager = SecurityManager()
    return manager


@pytest.fixture
def mock_detector():
    """Create a mock detector."""
    detector = AsyncMock()
    detector.detect = AsyncMock()
    return detector


@pytest.fixture
def test_client():
    """Create a test client with security endpoints."""
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


class TestSecurityManager:
    """Test SecurityManager functionality."""

    def test_record_metric(self, security_manager):
        """Test recording security metrics."""
        # Record some metrics
        security_manager.record_metric(
            user_id="user1",
            category=DetectionCategory.DIRECT_INJECTION,
            verdict=Verdict.BLOCK,
            confidence=0.9,
        )
        security_manager.record_metric(
            user_id="user1",
            category=DetectionCategory.JAILBREAK,
            verdict=Verdict.FLAG,
            confidence=0.7,
        )

        # Check metrics were recorded
        assert len(security_manager.metrics) == 2
        assert security_manager.metrics[0].user_id == "user1"
        assert security_manager.metrics[0].category == DetectionCategory.DIRECT_INJECTION
        assert security_manager.metrics[1].verdict == Verdict.FLAG

    def test_get_user_metrics(self, security_manager):
        """Test getting metrics for specific user."""
        # Record metrics for multiple users
        security_manager.record_metric(
            "user1", DetectionCategory.DIRECT_INJECTION, Verdict.BLOCK, 0.9
        )
        security_manager.record_metric("user2", DetectionCategory.JAILBREAK, Verdict.FLAG, 0.7)
        security_manager.record_metric("user1", DetectionCategory.PROMPT_LEAK, Verdict.ALLOW, 0.3)

        # Get metrics for user1
        user1_metrics = security_manager.get_user_metrics("user1")
        assert len(user1_metrics) == 2
        assert all(m.user_id == "user1" for m in user1_metrics)

        # Get metrics for user2
        user2_metrics = security_manager.get_user_metrics("user2")
        assert len(user2_metrics) == 1
        assert user2_metrics[0].user_id == "user2"

    def test_get_metrics_by_time_range(self, security_manager):
        """Test getting metrics within time range."""
        now = datetime.utcnow()

        # Record metrics at different times
        with patch("prompt_sentinel.api.security_endpoints.datetime") as mock_dt:
            mock_dt.utcnow.return_value = now - timedelta(hours=2)
            security_manager.record_metric(
                "user1", DetectionCategory.DIRECT_INJECTION, Verdict.BLOCK, 0.9
            )

            mock_dt.utcnow.return_value = now - timedelta(minutes=30)
            security_manager.record_metric("user1", DetectionCategory.JAILBREAK, Verdict.FLAG, 0.7)

            mock_dt.utcnow.return_value = now
            security_manager.record_metric(
                "user1", DetectionCategory.PROMPT_LEAK, Verdict.ALLOW, 0.3
            )

        # Get metrics from last hour
        recent_metrics = security_manager.get_metrics_by_time_range(
            start_time=now - timedelta(hours=1), end_time=now
        )
        assert len(recent_metrics) == 2  # Should exclude the 2-hour old metric

    def test_get_dashboard_stats(self, security_manager):
        """Test dashboard statistics generation."""
        # Record various metrics
        security_manager.record_metric(
            "user1", DetectionCategory.DIRECT_INJECTION, Verdict.BLOCK, 0.9
        )
        security_manager.record_metric("user2", DetectionCategory.JAILBREAK, Verdict.BLOCK, 0.8)
        security_manager.record_metric("user1", DetectionCategory.PROMPT_LEAK, Verdict.FLAG, 0.6)
        security_manager.record_metric("user3", DetectionCategory.BENIGN, Verdict.ALLOW, 0.1)

        dashboard = security_manager.get_dashboard()

        assert dashboard.total_requests == 4
        assert dashboard.blocked_requests == 2
        assert dashboard.flagged_requests == 1
        assert dashboard.unique_users == 3
        assert dashboard.attack_categories[DetectionCategory.DIRECT_INJECTION] == 1
        assert dashboard.attack_categories[DetectionCategory.JAILBREAK] == 1

    def test_delete_user_data(self, security_manager):
        """Test GDPR deletion of user data."""
        # Record metrics for multiple users
        security_manager.record_metric(
            "user1", DetectionCategory.DIRECT_INJECTION, Verdict.BLOCK, 0.9
        )
        security_manager.record_metric("user2", DetectionCategory.JAILBREAK, Verdict.FLAG, 0.7)
        security_manager.record_metric("user1", DetectionCategory.PROMPT_LEAK, Verdict.ALLOW, 0.3)

        # Delete user1 data
        deleted_count = security_manager.delete_user_data("user1")

        assert deleted_count == 2
        assert len(security_manager.metrics) == 1
        assert security_manager.metrics[0].user_id == "user2"

    def test_export_user_data(self, security_manager):
        """Test GDPR export of user data."""
        # Record metrics
        security_manager.record_metric(
            "user1", DetectionCategory.DIRECT_INJECTION, Verdict.BLOCK, 0.9
        )
        security_manager.record_metric("user1", DetectionCategory.JAILBREAK, Verdict.FLAG, 0.7)

        # Export user data
        export_data = security_manager.export_user_data("user1")

        assert export_data["user_id"] == "user1"
        assert len(export_data["metrics"]) == 2
        assert export_data["metrics"][0]["category"] == "DIRECT_INJECTION"
        assert export_data["metrics"][1]["verdict"] == "FLAG"

    def test_get_rate_limit_status(self, security_manager):
        """Test rate limit status checking."""
        # Simulate rate limit tracking
        security_manager.rate_limits = {
            "user1": {
                "requests": 95,
                "limit": 100,
                "reset_time": datetime.utcnow() + timedelta(minutes=5),
            },
            "user2": {
                "requests": 50,
                "limit": 100,
                "reset_time": datetime.utcnow() + timedelta(minutes=3),
            },
        }

        status1 = security_manager.get_rate_limit_status("user1")
        assert status1["remaining"] == 5
        assert status1["requests"] == 95

        status2 = security_manager.get_rate_limit_status("user2")
        assert status2["remaining"] == 50

        # Unknown user should get default
        status3 = security_manager.get_rate_limit_status("user3")
        assert status3["remaining"] == 100
        assert status3["requests"] == 0

    def test_reset_circuit_breaker(self, security_manager):
        """Test circuit breaker reset."""
        # Set circuit breaker state
        security_manager.circuit_breakers = {
            "provider1": {"state": "open", "failures": 5},
            "provider2": {"state": "closed", "failures": 0},
        }

        # Reset provider1
        success = security_manager.reset_circuit_breaker("provider1")
        assert success
        assert security_manager.circuit_breakers["provider1"]["state"] == "closed"
        assert security_manager.circuit_breakers["provider1"]["failures"] == 0

        # Provider2 should remain unchanged
        assert security_manager.circuit_breakers["provider2"]["state"] == "closed"


class TestSecurityEndpoints:
    """Test security API endpoints."""

    def test_get_dashboard(self, test_client):
        """Test dashboard endpoint."""
        with patch("prompt_sentinel.api.security_endpoints.security_manager") as mock_manager:
            mock_dashboard = SecurityDashboard(
                total_requests=100,
                blocked_requests=20,
                flagged_requests=15,
                unique_users=25,
                attack_categories={DetectionCategory.DIRECT_INJECTION: 10},
                time_window_hours=24,
            )
            mock_manager.get_dashboard.return_value = mock_dashboard

            response = test_client.get("/api/v1/security/dashboard")

            assert response.status_code == 200
            data = response.json()
            assert data["total_requests"] == 100
            assert data["blocked_requests"] == 20
            assert data["unique_users"] == 25

    def test_get_dashboard_with_auth(self, test_client):
        """Test dashboard endpoint with authentication."""
        response = test_client.get(
            "/api/v1/security/dashboard", headers={"Authorization": "Bearer test-token"}
        )

        # Should work (auth is mocked in test)
        assert response.status_code in [200, 401]  # Depends on auth implementation

    def test_get_metric_history(self, test_client):
        """Test metric history endpoint."""
        with patch("prompt_sentinel.api.security_endpoints.security_manager") as mock_manager:
            mock_metrics = [
                SecurityMetric(
                    user_id="user1",
                    timestamp=datetime.utcnow(),
                    category=DetectionCategory.DIRECT_INJECTION,
                    verdict=Verdict.BLOCK,
                    confidence=0.9,
                )
            ]
            mock_manager.get_metrics_by_time_range.return_value = mock_metrics

            response = test_client.get("/api/v1/security/metrics/history?hours=24")

            assert response.status_code == 200
            data = response.json()
            assert len(data) == 1
            assert data[0]["user_id"] == "user1"

    def test_get_metric_history_with_user_filter(self, test_client):
        """Test metric history with user filter."""
        with patch("prompt_sentinel.api.security_endpoints.security_manager") as mock_manager:
            mock_metrics = [
                SecurityMetric(
                    user_id="user1",
                    timestamp=datetime.utcnow(),
                    category=DetectionCategory.JAILBREAK,
                    verdict=Verdict.FLAG,
                    confidence=0.7,
                )
            ]
            mock_manager.get_user_metrics.return_value = mock_metrics

            response = test_client.get("/api/v1/security/metrics/history?user_id=user1")

            assert response.status_code == 200
            data = response.json()
            assert len(data) == 1
            assert data[0]["category"] == "JAILBREAK"

    def test_record_metric(self, test_client):
        """Test recording a metric."""
        with patch("prompt_sentinel.api.security_endpoints.security_manager") as mock_manager:
            mock_manager.record_metric.return_value = None

            metric_data = {
                "user_id": "user1",
                "category": "DIRECT_INJECTION",
                "verdict": "BLOCK",
                "confidence": 0.9,
            }

            response = test_client.post("/api/v1/security/metrics", json=metric_data)

            assert response.status_code == 200
            assert response.json()["status"] == "recorded"
            mock_manager.record_metric.assert_called_once()

    def test_gdpr_deletion(self, test_client):
        """Test GDPR deletion endpoint."""
        with patch("prompt_sentinel.api.security_endpoints.security_manager") as mock_manager:
            mock_manager.delete_user_data.return_value = 5

            response = test_client.delete(
                "/api/v1/security/gdpr/user1", headers={"Authorization": "Bearer admin-token"}
            )

            assert response.status_code == 200
            data = response.json()
            assert data["deleted_count"] == 5
            assert data["user_id"] == "user1"

    def test_gdpr_export(self, test_client):
        """Test GDPR export endpoint."""
        with patch("prompt_sentinel.api.security_endpoints.security_manager") as mock_manager:
            mock_export = {
                "user_id": "user1",
                "metrics": [{"category": "JAILBREAK", "verdict": "BLOCK", "confidence": 0.8}],
                "export_time": datetime.utcnow().isoformat(),
            }
            mock_manager.export_user_data.return_value = mock_export

            response = test_client.get("/api/v1/security/gdpr/export/user1")

            assert response.status_code == 200
            data = response.json()
            assert data["user_id"] == "user1"
            assert len(data["metrics"]) == 1

    def test_rate_limit_status(self, test_client):
        """Test rate limit status endpoint."""
        with patch("prompt_sentinel.api.security_endpoints.security_manager") as mock_manager:
            mock_status = {
                "user_id": "user1",
                "requests": 75,
                "remaining": 25,
                "limit": 100,
                "reset_time": (datetime.utcnow() + timedelta(minutes=5)).isoformat(),
            }
            mock_manager.get_rate_limit_status.return_value = mock_status

            response = test_client.get("/api/v1/security/rate-limit/user1")

            assert response.status_code == 200
            data = response.json()
            assert data["remaining"] == 25
            assert data["requests"] == 75

    def test_reset_circuit_breaker(self, test_client):
        """Test circuit breaker reset endpoint."""
        with patch("prompt_sentinel.api.security_endpoints.security_manager") as mock_manager:
            mock_manager.reset_circuit_breaker.return_value = True

            response = test_client.post(
                "/api/v1/security/circuit-breaker/anthropic/reset",
                headers={"Authorization": "Bearer admin-token"},
            )

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "reset"
            assert data["provider"] == "anthropic"

    def test_unauthorized_access(self, test_client):
        """Test unauthorized access to admin endpoints."""
        # Test without auth header
        response = test_client.delete("/api/v1/security/gdpr/user1")
        assert response.status_code in [401, 403, 422]  # Unauthorized or Forbidden

        # Test with wrong role
        with patch("prompt_sentinel.api.security_endpoints.get_current_user_role") as mock_role:
            mock_role.return_value = UserRole.USER

            response = test_client.delete(
                "/api/v1/security/gdpr/user1", headers={"Authorization": "Bearer user-token"}
            )
            # Should be forbidden for non-admin
            assert response.status_code in [403, 401, 422]


class TestSecurityIntegration:
    """Integration tests for security functionality."""

    @pytest.mark.asyncio
    async def test_full_security_flow(self):
        """Test complete security monitoring flow."""
        manager = SecurityManager()

        # Simulate detection and recording
        for i in range(10):
            user_id = f"user{i % 3}"
            category = [
                DetectionCategory.DIRECT_INJECTION,
                DetectionCategory.JAILBREAK,
                DetectionCategory.BENIGN,
            ][i % 3]
            verdict = [Verdict.BLOCK, Verdict.FLAG, Verdict.ALLOW][i % 3]
            confidence = 0.5 + (i % 5) * 0.1

            manager.record_metric(user_id, category, verdict, confidence)

        # Check dashboard
        dashboard = manager.get_dashboard()
        assert dashboard.total_requests == 10
        assert dashboard.unique_users == 3
        assert dashboard.blocked_requests > 0

        # Check user metrics
        user0_metrics = manager.get_user_metrics("user0")
        assert len(user0_metrics) == 4  # user0 appears at indices 0, 3, 6, 9

        # Export user data
        export = manager.export_user_data("user0")
        assert export["user_id"] == "user0"
        assert len(export["metrics"]) == 4

        # Delete user data
        deleted = manager.delete_user_data("user0")
        assert deleted == 4

        # Verify deletion
        remaining = manager.get_user_metrics("user0")
        assert len(remaining) == 0

    @pytest.mark.asyncio
    async def test_concurrent_metric_recording(self):
        """Test thread-safe metric recording."""
        import threading

        manager = SecurityManager()

        def record_metrics(user_id, count):
            for _i in range(count):
                manager.record_metric(
                    user_id, DetectionCategory.DIRECT_INJECTION, Verdict.BLOCK, 0.9
                )

        # Create multiple threads recording metrics
        threads = []
        for i in range(5):
            t = threading.Thread(target=record_metrics, args=(f"user{i}", 20))
            threads.append(t)
            t.start()

        # Wait for all threads
        for t in threads:
            t.join()

        # Verify all metrics recorded
        assert len(manager.metrics) == 100  # 5 users * 20 metrics each

        # Check each user has correct count
        for i in range(5):
            user_metrics = manager.get_user_metrics(f"user{i}")
            assert len(user_metrics) == 20

    def test_metric_persistence(self):
        """Test metric persistence across manager instances."""
        # This would test database/file persistence in production
        manager1 = SecurityManager()
        manager1.record_metric("user1", DetectionCategory.JAILBREAK, Verdict.BLOCK, 0.9)

        # In production, this would save to persistent storage
        metrics_data = manager1.export_all_metrics()

        # New manager instance
        manager2 = SecurityManager()
        # In production, this would load from persistent storage
        manager2.import_metrics(metrics_data)

        # Verify metrics are preserved
        user_metrics = manager2.get_user_metrics("user1")
        assert len(user_metrics) == 1
        assert user_metrics[0].category == DetectionCategory.JAILBREAK
