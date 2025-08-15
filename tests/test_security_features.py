# Elastic License 2.0
#
# Copyright (c) 2024-present, PromptSentinel
#
# This source code is licensed under the Elastic License 2.0 found in the
# LICENSE file in the root directory of this source tree.

"""Comprehensive tests for security features."""

import asyncio
import json
from unittest.mock import MagicMock

import pytest
from fastapi import Request

from prompt_sentinel.gdpr.encryption import FieldEncryption, generate_master_key
from prompt_sentinel.gdpr.lifecycle import (
    DataCategory,
    DataLifecycleManager,
    RetentionAction,
    RetentionPolicy,
)
from prompt_sentinel.gdpr.masking import MaskingStrategy, PromptMasker
from prompt_sentinel.security.auth_system import APIKeyManager, UserRole
from prompt_sentinel.security.circuit_breaker import (
    CircuitBreakerError,
    CircuitState,
    LLMCircuitBreaker,
)
from prompt_sentinel.security.config_validator import SecurityConfigValidator
from prompt_sentinel.security.enhanced_rate_limiter import (
    DDoSProtectionMiddleware,
    ThreatLevel,
)
from prompt_sentinel.security.metrics_dashboard import (
    AlertSeverity,
    MetricType,
    SecurityAlert,
    SecurityMetric,
    SecurityMetricsDashboard,
)


class TestFieldEncryption:
    """Test field-level encryption for GDPR compliance."""

    def test_generate_key(self):
        """Test encryption key generation."""
        key = generate_master_key()
        assert isinstance(key, str)
        assert len(key) == 44  # Base64 encoded 32 bytes

    def test_encrypt_decrypt_string(self):
        """Test string encryption and decryption."""
        key = generate_master_key()
        encryption = FieldEncryption(key)

        original = "This is sensitive PII data"
        encrypted = encryption.encrypt_field(original)

        assert encrypted != original
        assert isinstance(encrypted, str)

        decrypted = encryption.decrypt_field(encrypted)
        assert decrypted == original

    def test_encrypt_decrypt_dict(self):
        """Test dictionary field encryption."""
        key = generate_master_key()
        encryption = FieldEncryption(key)

        original = {"name": "John Doe", "ssn": "123-45-6789", "email": "john@example.com"}
        encrypted = encryption.encrypt_dict(original, ["ssn", "email"])

        assert "ssn" not in encrypted
        assert "ssn_encrypted" in encrypted
        assert "email" not in encrypted
        assert "email_encrypted" in encrypted
        assert encrypted["name"] == "John Doe"

        decrypted = encryption.decrypt_dict(encrypted, ["ssn", "email"])
        assert decrypted == original

    def test_encryption_error_handling(self):
        """Test encryption error handling."""
        # Invalid key
        with pytest.raises(Exception):  # noqa: B017
            FieldEncryption("invalid_key")

        # Decrypt with wrong key
        key1 = generate_master_key()
        key2 = generate_master_key()

        encryption1 = FieldEncryption(key1)
        encryption2 = FieldEncryption(key2)

        encrypted = encryption1.encrypt_field("secret")

        with pytest.raises(Exception):  # noqa: B017
            encryption2.decrypt_field(encrypted)


class TestPromptMasking:
    """Test prompt masking utilities."""

    def test_mask_redact_strategy(self):
        """Test redaction masking strategy."""
        masker = PromptMasker()

        prompt = "My email is john@example.com and SSN is 123-45-6789"
        masked, metadata = masker.mask_prompt(prompt, MaskingStrategy.REDACT)

        assert "john@example.com" not in masked
        assert "123-45-6789" not in masked
        assert "[EMAIL]" in masked or "REDACTED" in masked
        assert metadata["masked_count"] >= 2

    def test_mask_hash_strategy(self):
        """Test hash masking strategy."""
        masker = PromptMasker()

        prompt = "API key: sk-abc123xyz789"
        masked, metadata = masker.mask_prompt(prompt, MaskingStrategy.HASH)

        assert "sk-abc123xyz789" not in masked
        assert "[HASH:" in masked
        assert metadata["masked_count"] >= 1

    def test_mask_partial_strategy(self):
        """Test partial masking strategy."""
        masker = PromptMasker()

        prompt = "Call me at 555-123-4567"
        masked, metadata = masker.mask_prompt(prompt, MaskingStrategy.PARTIAL)

        assert "555-123-4567" not in masked
        assert "***" in masked
        assert metadata["masked_count"] >= 1

    def test_privacy_report(self):
        """Test privacy report generation."""
        masker = PromptMasker()

        prompt = """
        My SSN is 123-45-6789 and credit card is 4111-1111-1111-1111.
        Email: test@example.com
        """

        report = masker.create_privacy_report(prompt)

        assert report["pii_detected"]
        assert report["pii_count"] >= 3
        assert report["privacy_risk_score"] > 50
        assert "SSN" in str(report["pii_types"]) or "ssn" in str(report["pii_types"])


class TestDataLifecycleManager:
    """Test data lifecycle management for GDPR."""

    @pytest.mark.asyncio
    async def test_retention_policies(self):
        """Test retention policy configuration."""
        manager = DataLifecycleManager()

        # Check default policies
        policy = manager.get_policy(DataCategory.DETECTION_LOGS)
        assert policy is not None
        assert policy.retention_days == 30
        assert policy.action == RetentionAction.DELETE

        # Set custom policy
        custom_policy = RetentionPolicy(
            DataCategory.METRICS, retention_days=180, action=RetentionAction.ANONYMIZE
        )
        manager.set_policy(custom_policy)

        updated = manager.get_policy(DataCategory.METRICS)
        assert updated.retention_days == 180

    @pytest.mark.asyncio
    async def test_deletion_request(self):
        """Test GDPR deletion request handling."""
        manager = DataLifecycleManager()

        result = await manager.handle_deletion_request(
            data_subject_id="user123",
            categories=[DataCategory.CACHED_PROMPTS, DataCategory.DETECTION_LOGS],
        )

        assert result["data_subject_id"] == "user123"
        assert "categories" in result
        assert "total_deleted" in result

    @pytest.mark.asyncio
    async def test_export_request(self):
        """Test GDPR data export request."""
        manager = DataLifecycleManager()

        result = await manager.handle_data_export_request(
            data_subject_id="user456", categories=[DataCategory.DETECTION_LOGS]
        )

        assert result["data_subject_id"] == "user456"
        assert "categories" in result
        assert "export_timestamp" in result


class TestAPIKeyAuthentication:
    """Test API key authentication system."""

    def test_generate_api_key(self):
        """Test API key generation."""
        manager = APIKeyManager()

        key_string, api_key = manager.generate_api_key(
            client_id="client123", name="Test Key", role=UserRole.USER
        )

        assert key_string.startswith(manager.settings.api_key_prefix)
        assert api_key.client_id == "client123"
        assert api_key.role == UserRole.USER
        assert not api_key.revoked

    def test_validate_api_key(self):
        """Test API key validation."""
        manager = APIKeyManager()

        # Generate key
        key_string, _ = manager.generate_api_key(
            client_id="client456", name="Valid Key", role=UserRole.ADMIN
        )

        # Validate correct key
        validated = manager.validate_api_key(key_string)
        assert validated is not None
        assert validated.client_id == "client456"
        assert validated.role == UserRole.ADMIN

        # Validate incorrect key
        invalid = manager.validate_api_key("invalid_key")
        assert invalid is None

    def test_revoke_api_key(self):
        """Test API key revocation."""
        manager = APIKeyManager()

        key_string, api_key = manager.generate_api_key(
            client_id="client789", name="Revokable Key", role=UserRole.USER
        )

        # Revoke key
        manager.revoke_api_key(api_key.key_id)

        # Validation should fail
        validated = manager.validate_api_key(key_string)
        assert validated is None

    def test_role_based_access(self):
        """Test role-based access control."""
        manager = APIKeyManager()

        # Test role hierarchy
        assert manager.has_permission(UserRole.ADMIN, UserRole.USER)
        assert manager.has_permission(UserRole.USER, UserRole.READONLY)
        assert not manager.has_permission(UserRole.READONLY, UserRole.USER)
        assert not manager.has_permission(UserRole.SERVICE, UserRole.ADMIN)


class TestEnhancedRateLimiting:
    """Test enhanced rate limiting with DDoS protection."""

    @pytest.mark.asyncio
    async def test_token_bucket_algorithm(self):
        """Test token bucket rate limiting."""
        from prompt_sentinel.middleware.rate_limiter import RateLimiter
        limiter = RateLimiter(requests_per_minute=60, burst_size=10)

        # Should allow initial burst
        for _ in range(10):
            allowed, _ = limiter.check_rate_limit("client1")
            assert allowed

        # Should throttle after burst
        allowed, _ = limiter.check_rate_limit("client1")
        assert not allowed or limiter.buckets["client1"]["tokens"] < 1

    @pytest.mark.asyncio
    async def test_ddos_protection(self):
        """Test DDoS protection middleware."""
        ddos = DDoSProtectionMiddleware(block_threshold=10, monitor_window=60)

        # Create mock request
        request = MagicMock(spec=Request)
        request.client.host = "192.168.1.100"
        request.headers = {"user-agent": "TestClient"}
        request.url.path = "/api/v1/detect"

        # Normal requests should pass
        for _ in range(5):
            allowed, reason, threat = await ddos.check_request(request)
            assert allowed
            assert threat == ThreatLevel.NONE

        # Rapid requests should trigger protection
        for _ in range(20):
            await ddos.check_request(request)

        # Should eventually block
        allowed, reason, threat = await ddos.check_request(request)
        if not allowed:
            assert reason is not None
            assert threat in [ThreatLevel.MEDIUM, ThreatLevel.HIGH]

    def test_rate_limit_headers(self):
        """Test rate limit response headers."""
        from prompt_sentinel.middleware.rate_limiter import RateLimiter
        limiter = RateLimiter()

        allowed, headers = limiter.check_rate_limit("client2")

        assert "X-RateLimit-Limit" in headers
        assert "X-RateLimit-Remaining" in headers
        assert "X-RateLimit-Reset" in headers


class TestCircuitBreakers:
    """Test circuit breaker pattern for LLM providers."""

    @pytest.mark.asyncio
    async def test_circuit_breaker_states(self):
        """Test circuit breaker state transitions."""
        breaker = LLMCircuitBreaker(
            provider_name="test_provider",
            failure_threshold=3,
            recovery_timeout=1,
            half_open_max_calls=2,
        )

        # Initial state should be CLOSED
        assert breaker.state == CircuitState.CLOSED

        # Simulate failures
        async def failing_func():
            raise Exception("Provider error")

        for _ in range(3):
            with pytest.raises(Exception):  # noqa: B017
                await breaker.call(failing_func)

        # Should be OPEN after threshold
        assert breaker.state == CircuitState.OPEN

        # Should reject calls when OPEN
        with pytest.raises(CircuitBreakerError):
            await breaker.call(failing_func)

        # Wait for recovery timeout
        await asyncio.sleep(1.1)

        # Should transition to HALF_OPEN
        async def success_func():
            return "success"

        result = await breaker.call(success_func)
        assert result == "success"
        assert breaker.state in [CircuitState.HALF_OPEN, CircuitState.CLOSED]

    @pytest.mark.asyncio
    async def test_circuit_breaker_recovery(self):
        """Test circuit breaker recovery."""
        breaker = LLMCircuitBreaker(
            provider_name="test_provider", failure_threshold=2, recovery_timeout=0.5
        )

        # Trip the breaker
        async def failing_func():
            raise Exception("Error")

        for _ in range(2):
            with pytest.raises(Exception):  # noqa: B017
                await breaker.call(failing_func)

        assert breaker.state == CircuitState.OPEN

        # Wait and recover
        await asyncio.sleep(0.6)

        async def success_func():
            return "recovered"

        # Should allow test call
        result = await breaker.call(success_func)
        assert result == "recovered"

        # Should close after successful calls
        result = await breaker.call(success_func)
        assert breaker.state == CircuitState.CLOSED


class TestSecurityMetricsDashboard:
    """Test security metrics dashboard."""

    @pytest.mark.asyncio
    async def test_record_metrics(self):
        """Test metric recording."""
        dashboard = SecurityMetricsDashboard()

        await dashboard.record_metric(
            MetricType.AUTHENTICATION,
            "failed_authentications",
            1,
            metadata={"client_id": "test123"},
        )

        await dashboard.record_metric(
            MetricType.INJECTION_ATTEMPTS, "injection_detected", 1, metadata={"confidence": 0.95}
        )

        summary = dashboard.get_dashboard_summary()

        assert "metrics_by_type" in summary
        assert MetricType.AUTHENTICATION.value in summary["metrics_by_type"]
        assert MetricType.INJECTION_ATTEMPTS.value in summary["metrics_by_type"]

    @pytest.mark.asyncio
    async def test_alert_thresholds(self):
        """Test alert threshold triggering."""
        dashboard = SecurityMetricsDashboard()
        alerts_triggered = []

        async def alert_handler(alert: SecurityAlert):
            alerts_triggered.append(alert)

        dashboard.add_alert_handler(alert_handler)

        # Set low threshold for testing
        dashboard.set_threshold(
            "test_threshold",
            MetricType.AUTHENTICATION,
            "failed_authentications",
            threshold=2,
            severity=AlertSeverity.HIGH,
            window_minutes=1,
        )

        # Trigger threshold
        for _ in range(3):
            await dashboard.record_metric(MetricType.AUTHENTICATION, "failed_authentications", 1)

        # Check alert was triggered
        assert len(alerts_triggered) > 0
        assert alerts_triggered[0].severity == AlertSeverity.HIGH

    def test_metrics_export(self):
        """Test metrics export formats."""
        dashboard = SecurityMetricsDashboard()

        # Add test metrics
        metric = SecurityMetric(
            metric_type=MetricType.API_USAGE, name="api_requests", value=100, unit="count"
        )
        dashboard.metrics_buffer.append(metric)

        # Test JSON export
        json_export = dashboard.export_metrics("json")
        data = json.loads(json_export)
        assert len(data) > 0
        assert data[0]["name"] == "api_requests"

        # Test Prometheus export
        prom_export = dashboard.export_metrics("prometheus")
        assert "security_api_usage_api_requests" in prom_export

        # Test CSV export
        csv_export = dashboard.export_metrics("csv")
        assert "api_requests" in csv_export

    @pytest.mark.asyncio
    async def test_health_check(self):
        """Test dashboard health check."""
        dashboard = SecurityMetricsDashboard()

        # Record recent metric
        await dashboard.record_metric(MetricType.PERFORMANCE, "response_time_ms", 125.5)

        health = await dashboard.run_health_check()

        assert health["status"] in ["healthy", "degraded"]
        assert "checks" in health
        assert MetricType.PERFORMANCE.value in health["checks"]


class TestSecurityConfigValidator:
    """Test security configuration validation."""

    def test_validate_passwords(self):
        """Test password strength validation."""
        validator = SecurityConfigValidator()

        # Weak passwords
        assert not validator.validate_password_strength("12345")
        assert not validator.validate_password_strength("password")
        assert not validator.validate_password_strength("abc123")

        # Strong password
        assert validator.validate_password_strength("Str0ng!Pass#2024")

    def test_validate_api_keys(self):
        """Test API key format validation."""
        validator = SecurityConfigValidator()

        # Invalid formats
        assert not validator.validate_api_key_format("short")
        assert not validator.validate_api_key_format("password123")

        # Valid format
        assert validator.validate_api_key_format("sk-" + "a" * 32)

    def test_validate_ssl_config(self):
        """Test SSL configuration validation."""
        validator = SecurityConfigValidator()

        report = validator.validate_ssl_config()
        assert "status" in report
        assert "recommendation" in report

    def test_validate_all_config(self):
        """Test comprehensive configuration validation."""
        validator = SecurityConfigValidator()

        report = validator.validate_all()

        assert "timestamp" in report
        assert "checks" in report
        assert "score" in report
        assert "recommendations" in report
        assert report["score"] >= 0
        assert report["score"] <= 100


class TestSecurityIntegration:
    """Integration tests for security features."""

    @pytest.mark.asyncio
    async def test_end_to_end_security_flow(self):
        """Test complete security flow."""
        # 1. Generate API key
        api_manager = APIKeyManager()
        key_string, api_key = api_manager.generate_api_key(
            client_id="integration_test", name="Integration Test", role=UserRole.USER
        )

        # 2. Validate API key
        validated = api_manager.validate_api_key(key_string)
        assert validated is not None

        # 3. Check rate limiting
        from prompt_sentinel.middleware.rate_limiter import RateLimiter
        limiter = RateLimiter()
        allowed, headers = limiter.check_rate_limit("integration_test")
        assert allowed

        # 4. Record metrics
        dashboard = SecurityMetricsDashboard()
        await dashboard.record_metric(
            MetricType.API_USAGE, "api_requests", 1, metadata={"client_id": "integration_test"}
        )

        # 5. Mask sensitive data
        masker = PromptMasker()
        prompt = "Process payment for card 4111-1111-1111-1111"
        masked, _ = masker.mask_prompt(prompt, MaskingStrategy.REDACT)
        assert "4111-1111-1111-1111" not in masked

        # 6. Encrypt for storage
        encryption = FieldEncryption()
        encrypted = encryption.encrypt_field(prompt)
        assert encrypted != prompt

        # 7. Handle GDPR request
        lifecycle = DataLifecycleManager()
        deletion_result = await lifecycle.handle_deletion_request(
            data_subject_id="integration_test", categories=[DataCategory.CACHED_PROMPTS]
        )
        assert deletion_result["data_subject_id"] == "integration_test"

    @pytest.mark.asyncio
    async def test_security_monitoring_flow(self):
        """Test security monitoring and alerting flow."""
        dashboard = SecurityMetricsDashboard()
        alerts = []

        async def capture_alerts(alert: SecurityAlert):
            alerts.append(alert)

        dashboard.add_alert_handler(capture_alerts)

        # Simulate attack pattern
        for _ in range(6):
            await dashboard.record_metric(
                MetricType.INJECTION_ATTEMPTS,
                "injection_detected",
                1,
                metadata={"attack_type": "prompt_injection"},
            )

        # Check alerts were triggered
        await asyncio.sleep(0.1)  # Allow async processing

        # Verify dashboard state
        summary = dashboard.get_dashboard_summary()
        assert summary["metrics_by_type"][MetricType.INJECTION_ATTEMPTS.value]["count"] >= 6

        # Check health status
        health = await dashboard.run_health_check()
        assert health["status"] in ["healthy", "degraded", "critical"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
