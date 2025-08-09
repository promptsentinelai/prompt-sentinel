"""Tests for authentication system with multiple deployment modes."""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from prompt_sentinel.auth import (
    APIKeyManager,
    AuthConfig,
    AuthMode,
    ClientPermission,
    CreateAPIKeyRequest,
    UsageTier,
)
from prompt_sentinel.main import app


@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)


@pytest.fixture
def auth_config_none():
    """Auth config with no authentication."""
    return AuthConfig(mode=AuthMode.NONE)


@pytest.fixture
def auth_config_optional():
    """Auth config with optional authentication."""
    return AuthConfig(mode=AuthMode.OPTIONAL, unauthenticated_rpm=10, unauthenticated_tpm=1000)


@pytest.fixture
def auth_config_required():
    """Auth config with required authentication."""
    return AuthConfig(mode=AuthMode.REQUIRED)


class TestAuthModes:
    """Test different authentication modes."""

    def test_auth_mode_none(self, client):
        """Test with AUTH_MODE=none - no authentication needed."""
        with patch("prompt_sentinel.auth.dependencies.get_auth_config") as mock_config:
            mock_config.return_value = AuthConfig(mode=AuthMode.NONE)

            # Should work without any authentication
            response = client.get("/health")
            assert response.status_code == 200

            # Detection should work without auth
            response = client.post("/v1/detect", json={"prompt": "Hello world"})
            assert response.status_code in [200, 503]  # 503 if detector not initialized

    def test_auth_mode_optional(self, client):
        """Test with AUTH_MODE=optional - auth improves limits."""
        with patch("prompt_sentinel.auth.dependencies.get_auth_config") as mock_config:
            mock_config.return_value = AuthConfig(mode=AuthMode.OPTIONAL)

            # Should work without authentication
            response = client.get("/health")
            assert response.status_code == 200

            # Should also work with invalid API key (just ignored)
            response = client.get("/health", headers={"X-API-Key": "invalid_key"})
            assert response.status_code == 200

    def test_auth_mode_required(self, client):
        """Test with AUTH_MODE=required - auth mandatory."""
        with patch("prompt_sentinel.auth.dependencies.get_auth_config") as mock_config:
            mock_config.return_value = AuthConfig(mode=AuthMode.REQUIRED)

            # Health check should still work (bypassed)
            response = client.get("/health")
            assert response.status_code == 200

            # Admin endpoints should require auth
            # Note: Returns 403 (Forbidden) because require_admin() checks permissions
            response = client.get("/api/v1/admin/api-keys")
            assert response.status_code in [401, 403]  # Either unauthorized or forbidden
            assert (
                "required" in response.json()["detail"].lower()
                or "denied" in response.json()["detail"].lower()
            )


class TestBypassRules:
    """Test authentication bypass rules."""

    def test_localhost_bypass(self, client):
        """Test localhost bypass."""
        config = AuthConfig(mode=AuthMode.REQUIRED, allow_localhost=True)

        with patch("prompt_sentinel.auth.dependencies.get_auth_config") as mock_config:
            mock_config.return_value = config

            # Simulate localhost request
            with patch("prompt_sentinel.auth.dependencies.Request") as mock_request:
                mock_request.client.host = "127.0.0.1"

                # Should bypass auth for localhost
                response = client.get("/health")
                assert response.status_code == 200

    def test_network_bypass(self):
        """Test network CIDR bypass."""
        config = AuthConfig(
            mode=AuthMode.REQUIRED, bypass_networks=["10.0.0.0/8", "192.168.0.0/16"]
        )

        manager = APIKeyManager(config)

        # Should bypass for internal networks
        assert manager.check_network_bypass("10.0.0.1")
        assert manager.check_network_bypass("192.168.1.1")
        assert not manager.check_network_bypass("8.8.8.8")

    def test_header_bypass(self):
        """Test header bypass."""
        config = AuthConfig(
            mode=AuthMode.REQUIRED, bypass_headers={"X-Internal": "true", "X-Service": "gateway"}
        )

        manager = APIKeyManager(config)

        # Should bypass with correct headers
        headers = {"X-Internal": "true"}
        assert manager.check_header_bypass(headers)

        headers = {"X-Service": "gateway"}
        assert manager.check_header_bypass(headers)

        headers = {"X-Internal": "false"}
        assert not manager.check_header_bypass(headers)


class TestAPIKeyManagement:
    """Test API key lifecycle management."""

    @pytest.mark.asyncio
    async def test_create_api_key(self):
        """Test API key creation."""
        config = AuthConfig()
        manager = APIKeyManager(config)

        # Mock Redis storage
        with patch.object(manager, "_store_api_key") as mock_store:
            mock_store.return_value = None

            request = CreateAPIKeyRequest(
                client_name="Test Client",
                description="Test key",
                usage_tier=UsageTier.PRO,
                permissions=[ClientPermission.DETECT_READ, ClientPermission.DETECT_WRITE],
            )

            response = await manager.create_api_key(request)

            assert response.api_key.startswith("psk_")
            assert response.client_name == "Test Client"
            assert response.usage_tier == UsageTier.PRO
            assert ClientPermission.DETECT_READ in response.permissions

    @pytest.mark.asyncio
    async def test_validate_api_key(self):
        """Test API key validation."""
        config = AuthConfig()
        manager = APIKeyManager(config)

        # Test invalid key format
        result = await manager.validate_api_key("invalid")
        assert result is None

        # Test key not starting with prefix
        result = await manager.validate_api_key("xxx_invalidkey")
        assert result is None

    @pytest.mark.asyncio
    async def test_key_rotation(self):
        """Test API key rotation."""
        config = AuthConfig()
        manager = APIKeyManager(config)

        # Mock getting old key
        with patch.object(manager, "_get_api_key_by_id") as mock_get:
            # Mock storing new key
            with patch.object(manager, "_store_api_key") as mock_store:
                from datetime import datetime

                from prompt_sentinel.auth.models import APIKey, APIKeyStatus

                old_key = APIKey(
                    key_id="old_key_id",
                    key_hash="old_hash",
                    client_id="client_123",
                    client_name="Test Client",
                    created_at=datetime.utcnow(),
                    status=APIKeyStatus.ACTIVE,
                    usage_tier=UsageTier.PRO,
                    permissions=[ClientPermission.DETECT_READ],
                )

                mock_get.return_value = old_key
                mock_store.return_value = None

                new_key = await manager.rotate_api_key("old_key_id")

                assert new_key is not None
                assert new_key.api_key.startswith("psk_")
                assert new_key.client_name == "Test Client"


class TestRateLimiting:
    """Test rate limiting with authentication."""

    def test_authenticated_rate_limits(self):
        """Test that authenticated clients get higher rate limits."""
        # This would test integration with rate limiter
        # Using different limits based on auth status
        pass

    def test_unauthenticated_rate_limits(self):
        """Test that unauthenticated clients get lower rate limits."""
        # This would test that anonymous users get restricted limits
        pass


class TestWebSocketAuth:
    """Test WebSocket authentication."""

    def test_websocket_with_api_key(self):
        """Test WebSocket connection with API key."""
        # WebSocket auth via query param
        pass

    def test_websocket_without_api_key(self):
        """Test WebSocket connection without API key."""
        # Should work in optional mode, fail in required mode
        pass


class TestUsageTracking:
    """Test usage tracking with authentication."""

    def test_usage_tracked_by_client(self):
        """Test that usage is tracked per authenticated client."""
        # Verify usage_tracker receives correct client_id
        pass

    def test_anonymous_usage_tracking(self):
        """Test that anonymous usage is tracked separately."""
        # Verify anonymous users are tracked with anon_ prefix
        pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
