"""Comprehensive tests for the AuthenticationMiddleware module."""

import json
from unittest.mock import AsyncMock, MagicMock, Mock, call, patch

import pytest
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.datastructures import Headers
from starlette.middleware.base import BaseHTTPMiddleware

from prompt_sentinel.auth.middleware import AuthenticationMiddleware
from prompt_sentinel.auth.models import (
    AuthConfig,
    AuthMethod,
    AuthMode,
    Client,
    ClientPermission,
    UsageTier,
)


class TestAuthenticationMiddleware:
    """Test suite for AuthenticationMiddleware."""

    @pytest.fixture
    def app(self):
        """Create a FastAPI application."""
        return FastAPI()

    @pytest.fixture
    def auth_config(self):
        """Create test auth configuration."""
        return AuthConfig(
            mode=AuthMode.OPTIONAL,
            enforce_https=False,
            bypass_networks=["127.0.0.1/32", "10.0.0.0/8"],
            bypass_headers={"X-Internal": "true", "X-Service": "trusted"},
            allow_localhost=True,
            unauthenticated_rpm=10,
            unauthenticated_tpm=1000,
        )

    @pytest.fixture
    def api_key_manager(self):
        """Create mock API key manager."""
        manager = MagicMock()
        manager.check_network_bypass = MagicMock(return_value=False)
        manager.check_header_bypass = MagicMock(return_value=False)
        manager.validate_api_key = AsyncMock(return_value=None)
        return manager

    @pytest.fixture
    def middleware(self, app, auth_config, api_key_manager):
        """Create AuthenticationMiddleware instance."""
        return AuthenticationMiddleware(
            app=app, auth_config=auth_config, api_key_manager=api_key_manager
        )

    @pytest.fixture
    def mock_request(self):
        """Create a mock request."""
        request = MagicMock(spec=Request)
        request.url.path = "/api/v1/detect"
        request.url.scheme = "http"
        request.client = MagicMock()
        request.client.host = "192.168.1.1"
        request.headers = Headers({"content-type": "application/json"})
        request.state = MagicMock()
        return request

    @pytest.fixture
    def mock_call_next(self):
        """Create a mock call_next function."""

        async def call_next(request):
            response = MagicMock(spec=Response)
            response.headers = {}
            return response

        return AsyncMock(side_effect=call_next)

    def test_initialization(self, app, auth_config, api_key_manager):
        """Test middleware initialization."""
        middleware = AuthenticationMiddleware(
            app=app, auth_config=auth_config, api_key_manager=api_key_manager
        )

        assert middleware.auth_config == auth_config
        assert middleware.api_key_manager == api_key_manager

    def test_initialization_defaults(self, app):
        """Test middleware initialization with defaults."""
        with patch("prompt_sentinel.auth.middleware.get_auth_config") as mock_get_config:
            with patch("prompt_sentinel.auth.middleware.get_api_key_manager") as mock_get_manager:
                mock_config = MagicMock()
                mock_get_config.return_value = mock_config
                mock_manager = MagicMock()
                mock_get_manager.return_value = mock_manager

                middleware = AuthenticationMiddleware(app)

                assert middleware.auth_config == mock_config
                assert middleware.api_key_manager == mock_manager
                mock_get_config.assert_called_once()
                mock_get_manager.assert_called_once_with(mock_config)

    @pytest.mark.asyncio
    async def test_dispatch_system_endpoints(self, middleware, mock_call_next):
        """Test dispatch for system endpoints (health, docs)."""
        for path in ["/api/v1/health", "/docs", "/redoc", "/openapi.json"]:
            request = MagicMock(spec=Request)
            request.url.path = path
            request.state = MagicMock()

            response = await middleware.dispatch(request, mock_call_next)

            # Should set system client
            assert request.state.client.client_id == "system"
            assert request.state.client.client_name == "System"
            assert request.state.client.auth_method == AuthMethod.NONE
            assert request.state.client.usage_tier == UsageTier.INTERNAL

            mock_call_next.assert_called_with(request)

    @pytest.mark.asyncio
    async def test_dispatch_admin_endpoint_auth_none(self, middleware, mock_call_next):
        """Test dispatch for admin endpoints when auth mode is NONE."""
        middleware.auth_config.mode = AuthMode.NONE

        request = MagicMock(spec=Request)
        request.url.path = "/admin/settings"
        request.state = MagicMock()

        response = await middleware.dispatch(request, mock_call_next)

        # Should set admin client
        assert request.state.client.client_id == "admin"
        assert request.state.client.client_name == "Admin"
        assert request.state.client.auth_method == AuthMethod.NONE
        assert request.state.client.usage_tier == UsageTier.INTERNAL

    @pytest.mark.asyncio
    async def test_dispatch_admin_endpoint_auth_required(
        self, middleware, mock_request, mock_call_next
    ):
        """Test dispatch for admin endpoints when auth mode is REQUIRED."""
        middleware.auth_config.mode = AuthMode.REQUIRED
        mock_request.url.path = "/admin/settings"

        response = await middleware.dispatch(mock_request, mock_call_next)

        # Should not bypass, will get anonymous client
        assert mock_request.state.client.auth_method == AuthMethod.ANONYMOUS

    @pytest.mark.asyncio
    async def test_dispatch_auth_mode_none(self, middleware, mock_request, mock_call_next):
        """Test dispatch when auth mode is NONE."""
        middleware.auth_config.mode = AuthMode.NONE

        response = await middleware.dispatch(mock_request, mock_call_next)

        # Should set local client
        assert mock_request.state.client.client_id == "local"
        assert mock_request.state.client.client_name == "Local Client"
        assert mock_request.state.client.auth_method == AuthMethod.NONE
        assert mock_request.state.client.usage_tier == UsageTier.INTERNAL

    @pytest.mark.asyncio
    async def test_dispatch_localhost_bypass(self, middleware, mock_request, mock_call_next):
        """Test dispatch with localhost bypass."""
        mock_request.client.host = "127.0.0.1"

        response = await middleware.dispatch(mock_request, mock_call_next)

        # Should set localhost bypass client
        assert mock_request.state.client.client_id == "localhost"
        assert mock_request.state.client.client_name == "Localhost"
        assert mock_request.state.client.auth_method == AuthMethod.BYPASS
        assert mock_request.state.client.usage_tier == UsageTier.INTERNAL

    @pytest.mark.asyncio
    async def test_dispatch_localhost_ipv6_bypass(self, middleware, mock_request, mock_call_next):
        """Test dispatch with IPv6 localhost bypass."""
        mock_request.client.host = "::1"

        response = await middleware.dispatch(mock_request, mock_call_next)

        # Should set localhost bypass client
        assert mock_request.state.client.client_id == "localhost"
        assert mock_request.state.client.auth_method == AuthMethod.BYPASS

    @pytest.mark.asyncio
    async def test_dispatch_localhost_bypass_disabled(
        self, middleware, mock_request, mock_call_next
    ):
        """Test dispatch when localhost bypass is disabled."""
        middleware.auth_config.allow_localhost = False
        mock_request.client.host = "127.0.0.1"

        response = await middleware.dispatch(mock_request, mock_call_next)

        # Should not bypass, will get anonymous client
        assert mock_request.state.client.client_id == "anon_127.0.0.1"
        assert mock_request.state.client.auth_method == AuthMethod.ANONYMOUS

    @pytest.mark.asyncio
    async def test_dispatch_network_bypass(self, middleware, mock_request, mock_call_next):
        """Test dispatch with network bypass."""
        mock_request.client.host = "10.0.0.5"
        middleware.api_key_manager.check_network_bypass.return_value = True

        response = await middleware.dispatch(mock_request, mock_call_next)

        # Should set network bypass client
        assert mock_request.state.client.client_id == "network_10.0.0.5"
        assert mock_request.state.client.client_name == "Internal Network (10.0.0.5)"
        assert mock_request.state.client.auth_method == AuthMethod.BYPASS
        assert mock_request.state.client.usage_tier == UsageTier.INTERNAL

    @pytest.mark.asyncio
    async def test_dispatch_header_bypass(self, middleware, mock_request, mock_call_next):
        """Test dispatch with header bypass."""
        mock_request.headers = Headers({"X-Internal": "true"})
        middleware.api_key_manager.check_header_bypass.return_value = True

        response = await middleware.dispatch(mock_request, mock_call_next)

        # Should set header bypass client
        assert mock_request.state.client.client_id == "header_bypass"
        assert mock_request.state.client.client_name == "Header Bypass"
        assert mock_request.state.client.auth_method == AuthMethod.BYPASS
        assert mock_request.state.client.usage_tier == UsageTier.INTERNAL

    @pytest.mark.asyncio
    async def test_dispatch_api_key_valid(self, middleware, mock_request, mock_call_next):
        """Test dispatch with valid API key."""
        mock_request.headers = Headers({"X-API-Key": "psk_test_key"})

        test_client = Client(
            client_id="test_client_id",
            client_name="Test Client",
            auth_method=AuthMethod.API_KEY,
            usage_tier=UsageTier.PRO,
            rate_limits={"rpm": 100, "tpm": 10000},
        )
        middleware.api_key_manager.validate_api_key.return_value = test_client

        response = await middleware.dispatch(mock_request, mock_call_next)

        # Should set the validated client
        assert mock_request.state.client == test_client
        assert mock_request.state.client_id == "test_client_id"
        assert mock_request.state.auth_method == AuthMethod.API_KEY

    @pytest.mark.asyncio
    async def test_dispatch_api_key_invalid_optional_mode(
        self, middleware, mock_request, mock_call_next
    ):
        """Test dispatch with invalid API key in optional mode."""
        middleware.auth_config.mode = AuthMode.OPTIONAL
        mock_request.headers = Headers({"X-API-Key": "psk_invalid_key"})
        middleware.api_key_manager.validate_api_key.return_value = None

        response = await middleware.dispatch(mock_request, mock_call_next)

        # Should fall back to anonymous client
        assert mock_request.state.client.client_id == "anon_192.168.1.1"
        assert mock_request.state.client.auth_method == AuthMethod.ANONYMOUS
        assert mock_request.state.client.usage_tier == UsageTier.FREE

    @pytest.mark.asyncio
    async def test_dispatch_api_key_invalid_required_mode(
        self, middleware, mock_request, mock_call_next
    ):
        """Test dispatch with invalid API key in required mode."""
        middleware.auth_config.mode = AuthMode.REQUIRED
        mock_request.headers = Headers({"X-API-Key": "psk_invalid_key"})
        middleware.api_key_manager.validate_api_key.return_value = None

        response = await middleware.dispatch(mock_request, mock_call_next)

        # Should still fall back to anonymous (dependency will handle error)
        assert mock_request.state.client.client_id == "anon_192.168.1.1"
        assert mock_request.state.client.auth_method == AuthMethod.ANONYMOUS

    @pytest.mark.asyncio
    async def test_dispatch_no_api_key_required_mode(
        self, middleware, mock_request, mock_call_next
    ):
        """Test dispatch with no API key in required mode."""
        middleware.auth_config.mode = AuthMode.REQUIRED

        response = await middleware.dispatch(mock_request, mock_call_next)

        # Should fall back to anonymous (dependency will handle error)
        assert mock_request.state.client.client_id == "anon_192.168.1.1"
        assert mock_request.state.client.auth_method == AuthMethod.ANONYMOUS

    @pytest.mark.asyncio
    async def test_dispatch_anonymous_rate_limits(self, middleware, mock_request, mock_call_next):
        """Test dispatch sets correct rate limits for anonymous clients."""
        middleware.auth_config.unauthenticated_rpm = 20
        middleware.auth_config.unauthenticated_tpm = 2000

        response = await middleware.dispatch(mock_request, mock_call_next)

        assert mock_request.state.client.auth_method == AuthMethod.ANONYMOUS
        assert mock_request.state.client.rate_limits == {"rpm": 20, "tpm": 2000}

    @pytest.mark.asyncio
    async def test_dispatch_https_enforcement_required(
        self, middleware, mock_request, mock_call_next
    ):
        """Test HTTPS enforcement for authenticated clients."""
        middleware.auth_config.enforce_https = True
        mock_request.url.scheme = "http"
        mock_request.headers = Headers({})  # No X-Forwarded-Proto

        response = await middleware.dispatch(mock_request, mock_call_next)

        # Non-bypass clients should get 403
        assert isinstance(response, JSONResponse)
        assert response.status_code == 403
        response_content = json.loads(response.body)
        assert response_content["detail"] == "HTTPS required"

    @pytest.mark.asyncio
    async def test_dispatch_https_enforcement_bypass_allowed(
        self, middleware, mock_request, mock_call_next
    ):
        """Test HTTPS enforcement allows bypass clients."""
        middleware.auth_config.enforce_https = True
        mock_request.url.scheme = "http"
        mock_request.client.host = "127.0.0.1"  # Localhost bypass

        response = await middleware.dispatch(mock_request, mock_call_next)

        # Bypass clients are allowed even without HTTPS
        mock_call_next.assert_called_with(mock_request)
        assert mock_request.state.client.auth_method == AuthMethod.BYPASS

    @pytest.mark.asyncio
    async def test_dispatch_https_via_proxy(self, middleware, mock_request, mock_call_next):
        """Test HTTPS detection via proxy headers."""
        middleware.auth_config.enforce_https = True
        mock_request.url.scheme = "http"
        mock_request.headers = Headers({"X-Forwarded-Proto": "https"})

        response = await middleware.dispatch(mock_request, mock_call_next)

        # Should allow request with proxy HTTPS header
        mock_call_next.assert_called_with(mock_request)

    @pytest.mark.asyncio
    async def test_dispatch_client_id_header(self, middleware, mock_request, mock_call_next):
        """Test that client ID is added to response headers."""
        mock_request.headers = Headers({"X-API-Key": "psk_test_key"})

        test_client = Client(
            client_id="test_client_id",
            client_name="Test Client",
            auth_method=AuthMethod.API_KEY,
            usage_tier=UsageTier.PRO,
        )
        middleware.api_key_manager.validate_api_key.return_value = test_client

        response = await middleware.dispatch(mock_request, mock_call_next)

        # Should add client ID to response headers
        assert response.headers["X-Client-ID"] == "test_client_id"

    @pytest.mark.asyncio
    async def test_dispatch_system_client_no_header(self, middleware, mock_call_next):
        """Test that system client ID is not added to response headers."""
        request = MagicMock(spec=Request)
        request.url.path = "/api/v1/health"
        request.state = MagicMock()

        response = await middleware.dispatch(request, mock_call_next)

        # Should not add system client ID to headers
        assert "X-Client-ID" not in response.headers

    @pytest.mark.asyncio
    async def test_dispatch_exception_optional_mode(self, middleware, mock_request, mock_call_next):
        """Test exception handling in optional mode."""
        middleware.auth_config.mode = AuthMode.OPTIONAL

        # Simulate exception in _get_client
        with patch.object(middleware, "_get_client", side_effect=Exception("Auth error")):
            response = await middleware.dispatch(mock_request, mock_call_next)

        # Should set error client and continue
        assert mock_request.state.client.client_id == "error"
        assert mock_request.state.client.client_name == "Error"
        assert mock_request.state.client.auth_method == AuthMethod.ANONYMOUS
        assert mock_request.state.client.usage_tier == UsageTier.FREE
        mock_call_next.assert_called_with(mock_request)

    @pytest.mark.asyncio
    async def test_dispatch_exception_required_mode(self, middleware, mock_request, mock_call_next):
        """Test exception handling in required mode."""
        middleware.auth_config.mode = AuthMode.REQUIRED

        # Simulate exception in _get_client
        with patch.object(middleware, "_get_client", side_effect=Exception("Auth error")):
            response = await middleware.dispatch(mock_request, mock_call_next)

        # Should return 500 error
        assert isinstance(response, JSONResponse)
        assert response.status_code == 500
        response_content = json.loads(response.body)
        assert response_content["detail"] == "Authentication error"

    @pytest.mark.asyncio
    async def test_dispatch_exception_none_mode(self, middleware, mock_request, mock_call_next):
        """Test exception handling in none mode."""
        middleware.auth_config.mode = AuthMode.NONE

        # Simulate exception after _get_client
        mock_call_next.side_effect = Exception("Endpoint error")

        with pytest.raises(Exception, match="Endpoint error"):
            await middleware.dispatch(mock_request, mock_call_next)

    @pytest.mark.asyncio
    async def test_get_client_no_client_info(self, middleware, mock_request):
        """Test _get_client when request has no client info."""
        mock_request.client = None

        client = await middleware._get_client(mock_request)

        assert client.client_id == "anon_unknown"
        assert client.client_name == "Anonymous (unknown)"
        assert client.auth_method == AuthMethod.ANONYMOUS

    @pytest.mark.asyncio
    async def test_get_client_bypass_order(self, middleware, mock_request):
        """Test bypass checking order (localhost -> network -> header -> api key)."""
        # Set up all bypass conditions
        mock_request.client.host = "127.0.0.1"
        mock_request.headers = Headers({"X-Internal": "true", "X-API-Key": "psk_test"})
        middleware.api_key_manager.check_network_bypass.return_value = True
        middleware.api_key_manager.check_header_bypass.return_value = True

        client = await middleware._get_client(mock_request)

        # Should use localhost bypass (first in order)
        assert client.client_id == "localhost"
        assert client.auth_method == AuthMethod.BYPASS

    def test_is_https_direct(self, middleware, mock_request):
        """Test HTTPS detection for direct HTTPS connection."""
        mock_request.url.scheme = "https"

        assert middleware._is_https(mock_request) is True

    def test_is_https_proxy_header(self, middleware, mock_request):
        """Test HTTPS detection via proxy header."""
        mock_request.url.scheme = "http"
        mock_request.headers = Headers({"X-Forwarded-Proto": "https"})

        assert middleware._is_https(mock_request) is True

    def test_is_https_false(self, middleware, mock_request):
        """Test HTTPS detection returns false for HTTP."""
        mock_request.url.scheme = "http"
        mock_request.headers = Headers({})

        assert middleware._is_https(mock_request) is False

    def test_is_https_invalid_proxy_header(self, middleware, mock_request):
        """Test HTTPS detection with invalid proxy header value."""
        mock_request.url.scheme = "http"
        mock_request.headers = Headers({"X-Forwarded-Proto": "http"})

        assert middleware._is_https(mock_request) is False

    @pytest.mark.asyncio
    async def test_dispatch_logging(self, middleware, mock_request, mock_call_next):
        """Test that authentication is logged for non-NONE auth methods."""
        mock_request.headers = Headers({"X-API-Key": "psk_test_key"})

        test_client = Client(
            client_id="test_client_id",
            client_name="Test Client",
            auth_method=AuthMethod.API_KEY,
            usage_tier=UsageTier.PRO,
        )
        middleware.api_key_manager.validate_api_key.return_value = test_client

        with patch("prompt_sentinel.auth.middleware.logger") as mock_logger:
            response = await middleware.dispatch(mock_request, mock_call_next)

            # Should log authentication
            mock_logger.debug.assert_called_once()
            call_args = mock_logger.debug.call_args
            assert call_args[0][0] == "Request authenticated"
            assert call_args[1]["client_id"] == "test_client_id"
            assert call_args[1]["auth_method"] == "api_key"

    @pytest.mark.asyncio
    async def test_dispatch_no_logging_for_none_auth(
        self, middleware, mock_request, mock_call_next
    ):
        """Test that no logging occurs for NONE auth method."""
        middleware.auth_config.mode = AuthMode.NONE

        with patch("prompt_sentinel.auth.middleware.logger") as mock_logger:
            response = await middleware.dispatch(mock_request, mock_call_next)

            # Should not log for NONE auth method
            mock_logger.debug.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_client_rate_limit_inheritance(self, middleware, mock_request):
        """Test that rate limits are properly set for different client types."""
        # Test bypass client - no rate limits
        mock_request.client.host = "127.0.0.1"
        client = await middleware._get_client(mock_request)
        assert client.rate_limits == {}

        # Test anonymous client - gets config rate limits
        mock_request.client.host = "192.168.1.1"
        middleware.auth_config.unauthenticated_rpm = 50
        middleware.auth_config.unauthenticated_tpm = 5000
        client = await middleware._get_client(mock_request)
        assert client.rate_limits == {"rpm": 50, "tpm": 5000}

    @pytest.mark.asyncio
    async def test_dispatch_state_attributes(self, middleware, mock_request, mock_call_next):
        """Test that all required state attributes are set."""
        test_client = Client(
            client_id="test_client_id",
            client_name="Test Client",
            auth_method=AuthMethod.API_KEY,
            usage_tier=UsageTier.PRO,
        )

        with patch.object(middleware, "_get_client", return_value=test_client):
            response = await middleware.dispatch(mock_request, mock_call_next)

        # Check all state attributes are set
        assert mock_request.state.client == test_client
        assert mock_request.state.client_id == "test_client_id"
        assert mock_request.state.auth_method == AuthMethod.API_KEY

    @pytest.mark.asyncio
    async def test_dispatch_all_auth_modes(self, middleware, mock_request, mock_call_next):
        """Test dispatch with all auth modes."""
        for mode in [AuthMode.NONE, AuthMode.OPTIONAL, AuthMode.REQUIRED]:
            middleware.auth_config.mode = mode

            response = await middleware.dispatch(mock_request, mock_call_next)

            # Should always set a client
            assert hasattr(mock_request.state, "client")
            assert mock_request.state.client is not None

    @pytest.mark.asyncio
    async def test_dispatch_all_usage_tiers(self, middleware, mock_request, mock_call_next):
        """Test that all usage tiers can be handled."""
        for tier in [
            UsageTier.FREE,
            UsageTier.BASIC,
            UsageTier.PRO,
            UsageTier.ENTERPRISE,
            UsageTier.INTERNAL,
        ]:
            test_client = Client(
                client_id=f"client_{tier.value}",
                client_name=f"Client {tier.value}",
                auth_method=AuthMethod.API_KEY,
                usage_tier=tier,
            )

            mock_request.headers = Headers({"X-API-Key": f"psk_{tier.value}"})
            middleware.api_key_manager.validate_api_key.return_value = test_client

            response = await middleware.dispatch(mock_request, mock_call_next)

            assert mock_request.state.client.usage_tier == tier
