"""Comprehensive tests for authentication middleware."""

import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from prompt_sentinel.auth.middleware import AuthenticationMiddleware
from prompt_sentinel.auth.models import (
    APIKey,
    APIKeyStatus,
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
    def auth_config(self):
        """Create auth configuration."""
        return AuthConfig(
            mode=AuthMode.OPTIONAL,
            enforce_https=False,
            bypass_networks=["127.0.0.1/32", "10.0.0.0/8"],
            bypass_headers={"X-Internal": "true"},
            allow_localhost=True,
            unauthenticated_rpm=10,
            unauthenticated_tpm=1000,
        )

    @pytest.fixture
    def mock_api_key_manager(self):
        """Create mock API key manager."""
        manager = MagicMock()
        manager.validate_api_key = AsyncMock(return_value=None)
        manager.check_network_bypass = MagicMock(return_value=False)
        manager.check_header_bypass = MagicMock(return_value=False)
        return manager

    @pytest.fixture
    def app(self):
        """Create FastAPI app for testing."""
        app = FastAPI()
        
        @app.get("/test")
        async def test_endpoint():
            return {"message": "success"}
        
        @app.get("/public")
        async def public_endpoint():
            return {"message": "public"}
        
        return app

    @pytest.fixture
    def middleware(self, app, auth_config, mock_api_key_manager):
        """Create middleware instance."""
        return AuthenticationMiddleware(
            app,
            auth_config=auth_config,
            api_key_manager=mock_api_key_manager
        )

    @pytest.fixture
    def mock_request(self):
        """Create mock request."""
        request = MagicMock(spec=Request)
        request.headers = {}
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        request.url = MagicMock()
        request.url.path = "/test"
        request.url.scheme = "http"
        request.method = "GET"
        request.state = MagicMock()
        return request

    @pytest.mark.asyncio
    async def test_middleware_optional_mode_no_auth(self, middleware, mock_request):
        """Test middleware in optional mode without authentication."""
        async def call_next(request):
            return Response(content="success", status_code=200)
        
        response = await middleware.dispatch(mock_request, call_next)
        
        assert response.status_code == 200
        assert hasattr(mock_request.state, "client")
        assert mock_request.state.client.is_anonymous()

    @pytest.mark.asyncio
    async def test_middleware_optional_mode_with_valid_key(
        self, middleware, mock_request, mock_api_key_manager
    ):
        """Test middleware with valid API key in optional mode."""
        mock_request.headers = {"Authorization": "Bearer psk_test123"}
        
        valid_client = Client(
            client_id="test-client",
            api_key_id="key-123",
            name="Test Client",
            authenticated=True,
            auth_method=AuthMethod.API_KEY,
            permissions=[ClientPermission.DETECT_READ],
        )
        mock_api_key_manager.validate_api_key.return_value = valid_client
        
        async def call_next(request):
            return Response(content="success", status_code=200)
        
        response = await middleware.dispatch(mock_request, call_next)
        
        assert response.status_code == 200
        assert mock_request.state.client == valid_client
        assert mock_request.state.client.is_authenticated()
        mock_api_key_manager.validate_api_key.assert_called_once_with("psk_test123")

    @pytest.mark.asyncio
    async def test_middleware_required_mode_no_auth(self, middleware, mock_request):
        """Test middleware in required mode without authentication."""
        middleware.auth_config.mode = AuthMode.REQUIRED
        
        async def call_next(request):
            return Response(content="success", status_code=200)
        
        response = await middleware.dispatch(mock_request, call_next)
        
        # Should return 401 Unauthorized
        assert response.status_code == 401
        response_body = json.loads(response.body)
        assert response_body["detail"] == "Authentication required"

    @pytest.mark.asyncio
    async def test_middleware_required_mode_with_valid_key(
        self, middleware, mock_request, mock_api_key_manager
    ):
        """Test middleware in required mode with valid authentication."""
        middleware.auth_config.mode = AuthMode.REQUIRED
        mock_request.headers = {"Authorization": "Bearer psk_valid"}
        
        valid_client = Client(
            client_id="test-client",
            api_key_id="key-123",
            authenticated=True,
            auth_method=AuthMethod.API_KEY,
        )
        mock_api_key_manager.validate_api_key.return_value = valid_client
        
        async def call_next(request):
            return Response(content="success", status_code=200)
        
        response = await middleware.dispatch(mock_request, call_next)
        
        assert response.status_code == 200
        assert mock_request.state.client.is_authenticated()

    @pytest.mark.asyncio
    async def test_middleware_invalid_api_key(self, middleware, mock_request, mock_api_key_manager):
        """Test middleware with invalid API key."""
        mock_request.headers = {"Authorization": "Bearer invalid_key"}
        mock_api_key_manager.validate_api_key.return_value = None
        
        async def call_next(request):
            return Response(content="success", status_code=200)
        
        response = await middleware.dispatch(mock_request, call_next)
        
        # In optional mode, should still work but as anonymous
        assert response.status_code == 200
        assert mock_request.state.client.is_anonymous()

    @pytest.mark.asyncio
    async def test_middleware_localhost_bypass(self, middleware, mock_request):
        """Test localhost bypass in required mode."""
        middleware.auth_config.mode = AuthMode.REQUIRED
        middleware.auth_config.allow_localhost = True
        mock_request.client.host = "127.0.0.1"
        
        async def call_next(request):
            return Response(content="success", status_code=200)
        
        response = await middleware.dispatch(mock_request, call_next)
        
        assert response.status_code == 200
        assert mock_request.state.client.auth_method == AuthMethod.LOCALHOST

    @pytest.mark.asyncio
    async def test_middleware_network_bypass(self, middleware, mock_request, mock_api_key_manager):
        """Test network-based bypass."""
        middleware.auth_config.mode = AuthMode.REQUIRED
        mock_request.client.host = "10.0.0.5"
        mock_api_key_manager.check_network_bypass.return_value = True
        
        async def call_next(request):
            return Response(content="success", status_code=200)
        
        response = await middleware.dispatch(mock_request, call_next)
        
        assert response.status_code == 200
        assert mock_request.state.client.auth_method == AuthMethod.NETWORK_BYPASS
        mock_api_key_manager.check_network_bypass.assert_called_once_with("10.0.0.5")

    @pytest.mark.asyncio
    async def test_middleware_header_bypass(self, middleware, mock_request, mock_api_key_manager):
        """Test header-based bypass."""
        middleware.auth_config.mode = AuthMode.REQUIRED
        mock_request.headers = {"X-Internal": "true"}
        mock_api_key_manager.check_header_bypass.return_value = True
        
        async def call_next(request):
            return Response(content="success", status_code=200)
        
        response = await middleware.dispatch(mock_request, call_next)
        
        assert response.status_code == 200
        assert mock_request.state.client.auth_method == AuthMethod.HEADER_BYPASS

    @pytest.mark.asyncio
    async def test_middleware_https_enforcement(self, middleware, mock_request):
        """Test HTTPS enforcement."""
        middleware.auth_config.enforce_https = True
        middleware.auth_config.mode = AuthMode.REQUIRED
        mock_request.url.scheme = "http"
        mock_request.client.host = "192.168.1.1"  # Not localhost
        
        async def call_next(request):
            return Response(content="success", status_code=200)
        
        response = await middleware.dispatch(mock_request, call_next)
        
        assert response.status_code == 403
        response_body = json.loads(response.body)
        assert "HTTPS required" in response_body["detail"]

    @pytest.mark.asyncio
    async def test_middleware_public_endpoints(self, middleware, mock_request):
        """Test that certain endpoints can be marked as public."""
        middleware.auth_config.mode = AuthMode.REQUIRED
        mock_request.url.path = "/health"  # Common public endpoint
        
        async def call_next(request):
            return Response(content="healthy", status_code=200)
        
        response = await middleware.dispatch(mock_request, call_next)
        
        # Health endpoint should work without auth
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_middleware_x_api_key_header(self, middleware, mock_request, mock_api_key_manager):
        """Test API key in X-API-Key header."""
        mock_request.headers = {"X-API-Key": "psk_test456"}
        
        valid_client = Client(
            client_id="test-client",
            authenticated=True,
            auth_method=AuthMethod.API_KEY,
        )
        mock_api_key_manager.validate_api_key.return_value = valid_client
        
        async def call_next(request):
            return Response(content="success", status_code=200)
        
        response = await middleware.dispatch(mock_request, call_next)
        
        assert response.status_code == 200
        mock_api_key_manager.validate_api_key.assert_called_once_with("psk_test456")

    @pytest.mark.asyncio
    async def test_middleware_query_param_api_key(self, middleware, mock_request, mock_api_key_manager):
        """Test API key in query parameter."""
        mock_request.url.query = "api_key=psk_test789"
        mock_request.query_params = {"api_key": "psk_test789"}
        
        valid_client = Client(
            client_id="test-client",
            authenticated=True,
            auth_method=AuthMethod.API_KEY,
        )
        mock_api_key_manager.validate_api_key.return_value = valid_client
        
        async def call_next(request):
            return Response(content="success", status_code=200)
        
        response = await middleware.dispatch(mock_request, call_next)
        
        assert response.status_code == 200
        mock_api_key_manager.validate_api_key.assert_called_once_with("psk_test789")

    @pytest.mark.asyncio
    async def test_middleware_malformed_authorization_header(self, middleware, mock_request):
        """Test malformed authorization header."""
        mock_request.headers = {"Authorization": "InvalidFormat"}
        
        async def call_next(request):
            return Response(content="success", status_code=200)
        
        response = await middleware.dispatch(mock_request, call_next)
        
        # Should treat as anonymous in optional mode
        assert response.status_code == 200
        assert mock_request.state.client.is_anonymous()

    @pytest.mark.asyncio
    async def test_middleware_rate_limiting_headers(self, middleware, mock_request):
        """Test that rate limiting headers are added."""
        async def call_next(request):
            response = Response(content="success", status_code=200)
            return response
        
        response = await middleware.dispatch(mock_request, call_next)
        
        # Check for rate limit headers
        assert "X-RateLimit-Limit" in response.headers
        assert "X-RateLimit-Remaining" in response.headers
        assert "X-RateLimit-Reset" in response.headers

    @pytest.mark.asyncio
    async def test_middleware_disabled_mode(self, middleware, mock_request):
        """Test middleware in disabled mode."""
        middleware.auth_config.mode = AuthMode.DISABLED
        
        async def call_next(request):
            return Response(content="success", status_code=200)
        
        response = await middleware.dispatch(mock_request, call_next)
        
        assert response.status_code == 200
        # Should have anonymous client
        assert mock_request.state.client.is_anonymous()
        # Should not attempt to validate any keys
        middleware.api_key_manager.validate_api_key.assert_not_called()

    @pytest.mark.asyncio
    async def test_middleware_exception_handling(self, middleware, mock_request):
        """Test middleware handles exceptions gracefully."""
        async def call_next(request):
            raise Exception("Internal error")
        
        response = await middleware.dispatch(mock_request, call_next)
        
        # Should return 500 error
        assert response.status_code == 500

    @pytest.mark.asyncio
    async def test_middleware_forwarded_headers(self, middleware, mock_request):
        """Test handling of forwarded headers for proxy scenarios."""
        mock_request.headers = {
            "X-Forwarded-For": "203.0.113.1",
            "X-Forwarded-Proto": "https",
        }
        mock_request.url.scheme = "http"  # Behind proxy
        
        middleware.auth_config.enforce_https = True
        
        async def call_next(request):
            return Response(content="success", status_code=200)
        
        response = await middleware.dispatch(mock_request, call_next)
        
        # Should accept HTTPS from forwarded header
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_middleware_client_state_propagation(self, middleware, mock_request):
        """Test that client state is properly propagated to request."""
        mock_request.headers = {"Authorization": "Bearer psk_test"}
        
        test_client = Client(
            client_id="test-123",
            name="Test Client",
            authenticated=True,
            auth_method=AuthMethod.API_KEY,
            usage_tier=UsageTier.PRO,
            permissions=[ClientPermission.DETECT_READ, ClientPermission.DETECT_WRITE],
        )
        middleware.api_key_manager.validate_api_key.return_value = test_client
        
        async def call_next(request):
            # Verify client is available in request
            assert hasattr(request.state, "client")
            assert request.state.client.client_id == "test-123"
            assert request.state.client.usage_tier == UsageTier.PRO
            return Response(content="success", status_code=200)
        
        response = await middleware.dispatch(mock_request, call_next)
        assert response.status_code == 200


class TestAuthenticationMiddlewareIntegration:
    """Integration tests for authentication middleware."""

    @pytest.mark.asyncio
    async def test_full_auth_flow_with_real_manager(self):
        """Test complete authentication flow with real API key manager."""
        from prompt_sentinel.auth.api_key_manager import APIKeyManager
        
        config = AuthConfig(
            mode=AuthMode.REQUIRED,
            api_key_prefix="psk_",
            api_key_length=32,
        )
        
        manager = APIKeyManager(config)
        
        # Create an API key
        from prompt_sentinel.auth.models import CreateAPIKeyRequest
        
        create_request = CreateAPIKeyRequest(
            name="Test Key",
            description="Test key for integration test",
            permissions=[ClientPermission.DETECT_READ],
        )
        
        key_response = await manager.create_api_key(create_request)
        api_key = key_response.api_key
        
        # Create middleware with real manager
        app = FastAPI()
        middleware = AuthenticationMiddleware(app, config, manager)
        
        # Create request with API key
        request = MagicMock(spec=Request)
        request.headers = {"Authorization": f"Bearer {api_key}"}
        request.client = MagicMock()
        request.client.host = "192.168.1.1"
        request.url = MagicMock()
        request.url.path = "/test"
        request.url.scheme = "https"
        request.state = MagicMock()
        
        async def call_next(req):
            return Response(content="success", status_code=200)
        
        response = await middleware.dispatch(request, call_next)
        
        assert response.status_code == 200
        assert request.state.client.is_authenticated()
        assert request.state.client.api_key_id == key_response.key_id

    @pytest.mark.asyncio
    async def test_rate_limiting_enforcement(self):
        """Test that rate limiting is enforced for unauthenticated clients."""
        config = AuthConfig(
            mode=AuthMode.OPTIONAL,
            unauthenticated_rpm=2,  # Very low limit for testing
        )
        
        app = FastAPI()
        middleware = AuthenticationMiddleware(app, config, None)
        
        # Make multiple requests as anonymous user
        request = MagicMock(spec=Request)
        request.headers = {}
        request.client = MagicMock()
        request.client.host = "192.168.1.1"
        request.url = MagicMock()
        request.url.path = "/test"
        request.state = MagicMock()
        
        async def call_next(req):
            return Response(content="success", status_code=200)
        
        # First two requests should succeed
        for _ in range(2):
            response = await middleware.dispatch(request, call_next)
            assert response.status_code == 200
        
        # Third request should be rate limited
        response = await middleware.dispatch(request, call_next)
        assert response.status_code == 429  # Too Many Requests

    @pytest.mark.asyncio
    async def test_different_auth_modes(self):
        """Test behavior across different auth modes."""
        modes = [AuthMode.DISABLED, AuthMode.OPTIONAL, AuthMode.REQUIRED]
        
        for mode in modes:
            config = AuthConfig(mode=mode)
            app = FastAPI()
            middleware = AuthenticationMiddleware(app, config, None)
            
            request = MagicMock(spec=Request)
            request.headers = {}
            request.client = MagicMock()
            request.client.host = "192.168.1.1"
            request.url = MagicMock()
            request.url.path = "/test"
            request.url.scheme = "http"
            request.state = MagicMock()
            
            async def call_next(req):
                return Response(content="success", status_code=200)
            
            response = await middleware.dispatch(request, call_next)
            
            if mode == AuthMode.REQUIRED:
                assert response.status_code == 401
            else:
                assert response.status_code == 200


if __name__ == "__main__":
    pytest.main([__file__, "-v"])