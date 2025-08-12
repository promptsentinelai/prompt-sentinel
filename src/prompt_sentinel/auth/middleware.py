# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Authentication middleware for FastAPI.

This module provides middleware that handles authentication for all requests,
storing client information in request state for use by other components.
"""

from collections.abc import Callable

import structlog
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from .dependencies import get_api_key_manager, get_auth_config
from .models import AuthMethod, AuthMode, Client, UsageTier

logger = structlog.get_logger()


class AuthenticationMiddleware(BaseHTTPMiddleware):
    """Middleware for handling authentication across all requests.

    This middleware:
    - Validates API keys when provided
    - Applies bypass rules for trusted sources
    - Stores client information in request state
    - Integrates with rate limiting and monitoring
    """

    def __init__(self, app, auth_config=None, api_key_manager=None):
        """Initialize authentication middleware.

        Args:
            app: FastAPI application
            auth_config: Optional auth configuration (will create if not provided)
            api_key_manager: Optional API key manager (will create if not provided)
        """
        super().__init__(app)
        self.auth_config = auth_config or get_auth_config()
        self.api_key_manager = api_key_manager or get_api_key_manager(self.auth_config)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with authentication.

        Args:
            request: Incoming request
            call_next: Next middleware or endpoint

        Returns:
            Response from the endpoint or error response
        """
        # Skip auth for health checks and docs
        if request.url.path in ["/health", "/api/v1/health", "/docs", "/redoc", "/openapi.json"]:
            request.state.client = Client(
                client_id="system",
                client_name="System",
                auth_method=AuthMethod.NONE,
                usage_tier=UsageTier.INTERNAL,
            )
            return await call_next(request)

        # Skip auth for admin endpoints if using admin token
        # (This is a special case for initial setup)
        if request.url.path.startswith("/admin/") and self.auth_config.mode == AuthMode.NONE:
            request.state.client = Client(
                client_id="admin",
                client_name="Admin",
                auth_method=AuthMethod.NONE,
                usage_tier=UsageTier.INTERNAL,
            )
            return await call_next(request)

        client = None  # Initialize client variable
        try:
            # Determine client based on auth mode and request
            client = await self._get_client(request)

            # Store client in request state
            request.state.client = client
            request.state.client_id = client.client_id
            request.state.auth_method = client.auth_method

            # Log authentication
            if client.auth_method != AuthMethod.NONE:
                logger.debug(
                    "Request authenticated",
                    path=request.url.path,
                    client_id=client.client_id,
                    auth_method=client.auth_method.value,
                    usage_tier=client.usage_tier.value,
                )

            # Check HTTPS enforcement
            if self.auth_config.enforce_https and not self._is_https(request):
                if client.auth_method != AuthMethod.BYPASS:
                    return JSONResponse(status_code=403, content={"detail": "HTTPS required"})

            # Process request
            response = await call_next(request)

            # Add client ID to response headers for tracking
            # Check if client exists and has the expected attributes
            if client and hasattr(client, "client_id") and client.client_id != "system":
                response.headers["X-Client-ID"] = client.client_id

            return response

        except Exception as e:
            logger.error("Authentication middleware error", error=str(e), path=request.url.path)
            # Don't fail the request on middleware errors in optional mode
            if self.auth_config.mode != AuthMode.REQUIRED:
                request.state.client = Client(
                    client_id="error",
                    client_name="Error",
                    auth_method=AuthMethod.ANONYMOUS,
                    usage_tier=UsageTier.FREE,
                )
                return await call_next(request)
            else:
                return JSONResponse(status_code=500, content={"detail": "Authentication error"})

    async def _get_client(self, request: Request) -> Client:
        """Get client from request based on auth configuration.

        Args:
            request: Incoming request

        Returns:
            Client object with authentication details
        """
        # Mode: No authentication needed
        if self.auth_config.mode == AuthMode.NONE:
            return Client(
                client_id="local",
                client_name="Local Client",
                auth_method=AuthMethod.NONE,
                usage_tier=UsageTier.INTERNAL,
                rate_limits={},
            )

        # Check bypass conditions
        client_host = request.client.host if request.client else "unknown"

        # Localhost bypass
        if self.auth_config.allow_localhost and client_host in ["127.0.0.1", "::1", "localhost"]:
            return Client(
                client_id="localhost",
                client_name="Localhost",
                auth_method=AuthMethod.BYPASS,
                usage_tier=UsageTier.INTERNAL,
                rate_limits={},
            )

        # Network bypass
        if self.api_key_manager.check_network_bypass(client_host):
            return Client(
                client_id=f"network_{client_host}",
                client_name=f"Internal Network ({client_host})",
                auth_method=AuthMethod.BYPASS,
                usage_tier=UsageTier.INTERNAL,
                rate_limits={},
            )

        # Header bypass
        headers = dict(request.headers)
        if self.api_key_manager.check_header_bypass(headers):
            return Client(
                client_id="header_bypass",
                client_name="Header Bypass",
                auth_method=AuthMethod.BYPASS,
                usage_tier=UsageTier.INTERNAL,
                rate_limits={},
            )

        # Check API key
        api_key = request.headers.get("X-API-Key")
        if api_key:
            client = await self.api_key_manager.validate_api_key(api_key)
            if client:
                return client
            elif self.auth_config.mode == AuthMode.REQUIRED:
                # In required mode, invalid key = error
                # But we'll let the dependency handle the error response
                pass

        # Handle unauthenticated
        if self.auth_config.mode == AuthMode.REQUIRED and not api_key:
            # In required mode, no key = error
            # But we'll let the dependency handle the error response
            pass

        # Default to anonymous
        return Client(
            client_id=f"anon_{client_host}",
            client_name=f"Anonymous ({client_host})",
            auth_method=AuthMethod.ANONYMOUS,
            usage_tier=UsageTier.FREE,
            rate_limits={
                "rpm": self.auth_config.unauthenticated_rpm,
                "tpm": self.auth_config.unauthenticated_tpm,
            },
        )

    def _is_https(self, request: Request) -> bool:
        """Check if request is using HTTPS.

        Args:
            request: Incoming request

        Returns:
            True if HTTPS is being used
        """
        # Check scheme
        if request.url.scheme == "https":
            return True

        # Check forwarded headers (for proxies)
        forwarded_proto = request.headers.get("X-Forwarded-Proto")
        if forwarded_proto == "https":
            return True

        return False
