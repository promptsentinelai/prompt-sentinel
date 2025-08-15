# Elastic License 2.0
#
# Copyright (c) 2024-present, PromptSentinel
#
# This source code is licensed under the Elastic License 2.0 found in the
# LICENSE file in the root directory of this source tree.

"""Security headers middleware following OWASP recommendations."""

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from prompt_sentinel.config.settings import settings

logger = structlog.get_logger()


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Comprehensive security headers middleware following OWASP recommendations."""

    async def dispatch(self, request: Request, call_next):
        """Add security headers to responses."""
        response = await call_next(request)

        # Content Security Policy (CSP) - OWASP recommended
        csp_policy = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "  # Minimal for API service
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' data:; "
            "connect-src 'self' wss: https:; "
            "media-src 'none'; "
            "object-src 'none'; "
            "child-src 'none'; "
            "frame-src 'none'; "
            "worker-src 'none'; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
            "base-uri 'self'; "
            "manifest-src 'self'"
        )
        response.headers["Content-Security-Policy"] = csp_policy

        # HTTP Strict Transport Security (HSTS)
        if request.url.scheme == "https" or settings.auth_enforce_https:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        # X-Frame-Options (Clickjacking protection)
        response.headers["X-Frame-Options"] = "DENY"

        # X-Content-Type-Options (MIME sniffing protection)
        response.headers["X-Content-Type-Options"] = "nosniff"

        # X-XSS-Protection (Legacy browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions Policy (Feature Policy replacement)
        permissions_policy = (
            "camera=(), "
            "microphone=(), "
            "geolocation=(), "
            "gyroscope=(), "
            "magnetometer=(), "
            "payment=(), "
            "usb=(), "
            "interest-cohort=()"  # Disable FLoC
        )
        response.headers["Permissions-Policy"] = permissions_policy

        # Cross-Origin Embedder Policy
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"

        # Cross-Origin Opener Policy
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"

        # Cross-Origin Resource Policy
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

        # Cache Control for sensitive endpoints
        if self._is_sensitive_endpoint(request.url.path):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"

        # Server header removal (information disclosure)
        response.headers.pop("server", None)

        # Add API version for debugging (non-sensitive info)
        response.headers["X-API-Version"] = "1.0"

        return response

    def _is_sensitive_endpoint(self, path: str) -> bool:
        """Check if endpoint handles sensitive data."""
        sensitive_endpoints = [
            "/api/v1/detect",
            "/api/v1/analyze",
            "/api/v1/batch",
            "/api/v1/client",
            "/api/v1/metrics",
        ]
        return any(path.startswith(endpoint) for endpoint in sensitive_endpoints)


def configure_secure_cors(app: FastAPI) -> None:
    """Configure CORS with security best practices."""

    # Production CORS settings
    allowed_origins = []

    if settings.api_env == "production":
        # In production, only allow specific domains
        # You should replace these with your actual domains
        allowed_origins = [
            "https://yourdomain.com",
            "https://api.yourdomain.com",
            "https://app.yourdomain.com",
        ]
    else:
        # Development settings
        allowed_origins = [
            "http://localhost:3000",
            "http://localhost:8080",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:8080",
            "http://localhost:5173",  # Vite default
            "http://127.0.0.1:5173",
        ]

        # Add any additional development origins from environment
        dev_origins = settings.dev_cors_origins.split(",") if settings.dev_cors_origins else []
        allowed_origins.extend([origin.strip() for origin in dev_origins if origin.strip()])

    # Never use ["*"] in production - it's a security risk
    if settings.api_env == "production" and "*" in allowed_origins:
        logger.error("Wildcard CORS origins not allowed in production")
        allowed_origins.remove("*")

    logger.info("Configuring CORS", origins=allowed_origins, env=settings.api_env)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,  # Needed for auth cookies/headers
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],  # Explicit methods only
        allow_headers=[
            "Accept",
            "Accept-Language",
            "Content-Language",
            "Content-Type",
            "Authorization",
            "X-API-Key",
            "X-Request-ID",
            "X-Client-Version",
        ],  # Explicit headers only
        expose_headers=["X-Request-ID", "X-Process-Time", "X-API-Version"],
        max_age=86400,  # 24 hours cache for preflight
    )


class ContentTypeMiddleware(BaseHTTPMiddleware):
    """Ensure proper content types for API responses."""

    async def dispatch(self, request: Request, call_next):
        """Set appropriate content types."""
        response = await call_next(request)

        # Ensure JSON API responses have correct content type
        if request.url.path.startswith("/api/"):
            if "content-type" not in response.headers:
                response.headers["Content-Type"] = "application/json; charset=utf-8"

        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Limit request sizes to prevent DoS attacks."""

    def __init__(self, app, max_size: int = 10_000_000):  # 10MB default
        """
        Initialize request size limit middleware.

        Args:
            app: FastAPI application instance
            max_size: Maximum request size in bytes (default 10MB)
        """
        super().__init__(app)
        self.max_size = max_size

    async def dispatch(self, request: Request, call_next):
        """Check request size limits."""
        content_length = request.headers.get("content-length")

        if content_length:
            try:
                size = int(content_length)
                if size > self.max_size:
                    logger.warning(
                        "Request size limit exceeded",
                        size=size,
                        limit=self.max_size,
                        path=request.url.path,
                    )
                    from fastapi import HTTPException

                    raise HTTPException(
                        status_code=413,
                        detail=f"Request too large. Maximum size: {self.max_size} bytes",
                    )
            except ValueError:
                # Invalid content-length header
                logger.warning("Invalid content-length header", value=content_length)

        return await call_next(request)


def add_security_middleware(app: FastAPI) -> None:
    """Add all security middleware to the FastAPI app."""

    # Add in reverse order (last added is applied first)

    # Request size limiting (should be early)
    app.add_middleware(RequestSizeLimitMiddleware, max_size=10_000_000)

    # Content type handling
    app.add_middleware(ContentTypeMiddleware)

    # Security headers (should be late to catch all responses)
    app.add_middleware(SecurityHeadersMiddleware)

    # CORS (configure separately)
    configure_secure_cors(app)

    logger.info("Security middleware configured")


# Additional security configuration check
def validate_security_configuration() -> list[str]:
    """Validate security configuration at startup."""
    issues = []

    # Check for debug mode in production
    if settings.api_env == "production" and settings.debug:
        issues.append("Debug mode enabled in production")

    # Check for weak authentication
    if settings.auth_mode == "none" and settings.api_env == "production":
        issues.append("Authentication disabled in production")

    # Check HTTPS enforcement
    if not settings.auth_enforce_https and settings.api_env == "production":
        issues.append("HTTPS not enforced in production")

    # Check for default API key prefix
    if (
        hasattr(settings, "api_key_prefix")
        and settings.api_key_prefix == "psk_"
        and settings.api_env == "production"
    ):
        issues.append("Default API key prefix used in production")

    # Check for missing required environment variables
    required_env_vars = ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"]
    for var in required_env_vars:
        if not getattr(settings, var.lower(), None):
            if settings.api_env == "production":
                issues.append(f"Missing required environment variable: {var}")

    if issues:
        logger.warning("Security configuration issues detected", issues=issues)
        if settings.api_env == "production":
            # In production, these should be hard errors
            logger.critical("Critical security issues in production", issues=issues)

    return issues
