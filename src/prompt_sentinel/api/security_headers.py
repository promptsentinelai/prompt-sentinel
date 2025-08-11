# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Security headers middleware for FastAPI.

This module provides comprehensive security headers to protect against common
web vulnerabilities including XSS, clickjacking, MIME sniffing, and more.
"""

from collections.abc import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from prompt_sentinel.config.settings import Settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware to add security headers to all responses."""

    def __init__(
        self,
        app: ASGIApp,
        settings: Settings | None = None,
        enable_hsts: bool = True,
        enable_csp: bool = True,
        report_uri: str | None = None,
    ):
        """Initialize security headers middleware.

        Args:
            app: The ASGI application
            settings: Application settings
            enable_hsts: Enable HTTP Strict Transport Security
            enable_csp: Enable Content Security Policy
            report_uri: URI for CSP violation reports
        """
        super().__init__(app)
        self.settings = settings or Settings()
        self.enable_hsts = enable_hsts
        self.enable_csp = enable_csp
        self.report_uri = report_uri

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Add security headers to the response.

        Args:
            request: The incoming request
            call_next: The next middleware or route handler

        Returns:
            Response with security headers added
        """
        # Process the request
        response = await call_next(request)

        # Add security headers

        # X-Content-Type-Options: Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # X-Frame-Options: Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # X-XSS-Protection: Enable XSS filtering (for older browsers)
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Referrer-Policy: Control referrer information
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions-Policy: Control browser features
        response.headers["Permissions-Policy"] = (
            "geolocation=(), "
            "microphone=(), "
            "camera=(), "
            "payment=(), "
            "usb=(), "
            "magnetometer=(), "
            "accelerometer=(), "
            "gyroscope=()"
        )

        # HTTP Strict Transport Security (HSTS)
        if self.enable_hsts and request.url.scheme == "https":
            # max-age=31536000 (1 year), includeSubDomains
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        # Content-Security-Policy
        if self.enable_csp:
            csp_directives = [
                "default-src 'self'",
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net",  # For Swagger UI
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",  # For Swagger UI
                "img-src 'self' data: https:",
                "font-src 'self' data: https://cdn.jsdelivr.net",
                "connect-src 'self'",
                "frame-ancestors 'none'",
                "base-uri 'self'",
                "form-action 'self'",
            ]

            # Add report URI if configured
            if self.report_uri:
                csp_directives.append(f"report-uri {self.report_uri}")

            response.headers["Content-Security-Policy"] = "; ".join(csp_directives)

        # X-Permitted-Cross-Domain-Policies: Control Flash/PDF cross-domain access
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"

        # Cache-Control for sensitive endpoints
        if request.url.path.startswith("/api/") and request.method == "GET":
            # API responses should not be cached by default
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"

        # Remove unnecessary headers that might leak information
        if "X-Powered-By" in response.headers:
            del response.headers["X-Powered-By"]
        if "Server" in response.headers:
            del response.headers["Server"]

        return response


def get_security_headers(
    settings: Settings | None = None,
    enable_hsts: bool = True,
    enable_csp: bool = True,
) -> dict[str, str]:
    """Get a dictionary of security headers.

    This is useful for testing or manual header application.

    Args:
        settings: Application settings
        enable_hsts: Enable HTTP Strict Transport Security
        enable_csp: Enable Content Security Policy

    Returns:
        Dictionary of security headers
    """
    headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "X-Permitted-Cross-Domain-Policies": "none",
        "Permissions-Policy": (
            "geolocation=(), microphone=(), camera=(), payment=(), "
            "usb=(), magnetometer=(), accelerometer=(), gyroscope=()"
        ),
    }

    if enable_hsts:
        headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"

    if enable_csp:
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https:; "
            "font-src 'self' data: https://cdn.jsdelivr.net; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        headers["Content-Security-Policy"] = csp

    return headers
