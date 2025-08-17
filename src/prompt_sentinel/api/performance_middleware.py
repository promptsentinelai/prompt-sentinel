# Elastic License 2.0
#
# Copyright (c) 2024-present, PromptSentinel
#
# This source code is licensed under the Elastic License 2.0 found in the
# LICENSE file in the root directory of this source tree.

"""Performance optimization middleware for FastAPI.

Status: Experimental/Stub. Not wired into the main app by default. Keep for
future optimization work; production deployments should benchmark carefully
before enabling. Some features are placeholders and may change.
"""

import time
from collections.abc import Callable
from typing import Any

import orjson
import structlog
from fastapi import Request, Response
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import ORJSONResponse

logger = structlog.get_logger()


class OptimizedGZipMiddleware(GZipMiddleware):
    """Enhanced GZip middleware with better compression settings."""

    def __init__(self, app, minimum_size: int = 500, compresslevel: int = 6):
        """
        Initialize optimized GZip middleware.

        Args:
            app: FastAPI app instance
            minimum_size: Minimum response size to compress (bytes)
            compresslevel: Compression level (1-9, higher = better compression but slower)
        """
        super().__init__(app, minimum_size=minimum_size)
        self.compresslevel = compresslevel


class PerformanceMiddleware:
    """Middleware for performance monitoring and optimization."""

    def __init__(self, app):
        """Initialize performance middleware."""
        self.app = app

    async def __call__(self, request: Request, call_next: Callable) -> Response:
        """Process request with performance tracking."""
        start_time = time.perf_counter()

        # Add request ID for tracing
        request_id = request.headers.get("X-Request-ID", str(time.time()))
        request.state.request_id = request_id

        # Process request
        response = await call_next(request)

        # Add performance headers
        process_time = time.perf_counter() - start_time
        response.headers["X-Process-Time"] = f"{process_time:.3f}"
        response.headers["X-Request-ID"] = request_id

        # Log slow requests
        if process_time > 1.0:
            logger.warning(
                "Slow request detected",
                request_id=request_id,
                path=request.url.path,
                method=request.method,
                duration=process_time,
            )

        return response


class CacheControlMiddleware:
    """Middleware to add cache control headers."""

    def __init__(self, app):
        """Initialize cache control middleware."""
        self.app = app

    async def __call__(self, request: Request, call_next: Callable) -> Response:
        """Add cache control headers to responses."""
        response = await call_next(request)

        # Add cache headers for GET requests
        if request.method == "GET":
            if "/health" in request.url.path or "/metrics" in request.url.path:
                # Don't cache health/metrics
                response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            elif "/docs" in request.url.path or "/openapi" in request.url.path:
                # Cache documentation
                response.headers["Cache-Control"] = "public, max-age=3600"
            else:
                # Short cache for API responses
                response.headers["Cache-Control"] = "private, max-age=60"

        return response


def setup_performance_middleware(app):
    """
    Setup all performance middleware in optimal order.

    Args:
        app: FastAPI app instance
    """
    # Order matters! Add in reverse order of desired execution

    # 1. GZip compression (last to execute, compresses final response)
    app.add_middleware(OptimizedGZipMiddleware, minimum_size=500, compresslevel=6)

    # 2. Cache control headers
    app.add_middleware(CacheControlMiddleware)

    # 3. Performance monitoring (first to execute, tracks total time)
    app.add_middleware(PerformanceMiddleware)

    logger.info("Performance middleware configured")


class OptimizedJSONResponse(ORJSONResponse):
    """Optimized JSON response using orjson with custom options."""

    def render(self, content: Any) -> bytes:
        """
        Render content to JSON bytes with optimizations.

        Args:
            content: Content to serialize

        Returns:
            JSON bytes
        """
        return orjson.dumps(
            content,
            option=orjson.OPT_SERIALIZE_NUMPY | orjson.OPT_NAIVE_UTC | orjson.OPT_OMIT_MICROSECONDS,
        )
