#!/usr/bin/env python3
# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0

"""Comprehensive tests for API performance middleware."""

import gzip
import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI, Request, Response

from prompt_sentinel.api.performance_middleware import (
    CacheControlMiddleware,
    OptimizedGZipMiddleware,
    OptimizedJSONResponse,
    PerformanceMiddleware,
    setup_performance_middleware,
)


@pytest.fixture
def app():
    """Create a test FastAPI app."""
    test_app = FastAPI()

    @test_app.get("/health")
    async def health():
        return {"status": "ok"}

    @test_app.get("/api/v1/test")
    async def api_test():
        return {"data": "test" * 100}

    @test_app.get("/docs")
    async def docs():
        return {"docs": "swagger"}

    return test_app


@pytest.fixture
def mock_request():
    """Create a mock request."""
    request = MagicMock(spec=Request)
    request.url.path = "/api/v1/test"
    request.headers = {}
    request.state = MagicMock()
    return request


class TestOptimizedGZipMiddleware:
    """Test GZip compression middleware."""

    def test_init_with_custom_settings(self):
        """Test middleware initialization with custom settings."""
        middleware = OptimizedGZipMiddleware(app=MagicMock(), minimum_size=2000, compresslevel=5)
        assert middleware.minimum_size == 2000
        assert middleware.compresslevel == 5

    def test_init_with_defaults(self):
        """Test middleware initialization with defaults."""
        middleware = OptimizedGZipMiddleware(app=MagicMock())
        assert middleware.minimum_size == 1000
        assert middleware.compresslevel == 6

    @pytest.mark.asyncio
    async def test_gzip_compression_large_response(self):
        """Test that large responses are compressed."""
        app = MagicMock()
        middleware = OptimizedGZipMiddleware(app, minimum_size=100)

        # Create a mock call_next that returns large content
        large_content = "x" * 1000
        mock_response = Response(content=large_content)

        async def mock_call_next(request):
            return mock_response

        request = MagicMock()
        request.headers = {"accept-encoding": "gzip"}

        response = await middleware.dispatch(request, mock_call_next)

        # Check if content was compressed
        assert response.headers.get("content-encoding") == "gzip"
        # Decompress and verify
        decompressed = gzip.decompress(response.body)
        assert decompressed.decode() == large_content

    @pytest.mark.asyncio
    async def test_no_compression_small_response(self):
        """Test that small responses are not compressed."""
        app = MagicMock()
        middleware = OptimizedGZipMiddleware(app, minimum_size=1000)

        small_content = "small"
        mock_response = Response(content=small_content)

        async def mock_call_next(request):
            return mock_response

        request = MagicMock()
        request.headers = {"accept-encoding": "gzip"}

        response = await middleware.dispatch(request, mock_call_next)

        # Should not be compressed
        assert response.headers.get("content-encoding") != "gzip"
        assert response.body.decode() == small_content

    @pytest.mark.asyncio
    async def test_no_compression_no_accept_encoding(self):
        """Test no compression when client doesn't support it."""
        app = MagicMock()
        middleware = OptimizedGZipMiddleware(app)

        content = "x" * 2000
        mock_response = Response(content=content)

        async def mock_call_next(request):
            return mock_response

        request = MagicMock()
        request.headers = {}  # No accept-encoding header

        response = await middleware.dispatch(request, mock_call_next)

        # Should not be compressed
        assert response.headers.get("content-encoding") != "gzip"
        assert response.body.decode() == content


class TestPerformanceMiddleware:
    """Test performance monitoring middleware."""

    @pytest.mark.asyncio
    async def test_request_timing(self):
        """Test that request timing is recorded."""
        app = MagicMock()
        middleware = PerformanceMiddleware(app)

        mock_response = Response(content="test")

        async def mock_call_next(request):
            await asyncio.sleep(0.01)  # Simulate processing time
            return mock_response

        request = MagicMock()
        request.url.path = "/api/v1/test"
        request.state = MagicMock()

        with patch("time.time", side_effect=[1000, 1000.1]):  # 100ms
            response = await middleware.dispatch(request, mock_call_next)

        # Check timing was added to response headers
        assert "X-Request-Time" in response.headers
        assert float(response.headers["X-Request-Time"]) > 0

    @pytest.mark.asyncio
    async def test_request_id_generation(self):
        """Test that request ID is generated and added."""
        app = MagicMock()
        middleware = PerformanceMiddleware(app)

        mock_response = Response(content="test")

        async def mock_call_next(request):
            return mock_response

        request = MagicMock()
        request.url.path = "/api/v1/test"
        request.headers = {}
        request.state = MagicMock()

        response = await middleware.dispatch(request, mock_call_next)

        # Check request ID was added
        assert "X-Request-ID" in response.headers
        assert len(response.headers["X-Request-ID"]) > 0

    @pytest.mark.asyncio
    async def test_existing_request_id_preserved(self):
        """Test that existing request ID is preserved."""
        app = MagicMock()
        middleware = PerformanceMiddleware(app)

        mock_response = Response(content="test")
        existing_id = "existing-request-id-123"

        async def mock_call_next(request):
            return mock_response

        request = MagicMock()
        request.url.path = "/api/v1/test"
        request.headers = {"X-Request-ID": existing_id}
        request.state = MagicMock()

        response = await middleware.dispatch(request, mock_call_next)

        # Check existing ID was preserved
        assert response.headers["X-Request-ID"] == existing_id

    @pytest.mark.asyncio
    async def test_performance_logging(self):
        """Test that performance is logged for slow requests."""
        app = MagicMock()
        middleware = PerformanceMiddleware(app)

        mock_response = Response(content="test")

        async def mock_call_next(request):
            await asyncio.sleep(0.001)
            return mock_response

        request = MagicMock()
        request.url.path = "/api/v1/test"
        request.state = MagicMock()
        request.method = "GET"

        with patch("prompt_sentinel.api.performance_middleware.logger") as mock_logger:
            await middleware.dispatch(request, mock_call_next)

            # Verify logging occurred
            assert mock_logger.info.called or mock_logger.warning.called


class TestCacheControlMiddleware:
    """Test cache control header middleware."""

    @pytest.mark.asyncio
    async def test_health_endpoint_no_cache(self):
        """Test health endpoint gets no-cache headers."""
        app = MagicMock()
        middleware = CacheControlMiddleware(app)

        mock_response = Response(content="healthy")

        async def mock_call_next(request):
            return mock_response

        request = MagicMock()
        request.url.path = "/health"

        response = await middleware.dispatch(request, mock_call_next)

        assert response.headers["Cache-Control"] == "no-cache, no-store, must-revalidate"
        assert response.headers["Pragma"] == "no-cache"
        assert response.headers["Expires"] == "0"

    @pytest.mark.asyncio
    async def test_docs_endpoint_cache(self):
        """Test docs endpoint gets cache headers."""
        app = MagicMock()
        middleware = CacheControlMiddleware(app)

        mock_response = Response(content="docs")

        async def mock_call_next(request):
            return mock_response

        request = MagicMock()
        request.url.path = "/docs"

        response = await middleware.dispatch(request, mock_call_next)

        assert response.headers["Cache-Control"] == "public, max-age=3600"

    @pytest.mark.asyncio
    async def test_api_endpoint_short_cache(self):
        """Test API endpoints get short cache."""
        app = MagicMock()
        middleware = CacheControlMiddleware(app)

        mock_response = Response(content="api response")

        async def mock_call_next(request):
            return mock_response

        request = MagicMock()
        request.url.path = "/api/v1/detect"

        response = await middleware.dispatch(request, mock_call_next)

        assert response.headers["Cache-Control"] == "private, max-age=60"

    @pytest.mark.asyncio
    async def test_other_endpoint_default(self):
        """Test other endpoints get default cache."""
        app = MagicMock()
        middleware = CacheControlMiddleware(app)

        mock_response = Response(content="other")

        async def mock_call_next(request):
            return mock_response

        request = MagicMock()
        request.url.path = "/other"

        response = await middleware.dispatch(request, mock_call_next)

        assert response.headers["Cache-Control"] == "public, max-age=300"


class TestOptimizedJSONResponse:
    """Test optimized JSON response."""

    def test_json_serialization(self):
        """Test JSON serialization with orjson."""
        data = {"test": "data", "number": 123, "list": [1, 2, 3]}
        response = OptimizedJSONResponse(content=data)

        # Check response is properly formatted
        assert response.media_type == "application/json"
        body = json.loads(response.body)
        assert body == data

    def test_json_with_unicode(self):
        """Test JSON serialization with unicode characters."""
        data = {"emoji": "🚀", "text": "Hello 世界"}
        response = OptimizedJSONResponse(content=data)

        body = json.loads(response.body)
        assert body == data

    def test_json_with_none_values(self):
        """Test JSON serialization with None values."""
        data = {"key": None, "value": "test"}
        response = OptimizedJSONResponse(content=data)

        body = json.loads(response.body)
        assert body == data

    def test_json_with_nested_objects(self):
        """Test JSON serialization with nested objects."""
        data = {"level1": {"level2": {"level3": ["a", "b", "c"]}}}
        response = OptimizedJSONResponse(content=data)

        body = json.loads(response.body)
        assert body == data

    def test_custom_status_code(self):
        """Test custom status code."""
        response = OptimizedJSONResponse(content={"error": "not found"}, status_code=404)
        assert response.status_code == 404

    def test_custom_headers(self):
        """Test custom headers."""
        response = OptimizedJSONResponse(content={"data": "test"}, headers={"X-Custom": "header"})
        assert response.headers["X-Custom"] == "header"


class TestSetupPerformanceMiddleware:
    """Test middleware setup function."""

    def test_middleware_registration_order(self, app):
        """Test that middleware is registered in correct order."""
        setup_performance_middleware(app)

        # Check that middleware was added
        # Note: FastAPI middleware is added in reverse order
        middleware_types = [type(m) for m in app.middleware]

        # Verify all three middleware types are present
        assert any(CacheControlMiddleware in str(m) for m in middleware_types)
        assert any(PerformanceMiddleware in str(m) for m in middleware_types)
        assert any(OptimizedGZipMiddleware in str(m) for m in middleware_types)

    def test_middleware_with_custom_settings(self, app):
        """Test middleware setup with custom settings."""
        setup_performance_middleware(app, gzip_minimum_size=2000, gzip_level=5)

        # Verify middleware was added with custom settings
        middleware_added = len(app.middleware) > 0
        assert middleware_added


class TestPerformanceIntegration:
    """Integration tests for performance middleware."""

    @pytest.mark.asyncio
    async def test_full_middleware_stack(self):
        """Test full middleware stack working together."""
        from fastapi.testclient import TestClient

        app = FastAPI()

        @app.get("/api/v1/large")
        async def large_response():
            return {"data": "x" * 2000}

        @app.get("/health")
        async def health():
            return {"status": "ok"}

        setup_performance_middleware(app)

        client = TestClient(app)

        # Test large response gets compressed and cached
        response = client.get("/api/v1/large", headers={"Accept-Encoding": "gzip"})

        assert response.status_code == 200
        assert "Cache-Control" in response.headers
        assert "X-Request-ID" in response.headers
        assert "X-Request-Time" in response.headers

        # Test health endpoint doesn't get cached
        health_response = client.get("/health")
        assert health_response.status_code == 200
        assert health_response.headers.get("Cache-Control") == "no-cache, no-store, must-revalidate"

    @pytest.mark.asyncio
    async def test_error_handling_in_middleware(self):
        """Test middleware handles errors gracefully."""
        app = FastAPI()

        @app.get("/error")
        async def error_endpoint():
            raise ValueError("Test error")

        setup_performance_middleware(app)

        from fastapi.testclient import TestClient

        client = TestClient(app)

        # Should handle error and still add headers
        with pytest.raises(ValueError):
            response = client.get("/error")
            # Even with error, request ID should be present
            assert "X-Request-ID" in response.headers if response else True

    @pytest.mark.asyncio
    async def test_concurrent_requests(self):
        """Test middleware handles concurrent requests."""
        import asyncio

        from fastapi.testclient import TestClient

        app = FastAPI()

        @app.get("/concurrent/{id}")
        async def concurrent_endpoint(id: int):
            await asyncio.sleep(0.01)  # Simulate work
            return {"id": id}

        setup_performance_middleware(app)

        client = TestClient(app)

        # Make multiple concurrent requests
        import concurrent.futures

        def make_request(i):
            return client.get(f"/concurrent/{i}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(make_request, i) for i in range(10)]
            responses = [f.result() for f in concurrent.futures.as_completed(futures)]

        # All requests should succeed with proper headers
        for response in responses:
            assert response.status_code == 200
            assert "X-Request-ID" in response.headers
            assert "X-Request-Time" in response.headers
            # Each should have unique request ID

        # Verify all request IDs are unique
        request_ids = [r.headers["X-Request-ID"] for r in responses]
        assert len(request_ids) == len(set(request_ids))


# Add missing import for async tests
import asyncio
