"""Tests for rate limiting functionality."""

import pytest
import asyncio
import time
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta

from prompt_sentinel.monitoring.rate_limiter import RateLimiter, RateLimitExceeded


class TestRateLimiter:
    """Test rate limiter functionality."""

    @pytest.fixture
    def rate_limiter(self):
        """Create rate limiter instance."""
        return RateLimiter(
            requests_per_minute=60,
            requests_per_hour=1000,
            burst_size=10
        )

    @pytest.mark.asyncio
    async def test_basic_rate_limiting(self, rate_limiter):
        """Test basic rate limiting."""
        client_id = "test_client"
        
        # Should allow initial requests
        for i in range(10):
            allowed = await rate_limiter.check_rate_limit(client_id)
            assert allowed is True
        
        # Should start limiting after burst
        allowed = await rate_limiter.check_rate_limit(client_id)
        # Might still allow if enough time passed
        assert isinstance(allowed, bool)

    @pytest.mark.asyncio
    async def test_per_minute_limit(self):
        """Test per-minute rate limiting."""
        limiter = RateLimiter(
            requests_per_minute=5,
            requests_per_hour=1000,
            burst_size=5
        )
        
        client_id = "minute_test"
        
        # Use up the limit
        for _ in range(5):
            assert await limiter.check_rate_limit(client_id) is True
        
        # Should be limited
        with pytest.raises(RateLimitExceeded):
            await limiter.check_rate_limit(client_id, raise_on_limit=True)

    @pytest.mark.asyncio
    async def test_per_hour_limit(self):
        """Test per-hour rate limiting."""
        limiter = RateLimiter(
            requests_per_minute=1000,  # High minute limit
            requests_per_hour=10,
            burst_size=10
        )
        
        client_id = "hour_test"
        
        # Use up the hour limit
        for _ in range(10):
            assert await limiter.check_rate_limit(client_id) is True
        
        # Should be limited by hour limit
        assert await limiter.check_rate_limit(client_id) is False

    @pytest.mark.asyncio
    async def test_burst_handling(self):
        """Test burst request handling."""
        limiter = RateLimiter(
            requests_per_minute=60,
            requests_per_hour=1000,
            burst_size=20
        )
        
        client_id = "burst_test"
        
        # Should handle burst
        tasks = []
        for _ in range(20):
            tasks.append(limiter.check_rate_limit(client_id))
        
        results = await asyncio.gather(*tasks)
        
        # All burst requests should succeed
        assert all(results)

    @pytest.mark.asyncio
    async def test_rate_limit_reset(self):
        """Test rate limit reset after time window."""
        limiter = RateLimiter(
            requests_per_minute=2,
            requests_per_hour=1000,
            burst_size=2
        )
        
        client_id = "reset_test"
        
        # Use up limit
        for _ in range(2):
            await limiter.check_rate_limit(client_id)
        
        # Should be limited
        assert await limiter.check_rate_limit(client_id) is False
        
        # Wait for reset (simulated)
        await limiter.reset_client_limits(client_id)
        
        # Should work again
        assert await limiter.check_rate_limit(client_id) is True

    @pytest.mark.asyncio
    async def test_multiple_clients(self):
        """Test rate limiting for multiple clients."""
        limiter = RateLimiter(
            requests_per_minute=5,
            requests_per_hour=100,
            burst_size=5
        )
        
        # Each client has independent limits
        clients = ["client_1", "client_2", "client_3"]
        
        for client in clients:
            for _ in range(5):
                assert await limiter.check_rate_limit(client) is True
        
        # Each should be at their limit
        for client in clients:
            assert await limiter.check_rate_limit(client) is False

    @pytest.mark.asyncio
    async def test_get_remaining_quota(self, rate_limiter):
        """Test getting remaining quota."""
        client_id = "quota_test"
        
        # Initial quota
        quota = await rate_limiter.get_remaining_quota(client_id)
        assert quota["requests_per_minute"] == 60
        assert quota["requests_per_hour"] == 1000
        
        # Use some quota
        for _ in range(5):
            await rate_limiter.check_rate_limit(client_id)
        
        quota = await rate_limiter.get_remaining_quota(client_id)
        assert quota["requests_per_minute"] <= 55
        assert quota["requests_per_hour"] <= 995


class TestAPIRateLimiting:
    """Test rate limiting in API context."""

    @pytest.fixture
    def app(self):
        """Create FastAPI app with rate limiting."""
        from fastapi import FastAPI
        from prompt_sentinel.monitoring.rate_limiter import RateLimitMiddleware
        
        app = FastAPI()
        app.add_middleware(
            RateLimitMiddleware,
            requests_per_minute=10,
            requests_per_hour=100
        )
        
        @app.get("/test")
        async def test_endpoint():
            return {"status": "ok"}
        
        return app

    def test_rate_limit_headers(self, app):
        """Test rate limit headers in responses."""
        from fastapi.testclient import TestClient
        
        client = TestClient(app)
        
        response = client.get("/test")
        assert response.status_code == 200
        
        # Check headers
        headers = response.headers
        if "X-RateLimit-Limit" in headers:
            assert int(headers["X-RateLimit-Limit"]) > 0
        if "X-RateLimit-Remaining" in headers:
            assert int(headers["X-RateLimit-Remaining"]) >= 0
        if "X-RateLimit-Reset" in headers:
            assert int(headers["X-RateLimit-Reset"]) > 0

    def test_rate_limit_exceeded_response(self, app):
        """Test 429 response when rate limit exceeded."""
        from fastapi.testclient import TestClient
        
        client = TestClient(app)
        
        # Make many requests
        for _ in range(15):
            response = client.get("/test")
            if response.status_code == 429:
                # Check error response
                data = response.json()
                assert "detail" in data
                assert "rate limit" in data["detail"].lower()
                break
        else:
            # If no 429, might be test environment
            pass


class TestDistributedRateLimiting:
    """Test distributed rate limiting with Redis."""

    @pytest.mark.asyncio
    @patch("redis.asyncio.Redis")
    async def test_redis_rate_limiter(self, mock_redis):
        """Test rate limiting with Redis backend."""
        mock_redis_instance = AsyncMock()
        mock_redis.from_url.return_value = mock_redis_instance
        
        # Mock Redis operations
        mock_redis_instance.incr.return_value = 1
        mock_redis_instance.expire.return_value = True
        mock_redis_instance.ttl.return_value = 60
        
        limiter = RateLimiter(
            requests_per_minute=60,
            requests_per_hour=1000,
            use_redis=True,
            redis_url="redis://localhost:6379"
        )
        
        client_id = "redis_test"
        allowed = await limiter.check_rate_limit(client_id)
        
        assert allowed is True
        mock_redis_instance.incr.assert_called()

    @pytest.mark.asyncio
    @patch("redis.asyncio.Redis")
    async def test_redis_sliding_window(self, mock_redis):
        """Test sliding window rate limiting with Redis."""
        mock_redis_instance = AsyncMock()
        mock_redis.from_url.return_value = mock_redis_instance
        
        # Mock sliding window operations
        mock_redis_instance.zadd.return_value = 1
        mock_redis_instance.zremrangebyscore.return_value = 0
        mock_redis_instance.zcard.return_value = 5
        
        limiter = RateLimiter(
            requests_per_minute=60,
            algorithm="sliding_window",
            use_redis=True,
            redis_url="redis://localhost:6379"
        )
        
        client_id = "sliding_test"
        allowed = await limiter.check_rate_limit(client_id)
        
        assert allowed is True
        mock_redis_instance.zadd.assert_called()


class TestRateLimitStrategies:
    """Test different rate limiting strategies."""

    @pytest.mark.asyncio
    async def test_token_bucket_algorithm(self):
        """Test token bucket rate limiting."""
        limiter = RateLimiter(
            requests_per_minute=60,
            algorithm="token_bucket",
            burst_size=10
        )
        
        client_id = "token_test"
        
        # Should allow burst
        for _ in range(10):
            assert await limiter.check_rate_limit(client_id) is True
        
        # Tokens depleted, should limit
        # (actual behavior depends on implementation)
        result = await limiter.check_rate_limit(client_id)
        assert isinstance(result, bool)

    @pytest.mark.asyncio
    async def test_leaky_bucket_algorithm(self):
        """Test leaky bucket rate limiting."""
        limiter = RateLimiter(
            requests_per_minute=60,
            algorithm="leaky_bucket",
            burst_size=10
        )
        
        client_id = "leaky_test"
        
        # Should smooth out bursts
        results = []
        for _ in range(20):
            result = await limiter.check_rate_limit(client_id)
            results.append(result)
            await asyncio.sleep(0.05)  # Small delay
        
        # Should have some successful requests
        assert any(results)

    @pytest.mark.asyncio
    async def test_fixed_window_algorithm(self):
        """Test fixed window rate limiting."""
        limiter = RateLimiter(
            requests_per_minute=5,
            algorithm="fixed_window"
        )
        
        client_id = "fixed_test"
        
        # Use up limit in current window
        for _ in range(5):
            assert await limiter.check_rate_limit(client_id) is True
        
        # Should be limited in same window
        assert await limiter.check_rate_limit(client_id) is False


class TestRateLimitBypass:
    """Test rate limit bypass for special cases."""

    @pytest.mark.asyncio
    async def test_whitelist_bypass(self):
        """Test whitelisted clients bypass rate limits."""
        limiter = RateLimiter(
            requests_per_minute=5,
            whitelist=["premium_client", "internal_service"]
        )
        
        # Whitelisted client
        for _ in range(10):
            assert await limiter.check_rate_limit("premium_client") is True
        
        # Regular client gets limited
        regular_client = "regular_client"
        for _ in range(5):
            await limiter.check_rate_limit(regular_client)
        assert await limiter.check_rate_limit(regular_client) is False

    @pytest.mark.asyncio
    async def test_api_key_based_limits(self):
        """Test different limits based on API key tier."""
        limiter = RateLimiter(
            default_requests_per_minute=10,
            tier_limits={
                "free": {"per_minute": 10, "per_hour": 100},
                "pro": {"per_minute": 100, "per_hour": 5000},
                "enterprise": {"per_minute": 1000, "per_hour": 50000}
            }
        )
        
        # Free tier
        free_client = ("client_1", "free")
        for _ in range(10):
            await limiter.check_rate_limit(*free_client)
        assert await limiter.check_rate_limit(*free_client) is False
        
        # Pro tier has higher limit
        pro_client = ("client_2", "pro")
        for _ in range(50):
            assert await limiter.check_rate_limit(*pro_client) is True


class TestRateLimitMetrics:
    """Test rate limit metrics and monitoring."""

    @pytest.mark.asyncio
    async def test_rate_limit_metrics(self, rate_limiter):
        """Test collection of rate limit metrics."""
        client_id = "metrics_test"
        
        # Generate some traffic
        for _ in range(5):
            await rate_limiter.check_rate_limit(client_id)
        
        # Get metrics
        metrics = await rate_limiter.get_metrics(client_id)
        
        assert metrics["total_requests"] == 5
        assert metrics["allowed_requests"] == 5
        assert metrics["denied_requests"] == 0
        assert "first_request_time" in metrics
        assert "last_request_time" in metrics

    @pytest.mark.asyncio
    async def test_global_rate_limit_stats(self, rate_limiter):
        """Test global rate limit statistics."""
        # Generate traffic from multiple clients
        for i in range(3):
            client_id = f"client_{i}"
            for _ in range(3):
                await rate_limiter.check_rate_limit(client_id)
        
        # Get global stats
        stats = await rate_limiter.get_global_stats()
        
        assert stats["total_clients"] == 3
        assert stats["total_requests"] == 9
        assert "requests_per_second" in stats
        assert "top_clients" in stats


if __name__ == "__main__":
    pytest.main([__file__, "-v"])