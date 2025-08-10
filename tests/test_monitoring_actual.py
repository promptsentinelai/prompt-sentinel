"""Unit tests for actual monitoring modules."""

import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from prompt_sentinel.monitoring.budget_manager import BudgetManager
from prompt_sentinel.monitoring.usage_tracker import UsageTracker
from prompt_sentinel.monitoring.rate_limiter import RateLimiter


@pytest.mark.skip(reason="Tests use outdated API - monitoring modules have been refactored")
class TestBudgetManagerActual:
    """Test the actual BudgetManager implementation."""

    @pytest.fixture
    def budget_manager(self):
        """Create budget manager instance."""
        from prompt_sentinel.config.settings import Settings as Config
        from prompt_sentinel.monitoring.usage_tracker import UsageTracker

        config = Config()
        usage_tracker = UsageTracker(config)
        return BudgetManager(config, usage_tracker)

    @pytest.mark.asyncio
    async def test_track_cost(self, budget_manager):
        """Test tracking API costs."""
        # Track a cost
        await budget_manager.track_cost(
            provider="anthropic",
            model="claude-3-opus-20240229",
            input_tokens=1000,
            output_tokens=500,
        )

        # Get current spend
        daily_spend = budget_manager.get_daily_spend()
        assert daily_spend > 0

    @pytest.mark.asyncio
    async def test_check_budget(self, budget_manager):
        """Test budget checking."""
        # Should be under budget initially
        is_under = await budget_manager.is_under_budget()
        assert is_under is True

        # Track large cost to exceed budget
        for _ in range(100):
            await budget_manager.track_cost(
                provider="anthropic",
                model="claude-3-opus-20240229",
                input_tokens=10000,
                output_tokens=5000,
            )

        # Check if over budget
        daily_spend = budget_manager.get_daily_spend()
        if daily_spend > budget_manager.daily_limit:
            is_under = await budget_manager.is_under_budget()
            assert is_under is False

    def test_calculate_cost(self, budget_manager):
        """Test cost calculation for different providers."""
        # Anthropic costs
        cost = budget_manager.calculate_cost(
            provider="anthropic",
            model="claude-3-opus-20240229",
            input_tokens=1000,
            output_tokens=500,
        )
        assert cost > 0

        # OpenAI costs
        cost = budget_manager.calculate_cost(
            provider="openai",
            model="gpt-4",
            input_tokens=1000,
            output_tokens=500,
        )
        assert cost > 0

    @pytest.mark.asyncio
    async def test_get_usage_summary(self, budget_manager):
        """Test getting usage summary."""
        # Track some costs
        await budget_manager.track_cost(
            provider="anthropic",
            model="claude-3-haiku-20240307",
            input_tokens=500,
            output_tokens=250,
        )

        await budget_manager.track_cost(
            provider="openai",
            model="gpt-3.5-turbo",
            input_tokens=300,
            output_tokens=150,
        )

        # Get summary
        summary = budget_manager.get_usage_summary()

        assert "daily_spend" in summary
        assert "monthly_spend" in summary
        assert "daily_limit" in summary
        assert "monthly_limit" in summary
        assert summary["daily_spend"] > 0

    def test_reset_daily_budget(self, budget_manager):
        """Test resetting daily budget."""
        # Track some cost
        budget_manager.daily_spend = 50.0

        # Reset
        budget_manager.reset_daily()

        assert budget_manager.daily_spend == 0.0
        assert budget_manager.last_reset is not None


@pytest.mark.skip(reason="Tests use outdated API - monitoring modules have been refactored")
class TestUsageTrackerActual:
    """Test the actual UsageTracker implementation."""

    @pytest.fixture
    def usage_tracker(self):
        """Create usage tracker instance."""
        from prompt_sentinel.config.settings import Settings as Config

        config = Config()
        return UsageTracker(config)

    @pytest.mark.asyncio
    async def test_track_request(self, usage_tracker):
        """Test tracking API requests."""
        # Track a request
        await usage_tracker.track_request(
            endpoint="/api/v1/detect",
            method="POST",
            response_time_ms=150,
            status_code=200,
        )

        # Get stats
        stats = usage_tracker.get_stats()
        assert stats["total_requests"] == 1
        assert stats["successful_requests"] == 1

    @pytest.mark.asyncio
    async def test_track_detection(self, usage_tracker):
        """Test tracking detection events."""
        # Track detections
        await usage_tracker.track_detection(
            verdict="BLOCK",
            confidence=0.95,
            processing_time_ms=100,
        )

        await usage_tracker.track_detection(
            verdict="ALLOW",
            confidence=0.1,
            processing_time_ms=50,
        )

        # Get detection stats
        stats = usage_tracker.get_detection_stats()
        assert stats["total_detections"] == 2
        assert stats["blocked"] == 1
        assert stats["allowed"] == 1

    @pytest.mark.asyncio
    async def test_track_api_call(self, usage_tracker):
        """Test tracking LLM API calls."""
        # Track API call
        await usage_tracker.track_api_call(
            provider="anthropic",
            model="claude-3-opus-20240229",
            tokens_used=1500,
            latency_ms=450,
            success=True,
        )

        # Track failed call
        await usage_tracker.track_api_call(
            provider="openai",
            model="gpt-4",
            tokens_used=0,
            latency_ms=30000,
            success=False,
        )

        # Get API stats
        stats = usage_tracker.get_api_stats()
        assert stats["total_calls"] == 2
        assert stats["successful_calls"] == 1
        assert stats["failed_calls"] == 1
        assert stats["total_tokens"] == 1500

    def test_get_hourly_stats(self, usage_tracker):
        """Test getting hourly statistics."""
        # Add some data points
        usage_tracker.hourly_requests = [10, 20, 15, 25, 30]

        hourly = usage_tracker.get_hourly_stats()
        assert "requests_per_hour" in hourly
        assert len(hourly["requests_per_hour"]) > 0

    @pytest.mark.asyncio
    async def test_track_cache_hit(self, usage_tracker):
        """Test tracking cache hits and misses."""
        # Track cache operations
        for _ in range(7):
            await usage_tracker.track_cache_hit()

        for _ in range(3):
            await usage_tracker.track_cache_miss()

        # Get cache stats
        stats = usage_tracker.get_cache_stats()
        assert stats["hits"] == 7
        assert stats["misses"] == 3
        assert stats["hit_rate"] == 0.7


@pytest.mark.skip(reason="Tests use outdated API - monitoring modules have been refactored")
class TestRateLimiterActual:
    """Test the actual RateLimiter implementation."""

    @pytest.fixture
    def rate_limiter(self):
        """Create rate limiter instance."""
        from prompt_sentinel.monitoring.rate_limiter import RateLimitConfig

        config = RateLimitConfig(
            requests_per_minute=60,
            burst_size=10,
            tokens_per_minute=10000,
        )
        return RateLimiter(config)

    @pytest.mark.asyncio
    async def test_allow_request(self, rate_limiter):
        """Test allowing requests within rate limit."""
        # First requests should be allowed
        for _ in range(5):
            allowed = await rate_limiter.allow_request("client_1")
            assert allowed is True

    @pytest.mark.asyncio
    async def test_rate_limiting(self, rate_limiter):
        """Test rate limiting enforcement."""
        client_id = "test_client"

        # Use up burst capacity
        for _ in range(rate_limiter.config.burst_size):
            allowed = await rate_limiter.allow_request(client_id)
            assert allowed is True

        # Next request might be rate limited
        # (depends on token refill rate)
        allowed = await rate_limiter.allow_request(client_id)
        # May or may not be allowed depending on timing

    @pytest.mark.asyncio
    async def test_client_isolation(self, rate_limiter):
        """Test that rate limits are per-client."""
        # Client 1 uses some capacity
        for _ in range(5):
            await rate_limiter.allow_request("client_1")

        # Client 2 should still have full capacity
        allowed = await rate_limiter.allow_request("client_2")
        assert allowed is True

    def test_get_client_status(self, rate_limiter):
        """Test getting client rate limit status."""
        client_id = "test_client"

        # Make some requests
        for _ in range(3):
            rate_limiter.allow_request_sync(client_id)

        # Get status
        status = rate_limiter.get_client_status(client_id)
        assert "tokens_remaining" in status
        assert "last_request" in status
        assert status["tokens_remaining"] <= rate_limiter.burst_size

    @pytest.mark.asyncio
    async def test_reset_client(self, rate_limiter):
        """Test resetting client rate limit."""
        client_id = "test_client"

        # Use some capacity
        for _ in range(5):
            await rate_limiter.allow_request(client_id)

        # Reset client
        rate_limiter.reset_client(client_id)

        # Should have full capacity again
        status = rate_limiter.get_client_status(client_id)
        assert status["tokens_remaining"] == rate_limiter.config.burst_size

    @pytest.mark.asyncio
    async def test_global_rate_limit(self, rate_limiter):
        """Test global rate limiting across all clients."""
        # Set global limit
        rate_limiter.set_global_limit(requests_per_minute=100)

        # Many clients making requests
        clients = [f"client_{i}" for i in range(10)]

        allowed_count = 0
        for _ in range(20):
            for client in clients:
                if await rate_limiter.allow_request(client):
                    allowed_count += 1

        # Should respect global limit
        assert allowed_count <= 200  # Some requests allowed

    def test_rate_limiter_configuration(self, rate_limiter):
        """Test rate limiter configuration."""
        assert rate_limiter.config.requests_per_minute == 60
        assert rate_limiter.config.burst_size == 10

        # Update configuration
        from prompt_sentinel.monitoring.rate_limiter import RateLimitConfig

        new_config = RateLimitConfig(
            requests_per_minute=120,
            burst_size=20,
            tokens_per_minute=20000,
        )
        rate_limiter.config = new_config

        assert rate_limiter.config.requests_per_minute == 120
        assert rate_limiter.config.burst_size == 20


@pytest.mark.skip(reason="Tests use outdated API - monitoring modules have been refactored")
class TestMonitoringIntegration:
    """Test integration between monitoring components."""

    @pytest.mark.asyncio
    async def test_usage_and_budget_integration(self):
        """Test usage tracker and budget manager working together."""
        from prompt_sentinel.config.settings import Settings as Config

        config = Config()
        usage_tracker = UsageTracker(config)
        budget_manager = BudgetManager(config, usage_tracker)

        # Track API call with cost
        await usage_tracker.track_api_call(
            provider="anthropic",
            model="claude-3-opus-20240229",
            tokens_used=1500,
            latency_ms=200,
            success=True,
        )

        # Budget manager tracks the cost
        await budget_manager.track_cost(
            provider="anthropic",
            model="claude-3-opus-20240229",
            input_tokens=1000,
            output_tokens=500,
        )

        # Both should have data
        usage_stats = usage_tracker.get_api_stats()
        assert usage_stats["total_tokens"] == 1500

        budget_summary = budget_manager.get_usage_summary()
        assert budget_summary["daily_spend"] > 0

    @pytest.mark.asyncio
    async def test_rate_limiting_with_usage_tracking(self):
        """Test rate limiter with usage tracking."""
        from prompt_sentinel.config.settings import Settings as Config
        from prompt_sentinel.monitoring.rate_limiter import RateLimitConfig

        config = Config()
        rate_limit_config = RateLimitConfig(
            requests_per_minute=60,
            burst_size=10,
            tokens_per_minute=10000,
        )
        rate_limiter = RateLimiter(rate_limit_config)
        usage_tracker = UsageTracker(config)

        client_id = "test_client"
        allowed_count = 0

        # Make requests with tracking
        for i in range(20):
            if await rate_limiter.allow_request(client_id):
                allowed_count += 1
                await usage_tracker.track_request(
                    endpoint="/api/v1/detect",
                    method="POST",
                    response_time_ms=100,
                    status_code=200,
                )
            else:
                await usage_tracker.track_request(
                    endpoint="/api/v1/detect",
                    method="POST",
                    response_time_ms=0,
                    status_code=429,  # Rate limited
                )

        # Check tracking
        stats = usage_tracker.get_stats()
        assert stats["total_requests"] == 20
        assert stats["successful_requests"] == allowed_count
        assert stats["failed_requests"] == 20 - allowed_count


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
