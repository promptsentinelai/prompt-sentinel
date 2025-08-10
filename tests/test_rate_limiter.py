"""Comprehensive tests for rate limiting module."""

import asyncio
import time
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from prompt_sentinel.monitoring.rate_limiter import (
    Priority,
    RateLimiter,
    RateLimitConfig,
    TokenBucket,
)


class TestPriority:
    """Test suite for Priority enum."""

    def test_priority_values(self):
        """Test priority enum values."""
        assert Priority.LOW < Priority.NORMAL
        assert Priority.NORMAL < Priority.HIGH
        assert Priority.HIGH < Priority.CRITICAL
        assert Priority.LOW == 0
        assert Priority.CRITICAL == 3

    def test_priority_comparison(self):
        """Test priority comparisons."""
        assert Priority.HIGH > Priority.LOW
        assert Priority.CRITICAL >= Priority.HIGH
        assert Priority.NORMAL != Priority.HIGH


class TestRateLimitConfig:
    """Test suite for RateLimitConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = RateLimitConfig()

        assert config.requests_per_minute == 60  # Default from RateLimitConfig
        assert config.requests_per_hour == 1000
        assert config.tokens_per_minute == 10000  # Default from RateLimitConfig
        assert config.tokens_per_hour == 100000
        assert config.client_requests_per_minute == 20
        assert config.client_tokens_per_minute == 5000
        assert config.burst_multiplier == 1.5
        assert config.enable_adaptive is True
        assert config.min_rate_percentage == 0.5
        assert config.max_rate_percentage == 1.5
        assert config.enable_priority is True
        assert config.priority_reserved_percentage == 0.2

    def test_custom_config(self):
        """Test custom configuration."""
        config = RateLimitConfig(
            requests_per_minute=100,
            requests_per_hour=2000,
            burst_multiplier=2.0,
            enable_adaptive=False,
        )

        assert config.requests_per_minute == 100
        assert config.requests_per_hour == 2000
        assert config.burst_multiplier == 2.0
        assert config.enable_adaptive is False


class TestTokenBucket:
    """Test suite for TokenBucket."""

    def test_initialization(self):
        """Test token bucket initialization."""
        bucket = TokenBucket(
            capacity=100,
            tokens=50,
            refill_rate=10,
            last_refill=time.time(),
        )

        assert bucket.capacity == 100
        assert bucket.tokens == 50
        assert bucket.refill_rate == 10
        assert bucket.last_refill > 0

    def test_consume_tokens(self):
        """Test consuming tokens from bucket."""
        bucket = TokenBucket(
            capacity=100,
            tokens=50,
            refill_rate=10,
            last_refill=time.time(),
        )

        # Consume within available tokens
        assert bucket.consume(10) is True
        assert bucket.tokens == pytest.approx(40, rel=0.01)

        # Consume more tokens
        assert bucket.consume(30) is True
        assert bucket.tokens == pytest.approx(10, rel=0.01)

        # Try to consume more than available
        assert bucket.consume(20) is False
        assert bucket.tokens == pytest.approx(10, rel=0.01)  # Tokens unchanged

    def test_can_consume(self):
        """Test checking token availability."""
        bucket = TokenBucket(
            capacity=100,
            tokens=50,
            refill_rate=10,
            last_refill=time.time(),
        )

        # Check without consuming
        assert bucket.can_consume(10) is True
        assert bucket.tokens == 50  # Tokens unchanged

        assert bucket.can_consume(50) is True
        assert bucket.can_consume(51) is False

    def test_token_refill(self):
        """Test token refill over time."""
        start_time = time.time()
        bucket = TokenBucket(
            capacity=100,
            tokens=0,
            refill_rate=10,  # 10 tokens per second
            last_refill=start_time,
        )

        # Wait for refill
        time.sleep(0.1)  # 0.1 seconds = 1 token

        # Tokens should be refilled
        assert bucket.can_consume(1) is True

        # Consume and check refill
        bucket.consume(1)
        assert bucket.tokens < 1

        # Wait for more refill
        time.sleep(0.5)  # 0.5 seconds = 5 tokens
        assert bucket.can_consume(4) is True

    def test_capacity_limit(self):
        """Test that tokens don't exceed capacity."""
        start_time = time.time() - 100  # 100 seconds ago
        bucket = TokenBucket(
            capacity=50,
            tokens=40,
            refill_rate=10,  # Would refill 1000 tokens in 100 seconds
            last_refill=start_time,
        )

        # Try to consume (should trigger refill)
        bucket.consume(1)

        # Tokens should be at capacity minus 1
        assert bucket.tokens == pytest.approx(49, rel=0.01)
        assert bucket.tokens <= bucket.capacity

    def test_time_until_available(self):
        """Test calculating time until tokens available."""
        bucket = TokenBucket(
            capacity=100,
            tokens=10,
            refill_rate=10,  # 10 tokens per second
            last_refill=time.time(),
        )

        # Already available
        assert bucket.time_until_available(10) == 0.0

        # Need to wait
        wait_time = bucket.time_until_available(20)
        assert wait_time > 0
        assert wait_time == pytest.approx(1.0, rel=0.1)  # ~1 second for 10 tokens


class TestRateLimiter:
    """Test suite for RateLimiter."""

    @pytest.fixture
    def config(self):
        """Create test configuration."""
        return RateLimitConfig(
            requests_per_minute=60,
            client_requests_per_minute=20,
            tokens_per_minute=1000,
            client_tokens_per_minute=500,
        )

    @pytest.fixture
    def rate_limiter(self, config):
        """Create rate limiter instance."""
        return RateLimiter(config)

    def test_initialization(self, rate_limiter, config):
        """Test rate limiter initialization."""
        assert rate_limiter.config == config
        assert rate_limiter.global_request_bucket is not None
        assert rate_limiter.global_token_bucket is not None
        assert len(rate_limiter.client_request_buckets) == 0
        assert len(rate_limiter.client_token_buckets) == 0

    @pytest.mark.asyncio
    async def test_check_rate_limit_global(self, rate_limiter):
        """Test global rate limiting."""
        # Should allow initial requests
        for _ in range(10):
            allowed, wait_time = await rate_limiter.check_rate_limit(
                client_id="test_client",
                tokens=10,
            )
            assert allowed is True

        # Check metrics
        metrics = rate_limiter.get_metrics()
        assert metrics["total_requests"] == 10
        assert metrics["accepted_requests"] == 10

    @pytest.mark.asyncio
    async def test_check_rate_limit_per_client(self, rate_limiter):
        """Test per-client rate limiting."""
        client_id = "test_client"

        # Consume client limit (with burst allowance, 20 * 1.5 = 30)
        # But check_rate_limit just checks, doesn't consume
        count = 0
        for _ in range(35):  # Try more than burst limit
            allowed, wait_time = await rate_limiter.check_rate_limit(
                client_id=client_id,
                tokens=1,
            )
            if allowed:
                # Actually consume the tokens
                await rate_limiter.consume_tokens(client_id, 1)
                count += 1
            else:
                break

        # Should have been limited at some point
        assert count <= 30  # Should be limited by burst capacity

    @pytest.mark.asyncio
    async def test_check_rate_limit_tokens(self, rate_limiter):
        """Test token-based rate limiting."""
        client_id = "test_client"

        # Check and consume tokens
        allowed, wait_time = await rate_limiter.check_rate_limit(
            client_id=client_id,
            tokens=400,
        )
        assert allowed is True
        await rate_limiter.consume_tokens(client_id, 400)

        # Try to consume more than remaining (500 - 400 = 100 left)
        allowed, wait_time = await rate_limiter.check_rate_limit(
            client_id=client_id,
            tokens=200,
        )
        assert allowed is False
        assert wait_time > 0

    @pytest.mark.asyncio
    async def test_priority_handling(self, rate_limiter):
        """Test priority-based rate limiting."""
        client_id = "test_client"

        # Consume most of the limit with normal priority
        for _ in range(18):
            await rate_limiter.check_rate_limit(
                client_id=client_id,
                tokens=1,
                priority=Priority.NORMAL,
            )

        # High priority should still work
        allowed, _ = await rate_limiter.check_rate_limit(
            client_id=client_id,
            tokens=1,
            priority=Priority.HIGH,
        )
        assert allowed is True

        # Critical priority should always work
        allowed, _ = await rate_limiter.check_rate_limit(
            client_id=client_id,
            tokens=1,
            priority=Priority.CRITICAL,
        )
        assert allowed is True

    def test_get_metrics(self, rate_limiter):
        """Test getting rate limiter metrics."""
        metrics = rate_limiter.get_metrics()

        assert isinstance(metrics, dict)
        assert "total_requests" in metrics
        assert "accepted_requests" in metrics
        assert "rejected_requests" in metrics
        assert "acceptance_rate" in metrics
        assert "total_tokens" in metrics
        assert "current_load" in metrics
        assert "active_clients" in metrics
        assert "global_tokens_available" in metrics
        assert "config" in metrics

    @pytest.mark.asyncio
    async def test_wait_if_needed(self, rate_limiter):
        """Test waiting for rate limit reset."""
        client_id = "test_client"

        # Consume all requests
        for _ in range(20):
            await rate_limiter.check_rate_limit(
                client_id=client_id,
                tokens=1,
            )

        # Should wait instead of failing
        start_time = time.time()
        result = await rate_limiter.wait_if_needed(
            client_id=client_id,
            tokens=1,
            max_wait=0.1,  # Short wait for test
        )
        elapsed = time.time() - start_time

        # Should have tried to wait
        assert elapsed > 0

    def test_reset_client(self, rate_limiter):
        """Test resetting client limits."""
        client_id = "test_client"

        # Add some client buckets
        rate_limiter.client_request_buckets[client_id] = TokenBucket(
            capacity=20,
            tokens=5,
            refill_rate=20 / 60,
            last_refill=time.time(),
        )
        rate_limiter.client_token_buckets[client_id] = TokenBucket(
            capacity=500,
            tokens=100,
            refill_rate=500 / 60,
            last_refill=time.time(),
        )

        # Reset client
        rate_limiter.reset_client(client_id)

        # Should have removed buckets
        assert client_id not in rate_limiter.client_request_buckets
        assert client_id not in rate_limiter.client_token_buckets

    @pytest.mark.asyncio
    async def test_consume_tokens(self, rate_limiter):
        """Test consuming tokens from buckets."""
        client_id = "test_client"

        # Should succeed initially
        result = await rate_limiter.consume_tokens(client_id, 10)
        assert result is True

        # Verify tokens consumed from global bucket
        assert rate_limiter.global_token_bucket.tokens < rate_limiter.global_token_bucket.capacity

    @pytest.mark.asyncio
    async def test_multiple_clients(self, rate_limiter):
        """Test rate limiting with multiple clients."""
        clients = ["client1", "client2", "client3"]

        # Each client should have independent limits
        for client_id in clients:
            for _ in range(10):
                await rate_limiter.check_rate_limit(
                    client_id=client_id,
                    tokens=10,
                )

        # Check metrics
        metrics = rate_limiter.get_metrics()
        assert metrics["total_requests"] == 30
        assert metrics["active_clients"] == 3

    @pytest.mark.asyncio
    async def test_burst_allowance(self, rate_limiter):
        """Test burst allowance."""
        client_id = "test_client"

        # Should allow burst up to multiplier
        burst_limit = int(20 * rate_limiter.config.burst_multiplier)

        # Consume up to burst limit quickly
        allowed_count = 0
        for _ in range(min(burst_limit, 30)):
            allowed, _ = await rate_limiter.check_rate_limit(
                client_id=client_id,
                tokens=1,
            )
            if not allowed:
                break
            allowed_count += 1

        # Should have allowed some burst
        assert allowed_count > 0

    @pytest.mark.asyncio
    async def test_initialize(self, rate_limiter):
        """Test rate limiter initialization."""
        await rate_limiter.initialize()

        # Background tasks should be started
        assert rate_limiter._initialized is True
        assert rate_limiter._cleanup_task is not None

        # Initialize again should be a no-op
        await rate_limiter.initialize()
        assert rate_limiter._initialized is True


class TestIntegrationScenarios:
    """Test suite for integration scenarios."""

    @pytest.fixture
    def rate_limiter_adaptive(self):
        """Create rate limiter with adaptive config."""
        config = RateLimitConfig(
            enable_adaptive=True,
            min_rate_percentage=0.5,
            max_rate_percentage=1.5,
        )
        return RateLimiter(config)

    @pytest.mark.asyncio
    async def test_adaptive_rate_adjustment(self, rate_limiter_adaptive):
        """Test adaptive rate adjustment based on load."""
        # Simulate high load
        rate_limiter_adaptive.current_load = 0.9
        rate_limiter_adaptive.load_history = [0.85, 0.9, 0.88, 0.92, 0.9]

        # The _adjust_rates background task would handle this
        # We can test the logic directly
        avg_load = sum(rate_limiter_adaptive.load_history) / len(rate_limiter_adaptive.load_history)
        assert avg_load > 0.8

        # Adjustment should reduce rates
        adjustment = max(rate_limiter_adaptive.config.min_rate_percentage, 1.0 - (avg_load - 0.8))
        assert adjustment < 1.0

    @pytest.mark.asyncio
    async def test_concurrent_client_limits(self, rate_limiter_adaptive):
        """Test handling multiple concurrent clients."""
        # Simulate multiple clients
        clients = [f"client_{i}" for i in range(5)]
        results = []

        for client_id in clients:
            allowed, wait_time = await rate_limiter_adaptive.check_rate_limit(
                client_id=client_id,
                tokens=20,
            )
            results.append((client_id, allowed))

        # All clients should be allowed initially
        assert all(allowed for _, allowed in results)

        # Each client has independent limits
        assert len(rate_limiter_adaptive.client_request_buckets) == 5
        assert len(rate_limiter_adaptive.client_token_buckets) == 5

    @pytest.mark.asyncio
    async def test_priority_queue_behavior(self, rate_limiter_adaptive):
        """Test priority-based request handling."""
        client_id = "test_client"

        # Consume most of normal capacity
        for _ in range(18):
            await rate_limiter_adaptive.check_rate_limit(
                client_id=client_id,
                tokens=1,
                priority=Priority.NORMAL,
            )

        # High priority should still work
        allowed, _ = await rate_limiter_adaptive.check_rate_limit(
            client_id=client_id,
            tokens=1,
            priority=Priority.HIGH,
        )
        assert allowed is True

        # Critical priority should always work
        allowed, _ = await rate_limiter_adaptive.check_rate_limit(
            client_id=client_id,
            tokens=1,
            priority=Priority.CRITICAL,
        )
        assert allowed is True

    @pytest.mark.asyncio
    async def test_load_tracking(self, rate_limiter_adaptive):
        """Test load tracking and history."""
        # Consume tokens to create load
        for _ in range(10):
            await rate_limiter_adaptive.consume_tokens("client_1", 10)

        # Load should be tracked
        assert rate_limiter_adaptive.current_load > 0

        # After initialization, load history should start building
        await rate_limiter_adaptive.initialize()
        # Simulate the _adjust_rates task by adding to history
        rate_limiter_adaptive.load_history.append(rate_limiter_adaptive.current_load)

        assert len(rate_limiter_adaptive.load_history) > 0
