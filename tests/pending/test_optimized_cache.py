#!/usr/bin/env python3
# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0

"""Comprehensive tests for optimized cache functionality."""

import asyncio
import hashlib
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from prompt_sentinel.cache.optimized_cache import (
    BatchCache,
    CacheTier,
    OptimizedCache,
    RequestCoalescer,
)


@pytest.fixture
def redis_client():
    """Create a mock Redis client."""
    client = AsyncMock()
    client.get = AsyncMock(return_value=None)
    client.set = AsyncMock(return_value=True)
    client.delete = AsyncMock(return_value=1)
    client.mget = AsyncMock(return_value=[None])
    client.pipeline = MagicMock()
    client.ping = AsyncMock(return_value=True)
    return client


@pytest.fixture
def optimized_cache(redis_client):
    """Create an optimized cache instance."""
    return OptimizedCache(redis_client=redis_client, memory_size_mb=10, enable_tiering=True)


@pytest.fixture
def batch_cache(redis_client):
    """Create a batch cache instance."""
    return BatchCache(redis_client=redis_client, batch_size=10, batch_timeout_ms=100)


class TestOptimizedCache:
    """Test OptimizedCache functionality."""

    def test_init_with_defaults(self):
        """Test cache initialization with defaults."""
        cache = OptimizedCache()
        assert cache.memory_size_mb == 100
        assert cache.enable_tiering is True
        assert cache.stats["hits"] == 0
        assert cache.stats["misses"] == 0

    def test_init_with_custom_settings(self, redis_client):
        """Test cache initialization with custom settings."""
        cache = OptimizedCache(redis_client=redis_client, memory_size_mb=50, enable_tiering=False)
        assert cache.memory_size_mb == 50
        assert cache.enable_tiering is False
        assert cache.redis_client == redis_client

    def test_generate_fast_key(self, optimized_cache):
        """Test fast key generation with xxhash."""
        # Test with string
        key1 = optimized_cache._generate_fast_key("test_key")
        assert isinstance(key1, str)
        assert len(key1) > 0

        # Test with same string produces same key
        key2 = optimized_cache._generate_fast_key("test_key")
        assert key1 == key2

        # Test with different string produces different key
        key3 = optimized_cache._generate_fast_key("different_key")
        assert key1 != key3

    def test_generate_fast_key_fallback(self, optimized_cache):
        """Test key generation fallback to MD5."""
        with patch("prompt_sentinel.cache.optimized_cache.xxhash", None):
            # Should fall back to MD5
            key = optimized_cache._generate_fast_key("test_key")
            expected = hashlib.md5(b"test_key").hexdigest()
            assert key == expected

    @pytest.mark.asyncio
    async def test_get_memory_cache_hit(self, optimized_cache):
        """Test getting value from memory cache."""
        # Pre-populate memory cache
        key = optimized_cache._generate_fast_key("test_key")
        optimized_cache.memory_cache[key] = {"value": "test_value", "timestamp": time.time()}

        # Get from cache
        result = await optimized_cache.get("test_key")

        assert result == {
            "value": "test_value",
            "timestamp": optimized_cache.memory_cache[key]["timestamp"],
        }
        assert optimized_cache.stats["hits"] == 1
        assert optimized_cache.stats["memory_hits"] == 1

    @pytest.mark.asyncio
    async def test_get_redis_cache_hit(self, optimized_cache, redis_client):
        """Test getting value from Redis cache."""
        # Set Redis to return a value
        redis_client.get.return_value = b'{"value": "redis_value"}'

        # Get from cache (not in memory)
        result = await optimized_cache.get("test_key")

        assert result == {"value": "redis_value"}
        assert optimized_cache.stats["hits"] == 1
        assert optimized_cache.stats["redis_hits"] == 1
        # Should be promoted to memory cache
        key = optimized_cache._generate_fast_key("test_key")
        assert key in optimized_cache.memory_cache

    @pytest.mark.asyncio
    async def test_get_cache_miss(self, optimized_cache, redis_client):
        """Test cache miss."""
        redis_client.get.return_value = None

        result = await optimized_cache.get("test_key")

        assert result is None
        assert optimized_cache.stats["misses"] == 1

    @pytest.mark.asyncio
    async def test_set_with_tiering(self, optimized_cache, redis_client):
        """Test setting value with tiering enabled."""
        value = {"data": "test"}

        await optimized_cache.set("test_key", value, tier=CacheTier.BOTH)

        # Should be in memory cache
        key = optimized_cache._generate_fast_key("test_key")
        assert key in optimized_cache.memory_cache
        assert optimized_cache.memory_cache[key] == value

        # Should also be in Redis
        redis_client.set.assert_called_once()

    @pytest.mark.asyncio
    async def test_set_memory_only(self, optimized_cache, redis_client):
        """Test setting value in memory tier only."""
        value = {"data": "test"}

        await optimized_cache.set("test_key", value, tier=CacheTier.MEMORY)

        # Should be in memory cache
        key = optimized_cache._generate_fast_key("test_key")
        assert key in optimized_cache.memory_cache

        # Should not be in Redis
        redis_client.set.assert_not_called()

    @pytest.mark.asyncio
    async def test_set_redis_only(self, optimized_cache, redis_client):
        """Test setting value in Redis tier only."""
        value = {"data": "test"}

        await optimized_cache.set("test_key", value, tier=CacheTier.REDIS, ttl=300)

        # Should not be in memory cache
        key = optimized_cache._generate_fast_key("test_key")
        assert key not in optimized_cache.memory_cache

        # Should be in Redis
        redis_client.set.assert_called_once_with(key, '{"data":"test"}', ex=300)

    @pytest.mark.asyncio
    async def test_delete(self, optimized_cache, redis_client):
        """Test deleting from cache."""
        # Add to memory cache
        key = optimized_cache._generate_fast_key("test_key")
        optimized_cache.memory_cache[key] = {"value": "test"}

        # Delete
        await optimized_cache.delete("test_key")

        # Should be removed from memory
        assert key not in optimized_cache.memory_cache

        # Should be removed from Redis
        redis_client.delete.assert_called_once_with(key)

    @pytest.mark.asyncio
    async def test_get_multi_tier(self, optimized_cache, redis_client):
        """Test multi-tier cache lookup."""
        # Memory miss, Redis hit
        redis_client.get.return_value = b'{"value": "redis_value"}'

        value, tier = await optimized_cache.get_multi_tier("test_key")

        assert value == {"value": "redis_value"}
        assert tier == CacheTier.REDIS

        # Now should be in memory (promoted)
        value2, tier2 = await optimized_cache.get_multi_tier("test_key")
        assert value2 == {"value": "redis_value"}
        assert tier2 == CacheTier.MEMORY

    def test_evict_lru(self, optimized_cache):
        """Test LRU eviction from memory cache."""
        # Fill cache beyond capacity
        for i in range(1000):
            key = f"key_{i}"
            hashed_key = optimized_cache._generate_fast_key(key)
            optimized_cache.memory_cache[hashed_key] = {
                "value": f"value_{i}",
                "size": 1024,  # 1KB each
            }

        # Trigger eviction
        optimized_cache._evict_lru()

        # Cache should be reduced
        assert len(optimized_cache.memory_cache) < 1000

        # Most recent items should remain
        recent_key = optimized_cache._generate_fast_key("key_999")
        assert recent_key in optimized_cache.memory_cache

    @pytest.mark.asyncio
    async def test_warm_cache(self, optimized_cache, redis_client):
        """Test cache warming."""
        patterns = ["user:*", "session:*"]

        # Mock Redis scan
        redis_client.scan = AsyncMock(return_value=(0, [b"user:1", b"user:2", b"session:1"]))
        redis_client.mget = AsyncMock(
            return_value=[b'{"value": "user1"}', b'{"value": "user2"}', b'{"value": "session1"}']
        )

        warmed = await optimized_cache.warm_cache(patterns, max_keys=10)

        assert warmed == 3
        # Keys should be in memory cache
        assert any("user" in str(k) for k in optimized_cache.memory_cache.keys())

    def test_get_stats(self, optimized_cache):
        """Test getting cache statistics."""
        # Populate some stats
        optimized_cache.stats["hits"] = 10
        optimized_cache.stats["misses"] = 5
        optimized_cache.stats["memory_hits"] = 8
        optimized_cache.stats["redis_hits"] = 2

        stats = optimized_cache.get_stats()

        assert stats["hits"] == 10
        assert stats["misses"] == 5
        assert stats["hit_rate"] == 66.67  # 10/(10+5) * 100
        assert stats["memory_hit_rate"] == 80.0  # 8/10 * 100
        assert stats["memory_cache_size"] == 0

    def test_clear_memory_cache(self, optimized_cache):
        """Test clearing memory cache."""
        # Add items to memory cache
        optimized_cache.memory_cache["key1"] = {"value": "test1"}
        optimized_cache.memory_cache["key2"] = {"value": "test2"}

        optimized_cache.clear_memory_cache()

        assert len(optimized_cache.memory_cache) == 0

    @pytest.mark.asyncio
    async def test_concurrent_access(self, optimized_cache):
        """Test concurrent cache access."""

        async def cache_operation(key, value):
            await optimized_cache.set(key, value)
            result = await optimized_cache.get(key)
            return result

        # Run multiple concurrent operations
        tasks = [cache_operation(f"key_{i}", {"value": f"value_{i}"}) for i in range(10)]

        results = await asyncio.gather(*tasks)

        # All operations should succeed
        assert len(results) == 10
        for i, result in enumerate(results):
            assert result == {"value": f"value_{i}"}


class TestBatchCache:
    """Test BatchCache functionality."""

    def test_init(self, redis_client):
        """Test batch cache initialization."""
        cache = BatchCache(redis_client=redis_client, batch_size=20, batch_timeout_ms=200)
        assert cache.batch_size == 20
        assert cache.batch_timeout_ms == 200
        assert cache.redis_client == redis_client

    @pytest.mark.asyncio
    async def test_get_batch(self, batch_cache, redis_client):
        """Test batch get operation."""
        keys = ["key1", "key2", "key3"]
        redis_client.mget.return_value = [b'{"value": "1"}', None, b'{"value": "3"}']

        results = await batch_cache.get_batch(keys)

        assert len(results) == 3
        assert results[0] == {"value": "1"}
        assert results[1] is None
        assert results[2] == {"value": "3"}
        redis_client.mget.assert_called_once()

    @pytest.mark.asyncio
    async def test_set_batch(self, batch_cache, redis_client):
        """Test batch set operation."""
        items = [("key1", {"value": "1"}), ("key2", {"value": "2"}), ("key3", {"value": "3"})]

        pipeline = MagicMock()
        pipeline.set = MagicMock()
        pipeline.execute = AsyncMock(return_value=[True, True, True])
        redis_client.pipeline.return_value = pipeline

        success = await batch_cache.set_batch(items, ttl=300)

        assert success is True
        assert pipeline.set.call_count == 3
        pipeline.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_or_compute_batch(self, batch_cache, redis_client):
        """Test batch get-or-compute operation."""
        keys = ["key1", "key2", "key3"]
        redis_client.mget.return_value = [b'{"value": "cached"}', None, None]

        async def compute_fn(missing_keys):
            return {k: {"value": f"computed_{k}"} for k in missing_keys}

        results = await batch_cache.get_or_compute_batch(keys, compute_fn)

        assert len(results) == 3
        assert results["key1"] == {"value": "cached"}
        assert results["key2"] == {"value": "computed_key2"}
        assert results["key3"] == {"value": "computed_key3"}

    @pytest.mark.asyncio
    async def test_delete_batch(self, batch_cache, redis_client):
        """Test batch delete operation."""
        keys = ["key1", "key2", "key3"]
        redis_client.delete.return_value = 3

        deleted = await batch_cache.delete_batch(keys)

        assert deleted == 3
        redis_client.delete.assert_called_once_with(*keys)

    @pytest.mark.asyncio
    async def test_batch_chunking(self, batch_cache, redis_client):
        """Test automatic chunking for large batches."""
        batch_cache.batch_size = 2  # Small batch size for testing

        keys = ["key1", "key2", "key3", "key4", "key5"]
        redis_client.mget.side_effect = [
            [b'{"value": "1"}', b'{"value": "2"}'],
            [b'{"value": "3"}', b'{"value": "4"}'],
            [b'{"value": "5"}'],
        ]

        results = await batch_cache.get_batch(keys)

        assert len(results) == 5
        assert redis_client.mget.call_count == 3  # Called 3 times due to chunking

    def test_get_stats(self, batch_cache):
        """Test batch cache statistics."""
        batch_cache.stats["batch_gets"] = 10
        batch_cache.stats["batch_sets"] = 5
        batch_cache.stats["total_keys_processed"] = 150

        stats = batch_cache.get_stats()

        assert stats["batch_gets"] == 10
        assert stats["batch_sets"] == 5
        assert stats["avg_batch_size"] == 10.0  # 150 / (10+5)


class TestRequestCoalescer:
    """Test request coalescing functionality."""

    @pytest.mark.asyncio
    async def test_coalesce_requests(self):
        """Test coalescing multiple identical requests."""
        coalescer = RequestCoalescer()

        # Track call count
        call_count = 0

        async def expensive_operation(key):
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(0.01)  # Simulate work
            return f"result_{key}"

        # Make multiple concurrent requests for same key
        tasks = [coalescer.coalesce("key1", lambda: expensive_operation("key1")) for _ in range(5)]

        results = await asyncio.gather(*tasks)

        # All should get same result
        assert all(r == "result_key1" for r in results)
        # Operation should only be called once
        assert call_count == 1

    @pytest.mark.asyncio
    async def test_coalesce_different_keys(self):
        """Test coalescing with different keys."""
        coalescer = RequestCoalescer()

        call_counts = {}

        async def expensive_operation(key):
            call_counts[key] = call_counts.get(key, 0) + 1
            await asyncio.sleep(0.01)
            return f"result_{key}"

        # Make requests for different keys
        tasks = [
            coalescer.coalesce("key1", lambda: expensive_operation("key1")),
            coalescer.coalesce("key2", lambda: expensive_operation("key2")),
            coalescer.coalesce("key1", lambda: expensive_operation("key1")),  # Duplicate
        ]

        results = await asyncio.gather(*tasks)

        assert results[0] == "result_key1"
        assert results[1] == "result_key2"
        assert results[2] == "result_key1"

        # Each key should only be computed once
        assert call_counts["key1"] == 1
        assert call_counts["key2"] == 1

    @pytest.mark.asyncio
    async def test_coalesce_error_handling(self):
        """Test error handling in coalesced requests."""
        coalescer = RequestCoalescer()

        async def failing_operation():
            await asyncio.sleep(0.01)
            raise ValueError("Operation failed")

        # Multiple requests for same failing operation
        tasks = [coalescer.coalesce("fail", failing_operation) for _ in range(3)]

        # All should receive the same error
        with pytest.raises(ValueError) as exc_info:
            await asyncio.gather(*tasks, return_exceptions=False)

        assert "Operation failed" in str(exc_info.value)

    def test_get_stats(self):
        """Test coalescer statistics."""
        coalescer = RequestCoalescer()
        coalescer.stats["total_requests"] = 100
        coalescer.stats["coalesced_requests"] = 30

        stats = coalescer.get_stats()

        assert stats["total_requests"] == 100
        assert stats["coalesced_requests"] == 30
        assert stats["coalesce_rate"] == 30.0  # 30/100 * 100


class TestCacheIntegration:
    """Integration tests for cache system."""

    @pytest.mark.asyncio
    async def test_tiered_cache_flow(self, redis_client):
        """Test complete tiered cache flow."""
        cache = OptimizedCache(redis_client=redis_client)

        # Initial miss
        result = await cache.get("test_key")
        assert result is None
        assert cache.stats["misses"] == 1

        # Set in both tiers
        await cache.set("test_key", {"value": "test"}, tier=CacheTier.BOTH)

        # Memory hit
        result = await cache.get("test_key")
        assert result == {"value": "test"}
        assert cache.stats["memory_hits"] == 1

        # Clear memory cache
        cache.clear_memory_cache()

        # Redis hit (and promotion to memory)
        redis_client.get.return_value = b'{"value": "test"}'
        result = await cache.get("test_key")
        assert result == {"value": "test"}
        assert cache.stats["redis_hits"] == 1

        # Now in memory again
        result = await cache.get("test_key")
        assert cache.stats["memory_hits"] == 2

    @pytest.mark.asyncio
    async def test_batch_operations_with_coalescing(self):
        """Test batch operations with request coalescing."""
        redis_client = AsyncMock()
        redis_client.mget = AsyncMock(return_value=[None] * 5)
        redis_client.pipeline = MagicMock()

        cache = BatchCache(redis_client=redis_client)
        coalescer = RequestCoalescer()

        async def get_batch_coalesced(keys):
            return await coalescer.coalesce(
                f"batch_{','.join(keys)}", lambda: cache.get_batch(keys)
            )

        # Multiple concurrent requests for same batch
        tasks = [get_batch_coalesced(["k1", "k2", "k3"]) for _ in range(3)]

        results = await asyncio.gather(*tasks)

        # All should get same results
        assert all(r == results[0] for r in results)
        # Redis should only be called once
        assert redis_client.mget.call_count == 1

    @pytest.mark.asyncio
    async def test_cache_performance(self):
        """Test cache performance characteristics."""
        cache = OptimizedCache()

        # Measure write performance
        start = time.perf_counter()
        for i in range(1000):
            await cache.set(f"key_{i}", {"value": f"value_{i}"}, tier=CacheTier.MEMORY)
        write_time = time.perf_counter() - start

        # Measure read performance (all hits)
        start = time.perf_counter()
        for i in range(1000):
            await cache.get(f"key_{i}")
        read_time = time.perf_counter() - start

        # Performance assertions
        assert write_time < 1.0  # Should complete in under 1 second
        assert read_time < 0.5  # Reads should be faster
        assert cache.stats["hits"] == 1000
        assert cache.stats["memory_hits"] == 1000
