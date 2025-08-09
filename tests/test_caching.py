"""Tests for caching mechanisms in PromptSentinel."""

import pytest
import asyncio
import time
import hashlib
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta

from prompt_sentinel.cache.cache_manager import CacheManager
from prompt_sentinel.models.schemas import Message, Role, Verdict


class TestCacheManager:
    """Test cache manager functionality."""

    @pytest.fixture
    async def cache_manager(self):
        """Create cache manager instance."""
        manager = CacheManager(
            ttl=60,
            max_size=100,
            enable_redis=False
        )
        await manager.initialize()
        yield manager
        await manager.close()

    @pytest.mark.asyncio
    async def test_cache_set_get(self, cache_manager):
        """Test basic cache set and get operations."""
        key = "test_key"
        value = {"verdict": "ALLOW", "confidence": 0.95}
        
        # Set value
        await cache_manager.set(key, value)
        
        # Get value
        cached = await cache_manager.get(key)
        assert cached == value

    @pytest.mark.asyncio
    async def test_cache_expiration(self, cache_manager):
        """Test cache TTL expiration."""
        # Create cache with short TTL
        cache = CacheManager(ttl=1, max_size=10, enable_redis=False)
        await cache.initialize()
        
        key = "expire_test"
        value = {"data": "test"}
        
        await cache.set(key, value)
        assert await cache.get(key) == value
        
        # Wait for expiration
        await asyncio.sleep(1.1)
        assert await cache.get(key) is None
        
        await cache.close()

    @pytest.mark.asyncio
    async def test_cache_max_size(self, cache_manager):
        """Test cache size limits."""
        cache = CacheManager(ttl=60, max_size=3, enable_redis=False)
        await cache.initialize()
        
        # Fill cache
        for i in range(5):
            await cache.set(f"key_{i}", f"value_{i}")
        
        # Check that old entries are evicted
        assert await cache.get("key_0") is None  # Should be evicted
        assert await cache.get("key_4") == "value_4"  # Should exist
        
        await cache.close()

    @pytest.mark.asyncio
    async def test_cache_clear(self, cache_manager):
        """Test cache clearing."""
        # Add items
        await cache_manager.set("key1", "value1")
        await cache_manager.set("key2", "value2")
        
        # Clear cache
        await cache_manager.clear()
        
        # Check items are gone
        assert await cache_manager.get("key1") is None
        assert await cache_manager.get("key2") is None

    @pytest.mark.asyncio
    async def test_cache_delete(self, cache_manager):
        """Test cache deletion."""
        await cache_manager.set("key1", "value1")
        await cache_manager.set("key2", "value2")
        
        # Delete one key
        await cache_manager.delete("key1")
        
        assert await cache_manager.get("key1") is None
        assert await cache_manager.get("key2") == "value2"

    @pytest.mark.asyncio
    async def test_cache_stats(self, cache_manager):
        """Test cache statistics."""
        # Perform operations
        await cache_manager.set("key1", "value1")
        await cache_manager.get("key1")  # Hit
        await cache_manager.get("key2")  # Miss
        
        stats = await cache_manager.get_stats()
        assert stats["hits"] == 1
        assert stats["misses"] == 1
        assert stats["hit_rate"] == 0.5
        assert stats["size"] == 1


class TestDetectionCaching:
    """Test caching of detection results."""

    @pytest.fixture
    def messages(self):
        """Create test messages."""
        return [
            Message(role=Role.USER, content="What's the weather today?")
        ]

    def _get_cache_key(self, messages, mode="moderate"):
        """Generate cache key for messages."""
        content = "".join(m.content for m in messages)
        return hashlib.md5(f"{content}:{mode}".encode()).hexdigest()

    @pytest.mark.asyncio
    async def test_detection_result_caching(self, messages):
        """Test caching of detection results."""
        from prompt_sentinel.detection.detector import PromptDetector
        
        detector = PromptDetector()
        
        # Mock the actual detection
        with patch.object(detector, "_detect_internal") as mock_detect:
            mock_detect.return_value = AsyncMock(
                verdict=Verdict.ALLOW,
                reasons=[],
                confidence=0.95
            )
            
            # First call - should hit detection
            result1 = await detector.detect(messages)
            assert mock_detect.call_count == 1
            
            # Second call - should hit cache
            result2 = await detector.detect(messages)
            assert mock_detect.call_count == 1  # No additional call
            
            assert result1.verdict == result2.verdict

    @pytest.mark.asyncio
    async def test_cache_invalidation_on_config_change(self):
        """Test cache invalidation when configuration changes."""
        cache = CacheManager(ttl=60, max_size=100, enable_redis=False)
        await cache.initialize()
        
        key = "test_key"
        await cache.set(key, "value1")
        
        # Simulate config change
        await cache.invalidate_pattern("test_*")
        
        assert await cache.get(key) is None
        await cache.close()


class TestRedisCache:
    """Test Redis cache integration."""

    @pytest.mark.asyncio
    @patch("redis.asyncio.Redis")
    async def test_redis_connection(self, mock_redis):
        """Test Redis connection handling."""
        mock_redis_instance = AsyncMock()
        mock_redis.from_url.return_value = mock_redis_instance
        
        cache = CacheManager(
            ttl=60,
            max_size=100,
            enable_redis=True,
            redis_url="redis://localhost:6379"
        )
        
        await cache.initialize()
        mock_redis.from_url.assert_called_once()
        
        await cache.close()

    @pytest.mark.asyncio
    @patch("redis.asyncio.Redis")
    async def test_redis_fallback(self, mock_redis):
        """Test fallback to memory cache when Redis fails."""
        mock_redis.from_url.side_effect = Exception("Connection failed")
        
        cache = CacheManager(
            ttl=60,
            max_size=100,
            enable_redis=True,
            redis_url="redis://localhost:6379"
        )
        
        await cache.initialize()
        
        # Should fall back to memory cache
        await cache.set("key", "value")
        assert await cache.get("key") == "value"
        
        await cache.close()


class TestCacheWarming:
    """Test cache warming strategies."""

    @pytest.mark.asyncio
    async def test_cache_preload(self):
        """Test preloading cache with common patterns."""
        cache = CacheManager(ttl=300, max_size=100, enable_redis=False)
        await cache.initialize()
        
        # Preload common benign prompts
        common_prompts = [
            "What's the weather?",
            "Hello",
            "How are you?",
            "Help me with Python"
        ]
        
        for prompt in common_prompts:
            key = hashlib.md5(prompt.encode()).hexdigest()
            await cache.set(key, {
                "verdict": "ALLOW",
                "confidence": 0.99,
                "preloaded": True
            })
        
        # Check preloaded entries
        for prompt in common_prompts:
            key = hashlib.md5(prompt.encode()).hexdigest()
            result = await cache.get(key)
            assert result["preloaded"] is True
        
        await cache.close()

    @pytest.mark.asyncio
    async def test_cache_refresh(self):
        """Test cache refresh strategy."""
        cache = CacheManager(ttl=60, max_size=100, enable_redis=False)
        await cache.initialize()
        
        key = "refresh_test"
        original_value = {"version": 1, "data": "original"}
        
        await cache.set(key, original_value)
        
        # Simulate refresh
        new_value = {"version": 2, "data": "refreshed"}
        await cache.set(key, new_value, refresh=True)
        
        result = await cache.get(key)
        assert result["version"] == 2
        assert result["data"] == "refreshed"
        
        await cache.close()


class TestCachePerformance:
    """Test cache performance characteristics."""

    @pytest.mark.asyncio
    async def test_cache_lookup_speed(self):
        """Test cache lookup performance."""
        cache = CacheManager(ttl=60, max_size=1000, enable_redis=False)
        await cache.initialize()
        
        # Populate cache
        for i in range(100):
            await cache.set(f"key_{i}", f"value_{i}")
        
        # Measure lookup time
        start = time.perf_counter()
        for i in range(100):
            await cache.get(f"key_{i}")
        elapsed = time.perf_counter() - start
        
        # Should be very fast (< 10ms for 100 lookups)
        assert elapsed < 0.01
        
        await cache.close()

    @pytest.mark.asyncio
    async def test_concurrent_cache_access(self):
        """Test concurrent cache access."""
        cache = CacheManager(ttl=60, max_size=100, enable_redis=False)
        await cache.initialize()
        
        async def cache_operation(i):
            await cache.set(f"key_{i}", f"value_{i}")
            return await cache.get(f"key_{i}")
        
        # Concurrent operations
        tasks = [cache_operation(i) for i in range(50)]
        results = await asyncio.gather(*tasks)
        
        # All operations should succeed
        assert all(r == f"value_{i}" for i, r in enumerate(results))
        
        await cache.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])