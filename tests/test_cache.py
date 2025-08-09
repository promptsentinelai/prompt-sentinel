"""Tests for Redis cache functionality.

Tests both with and without Redis to ensure the system works in all scenarios.
"""

from unittest.mock import AsyncMock, patch

import pytest

from prompt_sentinel.cache.cache_manager import CacheManager
from prompt_sentinel.config.settings import settings


class TestCacheManager:
    """Test suite for cache manager functionality."""

    @pytest.fixture
    async def cache_manager(self):
        """Create a cache manager instance for testing."""
        manager = CacheManager()
        yield manager
        # Cleanup
        if manager.connected:
            await manager.disconnect()

    @pytest.mark.asyncio
    async def test_cache_disabled(self):
        """Test that cache manager works when Redis is disabled."""
        with patch.object(settings, "redis_enabled", False):
            manager = CacheManager()
            assert not manager.enabled
            assert not manager.connected

            # Should compute directly without caching
            compute_func = AsyncMock(return_value="result")
            result = await manager.get_or_compute("test_key", compute_func)

            assert result == "result"
            compute_func.assert_called_once()

    @pytest.mark.asyncio
    async def test_cache_connection_failure(self):
        """Test graceful fallback when Redis connection fails."""
        with patch.object(settings, "redis_enabled", True):
            manager = CacheManager()
            manager.enabled = True
            manager.connected = False  # Simulate connection failure

            # Should still compute result
            compute_func = AsyncMock(return_value="computed_value")
            result = await manager.get_or_compute("test_key", compute_func)

            assert result == "computed_value"
            compute_func.assert_called_once()

    @pytest.mark.asyncio
    async def test_cache_hit(self):
        """Test cache hit scenario."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True

        # Mock Redis client
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value='{"value": "cached_result"}')
        manager.client = mock_client

        # Should return cached value without computing
        compute_func = AsyncMock(return_value="new_result")
        result = await manager.get_or_compute("test_key", compute_func)

        # Check that cache metadata was added
        assert result["value"] == "cached_result"
        assert result["_cache_hit"]
        compute_func.assert_not_called()

    @pytest.mark.asyncio
    async def test_cache_miss(self):
        """Test cache miss scenario."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True

        # Mock Redis client
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=None)  # Cache miss
        mock_client.setex = AsyncMock(return_value=True)
        manager.client = mock_client

        # Should compute and cache result
        compute_func = AsyncMock(return_value="computed_result")
        result = await manager.get_or_compute("test_key", compute_func, ttl=300)

        assert result == "computed_result"
        compute_func.assert_called_once()
        mock_client.setex.assert_called_once()

    @pytest.mark.asyncio
    async def test_cache_on_error(self):
        """Test returning stale cache when compute fails."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True

        # Mock Redis client
        mock_client = AsyncMock()
        # First call returns None (miss), second returns stale data
        mock_client.get = AsyncMock(side_effect=[None, '{"value": "stale_data"}'])
        manager.client = mock_client

        # Compute function that fails
        compute_func = AsyncMock(side_effect=Exception("Compute failed"))

        # Should return stale cache on error
        result = await manager.get_or_compute("test_key", compute_func, cache_on_error=True)

        # Check that stale cache metadata was added
        assert result["value"] == "stale_data"
        assert result["_cache_stale"]

    def test_hash_key(self):
        """Test that cache keys are properly hashed."""
        manager = CacheManager()

        # Test basic hashing
        key1 = manager._hash_key("test:sensitive_data")
        assert "sensitive_data" not in key1
        assert key1.startswith("test:")

        # Test consistent hashing
        key2 = manager._hash_key("test:sensitive_data")
        assert key1 == key2

        # Test different keys produce different hashes
        key3 = manager._hash_key("test:other_data")
        assert key1 != key3

    @pytest.mark.asyncio
    async def test_max_ttl_enforcement(self):
        """Test that maximum TTL is enforced."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.max_ttl = 3600  # 1 hour max

        # Mock Redis client
        mock_client = AsyncMock()
        mock_client.setex = AsyncMock(return_value=True)
        manager.client = mock_client

        # Try to set with TTL > max
        await manager.set("test_key", "value", ttl=7200)

        # Should cap at max_ttl
        mock_client.setex.assert_called_once()
        call_args = mock_client.setex.call_args[0]
        assert call_args[1] == 3600  # TTL capped at max

    @pytest.mark.asyncio
    async def test_clear_pattern(self):
        """Test clearing cache entries by pattern."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True

        # Mock Redis client
        mock_client = AsyncMock()
        mock_client.scan = AsyncMock(return_value=(0, ["key1", "key2", "key3"]))
        mock_client.delete = AsyncMock(return_value=3)
        manager.client = mock_client

        # Clear pattern
        count = await manager.clear_pattern("test:*")

        assert count == 3
        mock_client.scan.assert_called_once()
        mock_client.delete.assert_called_once_with("key1", "key2", "key3")

    @pytest.mark.asyncio
    async def test_get_stats(self):
        """Test retrieving cache statistics."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True

        # Mock Redis client
        mock_client = AsyncMock()
        mock_client.info = AsyncMock(
            side_effect=[
                {"keyspace_hits": 100, "keyspace_misses": 50, "evicted_keys": 5},  # stats
                {"used_memory_human": "10MB", "used_memory_peak_human": "15MB"},  # memory
                {"db0": {"keys": 42}},  # keyspace
            ]
        )
        manager.client = mock_client

        # Get stats
        stats = await manager.get_stats()

        assert stats["enabled"]
        assert stats["connected"]
        assert stats["hits"] == 100
        assert stats["misses"] == 50
        assert stats["hit_rate"] == 66.67  # 100/(100+50) * 100
        assert stats["total_keys"] == 42
        assert stats["memory_used"] == "10MB"

    @pytest.mark.asyncio
    async def test_health_check(self):
        """Test health check functionality."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True

        # Mock Redis client
        mock_client = AsyncMock()
        mock_client.ping = AsyncMock(return_value=True)
        manager.client = mock_client

        # Health check should succeed
        is_healthy = await manager.health_check()
        assert is_healthy

        # Test failed health check
        mock_client.ping = AsyncMock(side_effect=Exception("Connection lost"))
        is_healthy = await manager.health_check()
        assert not is_healthy


class TestCacheIntegration:
    """Integration tests for cache with LLM classifier."""

    @pytest.mark.asyncio
    async def test_llm_classifier_caching(self):
        """Test that LLM classifier properly uses caching."""
        from prompt_sentinel.detection.llm_classifier import LLMClassifierManager
        from prompt_sentinel.models.schemas import Message, Role, Verdict

        # Create classifier with mocked provider
        with patch("prompt_sentinel.detection.llm_classifier.cache_manager") as mock_cache:
            mock_cache.enabled = True
            mock_cache.get_or_compute = AsyncMock(return_value=(Verdict.ALLOW, [], 0.95))

            classifier = LLMClassifierManager()
            messages = [Message(role=Role.USER, content="Test prompt")]

            # Classify with caching
            result = await classifier.classify(messages, use_cache=True)

            # Should use cache
            mock_cache.get_or_compute.assert_called_once()
            assert result[0] == Verdict.ALLOW

    @pytest.mark.asyncio
    async def test_llm_classifier_without_cache(self):
        """Test that LLM classifier works without caching."""
        from prompt_sentinel.detection.llm_classifier import LLMClassifierManager
        from prompt_sentinel.models.schemas import Message, Role, Verdict

        with patch("prompt_sentinel.detection.llm_classifier.cache_manager") as mock_cache:
            mock_cache.enabled = False

            # Mock provider
            classifier = LLMClassifierManager()
            classifier.providers = {}  # No providers = returns ALLOW

            messages = [Message(role=Role.USER, content="Test prompt")]

            # Classify without caching
            result = await classifier.classify(messages, use_cache=False)

            # Should not use cache
            mock_cache.get_or_compute.assert_not_called()
            assert result[0] == Verdict.ALLOW
