"""Extended comprehensive tests for Redis cache functionality.

Tests additional cache manager features to improve test coverage.
"""

import json
from unittest.mock import AsyncMock, patch

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from prompt_sentinel.cache.cache_manager import CacheManager
from prompt_sentinel.config.settings import settings


class TestCacheManagerExtended:
    """Extended test suite for cache manager functionality."""

    @pytest.fixture
    async def cache_manager(self):
        """Create a cache manager instance for testing."""
        manager = CacheManager()
        yield manager
        # Cleanup
        if manager.connected:
            await manager.disconnect()

    @pytest.mark.asyncio
    async def test_initialize_client_success(self):
        """Test successful Redis client initialization."""
        with patch.object(settings, "redis_enabled", True):
            with patch("redis.asyncio.ConnectionPool") as mock_pool:
                with patch("redis.asyncio.Redis") as mock_redis:
                    manager = CacheManager()

                    mock_pool.assert_called_once()
                    mock_redis.assert_called_once_with(connection_pool=mock_pool.return_value)
                    assert manager.client is not None

    @pytest.mark.asyncio
    async def test_initialize_client_failure(self):
        """Test Redis client initialization failure."""
        with patch.object(settings, "redis_enabled", True):
            with patch("redis.asyncio.ConnectionPool", side_effect=Exception("Connection failed")):
                manager = CacheManager()

                assert not manager.enabled
                assert manager.client is None

    @pytest.mark.asyncio
    async def test_connect_success(self):
        """Test successful Redis connection."""
        manager = CacheManager()
        manager.enabled = True
        manager.client = AsyncMock()
        manager.client.ping = AsyncMock(return_value=True)

        result = await manager.connect()

        assert result is True
        assert manager.connected is True
        manager.client.ping.assert_called_once()

    @pytest.mark.asyncio
    async def test_connect_failure(self):
        """Test Redis connection failure."""
        manager = CacheManager()
        manager.enabled = True
        manager.client = AsyncMock()
        manager.client.ping = AsyncMock(side_effect=RedisConnectionError("Connection failed"))

        result = await manager.connect()

        assert result is False
        assert manager.connected is False

    @pytest.mark.asyncio
    async def test_connect_max_attempts(self):
        """Test max connection attempts limit."""
        manager = CacheManager()
        manager.enabled = True
        manager.client = AsyncMock()
        manager._connection_attempts = 3

        result = await manager.connect()

        assert result is False
        assert not manager.client.ping.called

    @pytest.mark.asyncio
    async def test_disconnect(self):
        """Test Redis disconnection."""
        manager = CacheManager()
        manager.connected = True
        manager.client = AsyncMock()

        await manager.disconnect()

        assert manager.connected is False
        manager.client.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_disconnect_no_client(self):
        """Test disconnect when no client exists."""
        manager = CacheManager()
        manager.connected = True
        manager.client = None

        await manager.disconnect()  # Should not raise an exception

        # When client is None, connected state doesn't change
        assert manager.connected is True

    @pytest.mark.asyncio
    async def test_set_with_expiration(self):
        """Test setting cache value with custom expiration."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.setex = AsyncMock(return_value=True)

        result = await manager.set("test_key", {"data": "value"}, 300)

        assert result is True
        # Verify setex was called with hashed key and JSON data
        manager.client.setex.assert_called_once()
        call_args = manager.client.setex.call_args[0]
        assert len(call_args) == 3
        # Key should be hashed
        assert call_args[0] != "test_key"
        # TTL should be set
        assert call_args[1] == 300
        # Value should be JSON
        assert json.loads(call_args[2]) == {"data": "value"}

    @pytest.mark.asyncio
    async def test_set_ttl_enforcement(self):
        """Test TTL enforcement (max 1 hour)."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.setex = AsyncMock(return_value=True)

        # Try to set TTL longer than max
        await manager.set("test_key", "value", 5000)

        # Should be capped at max_ttl
        call_args = manager.client.setex.call_args[0]
        assert call_args[1] == manager.max_ttl

    @pytest.mark.asyncio
    async def test_get_existing_value(self):
        """Test getting existing cached value."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.get = AsyncMock(return_value='{"data": "cached_value"}')

        result = await manager.get("test_key")

        assert result == {"data": "cached_value"}

    @pytest.mark.asyncio
    async def test_get_nonexistent_value(self):
        """Test getting non-existent cached value."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.get = AsyncMock(return_value=None)

        result = await manager.get("test_key")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_json_decode_error(self):
        """Test handling JSON decode errors."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.get = AsyncMock(return_value="invalid_json")

        result = await manager.get("test_key")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_or_compute_cache_hit(self):
        """Test get_or_compute with cache hit."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.get = AsyncMock(return_value='{"result": "cached"}')

        compute_func = AsyncMock()
        result = await manager.get_or_compute("test_key", compute_func)

        assert result == {"result": "cached", "_cache_hit": True}
        compute_func.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_or_compute_cache_miss(self):
        """Test get_or_compute with cache miss."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.get = AsyncMock(return_value=None)
        manager.client.setex = AsyncMock(return_value=True)

        compute_func = AsyncMock(return_value={"result": "computed"})
        result = await manager.get_or_compute("test_key", compute_func, ttl=600)

        assert result == {"result": "computed"}
        compute_func.assert_called_once()
        manager.client.setex.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_or_compute_cache_on_error(self):
        """Test get_or_compute with cache_on_error feature."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()

        # First call returns None (cache miss), second call returns stale data
        manager.client.get = AsyncMock(side_effect=[None, '{"result": "stale"}'])
        compute_func = AsyncMock(side_effect=Exception("Compute failed"))

        result = await manager.get_or_compute("test_key", compute_func, cache_on_error=True)

        assert result == {"result": "stale", "_cache_stale": True}

    @pytest.mark.asyncio
    async def test_delete_key(self):
        """Test deleting cache key."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.delete = AsyncMock(return_value=1)

        result = await manager.delete("test_key")

        assert result is True
        manager.client.delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_key_not_found(self):
        """Test deleting non-existent key."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.delete = AsyncMock(return_value=0)

        result = await manager.delete("test_key")

        assert result is False

    @pytest.mark.asyncio
    async def test_clear_pattern_success(self):
        """Test clearing keys by pattern."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        # Mock scan method which returns (cursor, keys)
        manager.client.scan = AsyncMock(return_value=(0, ["key1", "key2", "key3"]))
        manager.client.delete = AsyncMock(return_value=3)

        result = await manager.clear_pattern("test_*")

        assert result == 3
        manager.client.scan.assert_called_once_with(0, match="test_*", count=100)
        manager.client.delete.assert_called_once_with("key1", "key2", "key3")

    @pytest.mark.asyncio
    async def test_clear_pattern_no_keys(self):
        """Test clearing pattern with no matching keys."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        # Mock scan method returning no keys
        manager.client.scan = AsyncMock(return_value=(0, []))
        manager.client.delete = AsyncMock()

        result = await manager.clear_pattern("test_*")

        assert result == 0
        assert not manager.client.delete.called

    @pytest.mark.asyncio
    async def test_get_stats_connected(self):
        """Test getting cache statistics when connected."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        
        # Mock info method to return different values based on argument
        def info_side_effect(category):
            if category == "stats":
                return {"keyspace_hits": 500, "keyspace_misses": 100, "evicted_keys": 0, "expired_keys": 0, "uptime_in_seconds": 3600}
            elif category == "memory":
                return {"used_memory_human": "1MB", "used_memory_peak_human": "2MB"}
            elif category == "keyspace":
                return {}
            return {}
        
        manager.client.info = AsyncMock(side_effect=info_side_effect)

        stats = await manager.get_stats()

        assert stats["connected"] is True
        assert stats["hits"] == 500
        assert stats["misses"] == 100
        assert stats["hit_rate"] == 83.33  # 500/(500+100) * 100
        assert stats["memory_used"] == "1MB"

    @pytest.mark.asyncio
    async def test_get_stats_not_connected(self):
        """Test getting cache statistics when not connected."""
        manager = CacheManager()
        manager.enabled = False

        stats = await manager.get_stats()

        assert stats["connected"] is False
        assert stats["enabled"] is False

    @pytest.mark.asyncio
    async def test_health_check_connected(self):
        """Test health check when connected."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.ping = AsyncMock(return_value=True)

        result = await manager.health_check()

        assert result is True

    @pytest.mark.asyncio
    async def test_health_check_not_connected(self):
        """Test health check when not connected."""
        manager = CacheManager()
        manager.enabled = False

        result = await manager.health_check()

        # When cache is disabled, health check returns True (not a problem)
        assert result is True

    def test_hash_key(self):
        """Test key hashing functionality."""
        manager = CacheManager()

        key1 = manager._hash_key("test_key")
        key2 = manager._hash_key("test_key")
        key3 = manager._hash_key("different_key")

        # Same input should produce same hash
        assert key1 == key2
        # Different input should produce different hash
        assert key1 != key3
        # Hash should have format "prefix:hash"
        assert ":" in key1
        prefix, hash_part = key1.split(":", 1)
        # Hash part should be hex string
        assert all(c in "0123456789abcdef" for c in hash_part)

    @pytest.mark.asyncio
    async def test_operation_when_disabled(self):
        """Test that operations work gracefully when cache is disabled."""
        manager = CacheManager()
        manager.enabled = False

        # All operations should work without Redis
        result = await manager.set("key", "value")
        assert result is False

        result = await manager.get("key")
        assert result is None

        compute_func = AsyncMock(return_value="computed")
        result = await manager.get_or_compute("key", compute_func)
        assert result == "computed"

        result = await manager.delete("key")
        assert result is False

        result = await manager.clear_pattern("*")
        assert result == 0

        stats = await manager.get_stats()
        assert not stats["connected"]

    @pytest.mark.asyncio
    async def test_set_error_handling(self):
        """Test error handling in set method."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.setex = AsyncMock(side_effect=RedisConnectionError("Connection lost"))

        result = await manager.set("test_key", "value")

        # Should return False on error but not raise exception
        assert result is False

    @pytest.mark.asyncio
    async def test_get_error_handling(self):
        """Test error handling in get method."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.get = AsyncMock(side_effect=RedisConnectionError("Connection lost"))

        result = await manager.get("test_key")

        # Should return None on error
        assert result is None


class TestCacheIntegrationExtended:
    """Extended integration tests for cache with other components."""

    @pytest.mark.asyncio
    async def test_get_or_compute_with_compute_error(self):
        """Test get_or_compute when compute function fails."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.get = AsyncMock(return_value=None)

        compute_func = AsyncMock(side_effect=Exception("Compute failed"))

        with pytest.raises(Exception, match="Compute failed"):
            await manager.get_or_compute("test_key", compute_func)

    @pytest.mark.asyncio
    async def test_error_recovery(self):
        """Test cache recovery after Redis errors."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()

        # First call fails
        manager.client.get = AsyncMock(side_effect=RedisConnectionError("Connection lost"))

        compute_func = AsyncMock(return_value="computed_result")
        result = await manager.get_or_compute("test_key", compute_func)

        # Should fall back to computation
        assert result == "computed_result"
        compute_func.assert_called_once()
