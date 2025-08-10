"""Comprehensive tests for the CacheManager module."""

import asyncio
import hashlib
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import redis.asyncio as redis
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError

from prompt_sentinel.cache.cache_manager import CacheManager


class TestCacheManager:
    """Test suite for CacheManager."""

    @pytest.fixture
    def mock_settings(self):
        """Mock settings for testing."""
        settings = MagicMock()
        settings.redis_enabled = True
        settings.redis_host = "localhost"
        settings.redis_port = 6379
        settings.redis_password = None
        return settings

    @pytest.fixture
    def disabled_settings(self):
        """Mock settings with Redis disabled."""
        settings = MagicMock()
        settings.redis_enabled = False
        settings.redis_host = "localhost"
        settings.redis_port = 6379
        settings.redis_password = None
        return settings

    def test_initialization_enabled(self, mock_settings):
        """Test CacheManager initialization when Redis is enabled."""
        with patch("prompt_sentinel.cache.cache_manager.settings", mock_settings):
            with patch.object(CacheManager, "_initialize_client") as mock_init:
                manager = CacheManager()

                assert manager.enabled is True
                assert manager.connected is False
                assert manager.max_ttl == 3600
                assert manager._connection_attempts == 0
                assert manager._max_connection_attempts == 3
                mock_init.assert_called_once()

    def test_initialization_disabled(self, disabled_settings):
        """Test CacheManager initialization when Redis is disabled."""
        with patch("prompt_sentinel.cache.cache_manager.settings", disabled_settings):
            manager = CacheManager()

            assert manager.enabled is False
            assert manager.connected is False
            assert manager.client is None

    @patch("prompt_sentinel.cache.cache_manager.redis.ConnectionPool")
    @patch("prompt_sentinel.cache.cache_manager.redis.Redis")
    def test_initialize_client_success(self, mock_redis_class, mock_pool_class, mock_settings):
        """Test successful Redis client initialization."""
        mock_pool = MagicMock()
        mock_pool_class.return_value = mock_pool
        mock_client = MagicMock()
        mock_redis_class.return_value = mock_client

        with patch("prompt_sentinel.cache.cache_manager.settings", mock_settings):
            manager = CacheManager()

            assert manager.client == mock_client
            mock_pool_class.assert_called_once()
            mock_redis_class.assert_called_once_with(connection_pool=mock_pool)

    @patch("prompt_sentinel.cache.cache_manager.redis.ConnectionPool")
    def test_initialize_client_failure(self, mock_pool_class, mock_settings):
        """Test Redis client initialization failure."""
        mock_pool_class.side_effect = Exception("Connection failed")

        with patch("prompt_sentinel.cache.cache_manager.settings", mock_settings):
            manager = CacheManager()

            assert manager.enabled is False
            assert manager.client is None

    @pytest.mark.asyncio
    async def test_connect_success(self):
        """Test successful Redis connection."""
        manager = CacheManager()
        manager.enabled = True
        manager.client = AsyncMock()
        manager.client.ping = AsyncMock()

        result = await manager.connect()

        assert result is True
        assert manager.connected is True
        assert manager._connection_attempts == 0
        manager.client.ping.assert_called_once()

    @pytest.mark.asyncio
    async def test_connect_not_enabled(self):
        """Test connection attempt when Redis is not enabled."""
        manager = CacheManager()
        manager.enabled = False

        result = await manager.connect()

        assert result is False
        assert manager.connected is False

    @pytest.mark.asyncio
    async def test_connect_no_client(self):
        """Test connection attempt when client is None."""
        manager = CacheManager()
        manager.enabled = True
        manager.client = None

        result = await manager.connect()

        assert result is False
        assert manager.connected is False

    @pytest.mark.asyncio
    async def test_connect_max_attempts_reached(self):
        """Test connection when max attempts are reached."""
        manager = CacheManager()
        manager.enabled = True
        manager.client = AsyncMock()
        manager._connection_attempts = 3
        manager._max_connection_attempts = 3

        result = await manager.connect()

        assert result is False
        assert manager.connected is False

    @pytest.mark.asyncio
    async def test_connect_redis_error(self):
        """Test connection failure due to Redis error."""
        manager = CacheManager()
        manager.enabled = True
        manager.client = AsyncMock()
        manager.client.ping = AsyncMock(side_effect=RedisConnectionError("Connection failed"))

        result = await manager.connect()

        assert result is False
        assert manager.connected is False
        assert manager._connection_attempts == 1

    @pytest.mark.asyncio
    async def test_connect_unexpected_error(self):
        """Test connection failure due to unexpected error."""
        manager = CacheManager()
        manager.enabled = True
        manager.client = AsyncMock()
        manager.client.ping = AsyncMock(side_effect=ValueError("Unexpected error"))

        result = await manager.connect()

        assert result is False
        assert manager.connected is False

    @pytest.mark.asyncio
    async def test_disconnect_success(self):
        """Test successful Redis disconnection."""
        manager = CacheManager()
        manager.client = AsyncMock()
        manager.connected = True
        manager.client.close = AsyncMock()

        await manager.disconnect()

        assert manager.connected is False
        manager.client.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_disconnect_no_client(self):
        """Test disconnection when no client exists."""
        manager = CacheManager()
        manager.client = None
        manager.connected = True

        await manager.disconnect()

        # Should complete without error, but connected stays True since client is None
        # The implementation only sets connected=False if both client and connected are truthy
        assert manager.connected is True

    @pytest.mark.asyncio
    async def test_disconnect_error(self):
        """Test disconnection with client error."""
        manager = CacheManager()
        manager.client = AsyncMock()
        manager.connected = True
        manager.client.close = AsyncMock(side_effect=Exception("Close failed"))

        await manager.disconnect()

        # Should still mark as disconnected despite error
        assert manager.connected is False

    @pytest.mark.asyncio
    async def test_get_or_compute_cache_disabled(self):
        """Test get_or_compute when cache is disabled."""
        manager = CacheManager()
        manager.enabled = False

        compute_func = AsyncMock(return_value="computed_result")

        result = await manager.get_or_compute("test_key", compute_func)

        assert result == "computed_result"
        compute_func.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_or_compute_not_connected(self):
        """Test get_or_compute when not connected to Redis."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = False

        compute_func = AsyncMock(return_value="computed_result")

        result = await manager.get_or_compute("test_key", compute_func)

        assert result == "computed_result"
        compute_func.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_or_compute_cache_hit(self):
        """Test get_or_compute with cache hit."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.get = AsyncMock(return_value={"data": "cached_result"})

        compute_func = AsyncMock()

        result = await manager.get_or_compute("test_key", compute_func)

        assert result == {"data": "cached_result", "_cache_hit": True}
        compute_func.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_or_compute_cache_hit_non_dict(self):
        """Test get_or_compute with cache hit for non-dict value."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.get = AsyncMock(return_value="cached_string")

        compute_func = AsyncMock()

        result = await manager.get_or_compute("test_key", compute_func)

        assert result == "cached_string"
        compute_func.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_or_compute_cache_miss(self):
        """Test get_or_compute with cache miss."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.get = AsyncMock(return_value=None)
        manager.set = AsyncMock()

        compute_func = AsyncMock(return_value="computed_result")

        result = await manager.get_or_compute("test_key", compute_func, ttl=600)

        assert result == "computed_result"
        compute_func.assert_called_once()
        manager.set.assert_called_once_with("test_key", "computed_result", 600)

    @pytest.mark.asyncio
    async def test_get_or_compute_get_error(self):
        """Test get_or_compute when get operation fails."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.get = AsyncMock(side_effect=Exception("Get failed"))
        manager.set = AsyncMock()

        compute_func = AsyncMock(return_value="computed_result")

        result = await manager.get_or_compute("test_key", compute_func)

        assert result == "computed_result"
        compute_func.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_or_compute_compute_error_cache_on_error_true(self):
        """Test get_or_compute when compute fails but cache_on_error=True."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.get = AsyncMock(side_effect=[None, {"data": "stale_cache"}])  # Miss, then stale hit

        compute_func = AsyncMock(side_effect=Exception("Compute failed"))

        result = await manager.get_or_compute("test_key", compute_func, cache_on_error=True)

        assert result == {"data": "stale_cache", "_cache_stale": True}

    @pytest.mark.asyncio
    async def test_get_or_compute_compute_error_no_stale_cache(self):
        """Test get_or_compute when compute fails and no stale cache available."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.get = AsyncMock(return_value=None)  # Always miss

        compute_func = AsyncMock(side_effect=Exception("Compute failed"))

        with pytest.raises(Exception, match="Compute failed"):
            await manager.get_or_compute("test_key", compute_func, cache_on_error=True)

    @pytest.mark.asyncio
    async def test_get_or_compute_set_error(self):
        """Test get_or_compute when set operation fails."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.get = AsyncMock(return_value=None)
        manager.set = AsyncMock(side_effect=Exception("Set failed"))

        compute_func = AsyncMock(return_value="computed_result")

        result = await manager.get_or_compute("test_key", compute_func)

        # Should still return computed result despite cache set failure
        assert result == "computed_result"

    @pytest.mark.asyncio
    async def test_get_success(self):
        """Test successful get operation."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.get = AsyncMock(return_value='{"data": "cached_value"}')

        result = await manager.get("test_key")

        assert result == {"data": "cached_value"}

    @pytest.mark.asyncio
    async def test_get_not_enabled(self):
        """Test get when cache is not enabled."""
        manager = CacheManager()
        manager.enabled = False

        result = await manager.get("test_key")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_not_connected(self):
        """Test get when not connected."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = False

        result = await manager.get("test_key")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_no_client(self):
        """Test get when client is None."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = None

        result = await manager.get("test_key")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_key_not_found(self):
        """Test get when key is not found."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.get = AsyncMock(return_value=None)

        result = await manager.get("nonexistent_key")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_json_decode_error(self):
        """Test get with JSON decode error."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.get = AsyncMock(return_value="invalid json")

        result = await manager.get("test_key")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_redis_error(self):
        """Test get with Redis error."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.get = AsyncMock(side_effect=RedisError("Redis failed"))

        result = await manager.get("test_key")

        assert result is None

    @pytest.mark.asyncio
    async def test_set_success(self):
        """Test successful set operation."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.setex = AsyncMock()

        result = await manager.set("test_key", {"data": "value"}, 300)

        assert result is True
        # Verify the key was hashed
        expected_hash = hashlib.sha256("test_key".encode()).hexdigest()[:16]
        manager.client.setex.assert_called_once_with(
            f"cache:{expected_hash}", 300, '{"data": "value"}'
        )

    @pytest.mark.asyncio
    async def test_set_not_enabled(self):
        """Test set when cache is not enabled."""
        manager = CacheManager()
        manager.enabled = False

        result = await manager.set("test_key", "value")

        assert result is False

    @pytest.mark.asyncio
    async def test_set_not_connected(self):
        """Test set when not connected."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = False

        result = await manager.set("test_key", "value")

        assert result is False

    @pytest.mark.asyncio
    async def test_set_no_client(self):
        """Test set when client is None."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = None

        result = await manager.set("test_key", "value")

        assert result is False

    @pytest.mark.asyncio
    async def test_set_ttl_enforcement(self):
        """Test that TTL is enforced to max_ttl."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.setex = AsyncMock()
        manager.max_ttl = 1000

        # TTL larger than max should be clamped
        await manager.set("test_key", "value", 2000)

        # Should use max_ttl instead of requested TTL
        args = manager.client.setex.call_args[0]
        assert args[1] == 1000  # TTL argument

    @pytest.mark.asyncio
    async def test_set_default_ttl(self):
        """Test set with default TTL."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.setex = AsyncMock()

        await manager.set("test_key", "value")

        # Should use default TTL of 300
        args = manager.client.setex.call_args[0]
        assert args[1] == 300

    @pytest.mark.asyncio
    async def test_set_serialization_error(self):
        """Test set with non-serializable value."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()

        # Object that can't be JSON serialized
        non_serializable = object()

        with patch(
            "prompt_sentinel.cache.cache_manager.json.dumps",
            side_effect=TypeError("Not serializable"),
        ):
            result = await manager.set("test_key", non_serializable)

        assert result is False

    @pytest.mark.asyncio
    async def test_set_redis_error(self):
        """Test set with Redis error."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.setex = AsyncMock(side_effect=RedisError("Redis failed"))

        result = await manager.set("test_key", "value")

        assert result is False

    @pytest.mark.asyncio
    async def test_delete_success(self):
        """Test successful delete operation."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.delete = AsyncMock(return_value=1)

        result = await manager.delete("test_key")

        assert result is True

    @pytest.mark.asyncio
    async def test_delete_not_found(self):
        """Test delete when key is not found."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.delete = AsyncMock(return_value=0)

        result = await manager.delete("nonexistent_key")

        assert result is False

    @pytest.mark.asyncio
    async def test_delete_not_enabled(self):
        """Test delete when cache is not enabled."""
        manager = CacheManager()
        manager.enabled = False

        result = await manager.delete("test_key")

        assert result is False

    @pytest.mark.asyncio
    async def test_delete_redis_error(self):
        """Test delete with Redis error."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.delete = AsyncMock(side_effect=RedisError("Redis failed"))

        result = await manager.delete("test_key")

        assert result is False

    def test_hash_key_with_prefix(self):
        """Test key hashing with prefix."""
        manager = CacheManager()

        result = manager._hash_key("llm:prompt_123")
        expected_hash = hashlib.sha256("llm:prompt_123".encode()).hexdigest()[:16]

        assert result == f"llm:{expected_hash}"

    def test_hash_key_without_prefix(self):
        """Test key hashing without prefix."""
        manager = CacheManager()

        result = manager._hash_key("simple_key")
        expected_hash = hashlib.sha256("simple_key".encode()).hexdigest()[:16]

        assert result == f"cache:{expected_hash}"

    @pytest.mark.asyncio
    async def test_clear_pattern_success(self):
        """Test successful pattern clearing."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.scan = AsyncMock(
            side_effect=[
                (10, ["key1", "key2"]),  # First scan result
                (0, ["key3"]),  # Second scan result (cursor 0 = end)
            ]
        )
        manager.client.delete = AsyncMock(side_effect=[2, 1])  # Delete results

        result = await manager.clear_pattern("test:*")

        assert result == 3  # 2 + 1 deleted keys
        assert manager.client.scan.call_count == 2

    @pytest.mark.asyncio
    async def test_clear_pattern_not_enabled(self):
        """Test clear_pattern when cache is not enabled."""
        manager = CacheManager()
        manager.enabled = False

        result = await manager.clear_pattern("*")

        assert result == 0

    @pytest.mark.asyncio
    async def test_clear_pattern_redis_error(self):
        """Test clear_pattern with Redis error."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.scan = AsyncMock(side_effect=RedisError("Scan failed"))

        result = await manager.clear_pattern("*")

        assert result == 0

    @pytest.mark.asyncio
    async def test_get_stats_disabled(self):
        """Test get_stats when cache is disabled."""
        manager = CacheManager()
        manager.enabled = False

        stats = await manager.get_stats()

        assert stats == {
            "enabled": False,
            "connected": False,
            "message": "Cache disabled in configuration",
        }

    @pytest.mark.asyncio
    async def test_get_stats_not_connected(self):
        """Test get_stats when cache is enabled but not connected."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = False

        stats = await manager.get_stats()

        assert stats == {
            "enabled": True,
            "connected": False,
            "message": "Cache enabled but not connected",
        }

    @pytest.mark.asyncio
    async def test_get_stats_success(self):
        """Test successful get_stats operation."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()

        # Mock Redis INFO responses
        manager.client.info = AsyncMock(
            side_effect=[
                {
                    "keyspace_hits": 100,
                    "keyspace_misses": 20,
                    "evicted_keys": 5,
                    "expired_keys": 10,
                    "uptime_in_seconds": 3600,
                },  # stats
                {"used_memory_human": "1.5MB", "used_memory_peak_human": "2.0MB"},  # memory
                {"db0": {"keys": 50, "expires": 10}},  # keyspace
            ]
        )

        stats = await manager.get_stats()

        assert stats["enabled"] is True
        assert stats["connected"] is True
        assert stats["hits"] == 100
        assert stats["misses"] == 20
        assert stats["hit_rate"] == 83.33  # 100/(100+20)*100
        assert stats["total_keys"] == 50
        assert stats["memory_used"] == "1.5MB"
        assert stats["evicted_keys"] == 5

    @pytest.mark.asyncio
    async def test_get_stats_redis_error(self):
        """Test get_stats with Redis error."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.info = AsyncMock(side_effect=RedisError("Info failed"))

        stats = await manager.get_stats()

        assert stats["enabled"] is True
        assert stats["connected"] is True
        assert "error" in stats

    @pytest.mark.asyncio
    async def test_health_check_disabled(self):
        """Test health_check when cache is disabled."""
        manager = CacheManager()
        manager.enabled = False

        result = await manager.health_check()

        assert result is True  # Disabled cache is considered healthy

    @pytest.mark.asyncio
    async def test_health_check_connected_success(self):
        """Test health_check when connected and ping succeeds."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.ping = AsyncMock()

        result = await manager.health_check()

        assert result is True
        manager.client.ping.assert_called_once()

    @pytest.mark.asyncio
    async def test_health_check_not_connected_reconnect_success(self):
        """Test health_check when not connected but reconnection succeeds."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = False
        manager.connect = AsyncMock(return_value=True)

        result = await manager.health_check()

        assert result is True
        manager.connect.assert_called_once()

    @pytest.mark.asyncio
    async def test_health_check_ping_failure(self):
        """Test health_check when ping fails."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.ping = AsyncMock(side_effect=RedisError("Ping failed"))

        result = await manager.health_check()

        assert result is False

    @pytest.mark.asyncio
    async def test_health_check_reconnect_failure(self):
        """Test health_check when not connected and reconnection fails."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = False
        manager.connect = AsyncMock(return_value=False)

        result = await manager.health_check()

        assert result is False

    @pytest.mark.asyncio
    async def test_get_or_compute_stale_cache_error_in_get(self):
        """Test get_or_compute when stale cache get fails during error handling."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True

        # First get returns None (cache miss), second get fails (stale cache attempt)
        manager.get = AsyncMock(side_effect=[None, Exception("Stale get failed")])

        compute_func = AsyncMock(side_effect=Exception("Compute failed"))

        with pytest.raises(Exception, match="Compute failed"):
            await manager.get_or_compute("test_key", compute_func, cache_on_error=True)

    def test_hash_key_edge_cases(self):
        """Test key hashing with edge cases."""
        manager = CacheManager()

        # Empty string
        result = manager._hash_key("")
        expected_hash = hashlib.sha256("".encode()).hexdigest()[:16]
        assert result == f"cache:{expected_hash}"

        # Multiple colons
        result = manager._hash_key("prefix:sub:key")
        expected_hash = hashlib.sha256("prefix:sub:key".encode()).hexdigest()[:16]
        assert result == f"prefix:{expected_hash}"

        # Just colon
        result = manager._hash_key(":")
        expected_hash = hashlib.sha256(":".encode()).hexdigest()[:16]
        assert result == f":{expected_hash}"

    @pytest.mark.asyncio
    async def test_clear_pattern_with_hashing(self):
        """Test clear_pattern with pattern that gets hashed."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()
        manager.client.scan = AsyncMock(return_value=(0, []))  # Empty result
        manager.client.delete = AsyncMock()

        # Pattern without wildcard should be hashed
        await manager.clear_pattern("specific:key")

        expected_hash = hashlib.sha256("specific:key".encode()).hexdigest()[:16]
        expected_pattern = f"specific:{expected_hash}"
        manager.client.scan.assert_called_with(0, match=expected_pattern, count=100)

    @pytest.mark.asyncio
    async def test_get_stats_zero_operations(self):
        """Test get_stats with zero cache operations (hit rate calculation)."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()

        # Mock Redis INFO responses with zero hits and misses
        manager.client.info = AsyncMock(
            side_effect=[
                {
                    "keyspace_hits": 0,
                    "keyspace_misses": 0,
                    "evicted_keys": 0,
                    "expired_keys": 0,
                    "uptime_in_seconds": 0,
                },  # stats
                {"used_memory_human": "0MB", "used_memory_peak_human": "0MB"},  # memory
                {},  # empty keyspace
            ]
        )

        stats = await manager.get_stats()

        assert stats["hit_rate"] == 0  # Should handle division by zero

    @pytest.mark.asyncio
    async def test_get_stats_complex_keyspace(self):
        """Test get_stats with complex keyspace structure."""
        manager = CacheManager()
        manager.enabled = True
        manager.connected = True
        manager.client = AsyncMock()

        manager.client.info = AsyncMock(
            side_effect=[
                {"keyspace_hits": 50, "keyspace_misses": 50},  # stats
                {"used_memory_human": "1MB"},  # memory
                {  # Complex keyspace with multiple databases
                    "db0": {"keys": 10, "expires": 5},
                    "db1": {"keys": 20, "expires": 10},
                    "non_dict_value": "should_be_ignored",
                },
            ]
        )

        stats = await manager.get_stats()

        assert stats["total_keys"] == 30  # 10 + 20, non-dict ignored
