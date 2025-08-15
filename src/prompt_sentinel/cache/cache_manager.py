# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Optional Redis cache manager with graceful fallback.

This module provides caching functionality that enhances performance but is not
required for the system to function. If Redis is unavailable or disabled,
all operations gracefully fall back to direct computation.

Key features:
- Automatic fallback when Redis is unavailable
- Secure key hashing to avoid storing sensitive data
- Maximum TTL enforcement for security
- Connection pooling and health checks
- Cache statistics and monitoring
"""

import hashlib
import json
import logging
from collections.abc import Callable
from typing import Any, TypeVar

import redis.asyncio as redis
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import RedisError

from prompt_sentinel.config.settings import settings

logger = logging.getLogger(__name__)

T = TypeVar("T")


class CacheManager:
    """
    Optional caching layer for PromptSentinel.

    Provides transparent caching with graceful degradation when Redis
    is unavailable. All methods handle Redis failures silently and
    fall back to direct computation.

    Security features:
    - Keys are hashed to avoid storing sensitive data
    - Maximum TTL enforced (1 hour)
    - No persistence to disk (ephemeral only)

    Attributes:
        enabled: Whether caching is enabled in configuration
        connected: Whether Redis is currently connected
        client: Redis client instance (if connected)
    """

    def __init__(self) -> None:
        """Initialize cache manager with optional Redis connection."""
        self.enabled = settings.redis_enabled
        self.client: redis.Redis | None = None
        self.connected = False
        self.max_ttl = 3600  # 1 hour max for security
        self._connection_attempts = 0
        self._max_connection_attempts = 3
        self.pool: redis.ConnectionPool | None = None  # Store reference to connection pool

        if self.enabled:
            self._initialize_client()

    def _initialize_client(self) -> None:
        """Initialize Redis client with connection pooling."""
        try:
            # Create connection pool for better resource management
            # Pool size based on expected concurrency
            pool_size = getattr(settings, "redis_pool_size", 20)
            # pool_timeout = getattr(settings, "redis_pool_timeout", 5)  # Reserved for future use

            pool = redis.ConnectionPool(
                host=settings.redis_host,
                port=settings.redis_port,
                password=settings.redis_password if settings.redis_password else None,
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2,
                socket_keepalive=True,
                socket_keepalive_options={},
                max_connections=pool_size,  # Configurable pool size
                health_check_interval=30,
                retry_on_timeout=False,
                retry_on_error=[RedisConnectionError],
                connection_pool_kwargs={
                    "max_idle_time": 60,  # Close idle connections after 60s
                    "retry_on_timeout": True,
                },
            )
            self.pool = pool  # Store pool reference for monitoring
            self.client = redis.Redis(connection_pool=pool)
            logger.debug(f"Redis client initialized with pool size {pool_size}")
        except Exception as e:
            logger.warning(f"Redis client initialization failed: {e}")
            self.enabled = False
            self.client = None

    async def connect(self) -> bool:
        """
        Test Redis connection and mark as connected if successful.

        Returns:
            bool: True if connected successfully, False otherwise
        """
        if not self.enabled or not self.client:
            return False

        if self._connection_attempts >= self._max_connection_attempts:
            logger.debug("Max connection attempts reached, skipping")
            return False

        try:
            self._connection_attempts += 1
            await self.client.ping()
            self.connected = True
            self._connection_attempts = 0  # Reset on success
            logger.info("Redis cache connected successfully")
            return True
        except (RedisError, RedisConnectionError, OSError) as e:
            logger.warning(f"Redis not available: {e}. Running without cache.")
            self.connected = False
            return False
        except Exception as e:
            logger.error(f"Unexpected error connecting to Redis: {e}")
            self.connected = False
            return False

    async def disconnect(self) -> None:
        """Gracefully disconnect from Redis."""
        if self.client and self.connected:
            try:
                await self.client.close()
                logger.info("Redis cache disconnected")
            except Exception as e:
                logger.debug(f"Error disconnecting from Redis: {e}")
            finally:
                self.connected = False

    async def get_or_compute(
        self, key: str, compute_func: Callable, ttl: int = 300, cache_on_error: bool = False
    ) -> Any:
        """
        Try to get value from cache, compute if missing.

        This is the main method for cached operations. It handles all
        failure scenarios gracefully and ensures the system continues
        to work even if Redis is unavailable.

        Args:
            key: Cache key (will be hashed for security)
            compute_func: Async function to compute value if not cached
            ttl: Time to live in seconds (capped at max_ttl)
            cache_on_error: Whether to return stale cache on compute error

        Returns:
            Cached or computed value

        Example:
            result = await cache_manager.get_or_compute(
                key="llm:prompt_hash",
                compute_func=lambda: classify_prompt(prompt),
                ttl=3600
            )
        """
        # If caching disabled or not connected, just compute
        if not self.enabled or not self.connected:
            return await compute_func()

        # Try to get from cache
        try:
            cached = await self.get(key)
            if cached is not None:
                logger.debug(f"Cache hit for key pattern: {key.split(':')[0]}")
                # Add cache metadata if dict
                if isinstance(cached, dict):
                    cached["_cache_hit"] = True
                return cached
        except Exception as e:
            logger.debug(f"Cache get failed: {e}")
            # Continue to compute

        # Compute the result
        try:
            result = await compute_func()
        except Exception:
            if cache_on_error:
                # Try to return cached version even if expired
                try:
                    cached = await self.get(key, ignore_expiry=True)
                    if cached:
                        logger.warning("Returning stale cache due to compute error")
                        if isinstance(cached, dict):
                            cached["_cache_stale"] = True
                        return cached
                except Exception:
                    logger.debug("Cache stale check failed, re-raising original error")
            raise

        # Try to cache the result, but don't fail if Redis is down
        try:
            await self.set(key, result, ttl)
        except Exception as e:
            logger.debug(f"Cache set failed: {e}")
            # Result is still valid, just not cached

        return result

    async def get(self, key: str, ignore_expiry: bool = False) -> Any | None:
        """
        Get value from cache.

        Args:
            key: Cache key (will be hashed)
            ignore_expiry: Whether to return expired values

        Returns:
            Cached value or None if not found/error
        """
        if not self.enabled or not self.connected or not self.client:
            return None

        try:
            hashed_key = self._hash_key(key)
            value = await self.client.get(hashed_key)
            if value:
                return json.loads(value)
        except json.JSONDecodeError as e:
            logger.warning(f"Cache value decode error for {key[:20]}: {e}")
        except Exception as e:
            logger.debug(f"Cache get error: {e}")

        return None

    async def set(self, key: str, value: Any, ttl: int | None = None) -> bool:
        """
        Set value in cache with TTL.

        Args:
            key: Cache key (will be hashed)
            value: Value to cache (must be JSON serializable)
            ttl: Time to live in seconds

        Returns:
            True if cached successfully, False otherwise
        """
        if not self.enabled or not self.connected or not self.client:
            return False

        # Enforce maximum TTL for security
        ttl = min(ttl or 300, self.max_ttl)

        try:
            hashed_key = self._hash_key(key)
            serialized = json.dumps(value, default=str)
            await self.client.setex(hashed_key, ttl, serialized)
            logger.debug(f"Cached key pattern: {key.split(':')[0]} with TTL: {ttl}s")
            return True
        except (TypeError, ValueError) as e:
            logger.warning(f"Cache serialization error: {e}")
            return False
        except Exception as e:
            logger.debug(f"Cache set error: {e}")
            return False

    async def delete(self, key: str) -> bool:
        """
        Delete a specific key from cache.

        Args:
            key: Cache key to delete

        Returns:
            True if deleted, False otherwise
        """
        if not self.enabled or not self.connected or not self.client:
            return False

        try:
            hashed_key = self._hash_key(key)
            result = await self.client.delete(hashed_key)
            return result > 0
        except Exception as e:
            logger.debug(f"Cache delete error: {e}")
            return False

    def _hash_key(self, key: str) -> str:
        """
        Hash cache keys for security.

        Prevents sensitive data from being stored as Redis keys.
        Maintains prefix for key organization.

        Args:
            key: Original cache key

        Returns:
            Hashed key with preserved prefix
        """
        # Extract prefix for organization (e.g., "llm", "detect", "pattern")
        parts = key.split(":", 1)
        prefix = parts[0] if len(parts) > 1 else "cache"

        # Hash the full key for security
        key_hash = hashlib.sha256(key.encode()).hexdigest()[:16]

        return f"{prefix}:{key_hash}"

    async def clear_pattern(self, pattern: str = "*") -> int:
        """
        Clear all keys matching a pattern.

        Args:
            pattern: Redis pattern (e.g., "llm:*", "*")

        Returns:
            Number of keys deleted
        """
        if not self.enabled or not self.connected or not self.client:
            return 0

        try:
            # For safety, hash common prefixes
            if ":" in pattern and not pattern.endswith("*"):
                pattern = self._hash_key(pattern)

            cursor = 0
            deleted = 0

            # Use SCAN for better performance with large keysets
            while True:
                cursor, keys = await self.client.scan(cursor, match=pattern, count=100)
                if keys:
                    deleted += await self.client.delete(*keys)
                if cursor == 0:
                    break

            logger.info(f"Cleared {deleted} cache entries matching pattern: {pattern}")
            return deleted
        except Exception as e:
            logger.warning(f"Cache clear failed: {e}")
            return 0

    async def get_stats(self) -> dict[str, Any]:
        """
        Get cache statistics for monitoring.

        Returns:
            Dictionary with cache stats or error status
        """
        if not self.enabled:
            return {
                "enabled": False,
                "connected": False,
                "message": "Cache disabled in configuration",
            }

        if not self.connected or not self.client:
            return {
                "enabled": True,
                "connected": False,
                "message": "Cache enabled but not connected",
            }

        try:
            # Get Redis INFO stats
            info = await self.client.info("stats")
            memory = await self.client.info("memory")
            keyspace = await self.client.info("keyspace")

            # Calculate hit rate
            hits = info.get("keyspace_hits", 0)
            misses = info.get("keyspace_misses", 0)
            total_ops = hits + misses
            hit_rate = (hits / total_ops * 100) if total_ops > 0 else 0

            # Get total keys
            total_keys = 0
            for db_info in keyspace.values():
                if isinstance(db_info, dict) and "keys" in db_info:
                    total_keys += db_info["keys"]

            # Add connection pool stats if available
            pool_stats: dict[str, Any] = {}
            if self.pool:
                pool_stats = {
                    "pool_size": self.pool.max_connections,
                    "pool_in_use": (
                        len(self.pool._in_use_connections)
                        if hasattr(self.pool, "_in_use_connections")
                        else 0
                    ),
                    "pool_available": (
                        len(self.pool._available_connections)
                        if hasattr(self.pool, "_available_connections")
                        else 0
                    ),
                }

            return {
                "enabled": True,
                "connected": True,
                "hits": hits,
                "misses": misses,
                "hit_rate": round(hit_rate, 2),
                "total_keys": total_keys,
                "memory_used": memory.get("used_memory_human", "0"),
                "memory_peak": memory.get("used_memory_peak_human", "0"),
                "evicted_keys": info.get("evicted_keys", 0),
                "expired_keys": info.get("expired_keys", 0),
                **pool_stats,  # Include pool statistics
                "uptime_seconds": info.get("uptime_in_seconds", 0),
            }
        except Exception as e:
            logger.error(f"Failed to get cache stats: {e}")
            return {"enabled": True, "connected": True, "error": str(e)}

    async def health_check(self) -> bool:
        """
        Perform a health check on the cache.

        Returns:
            True if healthy, False otherwise
        """
        if not self.enabled:
            return True  # Not enabled = not a problem

        try:
            if self.connected and self.client:
                await self.client.ping()
                return True
            else:
                # Try to reconnect
                return await self.connect()
        except Exception:
            return False


# Global cache instance - initialized once, used everywhere
cache_manager = CacheManager()
