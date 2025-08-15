# Elastic License 2.0
#
# Copyright (c) 2024-present, PromptSentinel
#
# This source code is licensed under the Elastic License 2.0 found in the
# LICENSE file in the root directory of this source tree.

"""Optimized caching layer with performance enhancements."""

import asyncio
import time
from collections import OrderedDict
from typing import Any

import structlog
import xxhash

from prompt_sentinel.cache.cache_manager import CacheManager

logger = structlog.get_logger()


class OptimizedCache:
    """Enhanced caching with two-tier architecture and performance optimizations."""

    def __init__(self, redis_cache: CacheManager | None = None, max_memory_items: int = 1000):
        """
        Initialize optimized cache with memory and Redis tiers.

        Args:
            redis_cache: Optional Redis cache manager
            max_memory_items: Maximum items in memory cache
        """
        self.redis_cache = redis_cache
        self.memory_cache: OrderedDict[str, tuple[Any, float, float]] = OrderedDict()
        self.max_memory_items = max_memory_items
        self.stats = {
            "memory_hits": 0,
            "memory_misses": 0,
            "redis_hits": 0,
            "redis_misses": 0,
            "total_requests": 0,
        }

    def _generate_fast_key(self, content: str, prefix: str = "detect") -> str:
        """
        Generate cache key using xxHash for better performance.

        Args:
            content: Content to hash
            prefix: Key prefix for namespacing

        Returns:
            Cache key with format: prefix:hash
        """
        # Use xxHash for 3-5x faster hashing than MD5/SHA
        hasher = xxhash.xxh64()
        hasher.update(content.encode("utf-8"))
        return f"{prefix}:{hasher.hexdigest()[:16]}"

    def _evict_lru(self) -> None:
        """Evict least recently used item from memory cache."""
        if len(self.memory_cache) >= self.max_memory_items:
            # Remove oldest item (first in OrderedDict)
            self.memory_cache.popitem(last=False)

    async def get_multi_tier(
        self, key: str, compute_func: Any, ttl: int = 300, memory_ttl: int = 60
    ) -> Any:
        """
        Multi-tier cache lookup: memory -> Redis -> compute.

        Args:
            key: Cache key
            compute_func: Function to compute value if not cached
            ttl: Redis TTL in seconds
            memory_ttl: Memory cache TTL in seconds

        Returns:
            Cached or computed value
        """
        self.stats["total_requests"] += 1

        # Level 1: Memory cache (fastest)
        if key in self.memory_cache:
            value, expiry, _ = self.memory_cache[key]
            if time.time() < expiry:
                # Move to end to mark as recently used
                self.memory_cache.move_to_end(key)
                self.stats["memory_hits"] += 1
                logger.debug("Memory cache hit", key=key[:20])
                return value
            else:
                # Expired, remove it
                del self.memory_cache[key]

        self.stats["memory_misses"] += 1

        # Level 2: Redis cache (if available)
        if self.redis_cache and self.redis_cache.connected:
            try:
                cached = await self.redis_cache.get(key)
                if cached is not None:
                    self.stats["redis_hits"] += 1
                    logger.debug("Redis cache hit", key=key[:20])

                    # Store in memory cache
                    self._evict_lru()
                    self.memory_cache[key] = (cached, time.time() + memory_ttl, time.time())
                    return cached
            except Exception as e:
                logger.warning("Redis cache error", error=str(e))

        self.stats["redis_misses"] += 1

        # Level 3: Compute
        result = await compute_func()

        # Store in both caches
        await self._store_multi_tier(key, result, ttl, memory_ttl)

        return result

    async def _store_multi_tier(self, key: str, value: Any, ttl: int, memory_ttl: int) -> None:
        """Store value in both cache tiers."""
        # Store in memory cache
        self._evict_lru()
        self.memory_cache[key] = (value, time.time() + memory_ttl, time.time())

        # Store in Redis (async, don't wait)
        if self.redis_cache and self.redis_cache.connected:
            asyncio.create_task(self._store_redis_async(key, value, ttl))

    async def _store_redis_async(self, key: str, value: Any, ttl: int) -> None:
        """Store in Redis asynchronously without blocking."""
        if self.redis_cache is None:
            return
        try:
            await self.redis_cache.set(key, value, ttl)
        except Exception as e:
            logger.debug("Redis store failed", error=str(e))

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        total_hits = self.stats["memory_hits"] + self.stats["redis_hits"]
        total_requests = self.stats["total_requests"]

        return {
            **self.stats,
            "memory_size": len(self.memory_cache),
            "hit_rate": (total_hits / total_requests * 100) if total_requests > 0 else 0,
            "memory_hit_rate": (
                (self.stats["memory_hits"] / total_requests * 100) if total_requests > 0 else 0
            ),
        }

    def clear_memory_cache(self) -> None:
        """Clear memory cache."""
        self.memory_cache.clear()
        logger.info("Memory cache cleared")

    async def warm_cache(self, common_prompts: list[str]) -> None:
        """
        Pre-warm cache with common prompts.

        Args:
            common_prompts: List of common prompts to cache
        """
        logger.info("Warming cache", count=len(common_prompts))

        for prompt in common_prompts:
            key = self._generate_fast_key(prompt)
            # Check if already cached
            if key not in self.memory_cache:
                # You would compute the detection result here
                # For now, just mark as warmed
                self.memory_cache[key] = (
                    {"warmed": True, "prompt": prompt[:50]},
                    time.time() + 3600,  # 1 hour
                    time.time(),
                )


class BatchCache:
    """Optimized caching for batch operations."""

    def __init__(self, cache: OptimizedCache):
        """Initialize batch cache."""
        self.cache = cache
        self.pending_computations: dict[str, asyncio.Future] = {}

    async def get_or_compute_batch(
        self, items: list[tuple[str, Any]], compute_func: Any, ttl: int = 300
    ) -> list[Any]:
        """
        Batch cache lookup with request coalescing.

        Args:
            items: List of (key, item) tuples
            compute_func: Function to compute missing items
            ttl: Cache TTL

        Returns:
            List of results in same order as input
        """
        results = [None] * len(items)
        missing_indices = []
        missing_items = []

        # Check cache for each item
        for i, (key, item) in enumerate(items):
            # Check if computation already pending
            if key in self.pending_computations:
                # Wait for pending computation
                results[i] = await self.pending_computations[key]
            else:
                # Try cache
                cached = await self.cache.get_multi_tier(
                    key,
                    lambda: None,
                    ttl,  # Don't compute yet
                )
                if cached is not None:
                    results[i] = cached
                else:
                    missing_indices.append(i)
                    missing_items.append(item)

        # Compute missing items in batch
        if missing_items:
            # Create futures for pending computations
            futures: dict[str, asyncio.Future[Any]] = {}
            for _idx, (key, _) in enumerate([items[i] for i in missing_indices]):
                futures[key] = asyncio.Future()
                self.pending_computations[key] = futures[key]

            try:
                # Compute all missing items at once
                computed_results = await compute_func(missing_items)

                # Store results and resolve futures
                for idx, result in enumerate(computed_results):
                    original_idx = missing_indices[idx]
                    key = items[original_idx][0]

                    results[original_idx] = result
                    await self.cache._store_multi_tier(key, result, ttl, 60)

                    # Resolve future for any waiting requests
                    if key in futures:
                        futures[key].set_result(result)
            finally:
                # Clean up pending computations
                for key in futures:
                    self.pending_computations.pop(key, None)

        return results
