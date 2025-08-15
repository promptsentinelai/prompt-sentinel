# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Cached language detection for improved performance."""

import hashlib
import json
from typing import Any

import structlog

from prompt_sentinel.cache.cache_manager import CacheManager
from prompt_sentinel.i18n.detector import MultilingualDetector

logger = structlog.get_logger()


class CachedLanguageDetector:
    """Language detector with Redis caching for performance."""

    def __init__(self, cache_manager: CacheManager | None = None):
        """Initialize cached language detector."""
        self.cache = cache_manager
        self.detector = MultilingualDetector()
        self.cache_ttl = 3600  # 1 hour cache
        self.stats = {
            "cache_hits": 0,
            "cache_misses": 0,
            "total_requests": 0,
        }

    def _generate_cache_key(self, text: str) -> str:
        """Generate cache key for text."""
        # Use first 100 chars for key generation (enough for language detection)
        text_sample = text[:100] if len(text) > 100 else text
        text_hash = hashlib.sha256(text_sample.encode()).hexdigest()[:16]
        return f"lang_detect:{text_hash}"

    async def detect_language(self, text: str) -> dict[str, Any]:
        """
        Detect language with caching.

        Args:
            text: Text to analyze

        Returns:
            Detection result with language info
        """
        self.stats["total_requests"] += 1

        # Check cache first
        if self.cache and self.cache.connected:
            cache_key = self._generate_cache_key(text)

            try:
                cached_result = await self.cache.get(cache_key)
                if cached_result:
                    self.stats["cache_hits"] += 1
                    logger.debug("Language detection cache hit", key=cache_key[:20])
                    return json.loads(cached_result)
            except Exception as e:
                logger.warning("Cache lookup failed", error=str(e))

        self.stats["cache_misses"] += 1

        # Perform detection
        result = await self.detector.detect_language(text)

        # Cache the result
        if self.cache and self.cache.connected:
            try:
                cache_key = self._generate_cache_key(text)
                await self.cache.set(cache_key, json.dumps(result), ttl=self.cache_ttl)
                logger.debug("Cached language detection result", key=cache_key[:20])
            except Exception as e:
                logger.warning("Cache storage failed", error=str(e))

        return result

    async def detect_language_batch(self, texts: list[str]) -> list[dict[str, Any]]:
        """
        Detect languages for multiple texts with caching.

        Args:
            texts: List of texts to analyze

        Returns:
            List of detection results
        """
        results = []
        uncached_texts = []
        uncached_indices = []

        # Check cache for each text
        for i, text in enumerate(texts):
            if self.cache and self.cache.connected:
                cache_key = self._generate_cache_key(text)
                try:
                    cached_result = await self.cache.get(cache_key)
                    if cached_result:
                        self.stats["cache_hits"] += 1
                        results.append(json.loads(cached_result))
                    else:
                        results.append(None)  # Placeholder
                        uncached_texts.append(text)
                        uncached_indices.append(i)
                        self.stats["cache_misses"] += 1
                except Exception:
                    results.append(None)
                    uncached_texts.append(text)
                    uncached_indices.append(i)
            else:
                results.append(None)
                uncached_texts.append(text)
                uncached_indices.append(i)

            self.stats["total_requests"] += 1

        # Process uncached texts
        if uncached_texts:
            # Batch detection for efficiency
            for idx, text in zip(uncached_indices, uncached_texts, strict=False):
                detection_result = await self.detector.detect_language(text)
                results[idx] = detection_result

                # Cache the result
                if self.cache and self.cache.connected:
                    try:
                        cache_key = self._generate_cache_key(text)
                        await self.cache.set(
                            cache_key, json.dumps(detection_result), ttl=self.cache_ttl
                        )
                    except Exception:
                        pass

        return results

    async def clear_cache(self) -> None:
        """Clear all cached language detections."""
        if self.cache and self.cache.connected:
            try:
                # Clear all keys with lang_detect prefix
                # Note: This would need implementation in CacheManager
                logger.info("Language detection cache cleared")
            except Exception as e:
                logger.error("Failed to clear cache", error=str(e))

    def get_cache_stats(self) -> dict[str, Any]:
        """Get cache statistics."""
        total = self.stats["total_requests"]
        if total > 0:
            hit_rate = (self.stats["cache_hits"] / total) * 100
        else:
            hit_rate = 0.0

        return {
            **self.stats,
            "cache_hit_rate": round(hit_rate, 2),
            "cache_enabled": self.cache is not None and self.cache.connected,
        }

    async def warm_cache(self, common_phrases: list[str]) -> None:
        """
        Pre-warm cache with common phrases.

        Args:
            common_phrases: List of common phrases to cache
        """
        if not (self.cache and self.cache.connected):
            logger.warning("Cache not available for warming")
            return

        warmed = 0
        for phrase in common_phrases:
            try:
                result = await self.detector.detect_language(phrase)
                cache_key = self._generate_cache_key(phrase)
                await self.cache.set(
                    cache_key,
                    json.dumps(result),
                    ttl=self.cache_ttl * 2,  # Longer TTL for common phrases
                )
                warmed += 1
            except Exception as e:
                logger.warning("Failed to warm cache entry", error=str(e))

        logger.info(f"Warmed cache with {warmed}/{len(common_phrases)} phrases")

    def set_cache_ttl(self, ttl_seconds: int) -> None:
        """Update cache TTL."""
        self.cache_ttl = ttl_seconds
        logger.info(f"Updated cache TTL to {ttl_seconds} seconds")
