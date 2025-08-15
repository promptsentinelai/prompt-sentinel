# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0

"""Detection result caching for improved performance."""

import hashlib
import json
import time
from typing import Any

import structlog

from prompt_sentinel.cache.cache_manager import CacheManager
from prompt_sentinel.models.schemas import (
    DetectionCategory,
    DetectionReason,
    Message,
    Verdict,
)

logger = structlog.get_logger()


class DetectionCache:
    """Cache for detection results to avoid redundant processing."""

    def __init__(self, cache_manager: CacheManager | None = None, ttl: int = 300):
        """
        Initialize detection cache.

        Args:
            cache_manager: Redis cache manager instance
            ttl: Time-to-live for cache entries in seconds (default: 5 minutes)
        """
        self.cache = cache_manager
        self.ttl = ttl
        self.stats = {
            "hits": 0,
            "misses": 0,
            "total_requests": 0,
            "cache_saves": 0,
            "cache_errors": 0,
        }
        self.enabled = cache_manager is not None

    def _generate_cache_key(self, messages: list[Message], mode: str = "default") -> str:
        """
        Generate cache key for detection request.

        Args:
            messages: Messages to detect
            mode: Detection mode (strict/moderate/permissive)

        Returns:
            Cache key string
        """
        # Create a stable hash of the messages
        content = json.dumps(
            [(m.role.value, m.content) for m in messages], sort_keys=True, separators=(",", ":")
        )
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]

        return f"detection:{mode}:{content_hash}"

    async def get(
        self, messages: list[Message], mode: str = "default"
    ) -> tuple[Verdict, list[DetectionReason], float] | None:
        """
        Get cached detection result.

        Args:
            messages: Messages to detect
            mode: Detection mode

        Returns:
            Cached result tuple or None if not found
        """
        self.stats["total_requests"] += 1

        if not self.enabled or not self.cache or not self.cache.connected:
            self.stats["misses"] += 1
            return None

        try:
            cache_key = self._generate_cache_key(messages, mode)
            cached_data = await self.cache.get(cache_key)

            if cached_data:
                self.stats["hits"] += 1
                data = json.loads(cached_data)

                # Reconstruct verdict
                verdict = Verdict(data["verdict"]) if data.get("verdict") else None

                # Reconstruct reasons
                reasons = []
                for r in data.get("reasons", []):
                    reasons.append(
                        DetectionReason(
                            category=DetectionCategory(r["category"]),
                            description=r["description"],
                            confidence=r["confidence"],
                            source=r.get("source", "cache"),
                        )
                    )

                confidence = data.get("confidence", 0.0)

                logger.debug("Cache hit", key=cache_key[:20], mode=mode)
                return verdict, reasons, confidence

        except Exception as e:
            logger.warning("Cache retrieval error", error=str(e))
            self.stats["cache_errors"] += 1

        self.stats["misses"] += 1
        return None

    async def set(
        self,
        messages: list[Message],
        mode: str,
        verdict: Verdict | None,
        reasons: list[DetectionReason],
        confidence: float,
    ) -> bool:
        """
        Cache detection result.

        Args:
            messages: Messages that were detected
            mode: Detection mode used
            verdict: Detection verdict
            reasons: Detection reasons
            confidence: Overall confidence

        Returns:
            True if cached successfully
        """
        if not self.enabled or not self.cache or not self.cache.connected:
            return False

        try:
            cache_key = self._generate_cache_key(messages, mode)

            # Serialize the result
            data = {
                "verdict": verdict.value if verdict else None,
                "reasons": [
                    {
                        "category": r.category.value,
                        "description": r.description,
                        "confidence": r.confidence,
                        "source": r.source,
                    }
                    for r in reasons
                ],
                "confidence": confidence,
                "cached_at": time.time(),
            }

            await self.cache.set(cache_key, json.dumps(data), ttl=self.ttl)
            self.stats["cache_saves"] += 1

            logger.debug("Cached detection result", key=cache_key[:20], mode=mode)
            return True

        except Exception as e:
            logger.warning("Cache storage error", error=str(e))
            self.stats["cache_errors"] += 1
            return False

    async def invalidate(self, pattern: str | None = None) -> int:
        """
        Invalidate cached entries.

        Args:
            pattern: Optional pattern to match keys (e.g., "detection:strict:*")

        Returns:
            Number of entries invalidated
        """
        if not self.enabled or not self.cache:
            return 0

        try:
            # Note: This would need implementation in CacheManager
            # to support pattern-based deletion
            if pattern:
                logger.info("Invalidating cache entries", pattern=pattern)
                # Would need to implement cache.delete_pattern(pattern)
                return 0
            else:
                # Clear all detection cache entries
                logger.info("Clearing all detection cache")
                # Would need to implement cache.clear_prefix("detection:")
                return 0

        except Exception as e:
            logger.error("Cache invalidation error", error=str(e))
            return 0

    def get_stats(self) -> dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary of cache statistics
        """
        total = self.stats["total_requests"]
        hit_rate = (self.stats["hits"] / total * 100) if total > 0 else 0

        return {
            **self.stats,
            "hit_rate": round(hit_rate, 2),
            "enabled": self.enabled,
            "ttl": self.ttl,
        }

    def reset_stats(self):
        """Reset cache statistics."""
        self.stats = {
            "hits": 0,
            "misses": 0,
            "total_requests": 0,
            "cache_saves": 0,
            "cache_errors": 0,
        }


class PatternCache:
    """Cache for compiled regex patterns."""

    def __init__(self):
        """Initialize pattern cache."""
        import re

        self.cache: dict[str, re.Pattern] = {}
        self.stats = {
            "compilations": 0,
            "cache_hits": 0,
        }

    def get_pattern(self, pattern: str, flags: int = 0) -> Any:
        """
        Get compiled pattern from cache or compile and cache it.

        Args:
            pattern: Regex pattern string
            flags: Regex compilation flags

        Returns:
            Compiled regex pattern
        """
        import re

        cache_key = f"{pattern}:{flags}"

        if cache_key in self.cache:
            self.stats["cache_hits"] += 1
            return self.cache[cache_key]

        # Compile and cache
        compiled = re.compile(pattern, flags)
        self.cache[cache_key] = compiled
        self.stats["compilations"] += 1

        return compiled

    def precompile_patterns(self, patterns: list[str], flags: int = 0):
        """
        Pre-compile a list of patterns.

        Args:
            patterns: List of regex patterns
            flags: Regex compilation flags
        """
        for pattern in patterns:
            if isinstance(pattern, str):
                self.get_pattern(pattern, flags)

    def clear(self):
        """Clear pattern cache."""
        self.cache.clear()
        logger.info("Pattern cache cleared", patterns_removed=len(self.cache))

    def get_stats(self) -> dict[str, Any]:
        """Get pattern cache statistics."""
        return {
            "patterns_cached": len(self.cache),
            "compilations": self.stats["compilations"],
            "cache_hits": self.stats["cache_hits"],
            "hit_rate": (
                self.stats["cache_hits"]
                / (self.stats["cache_hits"] + self.stats["compilations"])
                * 100
                if (self.stats["cache_hits"] + self.stats["compilations"]) > 0
                else 0
            ),
        }


# Global pattern cache instance
_pattern_cache = PatternCache()


def get_pattern_cache() -> PatternCache:
    """Get global pattern cache instance."""
    return _pattern_cache
