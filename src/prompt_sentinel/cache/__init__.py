"""Cache management module for PromptSentinel.

Provides optional Redis caching to improve performance and reduce LLM API costs.
The system works perfectly without Redis - caching is purely an optimization.
"""

from prompt_sentinel.cache.cache_manager import CacheManager, cache_manager

__all__ = ["CacheManager", "cache_manager"]