# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Cache management module for PromptSentinel.

Provides optional Redis caching to improve performance and reduce LLM API costs.
The system works perfectly without Redis - caching is purely an optimization.
"""

from prompt_sentinel.cache.cache_manager import CacheManager, cache_manager

__all__ = ["CacheManager", "cache_manager"]
