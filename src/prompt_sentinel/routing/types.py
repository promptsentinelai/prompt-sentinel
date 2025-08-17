# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Shared routing types to avoid circular imports."""

from enum import Enum


class DetectionStrategy(Enum):
    """Detection strategies with different performance/accuracy tradeoffs."""

    HEURISTIC_ONLY = "heuristic_only"  # Fastest, pattern matching only
    HEURISTIC_CACHED = "heuristic_cached"  # Fast with cache lookup
    HEURISTIC_LLM_CACHED = "heuristic_llm_cached"  # Balanced with cache
    HEURISTIC_LLM_PII = "heuristic_llm_pii"  # Comprehensive
    FULL_ANALYSIS = "full_analysis"  # Complete analysis, all methods
