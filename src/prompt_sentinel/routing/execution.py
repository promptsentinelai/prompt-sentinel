# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Routing execution helpers.

Encapsulates the logic for executing specific detection strategies and
optionally leveraging cache. This module is used by the router while
keeping router focused on selection and orchestration.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

import structlog

from prompt_sentinel.config.settings import settings
from prompt_sentinel.detection.detector import PromptDetector
from prompt_sentinel.models.schemas import DetectionResponse, Message, Verdict

from .types import DetectionStrategy

logger = structlog.get_logger()


class ExecutionEngine:
    """Executes detection based on routing strategy."""

    def __init__(self, detector: PromptDetector) -> None:
        self.detector = detector

    async def execute_strategy(
        self,
        messages: list[Message],
        strategy: DetectionStrategy,
        use_cache: bool,
        cache_key: str | None = None,
        cache_get: Callable[[str], Awaitable[dict | None]] | None = None,
        cache_set: Callable[[str, dict, int], Awaitable[None]] | None = None,
    ) -> DetectionResponse:
        """Execute a strategy with optional cache interaction supplied by caller."""
        # Cache lookup
        if use_cache and cache_key and cache_get:
            cached_result = await cache_get(cache_key)
            if cached_result:
                logger.debug("Cache hit for routed detection", strategy=strategy.value)
                return DetectionResponse(**cached_result)

        # Execute
        if strategy == DetectionStrategy.HEURISTIC_ONLY:
            response = await self._execute_heuristic_only(messages)
        elif strategy == DetectionStrategy.HEURISTIC_CACHED:
            response = await self._execute_heuristic_only(messages)
        elif strategy == DetectionStrategy.HEURISTIC_LLM_CACHED:
            response = await self._execute_heuristic_llm(messages)
        elif strategy == DetectionStrategy.HEURISTIC_LLM_PII:
            response = await self._execute_comprehensive(messages, include_pii=True)
        elif strategy == DetectionStrategy.FULL_ANALYSIS:
            response = await self._execute_full_analysis(messages)
        else:
            response = await self.detector.detect(messages)

        # Cache store
        if use_cache and cache_key and cache_set:
            try:
                await cache_set(cache_key, response.model_dump(), settings.cache_ttl_detection)
            except Exception as e:  # Best-effort
                logger.debug("Failed to cache routed detection result", error=str(e))

        return response

    async def _execute_heuristic_only(self, messages: list[Message]) -> DetectionResponse:
        return await self.detector.detect(
            messages, use_heuristics=True, use_llm=False, check_pii=False
        )

    async def _execute_heuristic_llm(self, messages: list[Message]) -> DetectionResponse:
        return await self.detector.detect(
            messages, use_heuristics=True, use_llm=True, check_pii=False
        )

    async def _execute_comprehensive(
        self, messages: list[Message], include_pii: bool = True
    ) -> DetectionResponse:
        return await self.detector.detect(
            messages, use_heuristics=True, use_llm=True, check_pii=include_pii
        )

    async def _execute_full_analysis(self, messages: list[Message]) -> DetectionResponse:
        tasks = [
            self.detector.detect(messages, use_heuristics=True, use_llm=False, check_pii=False),
            self.detector.detect(messages, use_heuristics=False, use_llm=True, check_pii=False),
            self.detector.detect(messages, use_heuristics=False, use_llm=False, check_pii=True),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_reasons: list[Any] = []
        max_confidence = 0.0
        most_severe_verdict = Verdict.ALLOW

        for result in results:
            if isinstance(result, Exception | BaseException):
                logger.error("Detection method failed", error=str(result))
                continue
            if hasattr(result, "reasons"):
                all_reasons.extend(result.reasons)
            if hasattr(result, "confidence"):
                max_confidence = max(max_confidence, result.confidence)
            if hasattr(result, "verdict"):
                if result.verdict == Verdict.BLOCK:
                    most_severe_verdict = Verdict.BLOCK
                elif result.verdict == Verdict.FLAG and most_severe_verdict != Verdict.BLOCK:
                    most_severe_verdict = Verdict.FLAG

        processing_time_ms = sum(
            float(r.processing_time_ms)
            for r in results
            if not isinstance(r, Exception) and hasattr(r, "processing_time_ms")
        )

        return DetectionResponse(
            verdict=most_severe_verdict,
            confidence=max_confidence,
            reasons=all_reasons,
            processing_time_ms=processing_time_ms,
        )
