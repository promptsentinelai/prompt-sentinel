# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Routing strategy selection utilities.

Encapsulates the logic for determining detection strategies based on
complexity scores and feature flags, and loading strategy configuration.
"""

from __future__ import annotations

from typing import Any

from .complexity_analyzer import ComplexityLevel, ComplexityScore, RiskIndicator
from .types import DetectionStrategy


class StrategySelector:
    """Selects routing strategies based on complexity and capabilities."""

    def __init__(self) -> None:
        self._config: dict[str, Any] = self._load_strategy_config()

        # Performance targets (milliseconds) — kept in router, but some callers may read here
        self.latency_targets = {
            DetectionStrategy.HEURISTIC_ONLY: 10,
            DetectionStrategy.HEURISTIC_CACHED: 15,
            DetectionStrategy.HEURISTIC_LLM_CACHED: 50,
            DetectionStrategy.HEURISTIC_LLM_PII: 500,
            DetectionStrategy.FULL_ANALYSIS: 2000,
        }

    def determine_strategy(
        self,
        complexity_score: ComplexityScore,
        performance_mode: bool,
        llm_enabled: bool,
        pii_enabled: bool,
    ) -> tuple[DetectionStrategy, str]:
        """Determine optimal detection strategy and reasoning.

        External flags are passed in to avoid tight coupling on settings.
        """

        if performance_mode:
            if complexity_score.level == ComplexityLevel.TRIVIAL:
                return DetectionStrategy.HEURISTIC_ONLY, "Performance mode: trivial complexity"
            if complexity_score.level == ComplexityLevel.SIMPLE:
                return DetectionStrategy.HEURISTIC_CACHED, "Performance mode: simple complexity"
            if complexity_score.level == ComplexityLevel.MODERATE:
                return (
                    DetectionStrategy.HEURISTIC_LLM_CACHED,
                    "Performance mode: moderate complexity",
                )
            return (
                DetectionStrategy.HEURISTIC_LLM_PII,
                "Performance mode: high complexity requires analysis",
            )

        strategy_map = {
            ComplexityLevel.TRIVIAL: DetectionStrategy.HEURISTIC_CACHED,
            ComplexityLevel.SIMPLE: DetectionStrategy.HEURISTIC_CACHED,
            ComplexityLevel.MODERATE: DetectionStrategy.HEURISTIC_LLM_CACHED,
            ComplexityLevel.COMPLEX: DetectionStrategy.HEURISTIC_LLM_PII,
            ComplexityLevel.CRITICAL: DetectionStrategy.FULL_ANALYSIS,
        }

        strategy = strategy_map[complexity_score.level]

        critical_risks = {
            RiskIndicator.INSTRUCTION_OVERRIDE,
            RiskIndicator.CODE_INJECTION,
            RiskIndicator.ROLE_MANIPULATION,
        }

        if any(risk in critical_risks for risk in complexity_score.risk_indicators):
            if strategy.value < DetectionStrategy.HEURISTIC_LLM_PII.value:
                strategy = DetectionStrategy.HEURISTIC_LLM_PII
                return strategy, f"Elevated to {strategy.value} due to critical risk indicators"

        if not llm_enabled and strategy in (
            DetectionStrategy.HEURISTIC_LLM_CACHED,
            DetectionStrategy.HEURISTIC_LLM_PII,
            DetectionStrategy.FULL_ANALYSIS,
        ):
            return (
                DetectionStrategy.HEURISTIC_ONLY,
                "LLM classification disabled, using heuristic only",
            )

        if not pii_enabled and strategy == DetectionStrategy.HEURISTIC_LLM_PII:
            return (
                DetectionStrategy.HEURISTIC_LLM_CACHED,
                "PII detection disabled, using cached LLM strategy",
            )

        return (
            strategy,
            f"Standard routing: {complexity_score.level.value} complexity → {strategy.value}",
        )

    def is_cache_eligible(
        self,
        strategy: DetectionStrategy,
        complexity_score: ComplexityScore,
        redis_enabled: bool,
        cache_connected: bool,
    ) -> bool:
        """Decide cache eligibility given environment flags."""
        if not redis_enabled or not cache_connected:
            return False
        if strategy == DetectionStrategy.HEURISTIC_ONLY:
            return False
        if RiskIndicator.ENCODING in complexity_score.risk_indicators:
            return False
        return strategy in (
            DetectionStrategy.HEURISTIC_CACHED,
            DetectionStrategy.HEURISTIC_LLM_CACHED,
            DetectionStrategy.HEURISTIC_LLM_PII,
        )

    def _load_strategy_config(self) -> dict:
        return {
            "performance_thresholds": {
                "low_latency": 50,
                "medium_latency": 500,
                "high_latency": 2000,
            },
            "complexity_overrides": {},
        }

    @property
    def config(self) -> dict[str, Any]:
        return self._config
